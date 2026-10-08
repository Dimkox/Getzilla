from __future__ import annotations

import contextlib
import json
import os
import re
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path

AGENTS = ('qwen', 'codex', 'claude', 'gemini', 'copilot', 'grok')
NATIVE_ONLY = frozenset({'gemini', 'copilot', 'grok'})
AGENT_KEY_ENV = {'gemini': 'GEMINI_API_KEY', 'copilot': 'COPILOT_GITHUB_TOKEN'}
PROVIDERS = ('openrouter', 'native')
DEFAULT_AGENT = 'qwen'
DEFAULT_PROVIDER = 'openrouter'
OPENROUTER_BASE_URL = 'https://openrouter.ai/api/v1'
OPENROUTER_ANTHROPIC_URL = 'https://openrouter.ai/api'
KEY_ENV = 'OPENROUTER_API_KEY'
DEFAULT_MODELS = {
    'qwen': 'qwen/qwen3-coder',
    'codex': 'openai/gpt-5.5',
}
NATIVE_LOGIN = {
    'qwen': "run 'qwen' and pick Qwen OAuth (or another provider) at the first prompt",
    'codex': "run 'codex login' and sign in with your ChatGPT account",
    'claude': "run 'claude' and sign in with your Anthropic account",
    'gemini': "run 'gemini' and sign in with Google (or set GEMINI_API_KEY)",
    'copilot': "run 'copilot' and type /login to sign in with GitHub (or set COPILOT_GITHUB_TOKEN)",
    'grok': "run 'grok' and sign in with your xAI account",
}
PROFILE_MARKER = '# Getzilla: model keys for coding agents'
ENV_FILE = '.getzilla/openrouter.env'
CLAUDE_TOKEN_ENV = 'ANTHROPIC_AUTH_TOKEN'  # nosec B105
NEW_TERMINAL = 'open a new terminal so the agent sees OPENROUTER_API_KEY'
_KEY_SHAPE = re.compile(r'^[A-Za-z0-9._\-]{16,512}$')


@dataclass(frozen=True)
class SetupResult:
    written: tuple[str, ...]
    next_steps: tuple[str, ...]


def validate_key(key: str, *, label: str = 'the OpenRouter key') -> str:
    key = key.strip()
    if not _KEY_SHAPE.match(key):
        raise ValueError(f'{label} must be 16-512 letters, digits, dots, dashes or underscores')
    return key


def _write_private(path: Path, content: str) -> None:
    """Atomically write an owner-only file, writing through a symlinked dotfile."""
    if path.is_symlink():
        path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f'.{path.name}.', suffix='.getzilla-tmp', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as handle:
            handle.write(content)
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise


def _load_json_object(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f'{path} is not plain JSON (comments are not supported here): {exc}; fix or move it, then run the setup again'
        ) from None
    if not isinstance(data, dict):
        raise ValueError(f'{path} is not a JSON object; fix or move it, then run the setup again')
    return data


def _object_at(data: dict, key: str, path: Path) -> dict:
    value = data.setdefault(key, {})
    if not isinstance(value, dict):
        raise ValueError(f'{path}: "{key}" is not an object; fix or move the file, then run the setup again')
    return value


def _dump_json(data: dict) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False) + '\n'


def _is_openrouter_entry(entry: object) -> bool:
    return isinstance(entry, dict) and entry.get('baseUrl') == OPENROUTER_BASE_URL


def _configure_qwen(home: Path, model: str, key: str) -> list[str]:
    settings_path = home / '.qwen/settings.json'
    settings = _load_json_object(settings_path)
    providers = _object_at(settings, 'modelProviders', settings_path)
    existing = providers.get('openai', [])
    if not isinstance(existing, list):
        raise ValueError(f'{settings_path}: "modelProviders.openai" is not a list; fix or move the file, then run the setup again')
    openai = [entry for entry in existing if not (_is_openrouter_entry(entry) and entry.get('id') == model)]
    openai.insert(0, {'id': model, 'name': f'{model} (OpenRouter)', 'envKey': KEY_ENV, 'baseUrl': OPENROUTER_BASE_URL})
    providers['openai'] = openai
    _object_at(_object_at(settings, 'security', settings_path), 'auth', settings_path)['selectedType'] = 'openai'
    _object_at(settings, 'model', settings_path)['name'] = model
    written = _store_env(home, {KEY_ENV: key})
    _write_private(settings_path, _dump_json(settings))
    return [*written, str(settings_path)]


def _unconfigure_qwen(home: Path) -> list[str]:
    settings_path = home / '.qwen/settings.json'
    settings = _load_json_object(settings_path)
    providers = settings.get('modelProviders')
    openai = providers.get('openai') if isinstance(providers, dict) else None
    if not isinstance(openai, list):
        return []
    ours = {entry.get('id') for entry in openai if _is_openrouter_entry(entry)}
    if not ours:
        return []
    providers['openai'] = [entry for entry in openai if not _is_openrouter_entry(entry)]
    model = settings.get('model')
    if isinstance(model, dict) and model.get('name') in ours:
        model.pop('name')
        auth = settings.get('security', {}).get('auth') if isinstance(settings.get('security'), dict) else None
        if isinstance(auth, dict) and auth.get('selectedType') == 'openai':
            auth.pop('selectedType')
    _write_private(settings_path, _dump_json(settings))
    return [str(settings_path)]


_CLAUDE_OPENROUTER_ENV = ('ANTHROPIC_BASE_URL', CLAUDE_TOKEN_ENV, 'ANTHROPIC_API_KEY')


def _configure_claude(home: Path, key: str) -> list[str]:
    settings_path = home / '.claude/settings.json'
    settings = _load_json_object(settings_path)
    env = _object_at(settings, 'env', settings_path)
    env.pop(CLAUDE_TOKEN_ENV, None)
    env.update({'ANTHROPIC_BASE_URL': OPENROUTER_ANTHROPIC_URL, 'ANTHROPIC_API_KEY': ''})
    written = _store_env(home, {KEY_ENV: key, CLAUDE_TOKEN_ENV: key})
    _write_private(settings_path, _dump_json(settings))
    return [*written, str(settings_path)]


def _unconfigure_claude(home: Path) -> list[str]:
    settings_path = home / '.claude/settings.json'
    settings = _load_json_object(settings_path)
    env = settings.get('env')
    removed = _store_env(home, {}, remove=(CLAUDE_TOKEN_ENV,))
    if not isinstance(env, dict) or env.get('ANTHROPIC_BASE_URL') != OPENROUTER_ANTHROPIC_URL:
        return removed
    for name in _CLAUDE_OPENROUTER_ENV:
        env.pop(name, None)
    _write_private(settings_path, _dump_json(settings))
    return [*removed, str(settings_path)]


_TABLE_HEADER = re.compile(r'^\s*\[')


def _split_top_level(text: str) -> tuple[list[str], list[str]]:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if _TABLE_HEADER.match(line):
            return lines[:index], lines[index:]
    return lines, []


def _toml_key(line: str, name: str) -> bool:
    return re.match(rf'^\s*{re.escape(name)}\s*=', line) is not None


def _read_exact(path: Path) -> str:
    if not path.is_file():
        return ''
    with path.open(encoding='utf-8', newline='') as handle:
        return handle.read()


def _load_toml(text: str, path: Path) -> dict:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f'{path} is not valid TOML ({exc}); fix or move it, then run the setup again') from None


def _configure_codex(home: Path, model: str, key: str) -> tuple[list[str], list[str]]:
    config_path = home / '.codex/config.toml'
    original = _read_exact(config_path)
    current = _load_toml(original, config_path)
    steps: list[str] = []
    top, tables = _split_top_level(original)
    provider = current.get('model_provider')
    if provider not in (None, 'openrouter'):
        steps.append(
            f'{config_path} already uses model_provider = "{provider}"; change it to "openrouter" to use OpenRouter'
        )
    else:
        top = [line for line in top if not (_toml_key(line, 'model_provider') or _toml_key(line, 'model'))]
        top = ['model_provider = "openrouter"', f'model = "{model}"', *top]
    providers = current.get('model_providers', {})
    if not isinstance(providers, dict):
        raise ValueError(f'{config_path}: model_providers is not a table')
    if 'openrouter' not in providers:
        if any(_toml_key(line, 'model_providers') for line in top):
            raise ValueError(
                f'{config_path} declares model_providers inline; add an openrouter entry there '
                f'(base_url = "{OPENROUTER_BASE_URL}", env_key = "{KEY_ENV}"), then run the setup again'
            )
        tables = [*tables, '', '[model_providers.openrouter]', 'name = "OpenRouter"',
                  f'base_url = "{OPENROUTER_BASE_URL}"', f'env_key = "{KEY_ENV}"', 'wire_api = "responses"']
    while top and not top[-1].strip():
        top.pop()
    text = '\n'.join([*top, *([''] if tables and top else []), *tables]).strip('\n') + '\n'
    _check_codex_edit(current, text, config_path, set_model=provider in (None, 'openrouter'), model=model)
    written = []
    backup = config_path.with_name('config.toml.getzilla-backup')
    if original and text != original and not backup.exists():
        _write_private(backup, original)
        written.append(str(backup))
    _write_private(config_path, text)
    written.append(str(config_path))
    written.extend(_store_env(home, {KEY_ENV: key}))
    return written, steps


def _check_codex_edit(before: dict, text: str, path: Path, *, set_model: bool, model: str) -> None:
    expected = json.loads(json.dumps(before))
    if set_model:
        expected['model_provider'] = 'openrouter'
        expected['model'] = model
    expected.setdefault('model_providers', {}).setdefault('openrouter', {
        'name': 'OpenRouter', 'base_url': OPENROUTER_BASE_URL, 'env_key': KEY_ENV, 'wire_api': 'responses',
    })
    try:
        after = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        after = None
    if after != expected:
        raise ValueError(
            f'{path} has a layout this setup cannot edit safely; nothing was changed. Add these lines yourself: '
            f'model_provider = "openrouter", model = "{model}" at the top, and a [model_providers.openrouter] table '
            f'with base_url = "{OPENROUTER_BASE_URL}", env_key = "{KEY_ENV}", wire_api = "responses"'
        )


def _shell_profiles(home: Path) -> list[Path]:
    shell = os.environ.get('SHELL', '')
    profiles = [home / '.bashrc']
    if sys.platform == 'darwin' or shell.endswith('zsh') or (home / '.zshrc').exists():
        profiles.append(home / '.zshrc')
    for login in ('.bash_profile', '.profile'):
        if (home / login).exists():
            profiles.append(home / login)
    return profiles


_ENV_LINE = re.compile(r"^export ([A-Z_][A-Z0-9_]*)='([^']*)'$")


def _read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if path.is_file():
        for line in path.read_text(encoding='utf-8').splitlines():
            match = _ENV_LINE.match(line.strip())
            if match:
                values[match.group(1)] = match.group(2)
    return values


def _store_env(home: Path, values: dict[str, str], *, remove: tuple[str, ...] = ()) -> list[str]:
    """Keep model keys as user environment variables every agent process inherits.

    POSIX: `~/.getzilla/openrouter.env` (owner-only) exported from the shell
    profiles. Windows: persistent user environment variables.
    """
    changed: list[str] = []
    if os.name == 'nt':
        for name, value in values.items():
            _set_windows_user_env(name, value)
            changed.append(f'user environment variable {name}')
        for name in remove:
            if _clear_windows_user_env(name):
                changed.append(f'removed user environment variable {name}')
        return changed
    env_path = home / ENV_FILE
    current = _read_env_file(env_path)
    merged = {**current, **values}
    for name in remove:
        merged.pop(name, None)
    if merged == current and (merged or not env_path.exists()):
        if merged:
            changed.extend(_ensure_profiles(home))
        return changed
    if merged:
        _write_private(env_path, ''.join(f"export {name}='{value}'\n" for name, value in sorted(merged.items())))
        changed.append(str(env_path))
        changed.extend(_ensure_profiles(home))
    else:
        env_path.unlink(missing_ok=True)
        changed.append(f'removed {env_path}')
        changed.extend(_remove_profiles(home))
    return changed


def _ensure_profiles(home: Path) -> list[str]:
    changed = []
    for profile in _shell_profiles(home):
        current = profile.read_text(encoding='utf-8') if profile.exists() else ''
        if PROFILE_MARKER not in current:
            with profile.open('a', encoding='utf-8') as handle:
                handle.write(f'\n{PROFILE_MARKER}\n[ -f "$HOME/{ENV_FILE}" ] && . "$HOME/{ENV_FILE}"\n')
            changed.append(str(profile))
    return changed


def _remove_profiles(home: Path) -> list[str]:
    changed = []
    for profile in (home / '.bashrc', home / '.zshrc', home / '.bash_profile', home / '.profile'):
        if not profile.is_file():
            continue
        lines = profile.read_text(encoding='utf-8').splitlines(keepends=True)
        kept: list[str] = []
        skip_next = False
        for line in lines:
            if line.strip() == PROFILE_MARKER:
                skip_next = True
                if kept and not kept[-1].strip():
                    kept.pop()
                continue
            if skip_next and ENV_FILE in line:
                skip_next = False
                continue
            skip_next = False
            kept.append(line)
        if kept != lines:
            _write_private(profile, ''.join(kept))
            changed.append(str(profile))
    return changed


def forget_key(home: Path) -> SetupResult:
    names = (KEY_ENV, CLAUDE_TOKEN_ENV, *AGENT_KEY_ENV.values())
    return SetupResult(tuple(_store_env(home, {}, remove=names)), ())


def _unconfigure_codex(home: Path) -> list[str]:
    removed: list[str] = []
    config_path = home / '.codex/config.toml'
    if not config_path.is_file():
        return removed
    original = _read_exact(config_path)
    if _load_toml(original, config_path).get('model_provider') != 'openrouter':
        return removed
    top, tables = _split_top_level(original)
    top = [line for line in top if not (_toml_key(line, 'model_provider') or (_toml_key(line, 'model') and '/' in line))]
    text = '\n'.join([*top, *tables]).strip('\n') + '\n'
    after = _load_toml(text, config_path)
    if 'model_provider' in after:
        raise ValueError(f'{config_path}: remove model_provider = "openrouter" yourself; nothing was changed')
    _write_private(config_path, text)
    return [*removed, str(config_path)]


def _set_windows_user_env(name: str, value: str) -> None:
    import ctypes
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Environment', 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
    result = ctypes.c_ulong()
    ctypes.windll.user32.SendMessageTimeoutW(0xFFFF, 0x001A, 0, 'Environment', 0x0002, 5000, ctypes.byref(result))


def _clear_windows_user_env(name: str) -> bool:
    import ctypes
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Environment', 0, winreg.KEY_SET_VALUE) as key:
        try:
            winreg.DeleteValue(key, name)
        except FileNotFoundError:
            return False
    result = ctypes.c_ulong()
    ctypes.windll.user32.SendMessageTimeoutW(0xFFFF, 0x001A, 0, 'Environment', 0x0002, 5000, ctypes.byref(result))
    return True


def configure(agent: str, provider: str, home: Path, *, key: str | None, model: str | None = None) -> SetupResult:
    if agent not in AGENTS:
        raise ValueError(f'unknown agent {agent!r}; choose one of {", ".join(AGENTS)}')
    if provider not in PROVIDERS:
        raise ValueError(f'unknown provider {provider!r}; choose one of {", ".join(PROVIDERS)}')
    if agent in NATIVE_ONLY:
        if agent in AGENT_KEY_ENV and key:
            written = _store_env(home, {AGENT_KEY_ENV[agent]: validate_key(key, label=AGENT_KEY_ENV[agent])})
            return SetupResult(tuple(written), (f'open a new terminal so the agent sees {AGENT_KEY_ENV[agent]}',
                                                f"run '{agent}' in your project"))
        return SetupResult((), (NATIVE_LOGIN[agent],))
    if provider == 'native':
        undo = {'qwen': _unconfigure_qwen, 'claude': _unconfigure_claude, 'codex': _unconfigure_codex}[agent]
        return SetupResult(tuple(undo(home)), (NATIVE_LOGIN[agent],))
    if not key:
        return SetupResult((), (
            'create a key at https://openrouter.ai/keys, then run: '
            f'python3 scripts/getzilla_setup_agent.py --agent {agent} --provider openrouter (it asks for the key)',
        ))
    key = validate_key(key)
    chosen = model or DEFAULT_MODELS.get(agent)
    if agent == 'qwen':
        return SetupResult(tuple(_configure_qwen(home, chosen, key)), (NEW_TERMINAL, "run 'qwen' in your project"))
    if agent == 'claude':
        return SetupResult(tuple(_configure_claude(home, key)), (
            NEW_TERMINAL, "run 'claude' in your project; if you were signed in to Anthropic before, run /logout once",
        ))
    written, steps = _configure_codex(home, chosen, key)
    return SetupResult(tuple(written), (*steps, NEW_TERMINAL, "run 'codex' in your project"))


def read_key(stream=None) -> str | None:
    stream = stream or sys.stdin
    value = stream.readline().strip()
    return value or None
