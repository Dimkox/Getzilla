from __future__ import annotations

import json
import os
import re
import secrets
import tomllib
from contextlib import contextmanager, suppress
from pathlib import Path, PurePosixPath
from typing import Iterator

from getzilla import fsx  # absolute like install_into.py; FIT-BOUNDED-WORKER-JOBS misreads `from . import fsx`

HARNESSES = ('qwen', 'claude', 'codex', 'gemini', 'copilot', 'grok')
CURSOR_OUTPUT = '.cursor/rules/getzilla'
GENERATED_ROOTS = ('.qwen', '.claude', '.codex', '.gemini', '.github/hooks', '.github/agents', CURSOR_OUTPUT)
HOOK_SOURCE = '.grok/hooks.json'
AGENT_SOURCE = '.grok/agents'
SKILL_SOURCE = '.agents/skills'
CURSOR_SOURCE = '.grok/cursor-rules'
CURSOR_MARKER = '<!-- Generated from .grok/cursor-rules/'  # marks the files Getzilla owns in .cursor/rules
CURSOR_KEYS = frozenset({'description', 'always_apply', 'globs', 'instructions'})
CURSOR_BUDGET = {True: 4096, False: 8192}  # bytes per always-applied core / per scoped rule
# Cursor splits `globs` on commas (https://cursor.com/docs/context/rules), so a pattern
# may not contain a comma, brace list, quote or whitespace.
_CURSOR_GLOB = re.compile(r'(?!/)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9_.*?/!\[\]-]+')
CODEX_HOOK_EVENTS = ('SessionStart', 'UserPromptSubmit', 'PreToolUse', 'PostToolUse', 'Stop')
GEMINI_EVENTS = {
    'SessionStart': 'SessionStart',
    'UserPromptSubmit': 'BeforeAgent',
    'PreToolUse': 'BeforeTool',
    'PostToolUse': 'AfterTool',
    'PreCompact': 'PreCompress',
    'Stop': 'AfterAgent',
    'SessionEnd': 'SessionEnd',
}
COPILOT_EVENTS = {
    'SessionStart': 'sessionStart',
    'UserPromptSubmit': 'userPromptSubmitted',
    'PreToolUse': 'preToolUse',
    'PostToolUse': 'postToolUse',
    'SessionEnd': 'sessionEnd',
}
COPILOT_HOOKS = '.github/hooks/getzilla.json'
QWEN_READ_ONLY_BLOCK = ('write_file', 'edit')
COPILOT_READ_ONLY_TOOLS = ('read', 'search', 'shell')
CLAUDE_READ_ONLY_TOOLS = ('Read', 'Grep', 'Glob', 'Bash', 'WebFetch', 'WebSearch')
LOCAL_FILES = frozenset({'settings.local.json', 'CLAUDE.local.md', '.env'})
_SCRIPT = re.compile(r'\.grok/hooks/([A-Za-z0-9_]+\.py)')


def _hook_events(root: Path) -> list[tuple[str, str, int]]:
    data = json.loads((root / HOOK_SOURCE).read_text(encoding='utf-8'))
    events: list[tuple[str, str, int]] = []
    for event, groups in data['hooks'].items():
        for group in groups:
            for hook in group['hooks']:
                match = _SCRIPT.search(hook['command'])
                if match is None:
                    raise ValueError(f'{HOOK_SOURCE}: {event} names no .grok/hooks script')
                events.append((event, match.group(1), int(hook.get('timeout', 60))))
    return events


def _command(script: str, harness: str) -> str:
    """A launcher that runs the project's own hook wherever the agent was started.

    The project directory the agent reports (CLAUDE_PROJECT_DIR, QWEN_PROJECT_DIR or
    GEMINI_PROJECT_DIR) wins; otherwise the outermost `.grok/hooks/<script>` above the
    working directory is used, so a hook planted in a subdirectory can never replace
    the project's. A relative path would also fail from a subdirectory with exit code
    2, which Claude-compatible agents treat as a blocking error. The hook learns which
    agent launched it through --harness. Only single quotes are used inside, so the
    same text works in sh, cmd and PowerShell.
    """
    target = f".grok/hooks/{script}"
    code = (
        "import os,pathlib,runpy,sys;"
        f"t='{target}';"
        "p=pathlib.Path;"
        "d=p.cwd();"
        "e=[p(os.environ[k]) for k in ('CLAUDE_PROJECT_DIR','QWEN_PROJECT_DIR','GEMINI_PROJECT_DIR') if os.environ.get(k)];"
        "f=next(q/t for q in (*e,*reversed(d.parents),d) if (q/t).is_file());"
        "sys.path.insert(0,str(f.parent));"
        f"sys.argv=[str(f),'--harness','{harness}'];"
        "runpy.run_path(str(f),run_name='__main__')"
    )
    return f'python3 -c "{code}" || python -c "{code}"'


def _hooks_block(events: list[tuple[str, str, int]], *, harness: str, milliseconds: bool,
                 only: tuple[str, ...] | None = None) -> dict:
    block: dict[str, list] = {}
    for event, script, timeout in events:
        if only is not None and event not in only:
            continue
        block.setdefault(event, []).append({'hooks': [{
            'type': 'command',
            'command': _command(script, harness),
            'timeout': timeout * 1000 if milliseconds else timeout,
        }]})
    return block


def _renamed_hooks_block(events: list[tuple[str, str, int]], *, harness: str, names: dict[str, str]) -> dict:
    block: dict[str, list] = {}
    for event, script, timeout in events:
        if event in names:
            block.setdefault(names[event], []).append({'hooks': [{
                'type': 'command',
                'command': _command(script, harness),
                'timeout': timeout * 1000,
            }]})
    return block


def _copilot_hooks(events: list[tuple[str, str, int]]) -> dict:
    block: dict[str, list] = {}
    for event, script, timeout in events:
        if event in COPILOT_EVENTS:
            command = _command(script, 'copilot')
            block.setdefault(COPILOT_EVENTS[event], []).append({
                'type': 'command',
                'bash': command,
                'powershell': command,
                'cwd': '.',
                'timeoutSec': timeout,
            })
    return {'version': 1, 'hooks': block}


def _json(data: dict) -> bytes:
    return (json.dumps(data, indent=2, ensure_ascii=False) + '\n').encode('utf-8')


def _yaml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _agents(root: Path) -> list[tuple[str, dict]]:
    agents = []
    for path in sorted((root / AGENT_SOURCE).glob('*.toml')):
        data = tomllib.loads(path.read_text(encoding='utf-8'))
        agents.append((path.stem, data))
    return agents


def _agent_markdown(name: str, data: dict, *, extra: list[str]) -> bytes:
    lines = ['---', f'name: {name}', f'description: {_yaml_string(data["description"])}', *extra, '---', '']
    body = data['developer_instructions'].strip()
    return ('\n'.join(lines) + body + '\n').encode('utf-8')


def _skills(root: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    base = root / SKILL_SOURCE
    for path in sorted(base.rglob('*')):
        if path.is_file():
            files[path.relative_to(base).as_posix()] = path.read_bytes()
    return files


def _cursor_rules(root: Path) -> dict[str, bytes]:
    """Prompt-only Cursor project rules; Cursor has no hooks, so it is not in HARNESSES."""
    out: dict[str, bytes] = {}
    always = 0
    for path in sorted((root / CURSOR_SOURCE).glob('*.toml')):
        source = f'{CURSOR_SOURCE}/{path.name}'
        rule = tomllib.loads(path.read_text(encoding='utf-8'))
        globs, scoped = rule.get('globs', []), rule.get('always_apply') is False
        if (set(rule) - CURSOR_KEYS or type(rule.get('always_apply')) is not bool
                or not isinstance(rule.get('description'), str) or not rule['description'].strip()
                or not isinstance(rule.get('instructions'), str) or not rule['instructions'].strip() or not isinstance(globs, list)
                or scoped != bool(globs) or not all(isinstance(g, str) and _CURSOR_GLOB.fullmatch(g) for g in globs)):
            raise ValueError(f'{source}: needs description, instructions and always_apply, and globs '
                             'exactly when always_apply is false; globs hold no comma, brace, quote or space')
        always += not scoped
        head = ['---', f'description: {_yaml_string(rule["description"])}']
        head += [f'globs: {",".join(globs)}'] if globs else []
        head += [f'alwaysApply: {str(not scoped).lower()}', '---', '',
                 f'{CURSOR_MARKER}{path.name} by scripts/getzilla_harness.py --write; do not edit. -->', '', '']
        content = ('\n'.join(head) + rule['instructions'].strip() + '\n').encode('utf-8')
        if len(content) > CURSOR_BUDGET[not scoped] or content.count(b'\n') > 500:
            raise ValueError(f'{source}: rendered rule exceeds its context budget')
        out[f'{CURSOR_OUTPUT}/{path.stem}.mdc'] = content
    if out and always != 1:
        raise ValueError(f'{CURSOR_SOURCE}: exactly one rule must set always_apply = true')
    return out


def render(root: Path) -> dict[str, bytes]:
    events = _hook_events(root)
    agents = _agents(root)
    skills = _skills(root)
    out: dict[str, bytes] = {}

    out['.qwen/settings.json'] = _json({
        'context': {'fileName': ['AGENTS.md']},
        'hooks': _hooks_block(events, harness='qwen', milliseconds=True),
    })
    out['.claude/settings.json'] = _json({
        'hooks': _hooks_block(events, harness='claude', milliseconds=False),
    })
    out['.claude/CLAUDE.md'] = b'@../AGENTS.md\n'
    out['.codex/hooks.json'] = _json({
        'hooks': _hooks_block(events, harness='codex', milliseconds=False, only=CODEX_HOOK_EVENTS),
    })
    out['.codex/config.toml'] = b'[features]\ncodex_hooks = true\n'
    out['.gemini/settings.json'] = _json({
        'context': {'fileName': ['AGENTS.md']},
        'hooks': _renamed_hooks_block(events, harness='gemini', names=GEMINI_EVENTS),
    })
    out[COPILOT_HOOKS] = _json(_copilot_hooks(events))

    for name, data in agents:
        read_only = data.get('sandbox_mode') == 'read-only'
        qwen_extra = ['disallowedTools:', *[f'  - {tool}' for tool in QWEN_READ_ONLY_BLOCK]] if read_only else []
        claude_extra = [f'tools: {", ".join(CLAUDE_READ_ONLY_TOOLS)}'] if read_only else []
        out[f'.qwen/agents/{name}.md'] = _agent_markdown(name, data, extra=qwen_extra)
        out[f'.claude/agents/{name}.md'] = _agent_markdown(name, data, extra=claude_extra)
        out[f'.codex/agents/{name}.toml'] = (root / AGENT_SOURCE / f'{name}.toml').read_bytes()
        out[f'.gemini/agents/{name}.md'] = _agent_markdown(name, data, extra=[])
        copilot_extra = [f'tools: {json.dumps(list(COPILOT_READ_ONLY_TOOLS))}'] if read_only else []
        out[f'.github/agents/{name}.agent.md'] = _agent_markdown(name, data, extra=copilot_extra)

    for rel, content in skills.items():
        out[f'.qwen/skills/{rel}'] = content
        out[f'.claude/skills/{rel}'] = content
        out[f'.gemini/skills/{rel}'] = content
    out.update(_cursor_rules(root))
    return out


def _generated(root: Path) -> Iterator[Path]:
    for base in GENERATED_ROOTS:
        if (root / base).is_dir():
            yield from sorted((root / base).rglob('*'), reverse=True)


def _owned(path: Path, rel: str) -> bool:
    """Cursor rules share .cursor/rules with the user's own: only marked files there are Getzilla's."""
    if not rel.startswith(CURSOR_OUTPUT + '/') or path.is_symlink() or not path.is_file():
        return True
    return CURSOR_MARKER.encode('utf-8') in path.read_bytes()[:4096]


def _unexpected(path: Path, rel: str, expected: dict[str, bytes]) -> bool:
    return ((path.is_file() or path.is_symlink()) and rel not in expected and path.name not in LOCAL_FILES
            and _owned(path, rel))


def _conflict(root: Path, rel: str) -> bool:
    """A linked parent, a directory or an unowned file where an output goes blocks every write."""
    path = root / rel
    return (any((root / parent).is_symlink() for parent in PurePosixPath(rel).parents)
            or (path.is_dir() and not path.is_symlink()) or not _owned(path, rel))


def drift(root: Path) -> list[str]:
    expected = render(root)
    problems = []
    for rel, content in sorted(expected.items()):
        path = root / rel
        if _conflict(root, rel):
            problems.append(f'conflict {rel}')
        elif not path.is_file():
            problems.append(f'missing {rel}')
        elif path.is_symlink() or path.read_bytes() != content:
            problems.append(f'stale {rel}')
    for path in reversed(list(_generated(root))):
        rel = path.relative_to(root).as_posix()
        if _unexpected(path, rel, expected):
            problems.append(f'unexpected {rel}')
    return problems


@contextmanager
def _parent(root: Path, rel: str, *, create: bool = False) -> Iterator[tuple[fsx.DirHandle, str]]:
    """Walk to rel's directory by descriptor, never following a link (no check-then-use race)."""
    *directories, name = rel.split('/')
    handles = [fsx.open_dir(root)]
    try:
        for part in directories:
            if create:
                with suppress(FileExistsError):
                    fsx.mkdir_at(handles[-1], part, 0o755)
            handles.append(fsx.open_dir_at(handles[-1], part))
        yield handles[-1], name
    finally:
        for handle in reversed(handles):
            fsx.close_dir(handle)


def _write_file(root: Path, rel: str, content: bytes) -> None:
    with _parent(root, rel, create=True) as (parent, name):
        temporary = f'.{name}.{secrets.token_hex(6)}.tmp'
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | fsx.O_NOFOLLOW | fsx.O_CLOEXEC
        descriptor = fsx.open_at(parent, temporary, flags, 0o644)
        try:
            with os.fdopen(descriptor, 'wb') as stream:
                fsx.fchmod(stream.fileno(), 0o644)
                stream.write(content)
            fsx.replace_at(parent, temporary, parent, name)
        except BaseException:
            with suppress(FileNotFoundError):
                fsx.unlink_at(parent, temporary)
            raise


def write(root: Path) -> list[str]:
    expected = render(root)
    conflicts = [rel for rel in sorted(expected) if _conflict(root, rel)]
    if conflicts:
        raise ValueError(f'nothing written; resolve conflict {", ".join(conflicts)}')
    changed = []
    for path in _generated(root):
        rel = path.relative_to(root).as_posix()
        if _unexpected(path, rel, expected):
            with _parent(root, rel) as (parent, name):
                fsx.unlink_at(parent, name)
            changed.append(f'removed {rel}')
        elif path.is_dir() and not path.is_symlink() and not any(path.iterdir()):
            with _parent(root, rel) as (parent, name):
                fsx.rmdir_at(parent, name)
    for rel, content in sorted(expected.items()):
        path = root / rel
        if path.is_file() and not path.is_symlink() and path.read_bytes() == content:
            continue
        _write_file(root, rel, content)
        changed.append(f'wrote {rel}')
    return changed
