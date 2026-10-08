"""Update third-party tools: agent CLIs and workflow sources to latest, OSV data, pinned OpenGrep.

Runs only when a person starts it (`python3 scripts/getzilla_update.py`); the
installers offer it at the end and wait for an explicit yes. Nothing here
touches a project: sources are cloned under ``~/.getzilla/vendor``, the OSV
mirror lives in ``~/.getzilla/osv`` and tools in ``~/.getzilla/bin``.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import hmac
import io
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

STATE_FILE = 'update-state.json'
LOCK_FILE = 'update.lock'
LOCK_STALE_SECONDS = 3600
DEFAULT_INTERVAL_HOURS = 1.0
OSV_BUCKET = 'https://osv-vulnerabilities.storage.googleapis.com'
OSV_ECOSYSTEMS = ('PyPI', 'npm', 'Go', 'crates.io', 'Packagist', 'RubyGems')
SOURCES = {
    'superpowers': 'https://github.com/obra/superpowers.git',
    'bmad': 'https://github.com/bmad-code-org/BMAD-METHOD.git',
    'spec-kit': 'https://github.com/github/spec-kit.git',
    'vibevm': 'https://github.com/vibevm/vibevm.git',
}
NPM_AGENTS = {
    'qwen': '@qwen-code/qwen-code@latest',
    'codex': '@openai/codex@latest',
    'gemini': '@google/gemini-cli@latest',
    'copilot': '@github/copilot@latest',
}
# OpenGrep is an executable the verifier runs, so it is pinned to one release and
# every asset is checked against its SHA-256 before it is written (issue #39).
# Keep OPENGREP_VERSION and the linux/x86_64 digest in lockstep with
# trust-ci/runner.Dockerfile, which the CI workflow verifies the same way
# (tests/test_updater.py enforces it). Digests are the release's published asset
# digests; bump all of them together.
OPENGREP_VERSION = '1.30.1'
OPENGREP_DOWNLOAD = 'https://github.com/opengrep/opengrep/releases/download/v{version}/{asset}'
OPENGREP_ASSETS = {
    ('linux', 'x86_64'): ('opengrep_manylinux_x86', 'd3195b9d8d5ae93179f6aa5f5daaba6a920a5a09d38c5d5ae5e60924050210c4'),
    ('linux', 'aarch64'): ('opengrep_manylinux_aarch64', 'a730f6fdce1e978ea29e610a2e0503bfe1ec31fce08979a9a84e3699f03e16ee'),
    ('darwin', 'arm64'): ('opengrep_osx_arm64', '7b788794e111ce3fb83f0aa52c100a3b85d37d8b59482262109031f50d4a8d91'),
    ('darwin', 'x86_64'): ('opengrep_osx_x86', 'a8c6d5f51bb38253b48e9a80fca63684aa2a0f9abfeacea27b8d8b5778476bae'),
    ('windows', 'amd64'): ('opengrep_windows_x86.exe', 'd3a45326ff63cabe90d94ebc679fcd4302440178a0e5bf0248a6f7b610db3b53'),
}
PATH_MARKER = '# Getzilla: tools in ~/.getzilla/bin'

Runner = Callable[[list[str], Path | None], subprocess.CompletedProcess]
Fetch = Callable[[str], bytes]


@dataclass(frozen=True)
class Result:
    component: str
    status: str
    detail: str


def home_dir() -> Path:
    return Path(os.environ.get('GETZILLA_STATE_HOME') or Path.home() / '.getzilla')


def _default_runner(command: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=900, check=False)  # nosec B603


def _default_fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={'User-Agent': 'getzilla-updater'})  # nosec B310
    with urllib.request.urlopen(request, timeout=300) as response:  # nosec B310
        return response.read()


def _tail(process: subprocess.CompletedProcess) -> str:
    text = (process.stderr or process.stdout or '').strip().splitlines()
    return text[-1] if text else f'exit {process.returncode}'


def update_agents(run: Runner, which: Callable[[str], str | None] = shutil.which) -> list[Result]:
    results = []
    npm = which('npm')
    for command, package in NPM_AGENTS.items():
        if not which(command):
            continue
        if not npm:
            results.append(Result(f'agent:{command}', 'skip', 'npm not found'))
            continue
        process = run([npm, 'install', '-g', package], None)
        results.append(Result(f'agent:{command}', 'ok' if process.returncode == 0 else 'fail',
                              package if process.returncode == 0 else _tail(process)))
    if which('claude'):
        process = run([which('claude') or 'claude', 'update'], None)
        results.append(Result('agent:claude', 'ok' if process.returncode == 0 else 'fail', _tail(process)))
    if which('grok'):
        if os.name == 'nt':
            shell = which('pwsh') or which('powershell') or 'powershell'
            command = [shell, '-NoProfile', '-Command', 'irm https://x.ai/cli/install.ps1 | iex']
        else:
            command = ['bash', '-c', 'curl -fsSL https://x.ai/cli/install.sh | bash']
        process = run(command, None)
        results.append(Result('agent:grok', 'ok' if process.returncode == 0 else 'fail', _tail(process)))
    if which('specify') and which('uv'):
        process = run([which('uv') or 'uv', 'tool', 'install', '--force', 'specify-cli', '--from',
                       f'git+{SOURCES["spec-kit"]}'], None)
        results.append(Result('tool:specify', 'ok' if process.returncode == 0 else 'fail', _tail(process)))
    return results


def update_sources(run: Runner, root: Path, sources: dict[str, str] | None = None) -> list[Result]:
    results = []
    vendor = root / 'vendor'
    vendor.mkdir(parents=True, exist_ok=True)
    for name, url in (sources or SOURCES).items():
        target = vendor / name
        if (target / '.git').is_dir():
            fetched = run(['git', '-C', str(target), 'fetch', '-q', '--depth', '1', 'origin', 'HEAD'], None)
            if fetched.returncode == 0:
                fetched = run(['git', '-C', str(target), 'reset', '-q', '--hard', 'FETCH_HEAD'], None)
        else:
            if target.exists():
                shutil.rmtree(target)
            fetched = run(['git', 'clone', '-q', '--depth', '1', url, str(target)], None)
        if fetched.returncode != 0:
            results.append(Result(f'source:{name}', 'fail', _tail(fetched)))
            continue
        head = run(['git', '-C', str(target), 'rev-parse', '--short=12', 'HEAD'], None)
        results.append(Result(f'source:{name}', 'ok', (head.stdout or '').strip()))
    return results


def _replace_bytes(path: Path, data: bytes, *, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f'.{path.name}.', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as handle:
            handle.write(data)
        if mode is not None:
            os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise


def _check_zip(data: bytes) -> None:
    """Refuse anything but a complete zip whose members pass their CRC checks.

    The OSV bucket publishes no checksum file, so this catches truncated or
    corrupted downloads and HTML error pages rather than a malicious mirror.
    """
    if not data.startswith(b'PK'):
        raise ValueError('not a zip archive')
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            broken = archive.testzip()
    except (zipfile.BadZipFile, zlib.error, EOFError, ValueError) as exc:
        raise ValueError(f'corrupt zip archive: {exc}') from exc
    if broken is not None:
        raise ValueError(f'corrupt zip archive: bad CRC in {broken}')


def update_osv(fetch: Fetch, root: Path) -> list[Result]:
    database = root / 'osv'
    results = []
    for ecosystem in OSV_ECOSYSTEMS:
        try:
            data = fetch(f'{OSV_BUCKET}/{ecosystem}/all.zip')
            _check_zip(data)
            _replace_bytes(database / ecosystem / 'all.zip', data)
            results.append(Result(f'osv:{ecosystem}', 'ok', f'{len(data) // 1024} KiB'))
        except Exception as exc:  # noqa: BLE001 - one ecosystem failing must not stop the others
            results.append(Result(f'osv:{ecosystem}', 'fail', str(exc)[:200]))
    return results


def _platform_key() -> tuple[str, str]:
    system = 'windows' if os.name == 'nt' else sys.platform
    if system.startswith('linux'):
        system = 'linux'
    return system, platform.machine().lower()


def _sha256_file(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open('rb') as handle:
            for block in iter(lambda: handle.read(1 << 20), b''):
                digest.update(block)
        return digest.hexdigest()
    except OSError:
        return None


def update_opengrep(fetch: Fetch, root: Path, key: tuple[str, str] | None = None) -> list[Result]:
    pinned = OPENGREP_ASSETS.get(key or _platform_key())
    if pinned is None:
        return [Result('tool:opengrep', 'skip', f'no OpenGrep build for {key or _platform_key()}')]
    asset_name, expected = pinned
    version = f'v{OPENGREP_VERSION}'
    target = root / 'bin' / ('opengrep.exe' if asset_name.endswith('.exe') else 'opengrep')
    if _sha256_file(target) == expected:
        if os.name != 'nt' and not os.access(target, os.X_OK):
            target.chmod(0o755)  # a restored or copied binary may have lost its execute bits
        return [Result('tool:opengrep', 'ok', f'{version} (already installed, sha256 verified)')]
    note = ''
    try:
        # Whatever sits at the target now does not match the pin: never leave it runnable,
        # even if the pinned download below fails.
        note = _quarantine(target)
        data = fetch(OPENGREP_DOWNLOAD.format(version=OPENGREP_VERSION, asset=asset_name))
        actual = hashlib.sha256(data).hexdigest()
        if not hmac.compare_digest(actual, expected):
            return [Result('tool:opengrep', 'fail',
                           f'{asset_name} {version}: sha256 {actual} does not match pinned {expected}; '
                           f'not installed{note}')]
        _replace_bytes(target, data, mode=0o755)
        return [Result('tool:opengrep', 'ok', f'{version} (sha256 verified){note}')]
    except Exception as exc:  # noqa: BLE001
        return [Result('tool:opengrep', 'fail', f'{str(exc)[:200]}{note}')]


def _quarantine(target: Path) -> str:
    """Move an unverified binary off its runnable name (``<name>.unverified``, no execute bits)."""
    if target.is_symlink():
        target.unlink()
        return '; unverified previous symlink removed'
    if not target.exists():
        return ''
    destination = target.with_name(target.name + '.unverified')
    os.replace(target, destination)
    if os.name != 'nt':
        destination.chmod(0o600)
    return f'; unverified previous binary quarantined to {destination}'


def export_environment(root: Path) -> list[str]:
    """Point every agent at the OSV mirror and put ~/.getzilla/bin on PATH."""
    from .agent_setup import _store_env  # local import keeps the hook path light

    changed = _store_env(Path.home(), {'GETZILLA_OSV_DB': str(root / 'osv')})
    if os.name == 'nt':
        if _add_windows_user_path(str(root / 'bin')):
            changed.append('user PATH')
        return changed
    for profile in (Path.home() / '.bashrc', Path.home() / '.zshrc', Path.home() / '.profile'):
        if profile.name != '.bashrc' and not profile.exists():
            continue
        text = profile.read_text(encoding='utf-8') if profile.exists() else ''
        if PATH_MARKER not in text:
            with profile.open('a', encoding='utf-8') as handle:
                handle.write(f'\n{PATH_MARKER}\ncase ":$PATH:" in *":$HOME/.getzilla/bin:"*) ;; '
                             '*) export PATH="$HOME/.getzilla/bin:$PATH" ;; esac\n')
            changed.append(str(profile))
    return changed


def _add_windows_user_path(directory: str) -> bool:
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Environment', 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
        try:
            current, kind = winreg.QueryValueEx(key, 'Path')
        except FileNotFoundError:
            current, kind = '', winreg.REG_EXPAND_SZ
        parts = [part for part in str(current).split(';') if part]
        if directory in parts:
            return False
        winreg.SetValueEx(key, 'Path', 0, kind, ';'.join([*parts, directory]))
    return True


def run_all(root: Path, *, run: Runner = _default_runner, fetch: Fetch = _default_fetch,
            which: Callable[[str], str | None] = shutil.which, components: tuple[str, ...] | None = None) -> list[Result]:
    wanted = set(components or ('agents', 'sources', 'osv', 'opengrep'))
    results: list[Result] = []
    if 'agents' in wanted:
        results += update_agents(run, which)
    if 'sources' in wanted:
        results += update_sources(run, root)
    if 'osv' in wanted:
        results += update_osv(fetch, root)
    if 'opengrep' in wanted:
        results += update_opengrep(fetch, root)
    return results


def _load_state(root: Path) -> dict:
    try:
        data = json.loads((root / STATE_FILE).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_state(root: Path, results: list[Result], now: float) -> None:
    state = {
        'last_run': now,
        'results': {item.component: {'status': item.status, 'detail': item.detail} for item in results},
    }
    _replace_bytes(root / STATE_FILE, (json.dumps(state, indent=2, sort_keys=True) + '\n').encode('utf-8'))


def interval_hours(environ: dict[str, str] | None = None) -> float:
    raw = (environ if environ is not None else os.environ).get('GETZILLA_UPDATE_INTERVAL_HOURS', '')
    try:
        return max(0.0, float(raw)) if raw.strip() else DEFAULT_INTERVAL_HOURS
    except ValueError:
        return DEFAULT_INTERVAL_HOURS


def is_due(root: Path, now: float, environ: dict[str, str] | None = None) -> bool:
    environ = environ if environ is not None else dict(os.environ)
    last = _load_state(root).get('last_run')
    return not isinstance(last, (int, float)) or now - last >= interval_hours(environ) * 3600


@contextlib.contextmanager
def update_lock(root: Path, now: float):
    root.mkdir(parents=True, exist_ok=True)
    path = root / LOCK_FILE
    with contextlib.suppress(OSError):
        if now - path.stat().st_mtime > LOCK_STALE_SECONDS:
            path.unlink()
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        yield False
        return
    try:
        os.write(descriptor, str(os.getpid()).encode())
        os.close(descriptor)
        yield True
    finally:
        with contextlib.suppress(OSError):
            path.unlink()


REMINDER_HOURS = 24.0


def reminder(root: Path, now: float) -> str | None:
    """A note for the agent to pass on when tools are stale; reads local state only, never updates."""
    last = _load_state(root).get('last_run')
    if isinstance(last, (int, float)) and now - last < REMINDER_HOURS * 3600:
        return None
    when = 'have never been updated' if not isinstance(last, (int, float)) else \
        f'were last updated {int((now - last) // 86400)} day(s) ago'
    return (f'Third-party tools (agent CLIs, Superpowers, BMAD, Spec Kit, vibevm, CVE database, OpenGrep) {when}. '
            'Offer the user to run `python3 scripts/getzilla_update.py` from the Getzilla folder; do not run it yourself.')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--now', action='store_true', help='update now (the default)')
    parser.add_argument('--if-due', action='store_true',
                        help='update only when GETZILLA_UPDATE_INTERVAL_HOURS (default 1) has passed since the last run')
    parser.add_argument('--only', action='append', choices=('agents', 'sources', 'osv', 'opengrep'),
                        help='limit to one component (repeatable)')
    parser.add_argument('--quiet', action='store_true')
    parser.add_argument('--status', action='store_true', help='print the last update results and exit')
    args = parser.parse_args(argv)
    root = home_dir()
    if args.status:
        print(json.dumps(_load_state(root), indent=2, sort_keys=True))
        return 0
    now = time.time()
    if args.if_due and not args.now and not is_due(root, now):
        if not args.quiet:
            print('Getzilla tools are up to date (checked recently).')
        return 0
    with update_lock(root, now) as acquired:
        if not acquired:
            if not args.quiet:
                print('Another Getzilla update is running.')
            return 0
        results = run_all(root, components=tuple(args.only) if args.only else None)
        if not args.only or 'osv' in args.only or 'opengrep' in args.only:
            with contextlib.suppress(Exception):
                export_environment(root)
        save_state(root, results, now)
    for item in results:
        if not args.quiet or item.status == 'fail':
            print(f'{item.status.upper():4} {item.component}: {item.detail}')
    return 1 if any(item.status == 'fail' for item in results) else 0


if __name__ == '__main__':
    raise SystemExit(main())
