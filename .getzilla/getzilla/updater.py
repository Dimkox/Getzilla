"""Update third-party tools: agent CLIs and workflow sources to latest, OSV data, pinned OpenGrep.

Runs only when a person starts it (`python3 scripts/getzilla_update.py`); the
installers offer it at the end and wait for an explicit yes. Nothing here
touches a project: sources are cloned under ``~/.getzilla/vendor``, the OSV
mirror lives in ``~/.getzilla/osv`` and tools in ``~/.getzilla/bin``.

``GETZILLA_UPDATE_MIRROR=<dir>`` replaces every download host with a local
directory and nothing reaches the network (see ``Mirror``).
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import hmac
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.parse
import zipfile
import zlib
from urllib.error import HTTPError
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Mapping

from .security_data import OSV_BUCKET, OSV_ECOSYSTEMS, copy_snapshot, osv_coverage, publish_snapshot

STATE_FILE = 'update-state.json'
LOCK_FILE = 'update.lock'
LOCK_STALE_SECONDS = 3600
DEFAULT_INTERVAL_HOURS = 1.0
SOURCES = {
    'superpowers': 'https://github.com/obra/superpowers.git',
    'bmad': 'https://github.com/bmad-code-org/BMAD-METHOD.git',
    'spec-kit': 'https://github.com/github/spec-kit.git',
    'vibevm': 'https://github.com/vibevm/vibevm.git',
}
JSCPD_VERSION = '4.0.5'
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
MIRROR_ENV = 'GETZILLA_UPDATE_MIRROR'
MIRROR_MANIFEST = 'getzilla-mirror.json'
# Where each download host lives inside an offline mirror; the first matching prefix wins.
MIRROR_LAYOUT = (
    (f'{OSV_BUCKET}/', 'osv'),
    ('https://github.com/opengrep/opengrep/releases/download/', 'opengrep'),
    ('https://github.com/', 'git'),
)

Runner = Callable[[list[str], Path | None], subprocess.CompletedProcess]
Fetch = Callable[[str], bytes]
Assets = Mapping[tuple[str, str], tuple[str, str]]


@dataclass(frozen=True)
class Result:
    component: str
    status: str
    detail: str


@dataclass(frozen=True)
class Mirror:
    """A local directory that replaces every download host (``GETZILLA_UPDATE_MIRROR``).

    Layout: ``osv/`` contains validated snapshots (manifest plus content objects,
    the ``GETZILLA_OSV_DB`` layout of known_vulns) and legacy ``all.zip`` exports,
    ``opengrep/v<version>/<asset>`` and ``git/<owner>/<repo>.git``. The pins stay those in this
    module and in toolchain.json, so a mirror of the real files needs nothing else. A mirror of
    small stand-in files (a test fixture) names its own pins in ``getzilla-mirror.json``:
    ``{"opengrep": {"<asset>": "<sha256>"}, "baseline": {"<id>": "<commit>"}}``; each result
    then says that its pin came from the mirror.
    """

    root: Path
    opengrep: Mapping[str, str]
    baseline: Mapping[str, str]

    @classmethod
    def from_environ(cls, environ: Mapping[str, str] | None = None) -> Mirror | None:
        raw = (environ if environ is not None else os.environ).get(MIRROR_ENV, '').strip()
        if not raw:
            return None
        root = Path(raw).expanduser()
        if not root.is_absolute() or not root.is_dir():
            raise ValueError(f'{MIRROR_ENV}={raw} must be an absolute path to a directory')
        manifest = root / MIRROR_MANIFEST
        try:
            pins = json.loads(manifest.read_text(encoding='utf-8')) if manifest.is_file() else {}
        except (OSError, ValueError) as exc:
            raise ValueError(f'{manifest}: {exc}') from exc
        if not isinstance(pins, dict):
            raise ValueError(f'{manifest}: must be a JSON object')
        return cls(root, _mirror_pins(pins, manifest, 'opengrep', r'[0-9a-f]{64}'),
                   _mirror_pins(pins, manifest, 'baseline', r'[0-9a-f]{40}|[0-9a-f]{64}'))

    def path(self, url: str) -> Path:
        for prefix, folder in MIRROR_LAYOUT:
            if url.startswith(prefix):
                parts = url[len(prefix):].split('/')
                if any(part in ('', '.', '..') or '\\' in part for part in parts):
                    break
                return self.root.joinpath(folder, *parts)
        raise ValueError(f'{url} has no place in the offline mirror {self.root}')

    def fetch(self, url: str) -> bytes:
        return self.path(url).read_bytes()

    def url(self, url: str) -> str:
        return self.path(url).as_uri()

    def note(self, pinned: bool) -> str:
        return f' [offline mirror {self.root}' + (f'; pin from {MIRROR_MANIFEST}]' if pinned else ']')


def _mirror_pins(pins: dict, manifest: Path, key: str, digest: str) -> dict[str, str]:
    value = pins.get(key, {})
    if not isinstance(value, dict) or not all(
            isinstance(name, str) and isinstance(pin, str) and re.fullmatch(digest, pin) for name, pin in value.items()):
        raise ValueError(f'{manifest}: "{key}" must map names to lowercase hex digests')
    return dict(value)


def home_dir() -> Path:
    return Path(os.environ.get('GETZILLA_STATE_HOME') or Path.home() / '.getzilla')


def _default_runner(command: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, encoding='utf-8', errors='replace',
                          timeout=900, check=False)  # nosec B603


def _default_fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={'User-Agent': 'getzilla-updater'})  # nosec B310
    with urllib.request.urlopen(request, timeout=300) as response:  # nosec B310
        return response.read()


_RELEASE_HOSTS = {'api.github.com', 'github.com', 'nodejs.org', 'www.python.org', 'getcomposer.org',
                  'pypi.org', 'files.pythonhosted.org', 'registry.npmjs.org', 'www.php.net', 'downloads.php.net',
                  'git-scm.com', 'www.kernel.org', 'release-assets.githubusercontent.com', 'downloads.claude.ai'}


def _release_origin(url):
    origin = urllib.parse.urlsplit(url)
    if origin.scheme != 'https' or origin.netloc not in _RELEASE_HOSTS or origin.fragment:
        raise ValueError('release redirect leaves official public origins')
    return origin


class _ReleaseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Check before the stdlib can send the redirected request.
        _release_origin(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_RELEASE_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _ReleaseRedirect())


def _release_refusal(error, origin):
    values = {}
    get_all = getattr(error.headers, 'get_all', None)
    for header, field in (('X-RateLimit-Remaining', 'remaining'), ('X-RateLimit-Reset', 'reset'),
                          ('Retry-After', 'retry_after')):
        rows = get_all(header) if callable(get_all) else None
        if (type(rows) is list and len(rows) == 1 and type(rows[0]) is str
                and re.fullmatch(r'[0-9]{1,19}', rows[0]) and int(rows[0]) < 2**63):
            values[field] = int(rows[0])
    source = 'github-api' if origin.netloc == 'api.github.com' else 'official-release'
    repository = r'/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+'
    kinds = (('latest-release', repository + r'/releases/latest'),
             ('tag-refs', repository + r'/git/(?:matching-refs/tags/|ref/tags/[^/]+|tags/[a-f0-9]{40})'),
             ('tagged-release', repository + r'/releases/tags/[^/]+'))
    endpoint = next((kind for kind, pattern in kinds
                     if source == 'github-api' and re.fullmatch(pattern, origin.path)), 'other')
    if (origin.netloc == 'github.com' and re.fullmatch(
            r'/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/releases/download/[^/]+/[^/]+', origin.path)):
        endpoint = 'release-asset'
    reason = ('quota-exhausted' if values.get('remaining') == 0 else
              'rate-limited' if error.code == 429 else 'forbidden')
    detail = f'official release request refused: source={source} status={error.code} reason={reason} endpoint={endpoint}'
    return detail + ''.join(f' {name}={value}' for name, value in values.items())


def _release_fetch(url: str) -> bytes:
    """Bounded public release transport, owned by the existing updater boundary."""
    origin = urllib.parse.urlsplit(url)
    _release_origin(url)
    catalog = origin.netloc == 'pypi.org' and re.fullmatch(r'/pypi/[A-Za-z0-9_.-]+/json', origin.path)
    archive = origin.path.endswith(('.tgz', '.tar.gz', '.tar.xz'))
    metadata_host = origin.netloc in {'api.github.com', 'pypi.org', 'git-scm.com'} or origin.netloc in {'registry.npmjs.org', 'www.php.net'} and not archive
    limit = 2*1024*1024 if metadata_host or origin.path.endswith(('.json', '.txt', '.sha256sum', '.asc', '/latest')) else 512*1024*1024
    decoded_limit = 64*1024*1024 if catalog else limit
    headers = {'User-Agent': 'Getzilla-release-resolver/1', 'Accept-Encoding': 'gzip' if catalog else 'identity'}
    request = urllib.request.Request(url, headers=headers)  # nosec B310
    started = time.monotonic()
    try:
        response = _RELEASE_OPENER.open(request, timeout=20)  # nosec B310
    except HTTPError as exc:
        if exc.code not in {403, 429}:
            raise
        try:
            detail = _release_refusal(exc, origin)
        finally:
            exc.close()
        raise ValueError(detail) from None
    with response:
        _release_origin(response.geturl())
        encoding = response.headers.get('Content-Encoding', 'identity')
        if encoding not in ({'identity', 'gzip'} if catalog else {'identity'}):
            raise ValueError('unsupported upstream release content encoding')
        decoder = zlib.decompressobj(16+zlib.MAX_WBITS) if encoding == 'gzip' else None
        wire_limit = limit if decoder else decoded_limit
        chunks, wire, decoded = [], 0, 0
        while True:
            if time.monotonic()-started > 60:
                raise ValueError('upstream release response exceeded total deadline')
            block = response.read1(min(65536, wire_limit-wire+1))
            if not block:
                break
            wire += len(block)
            if wire > wire_limit:
                raise ValueError('upstream release wire byte bound exceeded')
            try:
                body = decoder.decompress(block, decoded_limit-decoded+1) if decoder else block
            except zlib.error as exc:
                raise ValueError('invalid compressed release metadata') from exc
            decoded += len(body)
            if decoded > decoded_limit or decoder and decoder.unconsumed_tail:
                raise ValueError('upstream release decoded byte bound exceeded')
            chunks.append(body)
        if decoder and (not decoder.eof or decoder.unused_data):
            raise ValueError('truncated/trailing compressed release metadata')
    return b''.join(chunks)


def _tail(process: subprocess.CompletedProcess) -> str:
    text = (process.stderr or process.stdout or '').strip().splitlines()
    return text[-1] if text else f'exit {process.returncode}'


def update_agents(run: Runner, which: Callable[[str], str | None] = shutil.which, *, root=None, fetch=None) -> list[Result]:
    """Update installed agents through the same exact verified managed installer."""
    from .managed_environment import execute
    from .managed_software import install_software
    root = root or home_dir()
    results = []
    # Native calls require the isolated environment-capable runner, never an
    # ambient global npm installer. Explicit test runners may accept **kwargs.
    native = execute if run is _default_runner else run
    for command in (*NPM_AGENTS, 'claude', 'grok'):
        if not which(command):
            continue
        report = install_software(root, Path(__file__).resolve().parents[2], agent=command,
                                  fetch=fetch or _release_fetch, run=native, which=which)
        for row in report['components']:
            results.append(Result('agent:'+command+':'+row['component'],
                                  'ok' if row['status'] == 'complete' else 'fail', json.dumps(row)))
    return results


def update_jscpd(run: Runner, which: Callable[[str], str | None] = shutil.which, *, root=None, fetch=None) -> list[Result]:
    from .managed_environment import execute
    from .managed_software import install_software
    report = install_software(root or home_dir(), Path(__file__).resolve().parents[2], tools=('jscpd',),
                              fetch=fetch or _release_fetch, run=execute if run is _default_runner else run, which=which)
    return [Result('tool:'+row['component'], 'ok' if row['status'] == 'complete' else 'fail', json.dumps(row))
            for row in report['components']]


def update_sources(run: Runner, root: Path, sources: dict[str, str] | None = None, *, fetch=None) -> list[Result]:
    if sources is not None:
        # An offline snapshot/foreign URL cannot establish current official data.
        return [Result('sources', 'fail', 'snapshot source mapping cannot establish current stable releases; existing files preserved')]
    from .current_workflows import prepare_latest
    return [Result(step.component, step.status, step.detail) for step in prepare_latest(root, fetch=fetch or _release_fetch)]


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


def update_osv(fetch: Fetch, root: Path, *, now: datetime | None = None,
               source_database: Path | None = None) -> list[Result]:
    """Refresh independent ecosystems; local mirrors retain their original verified sync."""
    database = root / 'osv'
    bound_mirror = getattr(fetch, '__self__', None)
    if source_database is None and isinstance(bound_mirror, Mirror):
        source_database = bound_mirror.root / 'osv'
    results = []
    for ecosystem in OSV_ECOSYSTEMS:
        try:
            if source_database is not None:
                evidence = copy_snapshot(source_database, database, f'osv:{ecosystem}',
                                         now=now, required_scope={ecosystem})
            else:
                data = fetch(f'{OSV_BUCKET}/{ecosystem}/all.zip')
                current = now if now is not None else datetime.now(timezone.utc)
                evidence = publish_snapshot(
                    database, f'osv:{ecosystem}', data,
                    acquisition={'last_verified_sync_utc': current.isoformat(), 'retrieval_kind': 'download'},
                    coverage=osv_coverage(data, ecosystem), now=current)
            detail = f"{evidence['payload_size'] // 1024} KiB; verified sync {evidence['acquisition']['last_verified_sync_utc']}"
            if evidence.get('compatibility_export_warning'):
                detail += '; snapshot committed, legacy all.zip export unavailable'
            results.append(Result(f'osv:{ecosystem}', 'ok', detail))
        except Exception as exc:  # noqa: BLE001 - one ecosystem failing must not stop the others
            from .security_osv_diagnostics import bounded_alias_message, emit_alias_rejection
            emit_alias_rejection(ecosystem, exc)  # Full hashes before the compact200-character projection.
            results.append(Result(f'osv:{ecosystem}', 'fail', bounded_alias_message(exc) or str(exc)[:200]))
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


def update_opengrep(fetch: Fetch, root: Path, key: tuple[str, str] | None = None,
                    assets: Assets | None = None, *, run: Runner = _default_runner) -> list[Result]:
    if assets is None:
        from .opengrep_releases import install
        try:
            return install(fetch, root, key or _platform_key(), run=run)
        except (OSError, ValueError, zipfile.BadZipFile) as exc:
            return [Result('tool:opengrep', 'fail', str(exc)[:400])]
    # Explicit pinned fixture/offline compatibility; never the online latest path.
    pinned = assets.get(key or _platform_key())
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
            which: Callable[[str], str | None] = shutil.which, components: tuple[str, ...] | None = None,
            mirror: Mirror | None = None) -> list[Result]:
    if mirror is not None:
        return _run_from_mirror(root, mirror, run=run, which=which, components=components)
    wanted = set(components or ('agents', 'sources', 'osv', 'opengrep', 'jscpd', 'baseline'))
    results: list[Result] = []
    if 'agents' in wanted:
        results += update_agents(run, which, root=root, fetch=_release_fetch if fetch is _default_fetch else fetch)
    if {'sources', 'baseline'} & wanted:
        results += update_sources(run, root, fetch=_release_fetch if fetch is _default_fetch else fetch)
    if 'osv' in wanted:
        results += update_osv(fetch, root)
    if 'opengrep' in wanted:
        results += update_opengrep(_release_fetch if fetch is _default_fetch else fetch, root, run=run)
    if 'jscpd' in wanted:
        results += update_jscpd(run, which, root=root, fetch=_release_fetch if fetch is _default_fetch else fetch)
    return results


def _run_from_mirror(root: Path, mirror: Mirror, *, run: Runner, which: Callable[[str], str | None],
                     components: tuple[str, ...] | None) -> list[Result]:
    """Every component from the offline mirror; nothing here reaches the network."""
    wanted = set(components or ('agents', 'sources', 'osv', 'opengrep', 'jscpd', 'baseline'))
    results: list[Result] = []
    if 'agents' in wanted:
        results.append(Result('agents', 'skip', f'{MIRROR_ENV} is set: agent CLIs update only from the network'))
    if 'sources' in wanted:
        results += [Result(item.component, item.status, item.detail + mirror.note(False))
                    for item in update_sources(run, root, {name: mirror.url(url) for name, url in SOURCES.items()})]
    if 'osv' in wanted:
        results += [Result(item.component, item.status, item.detail + mirror.note(False))
                    for item in update_osv(mirror.fetch, root, source_database=mirror.root / 'osv')]
    if 'opengrep' in wanted:
        assets = {key: (asset, mirror.opengrep.get(asset, digest)) for key, (asset, digest) in OPENGREP_ASSETS.items()}
        pinned = assets.get(_platform_key(), ('',))[0] in mirror.opengrep
        results += [Result(item.component, item.status, item.detail + mirror.note(pinned))
                    for item in update_opengrep(mirror.fetch, root, assets=assets)]
    if 'jscpd' in wanted:
        results.append(Result('tool:jscpd', 'skip', f'{MIRROR_ENV} is set: npm updates require the network'))
    if 'baseline' in wanted:
        from .baseline import components as baseline_components, install_user
        config = {component_id: {**item, 'pinned_commit': mirror.baseline.get(component_id, item['pinned_commit'])}
                  for component_id, item in baseline_components().items()}
        for step in install_user(root, run=run, which=which, config=config, locate=mirror.url):
            pinned = step.component.removeprefix('baseline:') in mirror.baseline
            results.append(Result(step.component, step.status, step.detail + mirror.note(pinned)))
    results.append(Result('freshness', 'fail', 'offline snapshot imported; current official targets are unestablished'))
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
                        help='compatibility flag; every invocation still rechecks current official stable releases')
    parser.add_argument('--only', action='append', choices=('agents', 'sources', 'osv', 'opengrep', 'jscpd', 'baseline'),
                        help='limit to one component (repeatable); baseline resolves current official workflow payloads')
    parser.add_argument('--quiet', action='store_true')
    parser.add_argument('--status', action='store_true', help='print the last update results and exit')
    args = parser.parse_args(argv)
    root = home_dir()
    if args.status:
        print(json.dumps(_load_state(root), indent=2, sort_keys=True))
        return 0
    try:
        mirror = Mirror.from_environ()
    except ValueError as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 2
    now = time.time()
    with update_lock(root, now) as acquired:
        if not acquired:
            if not args.quiet:
                print('INCOMPLETE: another Getzilla update is running; freshness was not checked.')
            return 1
        if mirror is not None and not args.quiet:
            print(f'Offline mirror {mirror.root} ({MIRROR_ENV}): nothing is downloaded.')
        results = run_all(root, components=tuple(args.only) if args.only else None, mirror=mirror)
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
