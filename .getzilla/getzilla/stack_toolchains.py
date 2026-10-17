"""User-level toolchains for project stacks, installed only after the published checksum matches.

A toolchain lives in ``~/.getzilla/toolchains/<stack>/<version>/`` (``GETZILLA_TOOLCHAINS``
overrides the root) and its package caches in ``~/.getzilla/cache/<stack>``. Nothing here needs
administrator rights, changes the system or user PATH, or edits shell profiles: the toolchain's
directories reach only the environment of the check process (:meth:`Toolchain.process_env`).

Every refusal is a :class:`Blocker` with a stable code, so a verification report can say exactly
why a stack was not checked:

- ``TOOLCHAIN_UNAVAILABLE``: the source or the network cannot be reached;
- ``TOOLCHAIN_CHECKSUM_MISMATCH``: the download (or the published manifest) disagrees with the
  pinned digest; nothing is unpacked;
- ``TOOLCHAIN_NEEDS_ADMIN:<id>``: a prerequisite needs an administrator; the blocker carries the
  command for a human;
- ``TOOLCHAIN_UNSUPPORTED_PLATFORM:<platform>`` and ``TOOLCHAIN_ARCHIVE_UNSAFE``.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import platform as _platform
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

MARKER = '.getzilla-toolchain.json'
MARKER_SCHEMA = 'getzilla-toolchain-v1'
USER_AGENT = 'getzilla-toolchains'
CHUNK = 1 << 20

Fetch = Callable[[str, Path], None]
Run = Callable[[list[str], Mapping[str, str], Path | None], subprocess.CompletedProcess]
Which = Callable[[str], str | None]


class ToolchainError(Exception):
    def __init__(self, code: str, message: str, command: str | None = None) -> None:
        super().__init__(message)
        self.blocker = Blocker(code, message, command)


@dataclass(frozen=True)
class Blocker:
    code: str
    message: str
    command: str | None = None

    def detail(self, path: str) -> dict[str, str]:
        item = {'severity': 'error', 'code': self.code, 'path': path, 'message': self.message}
        if self.command:
            item['command'] = self.command
        return item


@dataclass(frozen=True)
class Toolchain:
    stack: str
    version: str
    home: Path
    bin_dirs: tuple[Path, ...]
    env: Mapping[str, str] = field(default_factory=dict)
    fetched: bool = False

    def process_env(self, base: Mapping[str, str] | None = None) -> dict[str, str]:
        """The check process environment: toolchain first on PATH, the caller's mapping untouched."""
        environment = dict(os.environ if base is None else base)
        environment['PATH'] = os.pathsep.join([*(str(path) for path in self.bin_dirs), environment.get('PATH', '')])
        environment.update(self.env)
        return environment


def toolchain_root() -> Path:
    return Path(os.environ.get('GETZILLA_TOOLCHAINS') or Path.home() / '.getzilla' / 'toolchains')


def cache_root(stack: str) -> Path:
    return Path(os.environ.get('GETZILLA_TOOLCHAIN_CACHE') or Path.home() / '.getzilla' / 'cache') / stack


def platform_key(system: str | None = None, machine: str | None = None) -> str:
    system = (system or _platform.system()).lower()
    machine = (machine or _platform.machine()).lower()
    name = {'linux': 'linux', 'darwin': 'darwin', 'windows': 'windows'}.get(system, system)
    arch = {'x86_64': 'x64', 'amd64': 'x64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(machine, machine)
    return f'{name}-{arch}'


def default_fetch(url: str, destination: Path) -> None:
    if not url.startswith('https://'):
        raise ValueError(f'refusing a non-https toolchain source: {url}')
    request = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
    with urllib.request.urlopen(request, timeout=300) as response, destination.open('wb') as handle:  # nosec B310 - https only, checked above
        shutil.copyfileobj(response, handle, CHUNK)


def default_run(command: list[str], env: Mapping[str, str], cwd: Path | None) -> subprocess.CompletedProcess:
    return subprocess.run(command, cwd=cwd, env=dict(env), text=True, encoding='utf-8', errors='replace', capture_output=True, timeout=1800, check=False)


# -- versions -------------------------------------------------------------------------------------

def _dotted(data: Any, key: str) -> Any:
    for part in key.split('.'):
        if not isinstance(data, dict):
            return None
        data = data.get(part)
    return data


def _toml(text: str) -> dict[str, Any]:
    try:
        import tomllib
    except ModuleNotFoundError:  # Python 3.10: only the flat table/key form pin files use
        data: dict[str, Any] = {}
        table = data
        for raw in text.splitlines():
            line = raw.split('#', 1)[0].strip()
            if line.startswith('[') and line.endswith(']'):
                table = data.setdefault(line.strip('[]').strip(), {})
            elif '=' in line:
                key, value = (part.strip() for part in line.split('=', 1))
                table[key] = value.strip('"\'')
        return data
    return tomllib.loads(text)


def read_pin(root: Path, pin: Mapping[str, str]) -> str | None:
    path = root / pin['path']
    try:
        text = path.read_text(encoding='utf-8')
    except (OSError, UnicodeError):
        return None
    kind = pin.get('kind', 'text')
    try:
        if kind == 'text':
            value: Any = next((line.strip() for line in text.splitlines() if line.strip() and not line.startswith('#')), None)
        elif kind == 'json':
            value = _dotted(json.loads(text), pin['key'])
        elif kind == 'toml':
            value = _dotted(_toml(text), pin['key'])
        elif kind == 'regex':
            match = re.search(pin['pattern'], text, re.MULTILINE)
            value = match.group(1) if match else None
        else:
            return None
    except (ValueError, KeyError):
        return None
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip().removeprefix('v')


def resolve_version(root: Path, spec: Mapping[str, Any]) -> tuple[str, str]:
    """The version a project pins (first pin file that names one), else the registry default."""
    for pin in spec.get('pin_files', []):
        value = read_pin(root, pin)
        if value:
            return value, pin['path']
    return str(spec['default_version']), 'stacks.json'


# -- integrity ------------------------------------------------------------------------------------

def _digest(path: Path, algorithm: str) -> str:
    name = 'sha512' if algorithm.startswith('sha512') else algorithm
    hasher = hashlib.new(name)
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b''):
            hasher.update(chunk)
    if algorithm.endswith('-base64'):
        return base64.b64encode(hasher.digest()).decode('ascii')
    return hasher.hexdigest()


def _same(left: str, right: str, algorithm: str) -> bool:
    return left == right if algorithm.endswith('-base64') else left.lower() == right.lower()


def _fetch_text(fetch: Fetch, url: str) -> str:
    with tempfile.TemporaryDirectory(prefix='getzilla-manifest-') as tmp:
        target = Path(tmp) / 'manifest'
        fetch(url, target)
        return target.read_text(encoding='utf-8')


def _manifest_digest(source: Mapping[str, Any], version: str, archive: str, fetch: Fetch) -> str | None:
    checksums = source.get('checksums')
    if not checksums:
        return None
    channel = '.'.join(version.split('.')[:2])
    text = _fetch_text(fetch, checksums['url'].format(version=version, channel=channel))
    if checksums['kind'] == 'sha256-list':
        for line in text.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1].lstrip('*') == archive:
                return parts[0]
        return None
    if checksums['kind'] == 'dotnet-releases':
        data = json.loads(text)
        for release in data.get('releases', []):
            for sdk in release.get('sdks', [release.get('sdk') or {}]):
                if sdk.get('version') != version:
                    continue
                for item in sdk.get('files', []):
                    if str(item.get('url', '')).endswith('/' + archive):
                        return item.get('hash')
        return None
    raise ToolchainError('TOOLCHAIN_UNAVAILABLE', f'unknown checksum manifest kind {checksums["kind"]!r}')


def expected_digest(source: Mapping[str, Any], version: str, key: str, archive: str, fetch: Fetch) -> str:
    """The digest to accept: the pinned one and the published one must agree when both exist."""
    algorithm = source['algorithm']
    pinned = (source.get('pinned') or {}).get(version, {}).get(key)
    try:
        published = _manifest_digest(source, version, archive, fetch)
    except (OSError, ValueError, urllib.error.URLError) as error:
        if pinned:
            return pinned
        raise ToolchainError('TOOLCHAIN_UNAVAILABLE', f'checksum manifest unavailable for {archive}: {error}') from error
    if pinned and published and not _same(pinned, published, algorithm):
        raise ToolchainError('TOOLCHAIN_CHECKSUM_MISMATCH',
                             f'published {algorithm} for {archive} differs from the digest pinned in stacks.json')
    digest = pinned or published
    if not digest:
        raise ToolchainError('TOOLCHAIN_UNAVAILABLE', f'no published {algorithm} for {archive}')
    return digest


def download_verified(url: str, digest: str, algorithm: str, destination: Path, fetch: Fetch) -> Path:
    """Fetch into the cache (reusing a verified copy); a mismatch leaves nothing behind."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_file() and _same(_digest(destination, algorithm), digest, algorithm):
        return destination
    partial = destination.with_name(destination.name + '.part')
    try:
        fetch(url, partial)
    except (OSError, ValueError, urllib.error.URLError) as error:
        partial.unlink(missing_ok=True)
        raise ToolchainError('TOOLCHAIN_UNAVAILABLE', f'cannot download {url}: {error}') from error
    actual = _digest(partial, algorithm)
    if not _same(actual, digest, algorithm):
        partial.unlink(missing_ok=True)
        raise ToolchainError('TOOLCHAIN_CHECKSUM_MISMATCH', f'{url}: {algorithm} {actual} does not match {digest}')
    os.replace(partial, destination)
    return destination


# -- unpacking ------------------------------------------------------------------------------------

def _safe_parts(name: str, strip: int) -> tuple[str, ...] | None:
    path = PurePosixPath(name.replace('\\', '/'))
    if path.is_absolute() or re.match(r'^[A-Za-z]:', name) or '..' in path.parts:
        raise ToolchainError('TOOLCHAIN_ARCHIVE_UNSAFE', f'archive member escapes the toolchain directory: {name}')
    parts = tuple(part for part in path.parts if part not in ('', '.'))[strip:]
    return parts or None


def _inside(base: Path, target: Path) -> bool:
    try:
        Path(os.path.normpath(target)).relative_to(os.path.normpath(base))
        return True
    except ValueError:
        return False


def unpack(archive: Path, destination: Path, strip: int = 0) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    if archive.name.endswith(('.zip', '.nupkg')):
        with zipfile.ZipFile(archive) as bundle:
            for info in bundle.infolist():
                parts = _safe_parts(info.filename, strip)
                if parts is None:
                    continue
                target = destination.joinpath(*parts)
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(info) as source, target.open('wb') as handle:
                    shutil.copyfileobj(source, handle, CHUNK)
                mode = (info.external_attr >> 16) & 0o777
                if mode:
                    os.chmod(target, mode | 0o600)
        return
    with tarfile.open(archive, 'r:*') as bundle:
        for member in bundle.getmembers():
            parts = _safe_parts(member.name, strip)
            if parts is None:
                continue
            target = destination.joinpath(*parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.issym():
                if os.path.isabs(member.linkname) or not _inside(destination, target.parent / member.linkname):
                    raise ToolchainError('TOOLCHAIN_ARCHIVE_UNSAFE', f'symlink leaves the toolchain: {member.name}')
                target.parent.mkdir(parents=True, exist_ok=True)
                target.unlink(missing_ok=True)
                os.symlink(member.linkname, target)
            elif member.islnk():
                linked = _safe_parts(member.linkname, strip)
                if linked is None:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                target.unlink(missing_ok=True)
                os.link(destination.joinpath(*linked), target)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                extracted = bundle.extractfile(member)
                assert extracted is not None
                with extracted, target.open('wb') as handle:
                    shutil.copyfileobj(extracted, handle, CHUNK)
                os.chmod(target, (member.mode & 0o777) | 0o600)


# -- installation ---------------------------------------------------------------------------------

def _expand(value: str, home: Path, cache: Path) -> str:
    return value.replace('{home}', str(home)).replace('{cache}', str(cache))


def _toolchain(stack: str, version: str, home: Path, spec: Mapping[str, Any], key: str, *, fetched: bool) -> Toolchain:
    bins = (spec.get('bin') or {}).get('windows' if key.startswith('windows') else 'posix', ['bin'])
    cache = cache_root(stack)
    env = {name: _expand(value, home, cache) for name, value in (spec.get('env') or {}).items()}
    if 'PSModulePath' in env:
        env['PSModulePath'] = os.pathsep.join([env['PSModulePath'], os.environ.get('PSModulePath', '')]).rstrip(os.pathsep)
    return Toolchain(stack, version, home, tuple(home / item for item in bins), env, fetched)


def installed(home: Path, version: str, key: str) -> bool:
    try:
        marker = json.loads((home / MARKER).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return False
    return isinstance(marker, dict) and marker.get('version') == version and marker.get('platform') == key


MSVC_COMPONENT = 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64'


def msvc_installed(run: Run, which: Which) -> bool:
    """The MSVC linker is rarely on PATH; Visual Studio's own locator says whether the C++ tools exist."""
    if which('link.exe'):
        return True
    vswhere = Path(os.environ.get('ProgramFiles(x86)') or r'C:\Program Files (x86)') / 'Microsoft Visual Studio' / 'Installer' / 'vswhere.exe'
    if not vswhere.is_file():
        return False
    try:
        proc = run([str(vswhere), '-latest', '-products', '*', '-requires', MSVC_COMPONENT, '-property', 'installationPath'],
                   dict(os.environ), None)
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0 and bool((proc.stdout or '').strip())


def missing_requirements(spec: Mapping[str, Any], version: str, key: str, which: Which,
                         run: Run = default_run) -> Blocker | None:
    for requirement in spec.get('requires', []):
        if key not in requirement.get('platforms', [key]):
            continue
        suffix = requirement.get('unless_channel_suffix')
        if suffix and version.endswith(suffix):
            continue
        present = msvc_installed(run, which) if requirement.get('detect') == 'msvc' else which(requirement['probe']) is not None
        if not present:
            return Blocker(f'TOOLCHAIN_NEEDS_ADMIN:{requirement["id"]}', requirement['message'], requirement.get('command'))
    return None


def _publish(staging: Path, home: Path, record: dict[str, Any]) -> None:
    (staging / MARKER).write_text(json.dumps(record, indent=2, sort_keys=True) + '\n', encoding='utf-8', newline='\n')
    if home.exists() and not (home / MARKER).is_file():
        shutil.rmtree(home)  # an earlier attempt that never finished
    try:
        os.replace(staging, home)
    except OSError:
        if not (home / MARKER).is_file():
            raise
        shutil.rmtree(staging, ignore_errors=True)  # another run published the same toolchain first


def _install_archive(stack: str, version: str, spec: Mapping[str, Any], key: str, home: Path, fetch: Fetch,
                     run: Run, which: Which) -> dict[str, Any]:
    source = spec['source']
    template = (source.get('archives') or {}).get(key)
    if not template:
        raise ToolchainError(f'TOOLCHAIN_UNSUPPORTED_PLATFORM:{key}', f'{stack} {version} has no official archive for {key}')
    archive = template.format(version=version)
    digest = expected_digest(source, version, key, archive, fetch)
    url = source['url'].format(version=version, archive=archive)
    downloaded = download_verified(url, digest, source['algorithm'], cache_root(stack) / 'downloads' / archive, fetch)
    staging = Path(tempfile.mkdtemp(prefix=f'.staging-{version}-', dir=home.parent))
    try:
        unpack(downloaded, staging, int(source.get('strip_components', 0)))
        record = {'schema': MARKER_SCHEMA, 'stack': stack, 'version': version, 'platform': key, 'source': url,
                  'algorithm': source['algorithm'], 'digest': digest,
                  'installed_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}
        _publish(staging, home, record)
        return record
    finally:
        shutil.rmtree(staging, ignore_errors=True)


# Source kind -> installer(stack, version, spec, platform, home, fetch, run, which); stacks add theirs.
INSTALLERS: dict[str, Callable[..., dict[str, Any]]] = {'archive': _install_archive}


def ensure_toolchain(stack: str, spec: Mapping[str, Any], version: str, *, fetch: Fetch = default_fetch,
                     run: Run = default_run, which: Which = shutil.which, key: str | None = None,
                     root: Path | None = None) -> Toolchain | Blocker:
    """Return the installed toolchain, installing it first when needed; never raises for a refusal."""
    key = key or platform_key()
    home = (root or toolchain_root()) / stack / version
    blocker = missing_requirements(spec, version, key, which, run)
    if blocker:
        return blocker
    if installed(home, version, key):
        return _toolchain(stack, version, home, spec, key, fetched=False)
    installer = INSTALLERS.get(spec['source']['kind'])
    if installer is None:
        return Blocker('TOOLCHAIN_UNAVAILABLE', f'no installer for source kind {spec["source"]["kind"]!r}')
    home.parent.mkdir(parents=True, exist_ok=True)
    try:
        installer(stack, version, spec, key, home, fetch, run, which)
    except ToolchainError as error:
        return error.blocker
    return _toolchain(stack, version, home, spec, key, fetched=True)
