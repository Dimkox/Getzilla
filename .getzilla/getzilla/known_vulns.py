"""Known-vulnerability check for a repository's pinned dependencies.

Reads lockfiles and pinned manifests (PyPI, npm, Go, crates.io, Packagist,
RubyGems), then looks every exact package version up in the OSV database,
which aggregates the GitHub Advisory Database, PyPA, RustSec, Go, npm and
NVD-derived records. Two sources, never both, and never implicit network:

* ``GETZILLA_OSV_DB=<dir>``: an offline mirror made by ``download_database``
  (``<dir>/<Ecosystem>/snapshot.json`` binds exact public OSV bytes). This is what a
  network-less sandbox such as Trust CI uses.
* ``GETZILLA_OSV_ONLINE=1`` with that directory: read an inventory-bound query
  transcript previously acquired by the explicit CLI ``--online --db DIR``.
  Scans and receipt consumers never refresh. ``query_online`` remains a
  separate observation helper, not a final scan or receipt proof.

Without a source the observation API says unconfigured; final CLI/receipt
consumers refuse applicable unchecked dependencies. Findings can be accepted
for a limited time in ``.getzilla/config/known-vulnerabilities.json``.
"""
from __future__ import annotations

import fnmatch
import hashlib
import io
import json
import os
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, field
from datetime import date, datetime
from itertools import chain
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable

from .security_data import SecurityDataError, osv_aliases, osv_decision_ids

try:
    import tomllib
except ModuleNotFoundError:
    tomllib = None  # type: ignore[assignment]

OSV_API = 'https://api.osv.dev/v1'
OSV_BUCKET = 'https://osv-vulnerabilities.storage.googleapis.com'
ECOSYSTEMS = ('PyPI', 'npm', 'Go', 'crates.io', 'Packagist', 'RubyGems', 'Maven')
CONFIG_PATH = '.getzilla/config/known-vulnerabilities.json'
DEFAULT_EXCLUDE = ('tests/**', '**/tests/**', '**/fixtures/**', '**/node_modules/**', '**/vendor/**', '.getzilla/runtime/**')
MAX_MANIFEST_BYTES = 32 * 1024 * 1024
QUERY_BATCH = 500
MAX_DETAIL_FETCHES = 300
MAX_INVENTORY_ENTRIES = 100000
MAX_INVENTORY_DEPTH = 64
MAX_INVENTORY_BYTES = 32 * 1024 * 1024
MAX_INVENTORY_PROOF_BYTES = 1024 * 1024

Fetch = Callable[[str, bytes | None], bytes]


class VulnerabilityError(RuntimeError):
    pass


@dataclass(frozen=True, order=True)
class Dependency:
    ecosystem: str
    name: str
    version: str
    manifest: str


@dataclass
class Finding:
    dependency: Dependency
    vuln_id: str
    aliases: list[str] = field(default_factory=list)
    summary: str = ''
    severity: str = ''
    fixed: list[str] = field(default_factory=list)
    accepted_until: str | None = None
    raw_aliases: list[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            'ecosystem': self.dependency.ecosystem,
            'package': self.dependency.name,
            'version': self.dependency.version,
            'manifest': self.dependency.manifest,
            'id': self.vuln_id,
            'aliases': self.aliases,
            'summary': self.summary,
            'severity': self.severity,
            'fixed': self.fixed,
            'accepted_until': self.accepted_until,
            'raw_aliases': list(self.aliases if self.raw_aliases is None else self.raw_aliases),
        }


def normalize_name(ecosystem: str, name: str) -> str:
    if ecosystem == 'PyPI':
        return re.sub(r'[-_.]+', '-', name).lower()
    if ecosystem in {'Packagist', 'npm'}:
        return name.lower()
    return name


def _pairs_from_requirements(text: str) -> Iterable[tuple[str, str]]:
    for raw in text.splitlines():
        # Hashed lockfiles end each requirement with a ` \` continuation before its --hash lines.
        line = raw.split('#', 1)[0].strip().removesuffix('\\').strip()
        if not line or line.startswith('-'):
            continue
        match = re.match(r'^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)\s*(?:;.*)?$', line)
        if match:
            yield match.group(1), match.group(2)


def _pairs_from_toml_packages(text: str, *, registry_only: bool) -> Iterable[tuple[str, str]]:
    if tomllib is None:
        raise ValueError('TOML lockfiles need Python 3.11 or newer')
    data = tomllib.loads(text)
    for item in data.get('package', []):
        if not isinstance(item, dict):
            if registry_only:
                raise ValueError('Cargo lock package is malformed')
            continue
        name, version = item.get('name'), item.get('version')
        if not isinstance(name, str) or not isinstance(version, str):
            if registry_only:
                raise ValueError('Cargo lock package identity is missing')
            continue
        source = item.get('source')
        if registry_only and source not in ('registry+https://github.com/rust-lang/crates.io-index',
                                            'sparse+https://index.crates.io/'):
            raise ValueError('Cargo source requires qualified manifest/registry resolution')
        if isinstance(source, dict) and ({'editable', 'directory', 'path', 'virtual', 'git'} & set(source)):
            continue
        yield name, version


def _pairs_from_pyproject(text: str) -> Iterable[tuple[str, str]]:
    if tomllib is None:
        raise ValueError('pyproject.toml needs Python 3.11 or newer')
    data = tomllib.loads(text)
    project = data.get('project') or {}
    build_system = data.get('build-system', {})
    if not isinstance(build_system, dict):
        raise ValueError('build-system must be a table')
    build_requires = build_system.get('requires', [])
    if not isinstance(build_requires, list) or not all(isinstance(item, str) for item in build_requires):
        raise ValueError('build-system.requires must be a list of strings')
    requirements = list(project.get('dependencies') or [])
    requirements.extend(build_requires)
    for group in (project.get('optional-dependencies') or {}).values():
        requirements.extend(group or [])
    development = data.get('dependency-groups', {})
    if not isinstance(development, dict):
        raise ValueError('malformed dependency groups')
    for group in development.values():
        if isinstance(group, list):
            requirements.extend(item for item in group if isinstance(item, str))
    yield from _pairs_from_requirements('\n'.join(str(item) for item in requirements))


def _pairs_from_pipfile_lock(text: str) -> Iterable[tuple[str, str]]:
    data = json.loads(text)
    for section in ('default', 'develop'):
        for name, item in (data.get(section) or {}).items():
            version = item.get('version') if isinstance(item, dict) else None
            if isinstance(version, str) and version.startswith('=='):
                yield name, version[2:]


def _pairs_from_package_lock(text: str) -> Iterable[tuple[str, str]]:
    data = json.loads(text)
    packages = data.get('packages')
    if isinstance(packages, dict):
        for path, item in packages.items():
            if not path or not isinstance(item, dict) or item.get('link'):
                continue
            name = item.get('name') or path.rsplit('node_modules/', 1)[-1]
            version = item.get('version')
            if isinstance(name, str) and isinstance(version, str):
                yield name, version
        return

    def walk(dependencies: dict[str, Any]) -> Iterable[tuple[str, str]]:
        for name, item in dependencies.items():
            if isinstance(item, dict):
                if isinstance(item.get('version'), str):
                    yield name, item['version']
                yield from walk(item.get('dependencies') or {})

    yield from walk(data.get('dependencies') or {})


def _pairs_from_pnpm_lock(text: str) -> Iterable[tuple[str, str]]:
    """pnpm-lock.yaml v6-v9: package keys under ``packages:`` ("/name@1.2.3" or "name@1.2.3(peer)")."""
    section = False
    for raw in text.splitlines():
        if not raw.strip():
            continue
        if not raw.startswith(' '):
            section = raw.rstrip() == 'packages:'
            continue
        match = re.match(r"^  '?/?((?:@[^@/\s']+/)?[^@/\s'(]+)[@/]([0-9][^():'\s]*)", raw) if section else None
        if match:
            yield match.group(1), match.group(2)


def _pairs_from_yarn_lock(text: str) -> Iterable[tuple[str, str]]:
    """yarn.lock v1 (classic) and berry: an entry header, then its ``version``."""
    name = None
    for raw in text.splitlines():
        if raw and not raw.startswith((' ', '#')) and raw.rstrip().endswith(':'):
            spec = raw.split(',', 1)[0].strip().strip('"').rstrip(':').strip('"')
            at = spec.find('@', 1)
            name = spec[:at] if at > 0 else None
            if name == '__metadata':
                name = None
            continue
        match = re.match(r'^  version:? "?([^"\s]+)"?$', raw)
        if match and name:
            version = match.group(1)
            if re.match(r'^[0-9]', version) and '-use.local' not in version:
                yield name, version
            name = None


def _pairs_from_gradle_lockfile(text: str) -> Iterable[tuple[str, str]]:
    """gradle.lockfile: ``group:artifact:version=configurations``; OSV names Maven packages group:artifact."""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or line.startswith('empty='):
            continue
        coordinates = line.split('=', 1)[0].split(':')
        if len(coordinates) == 3 and all(coordinates):
            yield f'{coordinates[0]}:{coordinates[1]}', coordinates[2]


def _pairs_from_go_mod(text: str) -> Iterable[tuple[str, str]]:
    block = False
    for raw in text.splitlines():
        line = raw.split('//', 1)[0].strip()
        if line.startswith('require ('):
            block = True
            continue
        if block and line == ')':
            block = False
            continue
        if line.startswith('require '):
            line = line[len('require '):].strip()
        elif not block:
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1].startswith('v'):
            yield parts[0], parts[1][1:]


def _pairs_from_composer_lock(text: str) -> Iterable[tuple[str, str]]:
    data = json.loads(text)
    for section in ('packages', 'packages-dev'):
        for item in data.get(section) or []:
            name, version = item.get('name'), item.get('version')
            if isinstance(name, str) and isinstance(version, str) and not version.startswith('dev-'):
                yield name, version.removeprefix('v')


def _pairs_from_gemfile_lock(text: str) -> Iterable[tuple[str, str]]:
    in_specs = False
    for raw in text.splitlines():
        if raw.strip() == 'specs:':
            in_specs = True
            continue
        if in_specs and raw and not raw.startswith(' '):
            in_specs = False
        match = re.match(r'^ {4}([A-Za-z0-9._-]+) \(([^)\s]+)\)$', raw) if in_specs else None
        if match:
            yield match.group(1), match.group(2).split('-', 1)[0]


MANIFESTS: dict[str, tuple[str, Callable[[str], Iterable[tuple[str, str]]]]] = {
    'uv.lock': ('PyPI', lambda text: _pairs_from_toml_packages(text, registry_only=False)),
    'poetry.lock': ('PyPI', lambda text: _pairs_from_toml_packages(text, registry_only=False)),
    'Pipfile.lock': ('PyPI', _pairs_from_pipfile_lock),
    'pyproject.toml': ('PyPI', _pairs_from_pyproject),
    'package-lock.json': ('npm', _pairs_from_package_lock),
    'npm-shrinkwrap.json': ('npm', _pairs_from_package_lock),
    'pnpm-lock.yaml': ('npm', _pairs_from_pnpm_lock),
    'yarn.lock': ('npm', _pairs_from_yarn_lock),
    'go.mod': ('Go', _pairs_from_go_mod),
    'Cargo.lock': ('crates.io', lambda text: _pairs_from_toml_packages(text, registry_only=True)),
    'composer.lock': ('Packagist', _pairs_from_composer_lock),
    'Gemfile.lock': ('RubyGems', _pairs_from_gemfile_lock),
    'gradle.lockfile': ('Maven', _pairs_from_gradle_lockfile),
}
REQUIREMENTS_RE = re.compile(r'^(?:.*-)?requirements(?:[-_.][A-Za-z0-9_-]+)?\.txt$')


def _manifest_parser(name: str) -> tuple[str, Callable[[str], Iterable[tuple[str, str]]]] | None:
    if name in MANIFESTS:
        return MANIFESTS[name]
    if REQUIREMENTS_RE.match(name):
        return 'PyPI', _pairs_from_requirements
    return None


def _excluded(path: str, patterns: Iterable[str]) -> bool:
    pure = PurePosixPath(path)
    return any(pure.match(pattern) or fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def _tracked_files(root: Path) -> list[str]:
    try:
        proc = subprocess.run(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=root,
                              capture_output=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired):
        proc = None
    if proc is not None and proc.returncode == 0:
        return sorted({item for item in proc.stdout.decode('utf-8', 'surrogateescape').split('\0') if item})
    files = []
    for path in root.rglob('*'):
        if path.is_file() and not path.is_symlink() and '.git' not in path.relative_to(root).parts:
            files.append(path.relative_to(root).as_posix())
    return sorted(files)


def _cargo_packages(root: Path, lock: str, files: set[str]) -> tuple[list[tuple[str, str]], set[str]]:
    """Resolve only manifest-owned local identities and the default crates.io source."""
    if tomllib is None:
        raise ValueError('Cargo manifests need Python 3.11 or newer')

    def document(relative):
        path = root / relative
        if (relative not in files or path.is_symlink() or not path.is_file()
                or path.stat().st_size > MAX_MANIFEST_BYTES):
            raise ValueError('Cargo manifest is missing or unsupported')
        value = tomllib.loads(_read_manifest_text(root, relative))
        if 'patch' in value or 'replace' in value:
            raise ValueError('Cargo source overrides require a qualified resolver')
        return value

    directory = PurePosixPath(lock).parent
    manifest = (directory / 'Cargo.toml').as_posix()
    documents = {manifest: document(manifest)} if manifest in files else {}
    workspace = documents.get(manifest, {}).get('workspace', {})
    if not isinstance(workspace, dict):
        raise ValueError('Cargo workspace is malformed')
    members = workspace.get('members', [])
    if (not isinstance(members, list) or workspace.get('exclude')
            or any(not isinstance(member, str) or not member or '\\' in member
                   or PurePosixPath(member).is_absolute()
                   or any(part in {'..', '*', '?', '['} or any(c in part for c in '*?[')
                          for part in PurePosixPath(member).parts) for member in members)):
        raise ValueError('Cargo workspace membership requires explicit in-tree paths')
    for member in members:
        relative = (directory / member / 'Cargo.toml').as_posix()
        if relative in documents:
            raise ValueError('Cargo workspace membership is ambiguous')
        documents[relative] = document(relative)
    inherited = workspace.get('package', {})
    workspace_dependencies = workspace.get('dependencies', {})
    if not isinstance(inherited, dict) or not isinstance(workspace_dependencies, dict):
        raise ValueError('Cargo workspace inheritance is malformed')
    local, identities = set(), {}
    for relative, data in documents.items():
        package = data.get('package')
        if package is None and relative == manifest and workspace:
            continue
        if not isinstance(package, dict):
            raise ValueError('Cargo package identity is missing')
        name, version = package.get('name'), package.get('version')
        if type(version) is dict and set(version) == {'workspace'} and version['workspace'] is True:
            version = inherited.get('version')
        if (not isinstance(name, str) or not name or not isinstance(version, str)
                or not version or name in {pair[0] for pair in local}):
            raise ValueError('Cargo local package identity is ambiguous')
        local.add((name, version))
        identities[relative] = name
    declared = set()
    for relative, data in documents.items():
        targets = data.get('target', {})
        if not isinstance(targets, dict) or any(not isinstance(target, dict) for target in targets.values()):
            raise ValueError('Cargo target dependency model is malformed')
        for section in (data, *targets.values()):
            for group in ('dependencies', 'dev-dependencies', 'build-dependencies'):
                dependencies = section.get(group, {})
                if not isinstance(dependencies, dict):
                    raise ValueError('Cargo dependency table is malformed')
                for alias, dependency in dependencies.items():
                    dependency_base = PurePosixPath(relative).parent
                    if not isinstance(alias, str) or not alias:
                        raise ValueError('Cargo dependency identity is malformed')
                    if isinstance(dependency, dict) and 'workspace' in dependency:
                        if (dependency['workspace'] is not True
                                or set(dependency) - {'workspace', 'features', 'optional', 'default-features'}
                                or alias not in workspace_dependencies):
                            raise ValueError('Cargo workspace dependency is unresolved')
                        dependency = workspace_dependencies[alias]
                        dependency_base = directory
                    if isinstance(dependency, str) and dependency:
                        declared.add(alias)
                        continue
                    if (not isinstance(dependency, dict) or set(dependency)
                            - {'version', 'features', 'optional', 'default-features', 'package', 'path'}):
                        raise ValueError('Cargo unsupported dependency source requires a qualified adapter')
                    name = dependency.get('package', alias)
                    if not isinstance(name, str) or not name:
                        raise ValueError('Cargo dependency package identity is malformed')
                    if 'path' in dependency:
                        path = dependency['path']
                        if not isinstance(path, str) or not path or '\\' in path or PurePosixPath(path).is_absolute():
                            raise ValueError('Cargo path dependency is unresolved')
                        import posixpath
                        target = posixpath.normpath((dependency_base / path / 'Cargo.toml').as_posix())
                        if target not in identities or identities[target] != name:
                            raise ValueError('Cargo path is not an identified workspace member')
                    elif isinstance(dependency.get('version'), str) and dependency['version']:
                        declared.add(name)
                    else:
                        raise ValueError('Cargo dependency version is unresolved')
    data = document(lock)
    packages = data.get('package')
    if not isinstance(packages, list):
        raise ValueError('Cargo lock packages are missing or malformed')
    pairs = []
    for package in packages:
        if not isinstance(package, dict):
            raise ValueError('Cargo lock package is malformed')
        name, version = package.get('name'), package.get('version')
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
            raise ValueError('Cargo lock package identity is missing')
        if 'source' not in package and (name, version) in local:
            continue
        if package.get('source') not in ('registry+https://github.com/rust-lang/crates.io-index',
                                         'sparse+https://index.crates.io/'):
            raise ValueError('Cargo source requires a qualified registry/artifact adapter')
        pairs.append((name, version))
    if declared - {name for name, _version in pairs}:
        raise ValueError('Cargo declaration has no exact qualified lock entry')
    if local - {(package.get('name'), package.get('version')) for package in packages}:
        raise ValueError('Cargo local package has no matching lock identity')
    return pairs, set(documents)


def collect_dependencies(root: Path, *, exclude: Iterable[str] = DEFAULT_EXCLUDE) -> tuple[list[Dependency], list[str]]:
    """Exact pinned dependencies and the manifests they came from."""
    patterns = tuple(exclude)
    dependencies: set[Dependency] = set()
    manifests: list[str] = []
    files = {relative for relative in _tracked_files(root) if not _excluded(relative, patterns)}
    cargo_manifests = set()
    for relative in sorted(files):
        parser = _manifest_parser(PurePosixPath(relative).name)
        if parser is None or _excluded(relative, patterns):
            continue
        path = root / relative
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_MANIFEST_BYTES:
            if PurePosixPath(relative).name == 'Cargo.lock':
                raise VulnerabilityError('Cargo lock cannot establish complete inventory')
            continue
        ecosystem, parse = parser
        try:
            if PurePosixPath(relative).name == 'Cargo.lock':
                pairs, identified = _cargo_packages(root, relative, files)
                cargo_manifests.update(identified)
            else:
                pairs = list(parse(_read_manifest_text(root, relative)))
        except (UnicodeDecodeError, ValueError) as exc:
            raise VulnerabilityError(f'cannot parse {relative}: {exc}') from exc
        manifests.append(relative)
        for name, version in pairs:
            dependencies.add(Dependency(ecosystem, name, version, relative))
    for relative in files - cargo_manifests:
        if PurePosixPath(relative).name != 'Cargo.toml':
            continue
        path = root / relative
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_MANIFEST_BYTES:
            raise VulnerabilityError('Cargo manifest cannot establish complete inventory')
        try:
            document = tomllib.loads(_read_manifest_text(root, relative)) if tomllib is not None else None
            if (document is None or any(document.get(key) for key in (
                    'dependencies', 'dev-dependencies', 'build-dependencies', 'target', 'workspace', 'patch', 'replace'))):
                raise ValueError('Cargo declarations require a matching qualified lockfile')
        except (UnicodeDecodeError, ValueError) as exc:
            raise VulnerabilityError(f'cannot parse {relative}: {exc}') from exc
    return sorted(dependencies), manifests


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True, allow_nan=False).encode('utf-8')).hexdigest()


def _read_manifest_text(root: Path, relative: str) -> str:
    from .component_state import BoundRoot, ComponentStateError
    try:
        with BoundRoot(root) as bound:
            snapshot = bound.read(relative, limit=MAX_MANIFEST_BYTES)
            if snapshot is None:
                raise ValueError('missing source input')
            bound.check()
            return snapshot.content.decode('utf-8')
    except (OSError, ValueError, UnicodeError, ComponentStateError):
        label = 'Cargo ' if PurePosixPath(relative).name.startswith('Cargo.') else ''
        raise VulnerabilityError(f'incomplete {label}inventory: unsafe or unreadable source input') from None


def _inventory_files(root: Path, patterns: tuple[str, ...]) -> list[str]:
    """Count entries before materialization; never follow source directory links."""
    declarations = {'Cargo.toml', 'package.json', 'composer.json', 'Gemfile', 'Pipfile',
                    'setup.py', 'setup.cfg', 'requirements.in',
                    'pom.xml', 'build.gradle', 'build.gradle.kts'}
    pending, selected, count = [('', 0)], [], 0
    try:
        while pending:
            relative, depth = pending.pop()
            if depth > MAX_INVENTORY_DEPTH:
                raise VulnerabilityError('incomplete inventory: directory depth exceeds bound')
            with os.scandir(root / relative) as entries:
                for entry in entries:
                    count += 1
                    if count > MAX_INVENTORY_ENTRIES:
                        raise VulnerabilityError('incomplete inventory: file census exceeds bound')
                    name = f'{relative}/{entry.name}' if relative else entry.name
                    if entry.name == '.git' or _excluded(name, patterns):
                        continue
                    if entry.is_symlink():
                        label = 'Cargo' if entry.name.startswith('Cargo.') else 'dependency'
                        raise VulnerabilityError(f'incomplete {label} inventory: linked source input')
                    if entry.is_dir(follow_symlinks=False):
                        if not _excluded(name + '/.inventory-child', patterns):
                            pending.append((name, depth + 1))
                    elif _manifest_parser(entry.name) is not None or entry.name in declarations:
                        if not entry.is_file(follow_symlinks=False):
                            raise VulnerabilityError('incomplete inventory: nonregular dependency input')
                        selected.append(name)
    except OSError:
        raise VulnerabilityError('incomplete inventory: unreadable source census') from None
    return sorted(selected)


def _default_registry_url(value: Any, ecosystem: str) -> bool:
    """Only declared default registry identities; never fetch a manifest URL."""
    if (type(value) is not str or not value or len(value) > 2048 or value != value.strip()
            or any(ord(character) <= 32 or ord(character) == 127 for character in value)):
        return False
    try:
        parsed = urllib.parse.urlsplit(value)
        if (parsed.scheme != 'https' or parsed.port not in {None, 443} or parsed.username is not None
                or parsed.password is not None or parsed.query or parsed.fragment):
            return False
        if ecosystem == 'PyPI':
            return parsed.hostname == 'pypi.org' and parsed.path in {'/simple', '/simple/'}
        return ecosystem == 'npm' and parsed.hostname == 'registry.npmjs.org'
    except ValueError:
        return False


def _strict_manifest_pairs(name: str, text: str, ecosystem: str, parse, texts: dict[str, str], relative: str):
    """Supported exact-pin forms only; unknown records remain incomplete."""
    if REQUIREMENTS_RE.fullmatch(name):
        for raw in text.splitlines():
            line = raw.split('#', 1)[0].strip().removesuffix('\\').strip()
            if not line or re.fullmatch(r'--hash=sha256:[a-fA-F0-9]{64}', line):
                continue
            if len(list(_pairs_from_requirements(line))) != 1:
                raise ValueError('unresolved requirement')
    elif name == 'pyproject.toml':
        data = tomllib.loads(text) if tomllib else None
        if not isinstance(data, dict):
            raise ValueError('unsupported TOML dependency model')
        project, backend = data.get('project', {}), data.get('build-system', {})
        if not isinstance(project, dict) or not isinstance(backend, dict):
            raise ValueError('unresolved dynamic dependency model')
        dynamic = project.get('dynamic', [])
        if (type(dynamic) is not list or any(type(item) is not str for item in dynamic)
                or {'dependencies', 'optional-dependencies'} & set(dynamic)):
            raise ValueError('unresolved dynamic dependency model')
        tools = data.get('tool', {})
        if type(tools) is not dict or type(tools.get('poetry', {})) is not dict or type(tools.get('uv', {})) is not dict:
            raise ValueError('malformed dependency tool declarations')
        if (any(key in tools.get('uv', {}) for key in ('sources', 'index', 'default-index', 'index-url', 'extra-index-url', 'find-links', 'no-index'))
                or any(key in tools.get('poetry', {}) for key in ('dependencies', 'dev-dependencies', 'group', 'source'))):
            raise ValueError('dependency declarations or source overrides require a qualified resolver')
        development = data.get('dependency-groups', {})
        if not isinstance(development, dict):
            raise ValueError('malformed dependency groups')
        # Collect every marker branch. Only direct literal pins need no resolver.
        from .lock_profile_validation import _marker_tree
        for requirements in development.values():
            if not isinstance(requirements, list):
                raise ValueError('malformed dependency group')
            for requirement in requirements:
                if not isinstance(requirement, str) or len(requirement.splitlines()) != 1:
                    raise ValueError('dependency group requires a qualified resolver')
                pin, separator, marker = requirement.partition(';')
                if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9._,-]+\])?==[A-Za-z0-9][A-Za-z0-9.+!_-]*', pin.strip()):
                    raise ValueError('dependency group requires an exact pin')
                if separator:
                    if not marker.strip():
                        raise ValueError('empty dependency marker')
                    _marker_tree(marker.strip())
        groups = project.get('optional-dependencies', {})
        if not isinstance(groups, dict):
            raise ValueError('malformed dependency groups')
        for group in [project.get('dependencies', []), backend.get('requires', []), *groups.values()]:
            if not isinstance(group, list) or any(type(item) is not str or len(list(_pairs_from_requirements(item))) != 1 for item in group):
                raise ValueError('unresolved project requirement')
    elif name in {'uv.lock', 'poetry.lock'}:
        data = tomllib.loads(text) if tomllib else None
        if not isinstance(data, dict) or not isinstance(data.get('package'), list):
            raise ValueError('malformed package census')
        for item in data['package']:
            if (not isinstance(item, dict) or type(item.get('name')) is not str or not item['name']
                    or type(item.get('version')) is not str or not item['version']):
                raise ValueError('unresolved lock identity')
            source = item.get('source')
            if isinstance(source, dict) and {'editable', 'directory', 'path', 'virtual', 'git'} & set(source):
                peer = str(PurePosixPath(relative).with_name('pyproject.toml'))
                project = tomllib.loads(texts.get(peer, '')).get('project', {})
                if (set(source) - {'editable', 'virtual'} or not source or set(source.values()) != {'.'}
                        or not isinstance(project, dict) or project.get('name') != item['name']):
                    raise ValueError('unqualified local or Git dependency')
            elif source is not None:
                if name == 'uv.lock':
                    valid = type(source) is dict and set(source) == {'registry'} and _default_registry_url(source['registry'], 'PyPI')
                else:
                    valid = (type(source) is dict and source.get('type') == 'legacy'
                             and not set(source) - {'type', 'url', 'reference'}
                             and _default_registry_url(source.get('url'), 'PyPI'))
                if not valid:
                    raise ValueError('unqualified explicit Python registry source')
    elif name == 'Pipfile.lock':
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError('malformed package census')
        metadata = data.get('_meta', {})
        if type(metadata) is not dict:
            raise ValueError('malformed Pipfile source metadata')
        sources = metadata.get('sources', [])
        if (type(sources) is not list or any(type(source) is not dict
                or type(source.get('name')) is not str or not source['name']
                or not _default_registry_url(source.get('url'), 'PyPI')
                or source.get('verify_ssl', True) is not True for source in sources)):
            raise ValueError('unqualified explicit Pipfile registry source')
        source_names = {source['name'] for source in sources}
        for key in ('default', 'develop'):
            group = data.get(key, {})
            if not isinstance(group, dict) or any(not isinstance(row, dict) or type(row.get('version')) is not str
                                               or not row['version'].startswith('==') for row in group.values()):
                raise ValueError('unresolved lock identity')
            if any('index' in row and (type(row['index']) is not str or row['index'] not in source_names) for row in group.values()):
                raise ValueError('unqualified Pipfile index identity')
    elif name in {'package-lock.json', 'npm-shrinkwrap.json'}:
        data = json.loads(text)
        if not isinstance(data, dict) or not ({'packages', 'dependencies'} & set(data)):
            raise ValueError('missing package census')
        if 'packages' in data:
            if not isinstance(data['packages'], dict):
                raise ValueError('malformed package census')
            for path, item in data['packages'].items():
                if not isinstance(item, dict) or (path and (item.get('link') or type(item.get('version')) is not str
                                                          or not re.fullmatch(r'[0-9][A-Za-z0-9.+_-]*', item['version']))):
                    raise ValueError('unresolved package source')
                if path and ('resolved' in item and not _default_registry_url(item['resolved'], 'npm')
                             or item.get('inBundle') or item.get('bundled')):
                    raise ValueError('unqualified explicit npm source')
        else:
            stack = [data['dependencies']]
            while stack:
                group = stack.pop()
                if not isinstance(group, dict):
                    raise ValueError('malformed package census')
                for item in group.values():
                    if not isinstance(item, dict) or type(item.get('version')) is not str or not re.fullmatch(r'[0-9][A-Za-z0-9.+_-]*', item['version']):
                        raise ValueError('unresolved package identity')
                    if ('resolved' in item and not _default_registry_url(item['resolved'], 'npm')
                            or item.get('inBundle') or item.get('bundled')):
                        raise ValueError('unqualified explicit npm source')
                    if 'dependencies' in item:
                        stack.append(item['dependencies'])
    elif name == 'composer.lock':
        data = json.loads(text)
        if not isinstance(data, dict) or not {'packages', 'packages-dev'} & set(data):
            raise ValueError('missing package census')
        for key in ('packages', 'packages-dev'):
            if not isinstance(data.get(key, []), list):
                raise ValueError('malformed package census')
            for item in data.get(key, []):
                if (not isinstance(item, dict) or type(item.get('name')) is not str or not item['name']
                        or type(item.get('version')) is not str
                        or not re.fullmatch(r'v?[0-9][A-Za-z0-9.+_-]*', item['version'])):
                    raise ValueError('unresolved package identity')
    elif name == 'go.mod':
        block = False
        for raw in text.splitlines():
            line = raw.split('//', 1)[0].strip()
            if not line or re.fullmatch(r'(?:module|go|toolchain)\s+\S+', line):
                continue
            if line == 'require (':
                block = True
            elif line == ')' and block:
                block = False
            elif not re.fullmatch(r'(?:require\s+)?\S+\s+v[0-9][A-Za-z0-9.+_-]*', line) or not (block or line.startswith('require ')):
                raise ValueError('unresolved Go source')
        if block:
            raise ValueError('incomplete Go requirement block')
    elif name == 'gradle.lockfile':
        if any(line.strip() and not line.strip().startswith(('#', 'empty='))
               and not re.fullmatch(r'[^:=\s]+:[^:=\s]+:[^:=\s]+=.*', line.strip()) for line in text.splitlines()):
            raise ValueError('unresolved Maven lock identity')
    else:
        # Native extraction supports these formats, but regex extraction alone
        # cannot establish their complete source/record census.
        raise ValueError('dependency format requires a qualified complete resolver')
    return list(parse(text))


_COMPOSER_RELEVANT = ('name', 'version', 'require', 'require-dev', 'conflict', 'replace',
             'provide', 'minimum-stability', 'prefer-stable', 'repositories', 'extra')
_COMPOSER_PACKAGE = re.compile(r'[a-z0-9][a-z0-9_.-]*/[a-z0-9][a-z0-9_.-]*\Z')
_COMPOSER_PLATFORM = re.compile(r'(?:php(?:-64bit|-ipv6|-zts|-debug)?|hhvm|(?:ext|lib)-[a-z0-9_.-]+|composer(?:-plugin-api|-runtime-api)?)\Z')


def _composer_json_pairs(items):
    result = {}
    for key, value in items:
        key.encode('utf-8', errors='strict')
        if key in result:
            raise ValueError('Composer duplicate JSON key')
        result[key] = value
    return result


def _composer_bad_number(value):
    raise ValueError('Composer floating or nonfinite JSON number is unsupported')


def _composer_json(text):
    value = json.loads(text, object_pairs_hook=_composer_json_pairs, parse_float=_composer_bad_number, parse_constant=_composer_bad_number)
    if type(value) is not dict:
        raise ValueError('Composer document must be an object')
    return value


def _composer_php_array(value):
    # JsonFile::parseJson decodes associative PHP arrays. Empty objects encode
    # as [] with the flags=0 used by Locker; ambiguous numeric keys stay closed.
    if type(value) is dict:
        if any(re.fullmatch(r'-?[0-9]+', key) for key in value):
            raise ValueError('Composer numeric object keys are unsupported')
        return {key: _composer_php_array(item) for key, item in value.items()} if value else []
    if type(value) is list:
        return [_composer_php_array(item) for item in value]
    if type(value) is int and not -(2**63) <= value < 2**63:
        raise ValueError('Composer integer exceeds native JSON range')
    if type(value) is str:
        value.encode('utf-8', errors='strict')
    return value


def _composer_content_hash(text):
    """Match Composer Locker::getContentHash and JsonFile::encode(flags=0)."""
    data = _composer_json(text)
    selected = {key: data[key] for key in _COMPOSER_RELEVANT if key in data}
    config = data.get('config', {})
    if type(config) is not dict:
        raise ValueError('Composer config must be an object')
    if config.get('platform') is not None:
        selected['config'] = {'platform': config['platform']}
    selected = {key: selected[key] for key in sorted(selected)}
    raw = json.dumps(_composer_php_array(selected), ensure_ascii=True, separators=(',', ':'),
                     allow_nan=False).replace('/', '\\/').encode('ascii')
    return hashlib.md5(raw, usedforsecurity=False).hexdigest()


def _composer_version(value):
    match = re.fullmatch(r'v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', value)
    if match is None:
        raise ValueError('Composer direct version needs a qualified stable resolver')
    return tuple(int(part) for part in match.groups())


def _composer_satisfies(version, constraint):
    """Exact/caret/tilde stable subset; other Composer solver forms refuse."""
    actual = _composer_version(version)
    match = re.fullmatch(r'([\^~]?)(?:v)?(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?(?:\.(0|[1-9][0-9]*))?', constraint)
    if match is None:
        raise ValueError('Composer constraint requires a qualified resolver')
    parts = [int(part) for part in match.groups()[1:] if part is not None]
    lower = tuple(parts + [0] * (3 - len(parts)))
    if not match[1]:
        return actual == lower
    index = (1 if len(parts) == 3 else 0) if match[1] == '~' else next(
        (i for i, value in enumerate(parts) if value), len(parts) - 1)
    upper = list(lower)
    upper[index] += 1
    upper[index + 1:] = [0] * (2 - index)
    return lower <= actual < tuple(upper)


def _validate_composer_binding(manifest_text, lock_text):
    """Bind supported direct declarations to their exact sibling lock census."""
    manifest, lock = _composer_json(manifest_text), _composer_json(lock_text)
    if lock.get('content-hash') != _composer_content_hash(manifest_text):
        raise ValueError('Composer manifest and lock content-hash differ')
    for key in ('conflict', 'replace', 'provide'):
        if key in manifest and type(manifest[key]) is not dict:
            raise ValueError('Composer graph declarations must be objects')
    if ('prefer-stable' in manifest and type(manifest['prefer-stable']) is not bool
            or 'minimum-stability' in manifest and (type(manifest['minimum-stability']) is not str
                or manifest['minimum-stability'] not in {'stable', 'RC', 'beta', 'alpha', 'dev'})
            or 'repositories' in manifest and type(manifest['repositories']) not in {dict, list}):
        raise ValueError('Composer resolution policy is malformed')
    if any(manifest.get(key) for key in ('conflict', 'replace', 'provide', 'repositories')) or lock.get('aliases'):
        raise ValueError('Composer alternate graph needs a qualified resolver')
    packages = {}
    production = set()
    for section in ('packages', 'packages-dev'):
        rows = lock.get(section)
        if type(rows) is not list:
            raise ValueError('Composer complete production and development census required')
        for row in rows:
            if (type(row) is not dict or type(row.get('name')) is not str or not _COMPOSER_PACKAGE.fullmatch(row['name'])
                    or type(row.get('version')) is not str or row['name'] in packages):
                raise ValueError('Composer package census malformed or duplicated')
            packages[row['name']] = row['version']
            if section == 'packages':
                production.add(row['name'])
    for section, platform_key in (('require', 'platform'), ('require-dev', 'platform-dev')):
        declared = manifest.get(section, {})
        if type(declared) is not dict:
            raise ValueError('Composer declarations must be objects')
        platform = {}
        for name, constraint in declared.items():
            if type(constraint) is not str or not constraint:
                raise ValueError('Composer declaration needs a constraint')
            if _COMPOSER_PLATFORM.fullmatch(name):
                if not re.fullmatch(r'\*|(?:>=|<=|>|<|==|=|\^|~)?\s*v?[0-9]+(?:\.[0-9]+){0,2}', constraint):
                    raise ValueError('Composer platform constraint needs a qualified resolver')
                platform[name] = constraint
            elif (not _COMPOSER_PACKAGE.fullmatch(name) or name not in packages
                    or section == 'require' and name not in production
                    or not _composer_satisfies(packages[name], constraint)):
                raise ValueError('Composer direct dependency is not covered by the lock')
        if lock.get(platform_key, {}) != platform:
            raise ValueError('Composer platform declarations differ from lock')
    config = manifest.get('config', {})
    overrides = config.get('platform', {})
    if type(overrides) is not dict or lock.get('platform-overrides', {}) != overrides:
        raise ValueError('Composer platform overrides need an exact declaration')
    if any(not _COMPOSER_PLATFORM.fullmatch(name) or value is not False and (
            type(value) is not str or not re.fullmatch(r'v?[0-9]+(?:\.[0-9]+){0,2}', value))
           for name, value in overrides.items()):
        raise ValueError('Composer platform override is unsupported')


def dependency_inventory(root: Path, config: dict[str, Any]) -> tuple[list[Dependency], list[str], dict[str, Any]]:
    from .component_state import BoundRoot, ComponentStateError
    patterns = tuple(config['exclude'])
    policy = _policy_snapshot(root)
    if load_config(root) != config:
        raise VulnerabilityError('security policy changed before inventory')
    files = _inventory_files(root, patterns)
    if len(files) > 4096:
        raise VulnerabilityError('incomplete inventory: manifest census exceeds bound')
    if any(_manifest_parser(PurePosixPath(relative).name) is None
           and PurePosixPath(relative).name not in {'Cargo.toml', 'composer.json'} for relative in files):
        raise VulnerabilityError('incomplete inventory: unsupported dependency declaration')
    snapshots, texts, total = {}, {}, 0
    try:
        with BoundRoot(root) as bound:
            for relative in files:
                snapshot = bound.read(relative, limit=min(MAX_MANIFEST_BYTES, MAX_INVENTORY_BYTES - total))
                if snapshot is None:
                    raise VulnerabilityError('incomplete inventory: source disappeared')
                total += len(snapshot.content)
                snapshots[relative] = snapshot
                texts[relative] = snapshot.content.decode('utf-8')
            dependencies, manifests, cargo = set(), [], set()
            for relative in files:
                name = PurePosixPath(relative).name
                parser = _manifest_parser(name)
                if parser is None:
                    continue
                ecosystem, parse = parser
                if name == 'Cargo.lock':
                    pairs, identified = _cargo_packages(root, relative, set(files))
                    cargo.update(identified)
                else:
                    pairs = _strict_manifest_pairs(name, texts[relative], ecosystem, parse, texts, relative)
                manifests.append(relative)
                dependencies.update(Dependency(ecosystem, package, version, relative) for package, version in pairs)
            for relative in files:
                name = PurePosixPath(relative).name
                if name == 'Cargo.toml':
                    if relative not in cargo and any(tomllib.loads(texts[relative]).get(key) for key in (
                            'dependencies', 'dev-dependencies', 'build-dependencies', 'target', 'workspace', 'patch', 'replace')):
                        raise ValueError('Cargo unresolved declaration requires a qualified lock')
                elif name == 'composer.json':
                    lock = str(PurePosixPath(relative).with_name('composer.lock'))
                    if lock not in texts:
                        raise ValueError('Composer declaration requires its sibling lock')
                    _validate_composer_binding(texts[relative], texts[lock])
                elif _manifest_parser(name) is None:
                    # The current closed collector has no complete resolver
                    # for these declarations; never infer structural absence.
                    raise ValueError('unresolved dependency declaration')
            for relative, previous in snapshots.items():
                if bound.read(relative, limit=MAX_MANIFEST_BYTES) != previous:
                    raise ValueError('dependency input changed during inventory')
            bound.check()
        if _policy_snapshot(root) != policy:
            raise ValueError('security policy changed during inventory')
        objects = [{'ecosystem': d.ecosystem, 'name': d.name, 'version': d.version, 'manifest': d.manifest} for d in sorted(dependencies)]
        proof = {'schema_version': 1, 'complete': True, 'selection': 'bounded-physical-source-with-explicit-exclusions',
                 'policy_sha256': _digest(config), 'objects': objects,
                 'policy_input': None if policy is None else {
                     'sha256': policy.sha256, 'mode': policy.mode, 'identity_sha256': _digest(list(policy.identity))},
                 'inputs': [{'path': p, 'sha256': s.sha256, 'mode': s.mode,
                             'identity_sha256': _digest(list(s.identity))} for p, s in sorted(snapshots.items())]}
        if len(json.dumps(proof).encode('utf-8')) > MAX_INVENTORY_PROOF_BYTES:
            raise ValueError('inventory proof exceeds bound')
        return sorted(dependencies), manifests, proof
    except (OSError, ValueError, UnicodeError, RecursionError, ComponentStateError) as error:
        label = 'Cargo ' if 'Cargo' in str(error) else ''
        raise VulnerabilityError(f'incomplete {label}dependency inventory') from None


def _policy_snapshot(root: Path):
    from .component_state import BoundRoot, ComponentStateError
    try:
        with BoundRoot(root) as bound:
            snapshot = bound.read(CONFIG_PATH, limit=65536)
            bound.check()
            return snapshot
    except (OSError, ValueError, ComponentStateError):
        raise VulnerabilityError('security policy is unsafe, unreadable or exceeds its bound') from None


def load_config(root: Path) -> dict[str, Any]:
    snapshot = _policy_snapshot(root)
    if snapshot is None:
        return {'exclude': list(DEFAULT_EXCLUDE), 'accept': []}
    try:
        from .security_data import _json
        data = _json(snapshot.content)
    except (OSError, ValueError) as exc:
        raise VulnerabilityError(f'invalid {CONFIG_PATH}: {exc}') from exc
    exclude = data.get('exclude', list(DEFAULT_EXCLUDE))
    accept = data.get('accept', [])
    if not isinstance(exclude, list) or not all(isinstance(item, str) for item in exclude):
        raise VulnerabilityError(f'{CONFIG_PATH}: exclude must be a list of glob strings')
    if not isinstance(accept, list):
        raise VulnerabilityError(f'{CONFIG_PATH}: accept must be a list')
    for item in accept:
        if not isinstance(item, dict) or not {'id', 'reason', 'expires'} <= set(item):
            raise VulnerabilityError(f'{CONFIG_PATH}: every accept entry needs id, reason and expires')
        if not str(item['reason']).strip():
            raise VulnerabilityError(f'{CONFIG_PATH}: accept reason must not be empty')
        try:
            date.fromisoformat(str(item['expires']))
        except ValueError as exc:
            raise VulnerabilityError(f'{CONFIG_PATH}: accept expires must be YYYY-MM-DD') from exc
    return {'exclude': exclude, 'accept': accept}


def _semver_key(version: str) -> tuple[Any, ...]:
    """SemVer2 precedence: prereleases precede final, builds do not order."""
    if not isinstance(version, str) or len(version) > 512:
        raise VulnerabilityError('unsupported SemVer version')
    match = re.fullmatch(
        r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'
        r'(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?'
        r'(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?', version)
    if match is None:
        raise VulnerabilityError('unsupported SemVer version')
    prerelease = []
    if match[4] is not None:
        for part in match[4].split('.'):
            if part.isdigit():
                if len(part) > 1 and part[0] == '0':
                    raise VulnerabilityError('unsupported SemVer prerelease')
                prerelease.append((0, int(part)))
            else:
                prerelease.append((1, part))
    return (int(match[1]), int(match[2]), int(match[3]),
            (0, tuple(prerelease)) if match[4] is not None else (1, ()))


def _pypi_key(version: str) -> tuple[Any, ...]:
    """Qualified canonical PEP440 subset; other forms remain explicit unknown."""
    if not isinstance(version, str) or len(version) > 512:
        raise VulnerabilityError('unsupported PyPI version (canonical PEP440 subset)')
    match = re.fullmatch(
        r'(?:(?P<epoch>[0-9]+)!)?(?P<release>[0-9]+(?:\.[0-9]+)*)'
        r'(?:(?P<pre>a|b|rc|c)(?P<pre_n>[0-9]+))?'
        r'(?:\.post(?P<post>[0-9]+))?(?:\.dev(?P<dev>[0-9]+))?'
        r'(?:\+(?P<local>[a-z0-9]+(?:\.[a-z0-9]+)*))?', version.lower())
    if match is None:
        raise VulnerabilityError('unsupported PyPI version (canonical PEP440 subset)')
    release = [int(part) for part in match['release'].split('.')]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    if match['pre']:
        pre = (0, {'a': 0, 'b': 1, 'rc': 2, 'c': 2}[match['pre']], int(match['pre_n']))
    elif match['dev'] is not None and match['post'] is None:
        pre = (-1, 0, 0)
    else:
        pre = (1, 0, 0)
    post = (-1, 0) if match['post'] is None else (0, int(match['post']))
    dev = (1, 0) if match['dev'] is None else (0, int(match['dev']))
    local = (0, ()) if match['local'] is None else (1, tuple(
        (1, int(part)) if part.isdigit() else (0, part) for part in match['local'].split('.')))
    return int(match['epoch'] or 0), tuple(release), pre, post, dev, local


def _range_key(version: str, *, kind: str, ecosystem: str) -> tuple[Any, ...]:
    if kind == 'SEMVER':
        return _semver_key(version)
    if kind == 'ECOSYSTEM' and ecosystem == 'PyPI':
        return _pypi_key(version)
    raise VulnerabilityError('unsupported OSV range comparator for ecosystem')


def _range_contains(version: str, item: dict[str, Any], *, ecosystem: str) -> bool:
    if not isinstance(item, dict):
        raise VulnerabilityError('malformed OSV range')
    kind = item.get('type')
    target = _range_key(version, kind=kind, ecosystem=ecosystem)
    events = item.get('events')
    if not isinstance(events, list) or not events:
        raise VulnerabilityError('malformed OSV range: nonempty events required')
    timeline, limits, roles, previous = [], [], set(), None
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            raise VulnerabilityError('malformed OSV event: one role required')
        role, value = next(iter(event.items()))
        if role not in {'introduced', 'fixed', 'last_affected', 'limit'} or not isinstance(value, str) or not value:
            raise VulnerabilityError('malformed OSV event')
        roles.add(role)
        if role == 'limit' and '*' in value:
            key = (2, ())
            limits.append(None)
        elif role == 'introduced' and value == '0':
            key = (0, ())
        else:
            key = (1, _range_key(value, kind=kind, ecosystem=ecosystem))
            if role == 'limit':
                limits.append(key[1])
        # OSV's general algorithm sorts input. This native qualified profile
        # instead refuses unsorted/ambiguous data rather than guessing clean.
        if previous is not None and key <= previous:
            raise VulnerabilityError('unsupported unsorted or ambiguous OSV events')
        previous = key
        if role != 'limit':
            timeline.append((key, role))
    if 'introduced' not in roles or {'fixed', 'last_affected'} <= roles:
        raise VulnerabilityError('malformed OSV range roles')
    included = False
    for key, role in timeline:
        if role == 'introduced' and (key[0] == 0 or key[1] <= target):
            included = True
        elif role == 'fixed' and key[1] <= target:
            included = False
        elif role == 'last_affected' and key[1] < target:
            included = False
    return included and (not limits or any(limit is None or target < limit for limit in limits))


def _in_ranges(version: str, affected: dict[str, Any], *, ecosystem: str | None = None) -> bool:
    if not isinstance(affected, dict) or not isinstance(version, str) or not version:
        raise VulnerabilityError('malformed OSV affected entry or target version')
    versions = affected.get('versions', [])
    if not isinstance(versions, list) or not all(isinstance(value, str) and value for value in versions):
        raise VulnerabilityError('malformed OSV enumerated versions')
    package = affected.get('package', {})
    if not isinstance(package, dict):
        raise VulnerabilityError('malformed OSV package')
    ecosystem = ecosystem if ecosystem is not None else package.get('ecosystem', '')
    ranges = affected.get('ranges', [])
    if not isinstance(ranges, list):
        raise VulnerabilityError('malformed OSV ranges')
    if not ranges and not versions:
        raise VulnerabilityError('OSV affected version coverage is unknown for matched package')
    # Validate ALL coverage before matching: a positive or accepted finding
    # must not erase an unsupported range in the same affected entry.
    matches = [_range_contains(version, item, ecosystem=ecosystem) for item in ranges]
    if version in versions:
        return True
    if versions:
        if ecosystem == 'PyPI':
            key = _pypi_key
            target = key(version)
            matches.extend(target == key(value) for value in versions)
        # Other complete lists use literal identity; a miss needs no ordering.
        # Declared ranges were validated above and do not broaden that identity.
    return any(matches)


def _aliases(record: dict[str, Any]) -> list[str]:
    """Validate transport shape; rejected diagnostics contain hashes only."""
    from .security_osv_diagnostics import alias_rejection
    def rejected(index=None):
        detail = alias_rejection(record, index)
        error = VulnerabilityError('OSV aliases must be null or a list of strings' + '; ' + json.dumps(detail, sort_keys=True))
        error.osv_alias_detail = detail
        return error
    if not isinstance(record, dict):
        raise rejected()
    try:
        return osv_aliases(record)
    except SecurityDataError as exc:
        raise rejected(getattr(exc, 'osv_alias_detail', {}).get('index')) from exc


def _describe(record: dict[str, Any], dependency: Dependency) -> Finding:
    aliases = _aliases(record)
    try:
        decision_ids = set(osv_decision_ids({'id': record.get('id'), 'aliases': aliases}))
    except SecurityDataError as exc:
        error = VulnerabilityError(str(exc))
        if hasattr(exc, 'osv_alias_detail'):
            error.osv_alias_detail = exc.osv_alias_detail
        raise error from exc
    severity = ''
    fixed: list[str] = []
    for affected in record.get('affected') or []:
        package = affected.get('package') or {}
        if package.get('ecosystem') != dependency.ecosystem:
            continue
        name = normalize_name(dependency.ecosystem, str(package.get('name', '')))
        if name == '*':
            if not _in_ranges(dependency.version, affected, ecosystem=dependency.ecosystem):
                continue
        elif name != normalize_name(dependency.ecosystem, dependency.name):
            continue
        specific = affected.get('database_specific') or {}
        severity = severity or str(specific.get('severity') or '')
        for item in affected.get('ranges') or []:
            for event in item.get('events') or []:
                if 'fixed' not in event or item.get('type') == 'GIT':
                    continue
                version = event['fixed']
                if item.get('type') not in {'SEMVER', 'ECOSYSTEM'} or not isinstance(version, str) or not version.strip():
                    raise VulnerabilityError('malformed OSV fixed version')
                if version not in fixed:
                    fixed.append(version)
    specific = record.get('database_specific') or {}
    severity = str(specific.get('severity') or severity or '')
    if not severity:
        for item in record.get('severity') or []:
            if item.get('score'):
                severity = f"{item.get('type', 'CVSS')} {item['score']}"
                break
    return Finding(
        dependency=dependency,
        vuln_id=str(record.get('id', '')),
        aliases=sorted(alias for alias in aliases if alias in decision_ids),
        raw_aliases=list(aliases),
        summary=str(record.get('summary') or record.get('details') or '')[:300],
        severity=severity,
        fixed=fixed,
    )


def _default_fetch(url: str, body: bytes | None) -> bytes:
    request = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json',
                                                              'User-Agent': 'getzilla-known-vulnerabilities'})
    with urllib.request.urlopen(request, timeout=60) as response:  # nosec B310 - fixed https OSV endpoints
        return response.read()


def query_online(dependencies: list[Dependency], *, fetch: Fetch = _default_fetch) -> list[Finding]:
    hits: list[tuple[Dependency, str]] = []
    for start in range(0, len(dependencies), QUERY_BATCH):
        chunk = dependencies[start:start + QUERY_BATCH]
        queries = [{'package': {'name': item.name, 'ecosystem': item.ecosystem}, 'version': item.version} for item in chunk]
        pending = list(range(len(chunk)))
        tokens: dict[int, str] = {}
        while pending:
            body = json.dumps({'queries': [
                {**queries[index], **({'page_token': tokens[index]} if index in tokens else {})} for index in pending
            ]}).encode('utf-8')
            try:
                answer = json.loads(fetch(f'{OSV_API}/querybatch', body))
            except (OSError, urllib.error.URLError, ValueError) as exc:
                raise VulnerabilityError(f'OSV query failed: {exc}') from exc
            results = answer.get('results') or []
            if len(results) != len(pending):
                raise VulnerabilityError('OSV query returned a different number of results')
            next_pending = []
            for index, result in zip(pending, results):
                for vuln in result.get('vulns') or []:
                    identifier = vuln.get('id') if isinstance(vuln, dict) else None
                    try:
                        osv_decision_ids({'id': identifier})
                    except SecurityDataError as exc:
                        raise VulnerabilityError(str(exc)) from exc
                    hits.append((chunk[index], identifier))
                if result.get('next_page_token'):
                    tokens[index] = result['next_page_token']
                    next_pending.append(index)
            pending = next_pending
    findings = []
    details: dict[str, dict[str, Any]] = {}
    for dependency, vuln_id in sorted(set(hits)):
        if vuln_id not in details and len(details) < MAX_DETAIL_FETCHES:
            try:
                details[vuln_id] = json.loads(fetch(f'{OSV_API}/vulns/{vuln_id}', None))
            except (OSError, urllib.error.URLError, ValueError) as exc:
                raise VulnerabilityError(f'OSV record {vuln_id} unavailable: {exc}') from exc
            _aliases(details[vuln_id])
        findings.append(_describe(details.get(vuln_id, {'id': vuln_id}), dependency))
    return findings


def query_offline(dependencies: list[Dependency], database: Path, *, now: datetime | None = None,
                  source_evidence: list[dict[str, Any]] | None = None) -> list[Finding]:
    from .security_data import SecurityDataError, confirm_snapshots, qualified_packagist, read_snapshot
    wanted: dict[str, dict[str, list[Dependency]]] = {}
    for item in dependencies:
        wanted.setdefault(item.ecosystem, {}).setdefault(normalize_name(item.ecosystem, item.name), []).append(item)
    findings: list[Finding] = []
    proofs = []
    for ecosystem, by_name in sorted(wanted.items()):
        try:
            payload, proof = read_snapshot(database, f'osv:{ecosystem}', now=now, required_scope={ecosystem})
        except SecurityDataError as error:
            raise VulnerabilityError(str(error)) from error
        if source_evidence is not None:
            source_evidence.append(proof)
        proofs.append(proof)
        with zipfile.ZipFile(io.BytesIO(payload)) as bundle:
            for member in bundle.namelist():
                if not member.endswith('.json'):
                    continue
                record = json.loads(bundle.read(member))
                _aliases(record)
                if record.get('withdrawn'):
                    continue
                for affected in record.get('affected') or []:
                    package = affected.get('package') or {}
                    if (ecosystem == 'Packagist' and qualified_packagist(package.get('ecosystem'))
                            and normalize_name(ecosystem, package.get('name', '')) in by_name):
                        raise VulnerabilityError('Packagist dependency registry identity requires a qualified adapter')
                    if package.get('ecosystem') != ecosystem:
                        continue
                    name = normalize_name(ecosystem, str(package.get('name', '')))
                    candidates = chain.from_iterable(by_name.values()) if name == '*' else by_name.get(name, ())
                    for dependency in candidates:
                        if _in_ranges(dependency.version, affected, ecosystem=ecosystem):
                            findings.append(_describe(record, dependency))
    if proofs:
        try:
            confirm_snapshots(database, proofs, now=now)
        except SecurityDataError as error:
            raise VulnerabilityError(str(error)) from error
    unique = {(item.dependency, item.vuln_id): item for item in findings}
    return [unique[key] for key in sorted(unique)]


def download_database(destination: Path, ecosystems: Iterable[str] = ECOSYSTEMS, *, fetch=None,
                      now: datetime | None = None) -> list[str]:
    """Publish qualified fixed-origin snapshots; raw bytes cannot mint acquisition."""
    from .security_acquisition import fetch_public, refresh_osv
    written = []
    for ecosystem in ecosystems:
        if ecosystem not in ECOSYSTEMS:
            raise VulnerabilityError(f'unsupported ecosystem: {ecosystem}')
        qualified = fetch_public if fetch is None else lambda url: fetch(url, None)
        result = refresh_osv(destination, [ecosystem], fetch=qualified, now=now)[0]
        if result['status'] != 'pass':
            raise VulnerabilityError(f'OSV refresh failed for {ecosystem}: {result["reason"]}')
        written.append(str(destination / ecosystem / 'snapshot.json'))
    return written


def query_snapshot(inventory: dict[str, Any], database: Path, *, now: datetime | None = None,
                   source_evidence: list[dict[str, Any]]) -> list[Finding]:
    from .security_data import SecurityDataError, confirm_snapshots, read_snapshot
    from .security_osv_query import SOURCE_ID, portable_inventory, validate_transcript
    try:
        portable = portable_inventory(inventory)
        scopes = {row['ecosystem'] for row in portable['objects']}
        payload, proof = read_snapshot(database, SOURCE_ID, now=now, required_scope=scopes)
        replay = validate_transcript(payload, expected_inventory=inventory)
        findings = []
        for hit in replay['hits']:
            for index in replay['plan'][hit['query_index']]['objects']:
                dependency = Dependency(**portable['objects'][index])
                # A validated API positive verdict is a finding; local range
                # comparison cannot erase it or make incomplete coverage clean.
                findings.append(_describe(replay['records'][hit['id']], dependency))
        confirm_snapshots(database, [proof], now=now)
        source_evidence.append(proof)
        return findings
    except SecurityDataError:
        raise VulnerabilityError('current qualified query snapshot is unavailable, incomplete or changed') from None


def scan(root: Path, *, environ: dict[str, str] | None = None, fetch: Fetch = _default_fetch,
         today: date | None = None, now: datetime | None = None) -> dict[str, Any]:
    env = os.environ if environ is None else environ
    config = load_config(root)
    dependencies, manifests, inventory = dependency_inventory(root, config)
    database = env.get('GETZILLA_OSV_DB', '').strip()
    online = env.get('GETZILLA_OSV_ONLINE', '').strip() == '1'
    report: dict[str, Any] = {'manifests': manifests, 'dependencies': len(dependencies), 'findings': [], 'accepted': [],
                              'inventory': inventory, 'source_evidence': [], 'source_mode': 'absent'}
    if not dependencies:
        report.update(status='skip', source=None, summary='no pinned dependencies in lockfiles or requirements')
        return report
    if database:
        if online:
            source = f'qualified OSV query snapshot {database}'
            report['source_mode'] = 'query'
            findings = query_snapshot(inventory, Path(database), now=now, source_evidence=report['source_evidence'])
        else:
            source = f'offline OSV mirror {database}'
            report['source_mode'] = 'offline'
            findings = query_offline(dependencies, Path(database), now=now, source_evidence=report['source_evidence'])
    elif online:
        raise VulnerabilityError('qualified online query source requires an explicitly selected database')
    else:
        report['source_mode'] = 'unconfigured'
        report.update(status='skip', source=None,
                      summary=f'{len(dependencies)} pinned dependencies not checked: set GETZILLA_OSV_DB or GETZILLA_OSV_ONLINE=1')
        return report
    current = today or date.today()
    accepted_ids = {}
    for item in config['accept']:
        if date.fromisoformat(str(item['expires'])) >= current:
            accepted_ids[str(item['id'])] = str(item['expires'])
    open_findings = []
    for finding in findings:
        try:
            names = osv_decision_ids(finding.to_dict())
        except SecurityDataError as exc:
            raise VulnerabilityError(str(exc)) from exc
        expiry = next((accepted_ids[name] for name in names if name in accepted_ids), None)
        if expiry:
            finding.accepted_until = expiry
            report['accepted'].append(finding.to_dict())
        else:
            open_findings.append(finding)
    report['findings'] = [item.to_dict() for item in open_findings]
    packages = {(item.dependency.ecosystem, item.dependency.name, item.dependency.version) for item in open_findings}
    report['source'] = source
    if open_findings:
        report.update(status='fail',
                      summary=f'{len(open_findings)} known vulnerabilities in {len(packages)} pinned packages ({source})')
    else:
        accepted = f', {len(report["accepted"])} accepted until expiry' if report['accepted'] else ''
        report.update(status='pass',
                      summary=f'no known vulnerabilities in {len(dependencies)} pinned dependencies ({source}){accepted}')
    # A query may take time: the initial inventory is not a final witness.
    if dependency_inventory(root, load_config(root))[2] != inventory:
        raise VulnerabilityError('security policy or inventory changed during the query')
    if report['source_mode'] in {'offline', 'query'}:
        from .security_data import confirm_snapshots
        try:
            confirm_snapshots(Path(database), report['source_evidence'], now=now)
        except SecurityDataError as error:
            raise VulnerabilityError(str(error)) from error
    return report


def lockfile_gate(report: dict[str, Any]) -> dict[str, Any]:
    """Apply lockfile admission to the native scan, retaining every observed advisory."""
    if (report['status'] != 'fail' or not report['findings']
            or report.get('source_mode') not in {'offline', 'query'} or not report.get('source_evidence')):
        return report
    blocking = sum(bool(item['fixed']) for item in report['findings'])
    reported = len(report['findings']) - blocking
    return {**report, 'status': 'fail' if blocking else 'pass',
            'summary': f"{report['summary']}: {blocking} with a fixed version, {reported} report only"}


def recheck_report(root: Path, report: dict[str, Any], *, environ: dict[str, str] | None = None,
                   now: datetime | None = None) -> None:
    """Re-derive native offline evidence from current configured inputs, never report paths."""
    if not isinstance(report, dict) or report.get('source_mode') not in {'offline', 'query', 'absent'}:
        raise VulnerabilityError('current source revalidation is unavailable for this report mode')
    current_environment = os.environ if environ is None else environ
    if report['source_mode'] in {'offline', 'query'} and not current_environment.get('GETZILLA_OSV_DB', '').strip():
        raise VulnerabilityError('current configured offline source is unavailable')
    # scan is read-only in every source mode. Resolve the current configured
    # selection, never a source kind or path supplied by this report.
    current = scan(root, environ=current_environment, now=now)
    stable = ('status', 'source_mode', 'inventory', 'dependencies', 'manifests', 'findings', 'accepted')
    if any(key not in report or report[key] != current[key] for key in stable):
        raise VulnerabilityError('security policy, inventory or substantive result changed before consumption')
    sources = report.get('source_evidence')
    actual = current['source_evidence']
    fields = ('source_id', 'source_url', 'content_sha256', 'payload_size', 'acquisition', 'coverage',
              'manifest_sha256', 'custody_sha256')
    if not isinstance(sources, list) or len(sources) != len(actual):
        raise VulnerabilityError('source evidence is missing or changed before consumption')
    for before, after in zip(sources, actual):
        if not isinstance(before, dict) or any(field not in before or before[field] != after[field] for field in fields):
            raise VulnerabilityError('source evidence is missing or changed before consumption')


def verification_sources(root: Path, details: dict[str, Any], *, require_stored: bool = False) -> dict[str, Any]:
    """Every modern PASS needs a current proof, including omitted-details callers."""
    if not isinstance(details, dict):
        raise VulnerabilityError('verification source proof is unavailable')
    if 'security_sources' in details:
        proof = details['security_sources']
    else:
        if require_stored:
            raise VulnerabilityError('verification source proof is missing')
        # Derive real structural non-applicability through production logic.
        # Never read a configured feed or invoke a network for this fallback.
        proof = scan(root, environ={})
        if proof['dependencies'] != 0 or proof['source_mode'] != 'absent':
            raise VulnerabilityError('verification requires the actual applicable source proof')
    recheck_report(root, proof, environ={} if isinstance(proof, dict) and proof.get('source_mode') == 'absent' else None)
    if proof.get('status') != 'pass' and not (proof.get('status') == 'skip' and proof.get('source_mode') == 'absent'):
        raise VulnerabilityError('current security source findings cannot establish verification pass')
    return proof
