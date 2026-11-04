"""Known-vulnerability check for a repository's pinned dependencies.

Reads lockfiles and pinned manifests (PyPI, npm, Go, crates.io, Packagist,
RubyGems), then looks every exact package version up in the OSV database,
which aggregates the GitHub Advisory Database, PyPA, RustSec, Go, npm and
NVD-derived records. Two sources, never both, and never implicit network:

* ``GETZILLA_OSV_DB=<dir>``: a validated snapshot made by ``download_database``.
  Every ecosystem requires its manifest and exact content object, verified
  within 72 hours. Legacy raw all.zip mirrors require an explicit refresh.
* ``GETZILLA_OSV_ONLINE=1``: the OSV API (``api.osv.dev``).

Without either the check is skipped and says so. Findings can be accepted
for a limited time in ``.getzilla/config/known-vulnerabilities.json``.
"""
from __future__ import annotations

import fnmatch
import io
import json
import os
import re
import subprocess
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from itertools import chain
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable

from .security_data import (OSV_BUCKET, OSV_ECOSYSTEMS, SecurityDataError,
                            osv_aliases, osv_coverage, publish_snapshot, qualified_packagist, read_snapshot)

try:
    import tomllib
except ModuleNotFoundError:
    tomllib = None  # type: ignore[assignment]

OSV_API = 'https://api.osv.dev/v1'
ECOSYSTEMS = OSV_ECOSYSTEMS
CONFIG_PATH = '.getzilla/config/known-vulnerabilities.json'
DEFAULT_EXCLUDE = ('tests/**', '**/tests/**', '**/fixtures/**', '**/node_modules/**', '**/vendor/**', '.getzilla/runtime/**')
MAX_MANIFEST_BYTES = 32 * 1024 * 1024
QUERY_BATCH = 500
MAX_DETAIL_FETCHES = 300

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
            continue
        name, version = item.get('name'), item.get('version')
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        source = item.get('source')
        if registry_only and not (isinstance(source, str) and source.startswith('registry+')):
            continue
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


def collect_dependencies(root: Path, *, exclude: Iterable[str] = DEFAULT_EXCLUDE) -> tuple[list[Dependency], list[str]]:
    """Exact pinned dependencies and the manifests they came from."""
    patterns = tuple(exclude)
    dependencies: set[Dependency] = set()
    manifests: list[str] = []
    for relative in _tracked_files(root):
        parser = _manifest_parser(PurePosixPath(relative).name)
        if parser is None or _excluded(relative, patterns):
            continue
        path = root / relative
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_MANIFEST_BYTES:
            continue
        ecosystem, parse = parser
        try:
            pairs = list(parse(path.read_text(encoding='utf-8')))
        except (UnicodeDecodeError, ValueError) as exc:
            raise VulnerabilityError(f'cannot parse {relative}: {exc}') from exc
        manifests.append(relative)
        for name, version in pairs:
            dependencies.add(Dependency(ecosystem, name, version, relative))
    return sorted(dependencies), manifests


def load_config(root: Path) -> dict[str, Any]:
    path = root / CONFIG_PATH
    if not path.is_file():
        return {'exclude': list(DEFAULT_EXCLUDE), 'accept': []}
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
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
    """SemVer 2.0.0 precedence; build metadata never changes precedence."""
    if not isinstance(version, str) or len(version) > 512:
        raise VulnerabilityError('unsupported SemVer version')
    match = re.fullmatch(
        r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'
        r'(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?'
        r'(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?', version)
    if match is None:
        raise VulnerabilityError(f'unsupported SemVer version: {version!r}')
    pre = []
    if match[4] is not None:
        for part in match[4].split('.'):
            if part.isdigit():
                if len(part) > 1 and part[0] == '0':
                    raise VulnerabilityError(f'unsupported SemVer prerelease: {version!r}')
                pre.append((0, int(part)))
            else:
                pre.append((1, part))
    return (int(match[1]), int(match[2]), int(match[3]),
            (0, tuple(pre)) if match[4] is not None else (1, ()))


def _pypi_key(version: str) -> tuple[Any, ...]:
    """Qualified canonical PEP 440 subset, not a full PEP 440 normalizer.

    Supports [epoch!]release[a|b|rcN][.postN][.devN][+local]. Alternative
    suffix spellings/separators and leading v/whitespace are refused.
    """
    if not isinstance(version, str) or len(version) > 512:
        raise VulnerabilityError('unsupported PyPI version (canonical PEP 440 subset)')
    match = re.fullmatch(
        r'(?:(?P<epoch>[0-9]+)!)?(?P<release>[0-9]+(?:\.[0-9]+)*)'
        r'(?:(?P<pre>a|b|rc)(?P<pre_n>[0-9]+))?'
        r'(?:\.post(?P<post>[0-9]+))?(?:\.dev(?P<dev>[0-9]+))?'
        r'(?:\+(?P<local>[a-z0-9]+(?:\.[a-z0-9]+)*))?', version.lower())
    if match is None:
        raise VulnerabilityError(f'unsupported PyPI version (canonical PEP 440 subset): {version!r}')
    release = [int(part) for part in match['release'].split('.')]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    if match['pre']:
        pre = (0, {'a': 0, 'b': 1, 'rc': 2}[match['pre']], int(match['pre_n']))
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
    raise VulnerabilityError(f'unsupported OSV range semantics: {kind!r} for {ecosystem or "unknown ecosystem"}')


def _range_contains(version: str, item: dict[str, Any], *, ecosystem: str) -> bool:
    if not isinstance(item, dict):
        raise VulnerabilityError('malformed OSV range: expected object')
    kind = item.get('type')
    target = _range_key(version, kind=kind, ecosystem=ecosystem)
    events = item.get('events')
    if not isinstance(events, list) or not events:
        raise VulnerabilityError('malformed OSV range: nonempty events required')
    ordered = []
    limits = []
    kinds = set()
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            raise VulnerabilityError('malformed OSV event: exactly one field required')
        role, value = next(iter(event.items()))
        if role not in {'introduced', 'fixed', 'last_affected', 'limit'} or not isinstance(value, str) or not value:
            raise VulnerabilityError('malformed OSV event: unsupported field or version')
        kinds.add(role)
        if role == 'limit':
            limits.append(None if '*' in value else _range_key(value, kind=kind, ecosystem=ecosystem))
        else:
            key = (0, ()) if role == 'introduced' and value == '0' else (
                1, _range_key(value, kind=kind, ecosystem=ecosystem))
            ordered.append((key, role))
    if 'introduced' not in kinds or {'fixed', 'last_affected'} <= kinds:
        raise VulnerabilityError('malformed OSV range: introduced required; fixed and last_affected cannot mix')
    # OSV only recommends ordered input. Always sort, with introduced='0' first.
    ordered.sort()
    for previous, current in zip(ordered, ordered[1:]):
        if previous[0] == current[0] and previous[1] != current[1]:
            raise VulnerabilityError('ambiguous OSV events at the same version')
    affected = False
    for key, role in ordered:
        if role == 'introduced' and (key[0] == 0 or key[1] <= target):
            affected = True
        elif role == 'fixed' and key[1] <= target:
            affected = False
        elif role == 'last_affected' and key[1] < target:
            affected = False
    return affected and (not limits or any(limit is None or target < limit for limit in limits))


def _in_ranges(version: str, affected: dict[str, Any], *, ecosystem: str | None = None) -> bool:
    if not isinstance(affected, dict):
        raise VulnerabilityError('malformed OSV affected entry')
    versions = affected.get('versions', [])
    if not isinstance(versions, list) or not all(isinstance(value, str) and value for value in versions):
        raise VulnerabilityError('malformed OSV enumerated versions')
    if version in versions:
        return True
    package = affected.get('package', {})
    if not isinstance(package, dict):
        raise VulnerabilityError('malformed OSV package')
    ecosystem = ecosystem if ecosystem is not None else package.get('ecosystem', '')
    ranges = affected.get('ranges', [])
    if not isinstance(ranges, list) or (not ranges and not versions):
        raise VulnerabilityError('malformed OSV affected entry: versions or ranges required')
    errors = []
    if versions:
        try:
            if ecosystem == 'PyPI':
                key = _pypi_key
            elif ranges and all(isinstance(item, dict) and item.get('type') == 'SEMVER' for item in ranges):
                key = _semver_key
            else:
                raise VulnerabilityError(f'unsupported enumerated-version normalization: {ecosystem}')
            target = key(version)
            if any(target == key(value) for value in versions):
                return True
        except VulnerabilityError as exc:
            errors.append(exc)
    for item in ranges:
        try:
            if _range_contains(version, item, ecosystem=ecosystem):
                return True
        except VulnerabilityError as exc:
            errors.append(exc)
    if errors:
        raise errors[0]
    return False


def _describe(record: dict[str, Any], dependency: Dependency) -> Finding:
    try:
        aliases = osv_aliases(record)
    except SecurityDataError as exc:
        raise VulnerabilityError(str(exc)) from exc
    severity = ''
    fixed: list[str] = []
    for affected in record.get('affected') or []:
        package = affected.get('package') or {}
        if (dependency.ecosystem == 'Packagist' and qualified_packagist(package.get('ecosystem'))
                and normalize_name('Packagist', str(package.get('name', ''))) in
                {'*', normalize_name('Packagist', dependency.name)}):
            raise VulnerabilityError('Packagist dependency registry identity is required for a custom-repository match')
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
                if 'fixed' in event and str(event['fixed']) not in fixed:
                    fixed.append(str(event['fixed']))
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
        aliases=sorted(aliases),
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
                    hits.append((chunk[index], str(vuln['id'])))
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
        findings.append(_describe(details.get(vuln_id, {'id': vuln_id}), dependency))
    return findings


def query_offline(dependencies: list[Dependency], database: Path, *, now: datetime | None = None,
                  source_evidence: list[dict[str, Any]] | None = None) -> list[Finding]:
    wanted: dict[str, dict[str, list[Dependency]]] = {}
    for item in dependencies:
        wanted.setdefault(item.ecosystem, {}).setdefault(normalize_name(item.ecosystem, item.name), []).append(item)
    findings: list[Finding] = []
    for ecosystem, by_name in sorted(wanted.items()):
        try:
            payload, evidence = read_snapshot(database, f'osv:{ecosystem}', now=now, required_scope={ecosystem})
        except SecurityDataError as exc:
            raise VulnerabilityError(str(exc)) from exc
        if source_evidence is not None:
            source_evidence.append(evidence)
        with zipfile.ZipFile(io.BytesIO(payload)) as bundle:
            for member in bundle.namelist():
                if not member.endswith('.json'):
                    continue
                record = json.loads(bundle.read(member))
                if record.get('withdrawn'):
                    continue
                for affected in record.get('affected') or []:
                    package = affected.get('package') or {}
                    if ecosystem == 'Packagist' and qualified_packagist(package.get('ecosystem')):
                        name = normalize_name(ecosystem, str(package.get('name', '')))
                        if name == '*' or name in by_name:
                            raise VulnerabilityError('Packagist dependency registry identity is required for a custom-repository match')
                    if package.get('ecosystem') != ecosystem:
                        continue
                    name = normalize_name(ecosystem, str(package.get('name', '')))
                    candidates = chain.from_iterable(by_name.values()) if name == '*' else by_name.get(name, ())
                    for dependency in candidates:
                        if _in_ranges(dependency.version, affected, ecosystem=dependency.ecosystem):
                            findings.append(_describe(record, dependency))
    unique = {(item.dependency, item.vuln_id): item for item in findings}
    return [unique[key] for key in sorted(unique)]


def download_database(destination: Path, ecosystems: Iterable[str] = ECOSYSTEMS, *, fetch: Fetch = _default_fetch,
                      now: datetime | None = None) -> list[str]:
    """Acquire and publish validated snapshots; run only on an explicit network-capable host."""
    written = []
    for ecosystem in ecosystems:
        if ecosystem not in ECOSYSTEMS:
            raise VulnerabilityError(f'unsupported ecosystem: {ecosystem}')
        try:
            data = fetch(f'{OSV_BUCKET}/{ecosystem}/all.zip', None)
            current = now if now is not None else datetime.now(timezone.utc)
            evidence = publish_snapshot(destination, f'osv:{ecosystem}', data,
                                        acquisition={'last_verified_sync_utc': current.isoformat(), 'retrieval_kind': 'download'},
                                        coverage=osv_coverage(data, ecosystem), now=current)
        except (OSError, SecurityDataError, ValueError) as exc:
            raise VulnerabilityError(f'OSV refresh failed for {ecosystem}: {exc}') from exc
        filename = 'snapshot.json' if evidence.get('compatibility_export_warning') else 'all.zip'
        written.append(str(destination / ecosystem / filename))
    return written


def scan(root: Path, *, environ: dict[str, str] | None = None, fetch: Fetch = _default_fetch,
         today: date | None = None, now: datetime | None = None) -> dict[str, Any]:
    env = os.environ if environ is None else environ
    config = load_config(root)
    dependencies, manifests = collect_dependencies(root, exclude=config['exclude'])
    database = env.get('GETZILLA_OSV_DB', '').strip()
    online = env.get('GETZILLA_OSV_ONLINE', '').strip() == '1'
    report: dict[str, Any] = {'manifests': manifests, 'dependencies': len(dependencies),
                              'findings': [], 'accepted': [], 'source_evidence': []}
    if not dependencies:
        report.update(status='skip', source=None, summary='no pinned dependencies in lockfiles or requirements')
        return report
    if database:
        source = f'offline OSV mirror {database}'
        findings = query_offline(dependencies, Path(database), now=now, source_evidence=report['source_evidence'])
    elif online:
        source = 'OSV API'
        findings = query_online(dependencies, fetch=fetch)
    else:
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
        names = {finding.vuln_id, *finding.aliases}
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
    return report
