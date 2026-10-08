"""Known-vulnerability check for a repository's pinned dependencies.

Reads lockfiles and pinned manifests (PyPI, npm, Go, crates.io, Packagist,
RubyGems), then looks every exact package version up in the OSV database,
which aggregates the GitHub Advisory Database, PyPA, RustSec, Go, npm and
NVD-derived records. Two sources, never both, and never implicit network:

* ``GETZILLA_OSV_DB=<dir>``: an offline mirror made by ``download_database``
  (``<dir>/<Ecosystem>/all.zip`` from the public OSV bucket). This is what a
  network-less sandbox such as Trust CI uses.
* ``GETZILLA_OSV_ONLINE=1``: the OSV API (``api.osv.dev``).

Without either the check is skipped and says so. Findings can be accepted
for a limited time in ``.getzilla/config/known-vulnerabilities.json``.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import subprocess
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable

try:
    import tomllib
except ModuleNotFoundError:
    tomllib = None  # type: ignore[assignment]

OSV_API = 'https://api.osv.dev/v1'
OSV_BUCKET = 'https://osv-vulnerabilities.storage.googleapis.com'
ECOSYSTEMS = ('PyPI', 'npm', 'Go', 'crates.io', 'Packagist', 'RubyGems')
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
        line = raw.split('#', 1)[0].strip()
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
    project = tomllib.loads(text).get('project') or {}
    requirements = list(project.get('dependencies') or [])
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
    'go.mod': ('Go', _pairs_from_go_mod),
    'Cargo.lock': ('crates.io', lambda text: _pairs_from_toml_packages(text, registry_only=True)),
    'composer.lock': ('Packagist', _pairs_from_composer_lock),
    'Gemfile.lock': ('RubyGems', _pairs_from_gemfile_lock),
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


def _version_key(version: str) -> tuple[Any, ...]:
    parts = re.split(r'[.\-+_]', version.lstrip('vV'))
    key: list[Any] = []
    for part in parts:
        match = re.match(r'^(\d+)(.*)$', part)
        if match:
            key.append((1, int(match.group(1)), match.group(2)))
        else:
            key.append((0, 0, part))
    return tuple(key)


def _in_ranges(version: str, affected: dict[str, Any]) -> bool:
    if version in (affected.get('versions') or []):
        return True
    target = _version_key(version)
    for item in affected.get('ranges') or []:
        if item.get('type') not in {'SEMVER', 'ECOSYSTEM'}:
            continue
        introduced = None
        for event in item.get('events') or []:
            if 'introduced' in event:
                introduced = event['introduced']
            elif introduced is not None and ('fixed' in event or 'last_affected' in event):
                low = introduced == '0' or _version_key(str(introduced)) <= target
                if 'fixed' in event:
                    high = target < _version_key(str(event['fixed']))
                else:
                    high = target <= _version_key(str(event['last_affected']))
                if low and high:
                    return True
                introduced = None
        if introduced is not None and (introduced == '0' or _version_key(str(introduced)) <= target):
            return True
    return False


def _describe(record: dict[str, Any], dependency: Dependency) -> Finding:
    severity = ''
    fixed: list[str] = []
    for affected in record.get('affected') or []:
        package = affected.get('package') or {}
        if package.get('ecosystem') != dependency.ecosystem:
            continue
        if normalize_name(dependency.ecosystem, str(package.get('name', ''))) != normalize_name(dependency.ecosystem, dependency.name):
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
        aliases=sorted(str(alias) for alias in record.get('aliases') or []),
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


def query_offline(dependencies: list[Dependency], database: Path) -> list[Finding]:
    wanted: dict[str, dict[str, list[Dependency]]] = {}
    for item in dependencies:
        wanted.setdefault(item.ecosystem, {}).setdefault(normalize_name(item.ecosystem, item.name), []).append(item)
    findings: list[Finding] = []
    for ecosystem, by_name in sorted(wanted.items()):
        archive = database / ecosystem / 'all.zip'
        if not archive.is_file():
            raise VulnerabilityError(f'offline OSV database has no {ecosystem}/all.zip under {database}')
        with zipfile.ZipFile(archive) as bundle:
            for member in bundle.namelist():
                if not member.endswith('.json'):
                    continue
                record = json.loads(bundle.read(member))
                if record.get('withdrawn'):
                    continue
                for affected in record.get('affected') or []:
                    package = affected.get('package') or {}
                    if package.get('ecosystem') != ecosystem:
                        continue
                    for dependency in by_name.get(normalize_name(ecosystem, str(package.get('name', ''))), []):
                        if _in_ranges(dependency.version, affected):
                            findings.append(_describe(record, dependency))
    unique = {(item.dependency, item.vuln_id): item for item in findings}
    return [unique[key] for key in sorted(unique)]


def download_database(destination: Path, ecosystems: Iterable[str] = ECOSYSTEMS, *, fetch: Fetch = _default_fetch) -> list[str]:
    """Refresh ``<destination>/<Ecosystem>/all.zip``; run on a host with network, never in the sandbox."""
    written = []
    for ecosystem in ecosystems:
        if ecosystem not in ECOSYSTEMS:
            raise VulnerabilityError(f'unsupported ecosystem: {ecosystem}')
        data = fetch(f'{OSV_BUCKET}/{ecosystem}/all.zip', None)
        target = destination / ecosystem / 'all.zip'
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix('.zip.partial')
        temporary.write_bytes(data)
        with zipfile.ZipFile(temporary) as bundle:
            if bundle.testzip() is not None:
                raise VulnerabilityError(f'corrupt OSV archive for {ecosystem}')
        os.replace(temporary, target)
        written.append(str(target))
    return written


def scan(root: Path, *, environ: dict[str, str] | None = None, fetch: Fetch = _default_fetch,
         today: date | None = None) -> dict[str, Any]:
    env = os.environ if environ is None else environ
    config = load_config(root)
    dependencies, manifests = collect_dependencies(root, exclude=config['exclude'])
    database = env.get('GETZILLA_OSV_DB', '').strip()
    online = env.get('GETZILLA_OSV_ONLINE', '').strip() == '1'
    report: dict[str, Any] = {'manifests': manifests, 'dependencies': len(dependencies), 'findings': [], 'accepted': []}
    if not dependencies:
        report.update(status='skip', source=None, summary='no pinned dependencies in lockfiles or requirements')
        return report
    if database:
        source = f'offline OSV mirror {database}'
        findings = query_offline(dependencies, Path(database))
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
