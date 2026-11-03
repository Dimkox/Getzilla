"""Pinned scanners over source data and immutable images, with explicit coverage.

No candidate modules, scanner configuration or ignore files are executed or
loaded. Source scanners consume a bounded copy of selected bytes. Only the
explicit refresh entry point may acquire image/database inputs over a network.
These observations prove local integrity; the CI provider supplies authority.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from . import verification_dispositions as dispositions
from .python_test_runner import execute
from .security_acquisition import MAX_DOWNLOAD, TRIVY_ARCHIVE_SHA256, TRIVY_VERSION, trivy_binary
from .security_data import MAX_AGE_SECONDS, SecurityDataError
from .updater import OPENGREP_ASSETS

TRUSTED_ROOT = Path(__file__).resolve().parents[2]
TRIVY_DB_URL = 'ghcr.io/aquasecurity/trivy-db:2'
MAX_REPORT = 64 * 1024 * 1024
MAX_SOURCE_FILE = 16 * 1024 * 1024
MAX_SOURCE_TOTAL = 256 * 1024 * 1024
_DIGEST_IMAGE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[a-f0-9]{64}\Z')
_SAST_SUFFIXES = {'.py', '.php', '.js', '.jsx', '.ts', '.tsx', '.java', '.go', '.rb', '.rs', '.c', '.cc', '.cpp', '.cs'}
_SAST_EXCLUDED = {'tests', 'fixtures', 'engineering', 'examples', 'dist', 'packages', 'vendor', 'node_modules'}


def _closed(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SecurityDataError('duplicate security report key')
        result[key] = value
    return result


def _regular(path: Path, *, limit: int, digest_only: bool = False):
    path = Path(path).absolute()
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink():
            raise SecurityDataError('security input contains a symlink')
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise SecurityDataError('security input is not a bounded regular file')
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    def identity(value):
        return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns
    digest = hashlib.sha256()
    chunks = []
    count = 0
    with os.fdopen(descriptor, 'rb') as stream:
        if identity(before) != identity(os.fstat(stream.fileno())):
            raise SecurityDataError('security input changed while opening')
        while chunk := stream.read(min(1024 * 1024, limit - count + 1)):
            count += len(chunk)
            if count > limit:
                raise SecurityDataError('security input exceeds the read bound')
            digest.update(chunk)
            if not digest_only:
                chunks.append(chunk)
        if identity(before) != identity(os.fstat(stream.fileno())):
            raise SecurityDataError('security input changed while reading')
    if identity(before) != identity(path.stat()) or count != before.st_size:
        raise SecurityDataError('security input was substituted during read')
    return (digest.hexdigest(), count) if digest_only else b''.join(chunks)


def _json(path: Path, limit: int = MAX_REPORT) -> dict:
    try:
        result = json.loads(_regular(path, limit=limit), object_pairs_hook=_closed,
                            parse_constant=lambda _: (_ for _ in ()).throw(SecurityDataError('nonfinite JSON')))
        if not isinstance(result, dict):
            raise ValueError('object required')
        return result
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise SecurityDataError('invalid security JSON') from exc


def _current(now):
    current = datetime.now(timezone.utc) if now is None else now
    if current.tzinfo is None or current.utcoffset() is None:
        raise SecurityDataError('security clock must be timezone-aware')
    return current.astimezone(timezone.utc)


def _fresh(value, now):
    try:
        instant = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if instant.tzinfo is None or instant.utcoffset() is None:
            raise ValueError('naive timestamp')
        age = (now - instant).total_seconds()
        if not 0 <= age <= MAX_AGE_SECONDS:
            raise ValueError('stale or future timestamp')
        return instant.astimezone(timezone.utc).isoformat()
    except (ValueError, TypeError, AttributeError) as exc:
        raise SecurityDataError('Trivy database acquisition/publication is not within 72 hours') from exc


def tools_directory(root: Path, environ=None) -> Path:
    env = os.environ if environ is None else environ
    return Path(env.get('GETZILLA_SECURITY_TOOLS') or root / '.getzilla/runtime/security-tools').absolute()


def trivy_database_source(tools: Path, *, now=None) -> dict:
    """Bind the exact Bolt DB file and actual producer metadata, not file mtime.

    `record_count` counts one database file, not asserted vulnerability rows.
    Schema interpretation is separately required from the pinned Trivy process.
    """
    current = _current(now)
    database = tools / 'cache/db/trivy.db'
    metadata = _json(tools / 'cache/db/metadata.json', limit=65536)
    if metadata.get('Version') != 2 or type(metadata.get('Version')) is not int:
        raise SecurityDataError('unsupported Trivy DB schema')
    downloaded = _fresh(metadata.get('DownloadedAt'), current)
    published = _fresh(metadata.get('UpdatedAt'), current)
    digest, size = _regular(database, limit=2 * MAX_DOWNLOAD, digest_only=True)
    if size == 0:
        raise SecurityDataError('empty Trivy database')
    return {'database': str(database.absolute()), 'source_id': 'trivy-db', 'source_url': TRIVY_DB_URL,
            'content_sha256': digest, 'payload_size': size,
            'acquisition': {'last_verified_sync_utc': downloaded, 'source_published_at': published,
                            'retrieval_kind': 'download', 'producer': f'trivy-{TRIVY_VERSION}'},
            'coverage': {'scopes': ['container-images'], 'complete': True, 'record_count': 1,
                         'schema': 'trivy-v2-database-file'}}


def pinned_tool(name: str, tools: Path) -> Path:
    executable = tools / 'bin' / name
    payload = _regular(executable, limit=MAX_DOWNLOAD)
    if name == 'opengrep':
        expected = OPENGREP_ASSETS.get(('linux', 'x86_64'))
        if expected is None or hashlib.sha256(payload).hexdigest() != expected[1]:
            raise SecurityDataError('OpenGrep executable differs from the reviewed release pin')
    elif name == 'trivy':
        archive = _regular(tools / 'archives' / TRIVY_ARCHIVE_SHA256, limit=MAX_DOWNLOAD)
        if payload != trivy_binary(archive):
            raise SecurityDataError('Trivy executable differs from the pinned archive member')
    else:
        raise SecurityDataError('unregistered security tool')
    return executable


def _environment(scratch: Path) -> dict:
    # Do not inherit candidate PYTHONPATH, TRIVY_*, SEMGREP_*, credentials,
    # Docker settings or automatic language/plugin configuration.
    result = {key: os.environ[key] for key in ('PATH', 'SYSTEMROOT', 'WINDIR', 'SSL_CERT_FILE', 'SSL_CERT_DIR') if key in os.environ}
    result.update(HOME=str(scratch), TMPDIR=str(scratch), TEMP=str(scratch), TMP=str(scratch),
                  DOCKER_CONFIG=str(scratch / 'docker'), PYTHONDONTWRITEBYTECODE='1',
                  SEMGREP_SEND_METRICS='off', OPENGREP_SEND_METRICS='off', NO_COLOR='1')
    return result


def _process(command: list[str], cwd: Path, scratch: Path, *, timeout=900):
    result = execute(command, cwd, _environment(scratch), timeout=timeout)
    if result.returncode not in {0, 1} or result.terminal_state != 'completed' or result.cleanup_error:
        raise SecurityDataError(f'security process failed: exit={result.returncode}, state={result.terminal_state}, cleanup={result.cleanup_error or "complete"}')
    return result


def image_report(report: dict, reference: str, *, expected_image_id: str | None = None) -> dict:
    if not _DIGEST_IMAGE.fullmatch(reference):
        raise SecurityDataError('image must be resolved to an immutable digest')
    metadata = report.get('Metadata', {})
    if (report.get('SchemaVersion') != 2 or report.get('ArtifactType') != 'container_image'
            or reference not in metadata.get('RepoDigests', [])
            or not re.fullmatch(r'sha256:[a-f0-9]{64}', str(metadata.get('ImageID', '')))
            or (expected_image_id is not None and metadata['ImageID'] != expected_image_id)):
        raise SecurityDataError('image report is missing or bound to another image')
    results = report.get('Results')
    if not isinstance(results, list) or not results:
        raise SecurityDataError('image report has no package coverage')
    findings, packages = [], 0
    for item in results:
        if not isinstance(item, dict) or item.get('Class') not in {'os-pkgs', 'lang-pkgs'}:
            raise SecurityDataError('unsupported image result coverage')
        listed = item.get('Packages', [])
        if not isinstance(listed, list) or any(not isinstance(p, dict) or not p.get('Name') or not p.get('Version') for p in listed):
            raise SecurityDataError('invalid image package inventory')
        packages += len(listed)
        for finding in item.get('Vulnerabilities') or []:
            if not isinstance(finding, dict) or not all(finding.get(field) for field in ('VulnerabilityID', 'PkgName', 'InstalledVersion')):
                raise SecurityDataError('invalid image vulnerability identity')
            findings.append({'id': finding['VulnerabilityID'], 'aliases': [], 'package': finding['PkgName'],
                             'version': finding['InstalledVersion'], 'fixed': finding.get('FixedVersion', ''),
                             'severity': finding.get('Severity', 'UNKNOWN'), 'image': reference,
                             'target': item.get('Target', '')})
    if packages == 0:
        raise SecurityDataError('zero package image needs explicit unsupported/empty-image review')
    if metadata.get('OS', {}).get('EOSL') is True:
        findings.append({'id': 'IMAGE-OS-END-OF-LIFE', 'aliases': [], 'image': reference})
    return {'package_count': packages, 'findings': findings, 'image_id': metadata['ImageID']}


def refresh_images(inventory: dict, tools: Path, *, now=None) -> list[dict]:
    """Explicit acquisition for the isolated runner; never starts an image."""
    trivy = pinned_tool('trivy', tools)
    results = []
    tools.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='refresh-', dir=tools) as directory:
        scratch = Path(directory)
        try:
            command = [str(trivy), 'image', '--download-db-only', '--db-repository', TRIVY_DB_URL,
                       '--cache-dir', str(tools / 'cache'), '--config', '', '--quiet', '--skip-version-check']
            result = _process(command, scratch, scratch)
            if result.returncode != 0:
                raise SecurityDataError('Trivy database acquisition failed')
            results.append({'source_id': 'trivy-db', 'status': 'pass', 'snapshot': trivy_database_source(tools, now=now)})
        except (OSError, ValueError, RuntimeError) as exc:
            results.append({'source_id': 'trivy-db', 'status': 'fail', 'reason': str(exc)})
        for reference in sorted({item['reference'] for item in inventory['images']}):
            try:
                if not _DIGEST_IMAGE.fullmatch(reference):
                    raise SecurityDataError('unresolved image reference; no mutable tag is acquired')
                result = _process(['docker', 'pull', '--platform', 'linux/amd64', reference], scratch, scratch)
                if result.returncode != 0:
                    raise SecurityDataError('immutable image acquisition failed')
                results.append({'image': reference, 'status': 'pass'})
            except (OSError, ValueError, RuntimeError) as exc:
                results.append({'image': reference, 'status': 'fail', 'reason': str(exc)})
    return results


def scan_images(inventory: dict, *, environ=None, now=None) -> dict:
    env = os.environ if environ is None else environ
    tools = tools_directory(TRUSTED_ROOT, env)
    results, gaps, findings = [], [], []
    try:
        trivy = pinned_tool('trivy', tools)
        source = trivy_database_source(tools, now=now)
        with tempfile.TemporaryDirectory(prefix='image-', dir=tools) as directory:
            scratch = Path(directory)
            for index, item in enumerate(inventory['images']):
                reference = item['reference']
                if not _DIGEST_IMAGE.fullmatch(reference):
                    gaps.append({'code': 'unresolved-image', 'reference': reference})
                    continue
                report_path = scratch / f'image-{index}.json'
                command = [str(trivy), 'image', '--scanners', 'vuln', '--image-src', 'docker',
                           '--cache-dir', str(tools / 'cache'), '--config', '', '--ignorefile', '',
                           '--offline-scan', '--skip-db-update', '--skip-java-db-update', '--skip-check-update',
                           '--skip-version-check', '--show-suppressed', '--list-all-pkgs', '--parallel', '1',
                           '--max-image-size', '2GB', '--format', 'json', '--output', str(report_path), reference]
                result = _process(command, scratch, scratch)
                if result.returncode != 0:
                    raise SecurityDataError('Trivy image process did not complete successfully')
                parsed = image_report(_json(report_path), reference, expected_image_id=item.get('image_id'))
                findings.extend(parsed['findings'])
                results.append({'image': reference, **parsed})
        if trivy_database_source(tools, now=now) != source:
            raise SecurityDataError('Trivy database changed during scanning')
    except (OSError, ValueError, RuntimeError) as exc:
        gaps.append({'code': 'image-scan-unavailable', 'message': str(exc)})
        source = None
    return {'outcome': 'blocked' if gaps else ('finding' if findings else 'pass'),
            'summary': f'{len(results)} image scans; {len(findings)} findings; {len(gaps)} gaps',
            'findings': findings, 'gaps': gaps, 'images': results,
            'data_sources': [source] if source is not None else []}


def _normalize(value: str) -> str:
    return str(value).replace('\\', '/').removeprefix('./')


def validate_tool_report(name: str, report: dict, targets: list[str]) -> dict:
    expected = {_normalize(value) for value in targets}
    if not expected:
        raise SecurityDataError('tool applicability needs source inventory, not an empty report')
    findings = []
    if name == 'opengrep':
        if not isinstance(report.get('results'), list) or not isinstance(report.get('errors'), list):
            raise SecurityDataError('incomplete OpenGrep report')
        # Partial parsing and timeouts can be warning-level diagnostics even
        # when the file appears in paths.scanned. None proves full coverage.
        if report['errors']:
            raise SecurityDataError('OpenGrep reported incomplete parse/scan coverage')
        observed = {_normalize(value) for value in report.get('paths', {}).get('scanned', [])}
        findings = [{'rule': value.get('check_id'), 'path': value.get('path'),
                     'line': value.get('start', {}).get('line')} for value in report['results']]
    elif name == 'bandit':
        if report.get('errors') != [] or not isinstance(report.get('results'), list):
            raise SecurityDataError('Bandit reported missing/error coverage')
        metrics = report.get('metrics', {})
        if metrics.get('_totals', {}).get('loc', 0) <= 0:
            raise SecurityDataError('Bandit checked zero source lines')
        observed = {_normalize(value) for value in metrics if value != '_totals'}
        findings = [{'rule': value.get('test_id'), 'path': value.get('filename'),
                     'line': value.get('line_number')} for value in report['results']]
    elif name == 'trivy-config':
        if report.get('SchemaVersion') != 2 or not isinstance(report.get('Results'), list):
            raise SecurityDataError('incomplete Trivy configuration report')
        observed = set()
        for item in report['Results']:
            summary = item.get('MisconfSummary', {})
            if item.get('Class') != 'config' or sum(summary.get(key, 0) for key in ('Successes', 'Failures', 'Exceptions')) <= 0:
                raise SecurityDataError('Trivy target has zero evaluated checks')
            if summary.get('Exceptions', 0):
                raise SecurityDataError('candidate suppression cannot qualify a configuration check')
            observed.add(_normalize(item.get('Target', '')))
            for value in item.get('Misconfigurations') or []:
                if value.get('Status', 'FAIL') != 'PASS':
                    findings.append({'rule': value.get('ID'), 'path': item.get('Target'), 'status': value.get('Status', 'FAIL')})
    else:
        raise SecurityDataError('unsupported source scanner')
    missing = expected - observed
    if missing:
        raise SecurityDataError(f'{name} omitted {len(missing)} required target files: {", ".join(sorted(missing)[:10])}')
    return {'outcome': 'finding' if findings else 'pass', 'summary': f'{len(expected)} files checked; {len(findings)} findings',
            'findings': findings, 'coverage': {'expected': sorted(expected), 'observed': sorted(observed)}}


def scan_secrets(root: Path, files: list[str], *, trusted_root: Path = TRUSTED_ROOT) -> dict:
    findings, gaps, binary = [], [], []
    total = 0
    try:
        policy = dispositions.Dispositions(trusted_root)
        for relative in files:
            raw = _regular(root / relative, limit=MAX_SOURCE_FILE)
            total += len(raw)
            if total > MAX_SOURCE_TOTAL:
                raise SecurityDataError('secret input inventory exceeds the bounded total')
            try:
                text = raw.decode('utf-8')
            except UnicodeError:
                binary.append({'path': relative, 'sha256': hashlib.sha256(raw).hexdigest(), 'reason': 'non-UTF8 binary; text-pattern scanner not applicable'})
                continue
            digest = hashlib.sha256(raw).hexdigest()
            for label, pattern in dispositions.SECRET_PATTERNS.items():
                for match in pattern.finditer(text):
                    line, column = dispositions.location(text, match.start())
                    entry = policy.secret(relative, digest, text, match) if label == 'generic-secret' else None
                    findings.append({'rule': label, 'path': relative, 'line': line, 'column': column,
                                     'file_sha256': digest, 'disposition': entry.get('id') if entry else None})
        policy.assert_current()
    except (OSError, ValueError, RuntimeError) as exc:
        gaps.append({'code': 'secret-input-unavailable', 'message': str(exc)})
    unresolved = [item for item in findings if item['disposition'] is None]
    return {'outcome': 'blocked' if gaps else ('finding' if unresolved else 'pass'),
            'summary': f'{len(unresolved)} unresolved text-pattern secret findings; {len(gaps)} coverage gaps',
            'findings': findings, 'gaps': gaps, 'binary_inputs': binary}


def scan_source(root: Path, inventory: dict, *, environ=None, trusted_root: Path = TRUSTED_ROOT) -> list[dict]:
    tools = tools_directory(root, environ)
    tools.mkdir(parents=True, exist_ok=True)
    selected = [value for value in inventory['files'] if not any(part in _SAST_EXCLUDED for part in Path(value).parts)
                and not value.startswith('.getzilla/sast/')]
    python = [value for value in selected if Path(value).suffix == '.py']
    sast = [value for value in selected if Path(value).suffix in _SAST_SUFFIXES]
    config = [value for value in selected if Path(value).name.lower().startswith('dockerfile')
              or Path(value).name.endswith('.Dockerfile') or Path(value).suffix == '.tf']
    # Compose files remain a required source inventory and are checked by their
    # native schema/build validations. Trivy's IaC engine does not claim Compose coverage.
    targets = {'opengrep': sast, 'bandit': python, 'trivy-config': config}
    reports = [{'name': 'secret-scan', **scan_secrets(root, inventory['files'], trusted_root=trusted_root)}]
    with tempfile.TemporaryDirectory(prefix='source-', dir=tools) as directory:
        scratch = Path(directory)
        source = scratch / 'input'
        source.mkdir()
        total = 0
        for relative in sorted(set(sast + config)):
            raw = _regular(root / relative, limit=MAX_SOURCE_FILE)
            total += len(raw)
            if total > MAX_SOURCE_TOTAL:
                raise SecurityDataError('source scan exceeds the bounded total')
            destination = source / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
        for name, files in targets.items():
            if not files:
                reports.append({'name': name, 'outcome': 'not_applicable', 'summary': 'complete source inventory contains no supported target files'})
                continue
            try:
                output = scratch / f'{name}.json'
                if name == 'bandit':
                    from yaml import safe_dump, safe_load
                    settings = safe_load(_regular(trusted_root / 'bandit.yaml', limit=65536))
                    if not isinstance(settings, dict):
                        raise SecurityDataError('trusted Bandit settings are invalid')
                    # Scope is already selected by exact path components above.
                    # Bandit's substring excludes otherwise hide e.g. tests_cli.py.
                    settings.pop('exclude_dirs', None)
                    bandit_config = scratch / 'bandit.yaml'
                    bandit_config.write_text(safe_dump(settings), encoding='utf-8')
                    command = [sys.executable, '-I', '-m', 'bandit', '-c', str(bandit_config),
                               '--ignore-nosec', '-q', '-f', 'json', '-o', str(output), '--', *files]
                elif name == 'opengrep':
                    command = [str(pinned_tool(name, tools)), 'scan', '--config', str(trusted_root / '.getzilla/sast/rules'),
                               '--taint-intrafile', '--json', '--quiet', '--strict', '--disable-version-check', '--disable-nosem',
                               '--no-git-ignore', '--timeout', '30', '--jobs', '1', '--output', str(output), *files]
                else:
                    command = [str(pinned_tool('trivy', tools)), 'config', '--config', '', '--ignorefile', '',
                               '--skip-check-update', '--skip-version-check', '--include-non-failures',
                               '--format', 'json', '--output', str(output), '.']
                _process(command, source, scratch)
                reports.append({'name': name, **validate_tool_report(name, _json(output), files)})
            except (OSError, ValueError, RuntimeError) as exc:
                reports.append({'name': name, 'outcome': 'blocked', 'summary': str(exc),
                                'gaps': [{'code': 'scanner-unavailable', 'message': str(exc)}]})
    return reports
