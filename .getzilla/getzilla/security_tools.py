"""Pinned scanners over source data and immutable images, with explicit coverage.

No candidate modules, scanner configuration or ignore files are executed or
loaded. Source scanners consume a bounded copy of selected bytes. Only the
explicit refresh entry point may acquire image/database inputs over a network.
These observations prove local integrity; the CI provider supplies authority.
"""
from __future__ import annotations

import codecs
from contextlib import nullcontext
import hashlib
import io
import json
import os
import re
import time
import stat
import sys
import tempfile
import tokenize
from datetime import datetime, timezone
from pathlib import Path

from . import verification_dispositions as dispositions
from .python_test_runner import execute
from .verification_actions import retain_stop, stop_details, updated_stop
from .security_acquisition import MAX_DOWNLOAD, TRIVY_ARCHIVE_SHA256, TRIVY_VERSION, trivy_binary
from .security_data import MAX_AGE_SECONDS, SecurityDataError
from .release_transport import OPENGREP_ASSETS
from .security_oci_layout import OCIError, Budget as OCIBudget, read_directory as read_oci_directory, read_owned_file
from .security_oci_transport import acquire_images as acquire_oci_images, retained_acquisition, validate_network_selection

TRUSTED_ROOT = Path(__file__).resolve().parents[2]
TRIVY_DB_URL = 'ghcr.io/aquasecurity/trivy-db:2'
MAX_REPORT = 64 * 1024 * 1024
MAX_SOURCE_FILE = 16 * 1024 * 1024
MAX_SOURCE_TOTAL = 256 * 1024 * 1024
_REVIEWED_BENCHMARK_PATH = 'engineering/benchmarks/issue162/results/large-results.json'
_REVIEWED_BENCHMARK_SIZE = 3_244_376
_REVIEWED_BENCHMARK_SHA256 = '4f64f31130d92b5477168a0aa97749273e2a46e2043176884d32b28c00067838'
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


def _process_detail(result, failure: str) -> str:
    """Emit closed diagnostic classes, never command/output/cleanup values.

    Scanner stderr can contain credentials and candidate source. Inspect only a
    bounded prefix and return fixed labels instead of attempting to redact an
    arbitrary free-form tail. Stdout is report data and is never diagnostic text.
    """
    diagnostic = result.stderr[:8192].lower()
    category = 'unclassified'
    for label, markers in (
        ('tls', ('x509:', 'certificate verify failed', 'tls handshake', 'unknown authority')),
        ('authentication', ('unauthorized', 'authentication required', 'access denied', 'forbidden')),
        ('network', ('proxyconnect', 'connection refused', 'network unreachable', 'no such host',
                     'dial tcp', 'connection reset', 'i/o timeout')),
        ('tool-unavailable', ('no such file or directory', 'executable file not found')),
        ('resource-limit', ('output limit exceeded', 'out of memory', 'no space left')),
    ):
        if any(marker in diagnostic for marker in markers):
            category = label
            break
    state = result.terminal_state if result.terminal_state in {'completed', 'timeout', 'cancelled'} else 'unknown'
    code = result.returncode if type(result.returncode) is int and -255 <= result.returncode <= 255 else 'unknown'
    cleanup = 'failed' if result.cleanup_error else 'complete'
    return f'security {failure}: exit={code}, state={state}, cleanup={cleanup}, diagnostic={category}; stop=' + json.dumps(stop_details(result), sort_keys=True)


def _process_error(result, failure):
    error = SecurityDataError(_process_detail(result, failure))
    retain_stop(error, updated_stop(result))
    return error


def _process(command: list[str], cwd: Path, scratch: Path, *, timeout=900, finding_exit=False):
    result = execute(command, cwd, _environment(scratch), timeout=timeout)
    allowed = {0, 1} if finding_exit else {0}
    if result.returncode not in allowed or result.terminal_state != 'completed' or result.cleanup_error:
        raise _process_error(result, 'process-failed')
    return result


def _process_report(output: Path, result) -> dict:
    try:
        return _json(output)
    except FileNotFoundError as exc:
        raise _process_error(result, 'report-missing') from exc
    except (OSError, ValueError, RuntimeError) as exc:
        raise _process_error(result, 'report-invalid') from exc


def image_report(report: dict, reference: str, *, expected_image_id: str | None = None, verified_oci=None) -> dict:
    if not _DIGEST_IMAGE.fullmatch(reference):
        raise SecurityDataError('image must be resolved to an immutable digest')
    metadata = report.get('Metadata', {})
    if verified_oci is not None:
        from .security_oci import scanner_identity
        scanner_identity(report, verified_oci)
        if verified_oci.reference != reference:
            raise SecurityDataError('OCI report source reference differs')
    if (report.get('SchemaVersion') != 2 or report.get('ArtifactType') != 'container_image'
            or verified_oci is None and reference not in metadata.get('RepoDigests', [])
            or not re.fullmatch(r'sha256:[a-f0-9]{64}', str(metadata.get('ImageID', '')))
            or (expected_image_id is not None and metadata['ImageID'] != expected_image_id)):
        raise SecurityDataError('image report is missing or bound to another image')
    return _image_packages(report, reference)


def _image_packages(report: dict, reference: str) -> dict:
    metadata = report.get('Metadata', {})
    if not isinstance(metadata, dict) or not isinstance(metadata.get('OS', {}), dict):
        raise SecurityDataError('invalid image package metadata')
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


def image_layout_report(report: dict, validated: dict, *, input_name: str) -> dict:
    """Pinned Trivy0.74 OCI-directory metadata, meaningful only with trusted execution.

    Archives intentionally have no RepoDigests. The caller must bind the actual
    input object set/argv/tool/DB before and after execution, not this JSON alone.
    """
    if not isinstance(report, dict) or not isinstance(report.get('Metadata'), dict) or not isinstance(report.get('Trivy'), dict):
        raise SecurityDataError('invalid OCI layout report metadata')
    metadata = report['Metadata']
    image_config = metadata.get('ImageConfig')
    if (report.get('SchemaVersion') != 2 or report.get('ArtifactType') != 'container_image'
            or report.get('ArtifactName') != input_name or report.get('Trivy', {}).get('Version') != TRIVY_VERSION
            or metadata.get('ImageID') != validated['config_digest']
            or metadata.get('DiffIDs') != validated['diff_ids']
            or metadata.get('RepoDigests') not in (None, [])
            or not isinstance(image_config, dict)
            or any(key not in image_config or image_config[key] != value for key, value in validated['config'].items())):
        raise SecurityDataError('OCI archive report differs from validated input/config/platform')
    return _image_packages(report, validated['manifest_digest'])


def image_acquisition_profile(inventory: dict, profile: dict | None) -> dict:
    """Require finite aggregate bounds before selecting any image transport."""
    keys = {'images', 'max_images', 'max_compressed_bytes', 'max_unpacked_bytes', 'max_storage_bytes',
            'max_manifest_bytes', 'max_layers', 'deadline_seconds', 'platform'}
    if not isinstance(profile, dict) or set(profile) != keys or profile.get('platform') not in {'linux/amd64', 'linux/arm64'}:
        raise SecurityDataError('image acquisition needs a complete explicit bounded profile')
    from .security_oci import active_limits
    limits = active_limits()
    limits['max_manifest_bytes'] = min(limits['max_manifest_bytes'], MAX_REPORT)
    if any(type(profile[key]) is not int or not 0 < profile[key] <= limit for key, limit in limits.items()):
        raise SecurityDataError('image acquisition profile exceeds existing finite ceilings')
    images = inventory.get('images')
    if not isinstance(images, list) or not all(isinstance(item, dict) for item in images):
        raise SecurityDataError('image inventory is malformed')
    references = sorted({item.get('reference', '') for item in images})
    if (profile['images'] != references or len(references) > profile['max_images']
            or any(not _DIGEST_IMAGE.fullmatch(reference) for reference in references)):
        raise SecurityDataError('image profile differs from complete immutable source identities')
    return profile


def refresh_images(inventory: dict, tools: Path, *, now=None, profile=None, image_artifacts=None, binding=None,
                   deadline=None, image_opener=None, network_selection=None) -> list[dict]:
    """Explicit acquisition for the isolated runner; never starts an image."""
    if not isinstance(inventory.get('images'), list):
        raise SecurityDataError('image acquisition requires a complete declared image list')
    results = []
    if inventory.get('images'):
        image_acquisition_profile(inventory, profile)
        if image_artifacts is not None:
            from .security_oci import import_layouts
            catalog = _json(Path(image_artifacts), limit=16 * 1024 * 1024)
            tools.mkdir(parents=True, exist_ok=True, mode=0o700)
            with import_layouts(catalog, inventory, profile, tools) as images:
                return [{'kind': 'oci-local-import', 'status': 'pass',
                         'assurance': 'local-byte-integrity-only-not-scan-or-authority',
                         'images': [{'reference': image.reference, 'manifest_sha256': image.manifest_digest,
                                     'config_sha256': image.config_digest, 'platform': image.platform}
                                    for image in images]}]
        selected_network = image_network_selection(inventory, network_selection)
        destination = tools / 'oci'
        destination.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            body = acquire_oci_images(inventory['images'], profile, destination, open_url=image_opener,
                now=now, binding=binding, deadline=deadline, network_selection=selected_network)
            raw, _ = read_owned_file(destination, 'manifest.json', 16 * 1024 * 1024)
            results.append({'kind': 'oci-image-acquisition', 'status': 'pass', 'qualification': 'UNVERIFIED',
                'manifest_sha256': hashlib.sha256(raw).hexdigest(), 'root': str(destination.absolute()),
                'records': body['records'], 'profile': profile, 'binding': binding, 'network_selection': selected_network})
        except OCIError as exc:
            raise SecurityDataError('bounded OCI acquisition refused: ' + str(exc)) from exc
    return results + refresh_image_database(tools, now=now)


def trivy_options(scratch):
    # The pinned CLI treats an empty --config value as an unreadable filename.
    # Both files are in the private scanner scratch directory, outside the source.
    config, ignore = scratch / "trivy.yaml", scratch / "empty.trivyignore"
    config.write_bytes(b"{}\n")
    ignore.write_bytes(b"")
    return ["--config", str(config), "--ignorefile", str(ignore)]


def refresh_image_database(tools: Path, *, now=None) -> list[dict]:
    """Explicit DB-only refresh; separate from local OCI import and image pulls."""
    results = []
    trivy = pinned_tool('trivy', tools)
    tools.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='refresh-', dir=tools) as directory:
        scratch = Path(directory)
        try:
            command = [str(trivy), 'image', '--download-db-only', '--db-repository', TRIVY_DB_URL,
                       '--cache-dir', str(tools / 'cache'), *trivy_options(scratch), '--quiet', '--skip-version-check']
            result = _process(command, scratch, scratch)
            if result.returncode != 0:
                raise SecurityDataError('Trivy database acquisition failed')
            results.append({'source_id': 'trivy-db', 'status': 'pass', 'snapshot': trivy_database_source(tools, now=now)})
        except (OSError, ValueError, RuntimeError) as exc:
            results.append({'source_id': 'trivy-db', 'status': 'fail', 'reason': str(exc)})
    return results


def image_network_selection(inventory: dict, selection: dict | None) -> dict:
    required = set()
    for item in inventory.get('images', []):
        reference = item.get('reference', '') if isinstance(item, dict) else ''
        registry, _, repository = reference.partition('/') if isinstance(reference, str) else ('', '', '')
        if not repository:
            raise SecurityDataError('OCI fixed registry selection is unavailable')
        if registry == 'docker.io':
            required.update({'registry-1.docker.io', 'auth.docker.io'})
        elif registry == 'ghcr.io':
            required.add('ghcr.io')
        else:
            raise SecurityDataError('OCI fixed registry selection is unavailable')
    try:
        return validate_network_selection(selection, required=required)
    except OCIError as exc:
        raise SecurityDataError('OCI numeric network selection is unqualified') from exc


def scan_layouts(inventory: dict, tools: Path, *, binding: dict, now=None, process=None,
                 profile=None, network_selection=None) -> dict:
    """Consume retained native layouts through an explicitly isolated runner port.

    No environment flag supplies this boundary. The ordinary process launcher
    does not enforce a physical quota and is deliberately not a fallback here.
    Controlled test ports prove contracts, never real scanner execution.
    """
    results, gaps, findings = [], [], []
    source = None
    try:
        root = tools / 'oci'
        retained = retained_acquisition(root, inventory['images'], binding=binding, now=now,
                                       profile=profile, network_selection=network_selection)
        if process is None:
            raise SecurityDataError('isolated OCI scanner execution boundary is unavailable')
        trivy = pinned_tool('trivy', tools)
        tool_before = _regular(trivy, limit=MAX_DOWNLOAD, digest_only=True)
        source = trivy_database_source(tools, now=now)
        deadline = time.monotonic() + min(retained['profile']['deadline_seconds'], 600)
        budget = OCIBudget(retained['profile'], deadline=deadline)
        budget.charge('storage', retained['counters']['storage_high_water_bytes'])
        with tempfile.TemporaryDirectory(prefix='oci-scan-', dir=tools) as directory:
            scratch = Path(directory)
            for index, record in enumerate(retained['records']):
                reference = record['subject']['reference']
                before = read_oci_directory(root / record['layout'], reference, record['platform'], budget=budget)
                if (before['manifest_digest'] != record['manifest_digest'] or before['config_digest'] != record['config_digest']
                        or before['diff_ids'] != record['diff_ids'] or
                        {name: {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)} for name, raw in before['objects'].items()} != record['objects']):
                    raise SecurityDataError('retained OCI object set changed')
                if {name: list(before['identities'][name]) for name in before['objects']} != record['object_identities']:
                    raise SecurityDataError('retained original OCI inodes were replaced')
                # A fresh private read-only input namespace avoids cache/source path reuse.
                selected = scratch / ('input-' + str(index))
                selected.mkdir(mode=0o700)
                for name, raw in before['objects'].items():
                    target = selected / name
                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    budget.charge('storage', len(raw))
                    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
                    with os.fdopen(descriptor, 'wb') as stream:
                        stream.write(raw)
                        stream.flush()
                        os.fsync(stream.fileno())
                selected_before = read_oci_directory(selected, reference, record['platform'], budget=budget)
                input_name = str(selected) + '@' + before['manifest_digest']
                output = scratch / ('report-' + str(index) + '.json')
                # Reserve the largest accepted report before the isolated port writes it.
                budget.charge('storage', MAX_REPORT)
                command = [str(trivy), 'image', '--input', input_name, '--scanners', 'vuln',
                    '--cache-dir', str(tools / 'cache'), *trivy_options(scratch),
                    '--offline-scan', '--skip-db-update', '--skip-java-db-update', '--skip-check-update',
                    '--skip-version-check', '--show-suppressed', '--list-all-pkgs', '--parallel', '1',
                    '--max-image-size', str(min(retained['profile']['max_unpacked_bytes'], 256 * 1024 * 1024)),
                    '--format', 'json', '--output', str(output)]
                result = process(command, scratch, scratch, timeout=max(0.001, deadline - time.monotonic()))
                if result.returncode != 0 or result.terminal_state != 'completed' or result.cleanup_error:
                    raise _process_error(result, 'OCI scanner process did not complete')
                parsed = image_layout_report(_process_report(output, result), before, input_name=input_name)
                after = read_oci_directory(root / record['layout'], reference, record['platform'], budget=budget)
                selected_after = read_oci_directory(selected, reference, record['platform'], budget=budget)
                current = retained_acquisition(root, inventory['images'], binding=binding, now=now,
                                               profile=profile, network_selection=network_selection)
                if (before['identities'] != after['identities'] or before['objects'] != after['objects']
                        or selected_before['identities'] != selected_after['identities']
                        or selected_before['objects'] != selected_after['objects']
                        or current != retained or _regular(trivy, limit=MAX_DOWNLOAD, digest_only=True) != tool_before
                        or trivy_database_source(tools, now=now) != source):
                    raise SecurityDataError('OCI input/tool/DB/source envelope changed during scan')
                budget.check()
                results.append({'image': reference, 'input_manifest_digest': before['manifest_digest'],
                    'input_archive_sha256': record['archive_sha256'], **parsed})
                findings.extend(parsed['findings'])
    except (OCIError, OSError, ValueError, RuntimeError) as exc:
        gaps.append({'code': 'image-scan-unavailable', 'message': str(exc)})
    if not gaps:
        gaps.append({'code': 'isolated-execution-unqualified',
                     'message': 'injected port proves contracts only, not actual scanner execution'})
    return {'outcome': 'blocked', 'qualification': 'UNVERIFIED', 'execution': 'UNEXECUTED',
            'summary': f'{len(results)} OCI contract observations; actual isolated scanner execution unqualified',
            'images': [], 'contract_observations': results, 'findings': [], 'gaps': gaps,
            'data_sources': []}


def _component_coverage(report, image, inventory, tools, trivy, pages):
    from . import security_image_authority as authority
    from .security_image_components import observe_components
    from .security_image_package_coverage import package_evidence

    if image is None:
        raise SecurityDataError('Installed component coverage requires exact offline OCI bytes')
    state = authority._LIVE
    source_root = None
    if state is not None:
        held = state['images'].get(image.reference)
        if (state['native_guard'] is not authority._GUARD or authority._GUARD is None
                or state['declared_inventory'] != inventory or held is None
                or (held.manifest_digest, held.config_digest, held.platform) !=
                   (image.manifest_digest, image.config_digest, image.platform)):
            raise SecurityDataError('Component scan differs from the owned image graph')
        image, source_root = held, state['root']
    packages = package_evidence(report, image, tools, trivy)
    observed = observe_components(image, source_root=source_root, packages=packages, advisory_pages=pages).document()
    if state is not None and 'postgresql_server' in observed:
        state.setdefault('postgresql_servers', {})[image.manifest_digest] = observed['postgresql_server']
    return [dict(gap, manifest=image.manifest_digest) for gap in observed['unresolved']]


def scan_images(inventory: dict, *, environ=None, now=None) -> dict:
    from .security_oci import ImageSecurityRefusal
    env = os.environ if environ is None else environ
    tools = tools_directory(TRUSTED_ROOT, env)
    if not env.get('GETZILLA_SECURITY_IMAGE_ARTIFACTS') and ((tools / 'oci/manifest.json').exists() or (tools / 'oci/manifest.json').is_symlink()):
        try:
            binding = json.loads(env.get('GETZILLA_SECURITY_OCI_BINDING', 'null'))
            profile = json.loads(env.get('GETZILLA_SECURITY_OCI_PROFILE', 'null'))
            network_selection = json.loads(env.get('GETZILLA_SECURITY_OCI_NETWORK_SELECTION', 'null'))
        except (ValueError, TypeError):
            binding = profile = network_selection = None
        return scan_layouts(inventory, tools, binding=binding, now=now, profile=profile, network_selection=network_selection)
    if not env.get('GETZILLA_SECURITY_IMAGE_ARTIFACTS') and any(
            row.get('selection_assurance') == 'declaration-only-unverified' for row in inventory['images']):
        return {'outcome':'blocked', 'summary':'declared images require verified offline OCI artifacts',
                'findings':[], 'gaps':[{'code':'unqualified-image-selection'}], 'images':[], 'data_sources':[]}
    results, gaps, findings = [], [], []
    source = None
    try:
        trivy = pinned_tool('trivy', tools)
        source = trivy_database_source(tools, now=now)
        with tempfile.TemporaryDirectory(prefix='image-', dir=tools) as directory:
            scratch = Path(directory)
            selected = env.get('GETZILLA_SECURITY_IMAGE_ARTIFACTS')
            if selected:
                from .security_oci import import_layouts
                catalog = _json(Path(selected), limit=16 * 1024 * 1024)
                profile = json.loads(env.get('GETZILLA_SECURITY_IMAGE_PROFILE', ''), object_pairs_hook=_closed)
                image_acquisition_profile(inventory, profile)
                imported = import_layouts(catalog, inventory, profile, scratch)
            else:
                if any(row.get('selection_assurance') == 'declaration-only-unverified' for row in inventory['images']):
                    raise SecurityDataError('Declared public images require verified local OCI graph; no daemon fallback')
                imported = nullcontext([])
            with imported as images:
                verified = {image.reference: image for image in images}
                pages = {}
                for index, item in enumerate(inventory['images']):
                    reference = item['reference']
                    if not _DIGEST_IMAGE.fullmatch(reference):
                        gaps.append({'code': 'unresolved-image', 'reference': reference})
                        continue
                    report_path = scratch / f'image-{index}.json'
                    image = verified.get(reference)
                    if selected and image is None:
                        raise SecurityDataError('Selected offline OCI identity is unavailable; no daemon fallback')
                    input_args = (['--input', str(image.layout) + '@' + image.manifest_digest] if image is not None
                                  else ['--image-src', 'docker'])
                    command = [str(trivy), 'image', '--scanners', 'vuln', *input_args,
                               '--cache-dir', str(tools / 'cache'), *trivy_options(scratch),
                               '--offline-scan', '--skip-db-update', '--skip-java-db-update', '--skip-check-update',
                               '--skip-version-check', '--show-suppressed', '--list-all-pkgs', '--parallel', '1',
                               '--max-image-size', '2GB', '--format', 'json', '--output', str(report_path),
                               *([] if image is not None else [reference])]
                    result = _process(command, scratch, scratch,
                                      timeout=image.remaining_seconds() if image is not None else 900)
                    if result.returncode != 0:
                        raise SecurityDataError('Trivy image process did not complete successfully')
                    raw_report = _process_report(report_path, result)
                    parsed = image_report(raw_report, reference, expected_image_id=item.get('image_id'), verified_oci=image)
                    from . import security_dind_exception as dind
                    blocking, accepted = dind.partition(parsed['findings'], image, inventory, now or datetime.now(timezone.utc))
                    findings.extend(blocking)
                    try:
                        gaps.extend(_component_coverage(raw_report, image, inventory, tools, trivy, pages))
                    except ImageSecurityRefusal as exc:
                        gaps.append(exc.report)
                    results.append({'image': reference, **parsed, 'accepted_evidence': accepted})
        if trivy_database_source(tools, now=now) != source:
            raise SecurityDataError('Trivy database changed during scanning')
    except (OSError, ValueError, RuntimeError) as exc:
        gaps.append({'code': 'image-scan-unavailable', 'message': str(exc)})
    return {'outcome': 'blocked' if gaps else ('finding' if findings else 'pass'),
            'summary': f'{len(results)} image scans; {len(findings)} findings; {len(gaps)} gaps',
            'findings': findings, 'gaps': gaps, 'images': results,
            'data_sources': [source] if source is not None else []}


def _normalize(value: str) -> str:
    return str(value).replace('\\', '/').removeprefix('./')


def validate_tool_report(name: str, report: dict, targets: list[str]) -> dict:
    if name == 'opengrep':
        from .opengrep_contract import OpenGrepError, validate_report
        try:
            observed = validate_report(report, targets, 0)
        except OpenGrepError:
            raise SecurityDataError('OpenGrep report or exact target coverage is incomplete') from None
        findings = [{'rule': item['rule'], 'path': item['path'], 'line': int(item['line'])}
                    for item in observed['findings']]
        return {'outcome': observed['outcome'], 'findings': findings, 'coverage': observed['coverage'],
                'summary': f'{len(targets)} files checked; {observed["finding_count"]} findings'}
    expected = {_normalize(value) for value in targets}
    if not expected:
        raise SecurityDataError('tool applicability needs source inventory, not an empty report')
    findings = []
    if name == 'bandit':
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


_COOKIE = re.compile(r'^[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)')
_SOURCE_CODECS = {'ascii', 'us-ascii', 'utf8', 'utf-8', 'utf-8-sig', 'latin1', 'latin-1',
                  'iso8859-1', 'iso-8859-1', 'cp1251', 'windows-1251', 'cp1252', 'windows-1252'}


def _opaque_asset(path: Path, raw: bytes) -> bool:
    """Classify undecodable assets for disclosure, never for a scanning exemption."""
    suffix = path.suffix.lower()
    return ((suffix == '.png' and raw.startswith(b'\x89PNG\r\n\x1a\n'))
            or (suffix in {'.jpg', '.jpeg'} and raw.startswith(b'\xff\xd8\xff'))
            or (suffix == '.gif' and raw.startswith((b'GIF87a', b'GIF89a')))
            or (suffix == '.webp' and raw[:4] == b'RIFF' and raw[8:12] == b'WEBP')
            or (suffix == '.avif' and raw[4:12] in {b'ftypavif', b'ftypavis'})
            or (suffix == '.woff2' and raw.startswith(b'wOF2')))


def _secret_text(relative: str, raw: bytes) -> str:
    path = Path(relative)
    first = raw[:512].split(b'\n', 1)[0]
    python = path.suffix.lower() in {'.py', '.pyw', '.pyi'} or (
        first.startswith(b'#!') and re.search(rb'[/ \t]python[0-9.]*(?:[ \t\r]|$)', first))
    if python:
        reader = io.BytesIO(raw)

        def checked_line():
            line = reader.readline()
            cookie = _COOKIE.match(line.removeprefix(codecs.BOM_UTF8).decode('utf-8'))
            if cookie and cookie[1].lower().replace('_', '-') not in _SOURCE_CODECS:
                # detect_encoding normally looks up the declared codec itself.
                # Bound that lookup to standard text codecs before giving it a line.
                raise ValueError('unsupported source encoding')
            return line

        encoding, _ = tokenize.detect_encoding(checked_line)
    elif raw.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        encoding = 'utf-32'
    elif raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        encoding = 'utf-16'
    else:
        encoding = 'utf-8-sig'
    text = raw.decode(encoding)
    if '\0' in text:
        raise ValueError('unqualified NUL-bearing text')
    return text


def _secret_input_core(root: Path, files: list[str], trusted_root: Path, *, file_limit: int, native: bool) -> dict:
    """One byte/encoding engine; projections never originate disposition authority."""
    findings, gaps, binary = [], [], []
    total = 0
    policy = None
    stage = 'policy'
    relative = '.'

    def gap(code, path=None):
        detail = {'code': code, 'message': 'secret input coverage is unavailable'}
        if path is not None:
            detail['path'] = path
        gaps.append(detail)
        if native:
            findings.append({'severity': 'error', 'effective_severity': 'error', 'code': code,
                             'path': path or '.', 'message': 'Secret input coverage is unavailable.'})

    try:
        try:
            policy = dispositions.Dispositions(trusted_root)
        except (dispositions.DispositionError, OSError):
            if not native:
                raise
            # Native findings remain visible when review policy cannot qualify.
            # An invalid policy never authorizes any disposition.
            findings.append(dispositions.invalid_finding())
            gaps.append({'code': 'disposition-config-invalid', 'message': 'reviewed disposition binding unavailable'})
        stage = 'input'
        for relative in files:
            reviewed_report = native and relative == _REVIEWED_BENCHMARK_PATH
            limit = _REVIEWED_BENCHMARK_SIZE if reviewed_report else file_limit
            raw = _regular(root / relative, limit=min(limit, MAX_SOURCE_TOTAL - total))
            total += len(raw)
            digest = hashlib.sha256(raw).hexdigest()
            if reviewed_report and len(raw) > file_limit and digest != _REVIEWED_BENCHMARK_SHA256:
                raise SecurityDataError("oversized benchmark report differs from reviewed content")
            try:
                views = [(_secret_text(relative, raw), False)]
            except (ValueError, SyntaxError, LookupError):
                views = []
                if _opaque_asset(Path(relative), raw):
                    binary.append({'path': relative, 'sha256': digest,
                                   'reason': 'recognized asset; visible bytes checked, opaque contents not decoded'})
                    if native:
                        findings.append({'severity': 'info', 'effective_severity': 'info',
                                         'code': 'secret-binary-input', 'path': relative,
                                         'file_sha256': digest,
                                         'message': 'Recognized asset; visible bytes checked, opaque contents not decoded.'})
                else:
                    gap('secret-text-coverage', relative)
            # The supported narrow codecs preserve ASCII. A wide decoder can hide
            # a separate contiguous ASCII string, so inspect visible bytes there
            # too. Latin-1 here is a 1:1 byte view, not an encoding assertion.
            if not views or raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE,
                                            codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
                views.append((raw.decode('latin-1'), True))
            for text, byte_view in views:
                for label, pattern in dispositions.SECRET_PATTERNS.items():
                    for match in pattern.finditer(text):
                        line, column = dispositions.location(text, match.start())
                        entry = (policy.secret(relative, digest, text, match)
                                 if policy and label == 'generic-secret' and not byte_view else None)
                        if native:
                            finding = {'severity': 'error', 'effective_severity': 'error', 'observation': True,
                                       'code': label, 'path': relative, 'line': line, 'column': column,
                                       'file_sha256': digest, 'message': 'Potential committed secret.'}
                            if policy:
                                policy.apply(finding, entry)
                        else:
                            finding = {'rule': label, 'path': relative, 'line': line, 'column': column,
                                       'file_sha256': digest, 'disposition': entry.get('id') if entry else None}
                        if byte_view:
                            finding['byte_offset'] = match.start()
                        findings.append(finding)
        stage = 'policy'
        if policy:
            policy.assert_current()
    except (OSError, ValueError, RuntimeError):
        if native and stage == 'policy':
            findings.append(dispositions.invalid_finding())
            gaps.append({'code': 'disposition-config-invalid', 'message': 'reviewed disposition binding unavailable'})
        else:
            gap('secret-input-unavailable', relative if native else None)
    if native:
        summary = dispositions.summary(policy, findings)
        findings.append(summary)
        text = (f'{summary["observed"]} potential secrets; {summary["disposed"]} disposed; '
                f'{summary["unresolved"]} unresolved')
        if gaps:
            text = 'secret input coverage incomplete; ' + text
        return {'outcome': 'blocked' if gaps else ('finding' if summary['unresolved'] else 'pass'),
                'summary': text, 'details': findings}
    unresolved = [item for item in findings if item['disposition'] is None]
    return {'outcome': 'blocked' if gaps else ('finding' if unresolved else 'pass'),
            'summary': f'{len(unresolved)} unresolved text-pattern secret findings; {len(gaps)} coverage gaps',
            'findings': findings, 'gaps': gaps, 'binary_inputs': binary}


def scan_secrets(root: Path, files: list[str], *, trusted_root: Path = TRUSTED_ROOT) -> dict:
    return _secret_input_core(root, files, trusted_root, file_limit=MAX_SOURCE_FILE, native=False)


def native_secret_observations(root: Path, files: list[str]) -> dict:
    return _secret_input_core(root, files, root, file_limit=dispositions.MAX_FILE_BYTES, native=True)


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
    targets = {'bandit': python, 'trivy-config': config}
    reports = [{'name': 'secret-scan', **scan_secrets(root, inventory['files'], trusted_root=trusted_root)}]
    try:
        from .security_opengrep import OpenGrepError, scan_source as observe_opengrep
        from .opengrep_contract import targets as target_roster
        declared = target_roster(sast) if sast else ()
        observed = observe_opengrep(root, rules_root=trusted_root / '.getzilla/sast/rules',
                                   executable=tools / 'bin/opengrep', profile='expanded')
        if observed['outcome'] in {'pass', 'finding', 'not_applicable'}:
            if tuple(observed['coverage']['expected']) != declared:
                raise OpenGrepError('inventory_target_coverage_incomplete')
        projection = {key: observed[key] for key in ('outcome', 'summary', 'coverage')}
        projection['findings'] = [{'rule': item['rule'], 'path': item['path'], 'line': int(item['line'])}
                                  for item in observed['findings']]
        reports.append({'name': 'opengrep', **projection})
    except (OSError, ValueError, RuntimeError):
        reports.append({'name': 'opengrep', 'outcome': 'blocked',
                        'summary': 'OpenGrep 1.30.1 incomplete: source, inventory or tool unavailable',
                        'gaps': [{'code': 'scanner-unavailable', 'message': 'source, inventory or tool unavailable'}]})
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
                    bandit_config.write_text(safe_dump(settings), encoding='utf-8', newline='\n')
                    command = [sys.executable, '-I', '-m', 'bandit', '-c', str(bandit_config),
                               '--ignore-nosec', '-q', '-f', 'json', '-o', str(output), '--', *files]
                else:
                    command = [str(pinned_tool('trivy', tools)), 'config', *trivy_options(scratch),
                               '--skip-check-update', '--skip-version-check', '--include-non-failures',
                               '--format', 'json', '--output', str(output), '.']
                # Only these tools define exit 1 as findings. Trivy config has
                # no --exit-code override and must complete with exit 0.
                result = _process(command, source, scratch, finding_exit=name in {'bandit', 'opengrep'})
                reports.append({'name': name, **validate_tool_report(name, _process_report(output, result), files)})
            except (OSError, ValueError, RuntimeError) as exc:
                reports.append({'name': name, 'outcome': 'blocked', 'summary': str(exc),
                                'gaps': [{'code': 'scanner-unavailable', 'message': str(exc)}]})
    return reports
