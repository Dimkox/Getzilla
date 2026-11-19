"""Export a narrow set of actual CI observations, never local authorization."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
from .util import dump_json, git_head, git_output, now_utc, tree_fingerprint
from . import verification_journal as diagnostics

_LOGS = ('core-tests.log', 'trust-ci-tests.log', 'factory-unit.log', 'factory-unit.json', 'smoke.log', 'install.log')


def _journal_binding(root, report, head):
    """Match a selected report/run to current source; this is not authority."""
    if report is None:
        return None  # Bare CLI history remains explicitly unbound.
    invalid = {'run_id': None, 'source': None, 'session_id': None}
    try:
        reference = report['diagnostics']
        identity = reference['run_id']
        if (type(identity) is not str or not diagnostics._RUN.fullmatch(identity)
                or reference.get('index') != f'.getzilla/runtime/verification-history/{identity}/index.json'
                or report.get('git_head') != head or type(report.get('tree_fingerprint')) is not str
                or not diagnostics._DIGEST.fullmatch(report['tree_fingerprint'])
                or report['tree_fingerprint'] != tree_fingerprint(root)):
            return invalid
        from .state import get_active_route
        session = (get_active_route(root) or {}).get('session_id')
        if type(session) is not str or not diagnostics._SESSION.fullmatch(session):
            session = None
        return {'run_id': identity, 'source': report['tree_fingerprint'], 'session_id': session}
    except (OSError, ValueError, KeyError, TypeError, RuntimeError):
        return invalid


def export_evidence(root: Path, output: Path, *, logs: Path, job: str, status: str, run_id: str) -> None:
    output.mkdir(parents=True, exist_ok=False)
    if output.is_symlink():
        raise ValueError('artifact directory must not be a symlink')
    head = git_head(root)
    if not head:
        raise ValueError('CI evidence requires an exact Git HEAD')
    if job == 'linux-core' and status == 'success':
        if head != os.environ.get('GETZILLA_EXPECTED_HEAD') or git_output(root, 'status', '--porcelain'):
            raise ValueError('successful core evidence requires a clean exact expected source')
    inventory = []
    journal_report = None
    for name in _LOGS:
        path = logs / name
        if path.is_file() and not path.is_symlink():
            content = path.read_bytes()
            if len(content) > 16 * 1024 * 1024:
                raise ValueError('CI log exceeds artifact bound')
            (output / name).write_bytes(content)
            inventory.append({'path': name, 'sha256': hashlib.sha256(content).hexdigest()})
    for name, source in (
        ('verification.json', root / '.getzilla/runtime/evidence/verification.json'),
        ('startup-capacity.json', root / '.getzilla/runtime/startup-capacity.json'),
    ):
        if not source.is_file() or source.is_symlink():
            continue
        content = source.read_bytes()
        record = json.loads(content)
        if name == 'verification.json':
            journal_report = record if record.get('ci_run_id') == run_id else {}
        if record.get('ci_run_id') != run_id or record.get('git_head') != head:
            continue
        (output / name).write_bytes(content)
        inventory.append({'path': name, 'sha256': hashlib.sha256(content).hexdigest()})
    dump_json(output / 'state.json', {'schema_version': 1, 'job': job, 'job_status': status,
        'local_reviews': 'not_available_in_ci', 'local_analysis': 'not_available_in_ci',
        'authority': 'CI run observations only; local approval grants are never exported'})
    journal_state = {'status': 'unavailable'}
    if (root / '.getzilla/runtime/verification-history').exists():
        candidates = diagnostics.export_entries(root, binding=_journal_binding(root, journal_report, head))
        journal_state = json.loads(candidates[0][1])
        remaining = 10_485_760 - sum(p.stat().st_size for p in output.iterdir() if p.is_file())
        for name, content in candidates:
            if len(inventory) >= 126 or len(content) > 1_048_576 or len(content) > remaining:
                journal_state['subset'] = True
                continue
            target = output / name
            target.parent.mkdir(mode=0o700, exist_ok=True)
            target.write_bytes(content)
            remaining -= len(content)
            inventory.append({'path': name, 'sha256': hashlib.sha256(content).hexdigest(),
                              'journal_association': journal_state['association']})
    dump_json(output / 'provenance.json', {'schema_version': 1, 'source': 'github-actions',
        'head': head, 'tree': git_output(root, 'rev-parse', 'HEAD^{tree}'), 'job': job,
        'run_id': run_id, 'attempt': os.environ.get('GITHUB_RUN_ATTEMPT', ''),
        'event_sha': os.environ.get('GITHUB_SHA'), 'base_sha': os.environ.get('GETZILLA_BASE_SHA'),
        'workflow_sha': os.environ.get('GITHUB_WORKFLOW_SHA'), 'workflow_ref': os.environ.get('GITHUB_WORKFLOW_REF'),
        'observed_at': now_utc(), 'files': inventory, 'diagnostics': journal_state})


def export_live_evidence(source: Path, output: Path) -> None:
    from .ci_admission import _bytes, _read, _verify_files
    from .live_acceptance import evidence_name
    if not (source / 'manifest.json').is_file():
        raise ValueError('live acceptance manifest is missing')
    manifest = _read(source / 'manifest.json')
    if manifest.get('schema') != 'getzilla-live-acceptance-v1':
        raise ValueError('unknown live evidence schema')
    _verify_files(source, manifest, maximum=128)
    # Export retains the original decision; the required aggregator independently
    # derives source/job expectations and validates it. Export never measures parser state.
    if not isinstance(manifest.get('binding'), dict):
        raise ValueError('live invocation binding is absent')
    names = [entry['path'] for entry in manifest['files']]
    if not all(evidence_name(name) for name in names):
        raise ValueError('unselected file in live evidence inventory')
    output.mkdir(parents=True, exist_ok=False)
    for name in ['manifest.json', *names]:
        (output / name).write_bytes(_bytes(source / name))


def export_local_evidence(root: Path, output: Path) -> None:
    """Portable observations for PR attachment; extraction never activates receipts or grants."""
    from .trace_storage import native_root
    with native_root(root) as anchor:
        _export_local_evidence(root, output, anchor)


_LEGACY_ROUTE_TEXT = frozenset({'route_id', 'created_at', 'updated_at', 'session_id', 'task', 'intent',
    'risk', 'complexity', 'base_commit', 'base_fingerprint', 'primary_skill', 'write_agent', 'status',
    'delivery_lane', 'logical_task_id', 'origin_session_id', 'workspace', 'change_id'})
_LEGACY_ROUTE_NUMBERS = frozenset({'schema_version', 'task_context_version', 'authority_epoch', 'state_revision'})
_LEGACY_ROUTE_LISTS = frozenset({'domains', 'task_domains', 'workflow_skills', 'analysis_agents',
    'review_agents', 'allowed_agents', 'quality_profiles', 'required_evidence', 'human_gates', 'rationale'})


def _primitive_legacy_record(value):
    if type(value) is not dict or any(type(item) not in {str, int, bool, type(None)} for item in value.values()):
        raise ValueError('legacy context projection unavailable')


def _legacy_route_projection(value):
    try:
        return _legacy_route_data(value)
    except (KeyError, TypeError, AttributeError):
        raise ValueError('legacy route projection unavailable') from None


def _legacy_route_data(value):
    """Closed legacy fields only; future additions cannot auto-export traces."""
    if not isinstance(value, dict):
        raise ValueError('legacy route projection unavailable')
    result = {}
    for key in _LEGACY_ROUTE_TEXT & value.keys():
        if value[key] is not None and not isinstance(value[key], str):
            raise ValueError('legacy route projection unavailable')
        result[key] = value[key]
    for key in _LEGACY_ROUTE_NUMBERS & value.keys():
        if type(value[key]) is not int:
            raise ValueError('legacy route projection unavailable')
        result[key] = value[key]
    for key in _LEGACY_ROUTE_LISTS & value.keys():
        if not isinstance(value[key], list) or any(not isinstance(item, str) for item in value[key]):
            raise ValueError('legacy route projection unavailable')
        result[key] = value[key]
    if 'delivery_expected' in value:
        if type(value['delivery_expected']) is not bool:
            raise ValueError('legacy route projection unavailable')
        result['delivery_expected'] = value['delivery_expected']
    # Preserve original pending/acknowledged scope through its frozen closed v1
    # shape, not a generic recursively copied metadata object.
    context = value.get('context')
    if context is not None:
        if (type(context) is not dict or context.get('version') != 1
                or value.get('task_context_version') != 1 or not isinstance(context.get('pending'), list)
                or any(type(context[key]) is not int for key in ('version', 'revision', 'pending_bytes'))
                or type(context.get('legacy_compatible')) is not bool
                or set(context) != {'version', 'revision', 'pending', 'pending_bytes', 'rejected', 'last_ack', 'legacy_compatible'}):
            raise ValueError('legacy context projection unavailable')
        for item in context['pending']:
            _primitive_legacy_record(item)
            if set(item) != {'id', 'event_id', 'text', 'digest', 'bytes', 'at'}:
                raise ValueError('legacy context projection unavailable')
        if context['rejected'] is not None:
            _primitive_legacy_record(context['rejected'])
            if set(context['rejected']) != {'id', 'event_id', 'digest', 'bytes', 'reason', 'at'}:
                raise ValueError('legacy context projection unavailable')
        ack = context['last_ack']
        if ack is not None:
            from .continuity import _validate_ack
            _validate_ack(value, ack)
            if set(ack) != {'version', 'operation_id', 'transaction_digest', 'route_id', 'logical_task_id',
                    'authority_epoch', 'previous_revision', 'revision', 'spec_digest', 'requirements_digest',
                    'items', 'acknowledged', 'rejected_resolution'}:
                raise ValueError('legacy context projection unavailable')
            for item in ack['acknowledged']:
                if set(item) != {'id', 'event_id', 'digest', 'bytes'}:
                    raise ValueError('legacy context projection unavailable')
            resolution = ack['rejected_resolution']
            if resolution is not None:
                keys = {'id', 'action', 'digest', 'bytes'} | ({'targets'} if resolution.get('action') == 'incorporated' else {'user_event_id', 'decision'})
                if set(resolution) != keys:
                    raise ValueError('legacy context projection unavailable')
        result['context'] = context
    return result


def _export_local_evidence(root: Path, output: Path, anchor) -> None:
    import re
    import zipfile
    from . import fsx
    from .review_source import REVIEW_REPORT_NAMES
    from .state import get_active_change, get_active_route
    from .workflow_storage import valid_package_path
    route, active = get_active_route(root, anchor=anchor) or {}, get_active_change(root, anchor=anchor) or {}
    route_id = route.get('route_id')
    if not isinstance(route_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', route_id):
        raise ValueError('a selected route is required')
    candidates = [(Path('.getzilla/runtime/active-route.json'), 'route.json')]
    if active:
        if not valid_package_path(active.get('path'), active.get('change_id')):
            raise ValueError('invalid selected package')
        package = Path(str(active['path']))
        for name in ('state.json', 'route.json', 'change-spec.yaml', 'brief.md', 'requirements.md',
                     'architecture.md', 'test-plan.md', 'tasks.md', 'decisions.md', 'release.md', 'rollback.md'):
            candidates.append((package / name, 'change/' + name))
        try:
            with anchor.parent(package / 'evidence/.inventory', private=False) as (directory, _):
                names = []
                with fsx.scandir(directory) as inventory:
                    for index, entry in enumerate(inventory):
                        if index >= 4096:
                            raise ValueError('portable evidence inventory limit')
                        names.append(entry.name)
                for name in sorted(names):
                    if name in REVIEW_REPORT_NAMES | {'startup-capacity.json'} or re.fullmatch(r'analysis-[A-Za-z0-9_-]+\.md', name):
                        candidates.append((package / 'evidence' / name, 'change/evidence/' + name))
        except FileNotFoundError:
            pass
    for name in REVIEW_REPORT_NAMES:
        candidates.append((Path(f'.getzilla/runtime/reviews/{route_id}/{name}'), 'reviews/' + name))
    for name in ('verification', 'code_review', 'test_review', 'bitrix_review', 'security_review', 'data_review', 'release_review'):
        receipt = Path(f'.getzilla/runtime/receipts/{route_id}/{name}.json')
        candidates.append((receipt, 'receipts/' + name + '.json'))
        if name == 'verification' and anchor.exists(receipt):
            envelope = json.loads(anchor.read(receipt))
            reference = (envelope.get('details') or {}).get('_verification_report')
            if isinstance(reference, dict):
                digest = reference.get('sha256')
                expected = f'.getzilla/runtime/receipts/{route_id}/reports/{digest}.json'
                if isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest) and reference.get('path') == expected:
                    candidates.append((Path(expected), f'receipts/reports/{digest}.json'))
    candidates.extend([(Path('.getzilla/runtime/startup-capacity.json'), 'startup-capacity.json'),
                       (Path('.getzilla/runtime/evidence/verification.json'), 'verification.json')])
    entries, total = [], 0
    journal_report = None
    for relative, destination in candidates:
        if not anchor.exists(relative, private=False):
            continue
        content = anchor.read(relative, private=False)
        if destination in {'route.json', 'change/route.json'}:
            content = json.dumps(_legacy_route_projection(json.loads(content)), sort_keys=True, indent=2).encode()
        if destination == 'verification.json':
            try:
                journal_report = json.loads(content)
            except ValueError:
                journal_report = {}
        total += len(content)
        if len(content) > 1_048_576 or total > 10_485_760 or len(entries) >= 128:
            raise ValueError('portable evidence exceeds size limits')
        entries.append((destination, content))
    source = anchor.git_source()
    head = source["head"]
    journal_state = {'status': 'unavailable'}
    if (root / '.getzilla/runtime/verification-history').exists():
        selected = diagnostics.export_entries(root, binding=_journal_binding(root, journal_report, head))
        journal_state = json.loads(selected[0][1])
        for name, content in selected:
            if len(content) > 1_048_576 or total + len(content) > 10_485_760 or len(entries) >= 128:
                journal_state['subset'] = True
                continue
            entries.append((name, content))
            total += len(content)
    manifest = {'schema_version': 1, 'source': 'local-workflow-observations', **source, 'route_id': route_id,
        'change_id': active.get('change_id'), 'observed_at': now_utc(),
        'route_projection': 'closed-legacy-v1', 'trace_metadata': 'excluded',
        'authority': 'Archive only; historical observations retain their original bindings, never merge authority',
        'files': [{'path': name, 'sha256': hashlib.sha256(content).hexdigest()} for name, content in entries], 'diagnostics': journal_state}
    anchor.check()
    def write_archive(destination):
        with zipfile.ZipFile(destination, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            anchor.check()
            archive.writestr('manifest.json', json.dumps(manifest, sort_keys=True, indent=2))
            for name, content in entries:
                anchor.check()
                archive.writestr(name, content)
    try:
        relative_output = output.relative_to(root) if output.is_absolute() else output
    except ValueError:
        # Existing explicit local destinations outside the source root retain
        # their legacy behavior; the anchor grants no authority over them.
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open('xb') as destination:
            write_archive(destination)
        return
    with anchor.parent(relative_output, private=False, create=True) as (parent, leaf):
        descriptor = fsx.open_at(parent, leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | fsx.O_NOFOLLOW | fsx.O_CLOEXEC, 0o600)
        try:
            with os.fdopen(descriptor, 'wb') as destination:
                descriptor = None
                write_archive(destination)
                destination.flush()
                os.fsync(destination.fileno())
            anchor.check_parent(parent)
            fsx.fsync_dir(parent)
        finally:
            # Failed output remains unavailable at the caller-selected name.
            # O_EXCL bounds same-path retries; pathname deletion cannot CAS
            # an expected inode and could remove a foreign replacement.
            if descriptor is not None:
                os.close(descriptor)
