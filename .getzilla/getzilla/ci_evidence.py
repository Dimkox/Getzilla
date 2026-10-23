"""Export a narrow set of actual CI observations, never local authorization."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from .util import dump_json, git_head, git_output, now_utc

_LOGS = ('core-tests.log', 'trust-ci-tests.log', 'smoke.log', 'install.log')


def export_evidence(root: Path, output: Path, *, logs: Path, job: str, status: str, run_id: str) -> None:
    output.mkdir(parents=True, exist_ok=False)
    if output.is_symlink():
        raise ValueError('artifact directory must not be a symlink')
    head = git_head(root)
    if not head:
        raise ValueError('CI evidence requires an exact Git HEAD')
    inventory = []
    for name in _LOGS:
        path = logs / name
        if path.is_file() and not path.is_symlink():
            content = path.read_bytes()
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
        if record.get('ci_run_id') != run_id or record.get('git_head') != head:
            continue
        (output / name).write_bytes(content)
        inventory.append({'path': name, 'sha256': hashlib.sha256(content).hexdigest()})
    dump_json(output / 'state.json', {'schema_version': 1, 'job': job, 'job_status': status,
        'local_reviews': 'not_available_in_ci', 'local_analysis': 'not_available_in_ci',
        'authority': 'CI run observations only; local approval grants are never exported'})
    dump_json(output / 'provenance.json', {'schema_version': 1, 'source': 'github-actions',
        'head': head, 'tree': git_output(root, 'rev-parse', 'HEAD^{tree}'), 'job': job,
        'run_id': run_id, 'observed_at': now_utc(), 'files': inventory})


def export_local_evidence(root: Path, output: Path) -> None:
    """Portable observations for PR attachment; extraction never activates receipts or grants."""
    import re
    import zipfile
    from .architecture import _read_regular_bytes
    from .review_source import REVIEW_REPORT_NAMES
    from .state import get_active_change, get_active_route
    from .workflow_storage import valid_package_path
    route, active = get_active_route(root) or {}, get_active_change(root) or {}
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
        evidence = root / package / 'evidence'
        if evidence.is_dir():
            for path in sorted(evidence.iterdir()):
                if path.name in REVIEW_REPORT_NAMES | {'startup-capacity.json'} or re.fullmatch(r'analysis-[A-Za-z0-9_-]+\.md', path.name):
                    candidates.append((package / 'evidence' / path.name, 'change/evidence/' + path.name))
    for name in REVIEW_REPORT_NAMES:
        candidates.append((Path(f'.getzilla/runtime/reviews/{route_id}/{name}'), 'reviews/' + name))
    for name in ('verification', 'code_review', 'test_review', 'bitrix_review', 'security_review', 'data_review', 'release_review'):
        receipt = Path(f'.getzilla/runtime/receipts/{route_id}/{name}.json')
        candidates.append((receipt, 'receipts/' + name + '.json'))
        if name == 'verification' and (root / receipt).is_file():
            envelope = json.loads(_read_regular_bytes(root, receipt.as_posix(), label='verification receipt'))
            reference = (envelope.get('details') or {}).get('_verification_report')
            if isinstance(reference, dict):
                digest = reference.get('sha256')
                expected = f'.getzilla/runtime/receipts/{route_id}/reports/{digest}.json'
                if isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest) and reference.get('path') == expected:
                    candidates.append((Path(expected), f'receipts/reports/{digest}.json'))
    candidates.extend([(Path('.getzilla/runtime/startup-capacity.json'), 'startup-capacity.json'),
                       (Path('.getzilla/runtime/evidence/verification.json'), 'verification.json')])
    entries, total = [], 0
    for relative, destination in candidates:
        if not (root / relative).exists() and not (root / relative).is_symlink():
            continue
        content = _read_regular_bytes(root, relative.as_posix(), label='portable evidence')
        total += len(content)
        if len(content) > 1_048_576 or total > 10_485_760 or len(entries) >= 128:
            raise ValueError('portable evidence exceeds size limits')
        entries.append((destination, content))
    head = git_head(root)
    if not head:
        raise ValueError('portable evidence requires an exact Git HEAD')
    manifest = {'schema_version': 1, 'source': 'local-workflow-observations', 'head': head,
        'tree': git_output(root, 'rev-parse', 'HEAD^{tree}'), 'route_id': route_id,
        'change_id': active.get('change_id'), 'observed_at': now_utc(),
        'authority': 'Archive only; historical observations retain their original bindings, never merge authority',
        'files': [{'path': name, 'sha256': hashlib.sha256(content).hexdigest()} for name, content in entries]}
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('manifest.json', json.dumps(manifest, sort_keys=True, indent=2))
        for name, content in entries:
            archive.writestr(name, content)
