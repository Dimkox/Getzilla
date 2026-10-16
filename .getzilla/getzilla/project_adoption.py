"""Zero-Git adoption: approved plan → snapshot → shadow → source commit → managed commit → publish.

The original folder is only read. Every mutation happens in the private state root (snapshot
store, journal) or in an operation-owned staging directory next to the target, which is
published to the absent target by one atomic no-replace rename after integrity verification.
A crash leaves either no target or a verified one. No remote is created and nothing is pushed.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from . import fsx
from .adoption_state import Journal, OperationState, default_state_root, now, operation_id_for
from .source_admission import validate_plan_approval
from .source_git import GitEntry, create_git_baseline
from .source_managed_layer import apply_managed_layer, payload_entries, plan_managed_layer
from .source_models import RECEIPT_SCHEMA, AdmissionPlan
from .source_paths import source_target_problem
from .source_provenance import build_source_provenance
from .source_shadow import materialize_shadow, shadow_identity
from .source_snapshot import AdoptionError, create_snapshot, load_snapshot, read_object
from .source_verification import verify_adoption

EXIT_CODES = {
    'INVALID_ARGUMENTS': 2, 'QUIESCENCE_REQUIRED': 2, 'PLAN_DIGEST_MISMATCH': 2,
    'BLOCKED_SECURITY': 3,
    'BLOCKED_UNSAFE_SOURCE': 4, 'BLOCKED_UNSUPPORTED_FS': 4, 'GIT_PRESENT': 4,
    'STALE_PLAN': 5, 'PLAN_NOT_READY': 5, 'PLAN_TAMPERED': 5,
    'TARGET_CONFLICT': 6, 'TARGET_EXISTS': 6, 'OPERATION_LOCKED': 6, 'UNKNOWN_OPERATION': 6, 'PUBLISHED': 6,
    'VERIFICATION_FAILED': 7, 'STORE_OBJECT_MODIFIED': 7, 'STORE_OBJECT_MISSING': 7,
    'TOOL_ERROR': 8, 'STATE_CORRUPT': 8, 'ERROR': 8,
}
# Failures that make the operation terminal: resuming would only repeat the refusal.
TERMINAL = {'BLOCKED_SECURITY': 'BLOCKED_SECURITY', 'STALE_PLAN': 'STALE_PLAN',
            'BLOCKED_UNSAFE_SOURCE': 'BLOCKED_UNSAFE_SOURCE'}


def exit_code(reason_code: str | None) -> int:
    return 0 if reason_code is None else EXIT_CODES.get(reason_code, 8)


def staging_path(target: Path, operation_id: str) -> Path:
    return target.parent / f'.{target.name}.getzilla-adopt-{operation_id[3:15]}'


def rename_noreplace(source: Path, target: Path) -> None:
    """Atomically rename `source` to the absent `target`; never replaces an existing target."""
    if fsx.WINDOWS:
        os.rename(source, target)  # MoveFileEx without MOVEFILE_REPLACE_EXISTING
        return
    libc = ctypes.CDLL(ctypes.util.find_library('c') or None, use_errno=True)
    if sys.platform.startswith('linux') and hasattr(libc, 'renameat2'):
        result = libc.renameat2(-100, os.fsencode(source), -100, os.fsencode(target), 1)  # AT_FDCWD, RENAME_NOREPLACE
    elif sys.platform == 'darwin' and hasattr(libc, 'renamex_np'):
        result = libc.renamex_np(os.fsencode(source), os.fsencode(target), 0x4)  # RENAME_EXCL
    else:
        raise AdoptionError('BLOCKED_UNSUPPORTED_FS', 'no atomic no-replace rename on this platform')
    if result != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise AdoptionError('TARGET_EXISTS', str(target))
        raise OSError(code, os.strerror(code), str(target))


def _remove_owned_staging(state: OperationState) -> None:
    staging = Path(state.staging)
    identity = state.artifacts.get('staging_identity')
    if not os.path.lexists(staging):
        return
    if identity is None or list(shadow_identity(staging)) != list(identity) or staging.is_symlink():
        raise AdoptionError('TARGET_CONFLICT', 'staging directory is not owned by this operation; left untouched')
    shutil.rmtree(staging)


def _receipt(state: OperationState, plan: AdmissionPlan) -> dict[str, Any]:
    artifacts = state.artifacts
    return {
        'schema_version': RECEIPT_SCHEMA, 'operation_id': state.operation_id, 'state': state.state,
        'plan_id': plan.plan_id, 'source_digest': plan.source_digest,
        'snapshot_digest': artifacts.get('snapshot_id'),
        'source_baseline': {'object_format': 'sha1', 'commit_oid': artifacts.get('source_commit'),
                            'tree_oid': artifacts.get('source_tree')},
        'managed_commit': artifacts.get('managed_commit'), 'runtime_payload_digest': artifacts.get('payload_digest'),
        'git_present_at_ingest': False,
        'integrity_status': artifacts.get('integrity_status', 'not_verified'),
        'project_health_status': 'not_run',
        'target': state.target if state.state == 'PUBLISHED_LOCAL' else None,
        'reason_code': state.reason_code,
        'admitted_files': len(plan.entries), 'excluded': [item.to_dict() for item in plan.exclusions],
    }


def _run_stages(journal: Journal, state: OperationState, plan: AdmissionPlan, home: Path, store: Path,
                quiesced: bool) -> None:
    source, target, staging = Path(state.source), Path(state.target), Path(state.staging)
    snapshot = create_snapshot(plan, source, store, quiesced=quiesced)
    journal.advance(state, 'SNAPSHOT_VERIFIED', snapshot_id=snapshot.snapshot_id)
    shadow = materialize_shadow(snapshot, store, staging, source)
    journal.advance(state, 'SHADOW_MATERIALIZED', staging_identity=list(shadow.identity))
    entries = [GitEntry(entry.path, '100755' if entry.executable else '100644', read_object(store, entry))
               for entry in snapshot.entries]
    baseline = create_git_baseline(staging, entries, source_digest=plan.source_digest or '',
                                   excluded=len(plan.exclusions), timestamp=state.timestamp)
    journal.advance(state, 'GIT_INITIALIZED')
    journal.advance(state, 'SOURCE_BASELINE_COMMITTED', source_commit=baseline.identity.commit_oid,
                    source_tree=baseline.identity.tree_oid)
    source_paths = {entry.path for entry in plan.entries}
    _payload, collisions = plan_managed_layer(staging, home, source_paths)
    if collisions:
        raise AdoptionError('TARGET_CONFLICT', 'source-owned files collide with the Getzilla layer: '
                            + ', '.join(collisions[:20]))
    journal.advance(state, 'GETZILLA_PLANNED')
    provenance = build_source_provenance(plan, snapshot, baseline)
    managed = apply_managed_layer(staging, home, provenance, source_paths, baseline.identity.commit_oid or '',
                                  timestamp=state.timestamp)
    journal.advance(state, 'MANAGED_LAYER_COMMITTED', managed_commit=managed.managed_commit,
                    managed_tree=managed.managed_tree, payload_digest=managed.payload_digest)
    verification = verify_adoption(staging, plan, source_commit=baseline.identity.commit_oid or '',
                                   managed_commit=managed.managed_commit, payload=payload_entries(home),
                                   timestamp=state.timestamp)
    if verification.integrity_status != 'verified':
        raise AdoptionError('VERIFICATION_FAILED', ', '.join(verification.problems[:10]))
    journal.advance(state, 'INTEGRITY_VERIFIED', integrity_status='verified')
    if list(shadow_identity(staging)) != state.artifacts['staging_identity']:
        raise AdoptionError('TARGET_CONFLICT', 'staging directory was replaced before publication')
    if os.path.lexists(target):
        raise AdoptionError('TARGET_EXISTS', 'the target appeared before publication')
    rename_noreplace(staging, target)
    if list(shadow_identity(target)) != state.artifacts['staging_identity']:
        raise AdoptionError('VERIFICATION_FAILED', 'published target is not the verified staging directory')
    journal.advance(state, 'PUBLISHED_LOCAL')


def _execute(plan: AdmissionPlan, *, state_root: Path, home: Path, quiesced: bool, resume: bool) -> dict[str, Any]:
    source, target = Path(plan.source_root), Path(plan.target)
    for root in (state_root,):
        problem = source_target_problem(source, root)
        if problem:
            raise AdoptionError('BLOCKED_UNSAFE_SOURCE', f'state root: {problem}')
    operation_id = operation_id_for(plan.plan_id)
    journal = Journal(state_root, operation_id)
    store = state_root / 'store'
    with journal.lock():
        if journal.exists():
            state = journal.load()
            if state.plan_id != plan.plan_id:
                raise AdoptionError('STATE_CORRUPT', 'operation belongs to another plan')
            if state.state == 'PUBLISHED_LOCAL':
                return _receipt(state, plan)  # idempotent: the verified receipt, nothing re-run
            if state.state in {'ABORTED', *TERMINAL.values()}:
                raise AdoptionError(state.reason_code or state.state, 'operation is terminal; plan again')
            if not resume:
                raise AdoptionError('OPERATION_LOCKED', 'operation in progress; use resume or abort')
            _remove_owned_staging(state)
            state = OperationState(operation_id=operation_id, plan_id=plan.plan_id, source=state.source,
                                   target=state.target, staging=state.staging, timestamp=state.timestamp,
                                   history=state.history + [{'state': 'RESUMED', 'at': now()}])
        else:
            if resume:
                raise AdoptionError('UNKNOWN_OPERATION', 'nothing to resume')
            state = OperationState(operation_id=operation_id, plan_id=plan.plan_id, source=str(source),
                                   target=str(target), staging=str(staging_path(target, operation_id)),
                                   timestamp=now())
            journal.write_json('plan.json', plan.to_dict())
            state.history.append({'state': 'PLAN_READY', 'at': now()})
            journal.save(state)
        problem = source_target_problem(source, Path(state.staging))
        if problem:
            raise AdoptionError('BLOCKED_UNSAFE_SOURCE', f'staging: {problem}')
        try:
            _run_stages(journal, state, plan, home, store, quiesced)
        except AdoptionError as exc:
            state.reason_code = exc.reason_code
            if exc.reason_code in TERMINAL:
                journal.advance(state, TERMINAL[exc.reason_code])
                if state.artifacts.get('staging_identity'):
                    _remove_owned_staging(state)
            else:
                journal.save(state)
            raise
        receipt = _receipt(state, plan)
        journal.write_json('receipt.json', receipt)
        return receipt


def run_adoption(plan: AdmissionPlan, expected_digest: str, *, quiesced: bool, home: Path,
                 state_root: Path | None = None) -> dict[str, Any]:
    approval = validate_plan_approval(plan, expected_digest)
    if not approval.ok:
        code = 'PLAN_DIGEST_MISMATCH' if 'PLAN_DIGEST_MISMATCH' in approval.errors else 'PLAN_NOT_READY'
        raise AdoptionError(code, ', '.join(approval.errors))
    return _execute(plan, state_root=state_root or default_state_root(), home=home, quiesced=quiesced, resume=False)


def _load_plan(journal: Journal) -> AdmissionPlan:
    import json
    return AdmissionPlan.from_dict(json.loads((journal.root / 'plan.json').read_text(encoding='utf-8')))


def resume_adoption(operation_id: str, *, quiesced: bool, home: Path, state_root: Path | None = None) -> dict[str, Any]:
    root = state_root or default_state_root()
    plan = _load_plan(Journal(root, operation_id))
    return _execute(plan, state_root=root, home=home, quiesced=quiesced, resume=True)


def abort_adoption(operation_id: str, *, state_root: Path | None = None) -> dict[str, Any]:
    root = state_root or default_state_root()
    journal = Journal(root, operation_id)
    with journal.lock():
        state = journal.load()
        if state.state == 'PUBLISHED_LOCAL':
            raise AdoptionError('PUBLISHED', 'a published target belongs to its owner; abort removes nothing')
        _remove_owned_staging(state)  # the shared snapshot store is never removed
        if state.state != 'ABORTED':
            state.reason_code = 'ABORTED'
            journal.advance(state, 'ABORTED')
        return {'operation_id': operation_id, 'state': 'ABORTED', 'removed_staging': state.staging}


def get_adoption_status(operation_id: str, *, state_root: Path | None = None) -> dict[str, Any]:
    journal = Journal(state_root or default_state_root(), operation_id)
    state = journal.load()
    record = state.to_dict()
    try:
        record['receipt'] = _receipt(state, _load_plan(journal))
    except (OSError, ValueError, AdoptionError):
        record['receipt'] = None
    return record


def verify_snapshot_store(state_root: Path, snapshot_id: str) -> None:
    load_snapshot(state_root / 'store', snapshot_id)
