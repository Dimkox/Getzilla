"""Source ↔ Git provenance without self-reference (Zero-Git, SOURCE_BASELINE_COMMITTED).

The record links the approved plan, the verified snapshot and the source-only commit. It is
committed in the managed layer and names only the earlier source commit, never the commit
that contains it; the final workspace commit lives in the external adoption receipt.
"""
from __future__ import annotations

import json
from typing import Any

from .source_git import GitBaselineReceipt, IsolatedGit, tree_entries
from .source_models import AdmissionPlan, ValidationResult
from .source_snapshot import SnapshotReceipt

PROVENANCE_PATH = '.getzilla/source-baseline.json'
SCHEMA = 'source-provenance-v1'


def build_source_provenance(plan: AdmissionPlan, snapshot: SnapshotReceipt, baseline: GitBaselineReceipt) -> dict[str, Any]:
    if snapshot.plan_id != plan.plan_id or snapshot.source_digest != plan.source_digest:
        raise ValueError('snapshot does not belong to the plan')
    return {
        'schema_version': SCHEMA,
        'git_present_at_ingest': False,
        'baseline_kind': 'admitted_source_baseline' if plan.exclusions else 'source_baseline',
        'plan_id': plan.plan_id,
        'policy_digest': plan.policy_digest,
        'scanner': {key: plan.scan[key] for key in ('scanner', 'scanner_version', 'rules_digest', 'status')},
        'source_digest': plan.source_digest,
        'path_profile': plan.path_profile,
        'executable_mode': plan.executable_mode,
        'snapshot_id': snapshot.snapshot_id,
        'consistency': snapshot.consistency,
        'admitted_files': len(plan.entries),
        'exclusions': [item.to_dict() for item in plan.exclusions],
        'source_commit': baseline.identity.to_dict(),
        'source_commit_author': baseline.author,
        'source_commit_time': baseline.timestamp,
    }


def provenance_bytes(record: dict[str, Any]) -> bytes:
    return (json.dumps(record, sort_keys=True, indent=2, ensure_ascii=False) + '\n').encode('utf-8')


def verify_source_provenance(record: dict[str, Any], plan: AdmissionPlan, git: IsolatedGit) -> ValidationResult:
    errors: list[str] = []
    if record.get('schema_version') != SCHEMA or record.get('git_present_at_ingest') is not False:
        errors.append('PROVENANCE_SCHEMA')
    if record.get('plan_id') != plan.plan_id or record.get('source_digest') != plan.source_digest:
        errors.append('PROVENANCE_PLAN_MISMATCH')
    commit = (record.get('source_commit') or {}).get('commit_oid')
    tree = (record.get('source_commit') or {}).get('tree_oid')
    try:
        actual_tree = git.run('rev-parse', f'{commit}^{{tree}}').decode().strip()
        message = git.run('cat-file', 'commit', commit).decode('utf-8', 'replace')
    except Exception:  # noqa: BLE001 - any Git failure is a verification failure
        return ValidationResult(False, tuple(errors + ['SOURCE_COMMIT_MISSING']))
    if actual_tree != tree:
        errors.append('SOURCE_TREE_MISMATCH')
    if f'Getzilla-Source-SHA256: {plan.source_digest}' not in message:
        errors.append('SOURCE_TRAILER_MISMATCH')
    expected = {entry.path: ('100755' if entry.executable else '100644', entry.sha256) for entry in plan.entries}
    listed = tree_entries(git, tree)
    if set(listed) != set(expected) or any(listed[path][0] != expected[path][0] for path in expected):
        errors.append('SOURCE_TREE_ENTRIES_MISMATCH')
    return ValidationResult(not errors, tuple(errors))
