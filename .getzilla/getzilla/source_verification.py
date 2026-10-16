"""Adoption integrity, kept apart from the imported application's health (INTEGRITY_VERIFIED).

`integrity_status=verified` means the shadow's bytes, the source commit, the managed commit and
the provenance match the approved plan and receipts. It says nothing about whether the client
application works: `project_health_status` stays `not_run`, because adoption never runs client
scripts, tests or package managers.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from .source_git import GitEntry, IsolatedGit, blob_oid, tree_entries
from .source_models import AdmissionPlan
from .source_provenance import PROVENANCE_PATH, verify_source_provenance


@dataclass(frozen=True)
class AdoptionVerification:
    integrity_status: str
    project_health_status: str
    problems: tuple[str, ...]

    def to_dict(self) -> dict:
        return {'integrity_status': self.integrity_status, 'project_health_status': self.project_health_status,
                'runtime_status': 'not_run', 'problems': list(self.problems)}


def verify_adoption(shadow: Path, plan: AdmissionPlan, *, source_commit: str, managed_commit: str,
                    payload: tuple[GitEntry, ...], timestamp: str) -> AdoptionVerification:
    problems: list[str] = []
    with IsolatedGit(shadow, timestamp=timestamp) as git:
        try:
            head = git.run('rev-parse', 'refs/heads/main').decode().strip()
            parent = git.run('rev-parse', f'{managed_commit}^').decode().strip()
            source_tree = git.run('rev-parse', f'{source_commit}^{{tree}}').decode().strip()
            managed_tree = git.run('rev-parse', f'{managed_commit}^{{tree}}').decode().strip()
        except Exception:  # noqa: BLE001
            return AdoptionVerification('failed', 'not_run', ('GIT_STATE_UNREADABLE',))
        if head != managed_commit:
            problems.append('HEAD_IS_NOT_MANAGED_COMMIT')
        if parent != source_commit:
            problems.append('MANAGED_PARENT_IS_NOT_SOURCE_COMMIT')
        if git.run('remote').strip():
            problems.append('REMOTE_PRESENT')
        source_listing = tree_entries(git, source_tree)
        expected_source = {entry.path: '100755' if entry.executable else '100644' for entry in plan.entries}
        if {path: mode for path, (mode, _oid) in source_listing.items()} != expected_source:
            problems.append('SOURCE_COMMIT_ENTRIES_MISMATCH')
        managed_listing = tree_entries(git, managed_tree)
        for entry in plan.entries:
            path = shadow.joinpath(*entry.path.split('/'))
            content = path.read_bytes() if path.is_file() and not path.is_symlink() else None
            if content is None or hashlib.sha256(content).hexdigest() != entry.sha256:
                problems.append(f'SOURCE_FILE_TAMPERED:{entry.path}')
            elif source_listing.get(entry.path, ('', ''))[1] != blob_oid(content):
                problems.append(f'SOURCE_BLOB_MISMATCH:{entry.path}')
        for entry in payload:
            if entry.path in expected_source:
                continue
            path = shadow.joinpath(*entry.path.split('/'))
            content = path.read_bytes() if path.is_file() and not path.is_symlink() else None
            if content != entry.content:
                problems.append(f'MANAGED_FILE_TAMPERED:{entry.path}')
            elif managed_listing.get(entry.path, ('', ''))[1] != blob_oid(entry.content):
                problems.append(f'MANAGED_BLOB_MISMATCH:{entry.path}')
        try:
            record = json.loads((shadow / PROVENANCE_PATH).read_text(encoding='utf-8'))
        except (OSError, ValueError):
            problems.append('PROVENANCE_UNREADABLE')
        else:
            result = verify_source_provenance(record, plan, git)
            problems.extend(result.errors)
            if record.get('source_commit', {}).get('commit_oid') != source_commit:
                problems.append('PROVENANCE_COMMIT_MISMATCH')
        extra = set(managed_listing) - set(expected_source) - {entry.path for entry in payload} - {PROVENANCE_PATH}
        if extra:
            problems.append('UNEXPECTED_TRACKED_FILES')
    return AdoptionVerification('failed' if problems else 'verified', 'not_run', tuple(problems))
