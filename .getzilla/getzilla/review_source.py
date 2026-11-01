"""Exact reviewed-source admission. Local evidence is not merge authority."""
from __future__ import annotations

import hashlib
import json
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any

from .architecture_diff import _exact_commit, _git, _git_blob
from .architecture import ArchitectureError, _read_regular_bytes
from .state import get_active_route
from .workflow_storage import valid_package_path


REVIEW_REPORT_NAMES = frozenset({
    'code-review.md', 'test-review.md', 'bitrix-review.md',
    'security-review.md', 'data-review.md', 'release-review.md',
})


def _safe_path(value: Any) -> str:
    if not isinstance(value, str) or not value or '\\' in value or '\x00' in value:
        raise ValueError('review report path is unsafe')
    parts = value.split('/')
    if any(part in ('', '.', '..') for part in parts) or PurePosixPath(value).is_absolute():
        raise ValueError('review report path is unsafe')
    return value


def review_source_binding(root: Path, reviewed_commit: str | None, report: str | None, *,
                          reviewed_context: str | None = None) -> dict[str, Any]:
    """Re-derive the full binding at write and consumption; no caller claims qualify."""
    if not isinstance(reviewed_commit, str) or not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', reviewed_commit):
        raise ValueError('reviewed commit must be an exact full commit SHA')
    _exact_commit(root, reviewed_commit, label='reviewed commit')
    head = (_git(root, ['rev-parse', '--verify', 'HEAD^{commit}']) or b'').decode('ascii').strip()
    if _git(root, ['merge-base', '--is-ancestor', reviewed_commit, head], allow_failure=True) is None:
        raise RuntimeError('reviewed commit is not an ancestor of frozen HEAD')
    if _git(root, ['status', '--porcelain=v1', '-z', '--untracked-files=all']):
        raise RuntimeError('review source requires a clean committed candidate')
    # package_status consumes receipt kinds; defer its path policy import to avoid a module cycle.
    from .package_status import _CHANGE_ID

    route = get_active_route(root) or {}
    route_id = route.get('route_id')
    if not isinstance(route_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', route_id):
        raise ValueError('review source requires a valid selected route')
    selected_present = True
    try:
        active = json.loads(_read_regular_bytes(root, '.getzilla/runtime/active-change.json',
                                               label='selected active change').decode('utf-8'))
    except ArchitectureError as exc:
        if not isinstance(exc.__cause__, FileNotFoundError):
            raise
        selected_present = False
        active = None
    prefixes = {'engineering/reviews/', f'.getzilla/runtime/reviews/{route_id}/'}
    if selected_present:
        if not isinstance(active, dict):
            raise ValueError('selected active change must be a valid package record')
        package = _safe_path(active.get('path'))
        change_id = active.get('change_id')
        if not isinstance(change_id, str) or not _CHANGE_ID.fullmatch(change_id) or not valid_package_path(package, change_id):
            raise ValueError('selected active change must be a valid package record')
        prefixes.add(package + '/evidence/')
    elif route.get('change_id') or not (
            route.get('delivery_lane') == 'light'
            or (route.get('complexity') == 'micro' and route.get('risk') == 'low')):
        raise ValueError('a durable selected route requires its active change package')
    allowed_reports = {prefix + name for prefix in prefixes for name in REVIEW_REPORT_NAMES}

    def regular_report(path: str, commit: str) -> bytes:
        path = _safe_path(path)
        if path not in allowed_reports:
            raise ValueError('review delta must contain conventional independent-review Markdown reports only')
        current = root
        for part in path.split('/')[:-1]:
            current = current / part
            info = current.lstat()
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise RuntimeError('review report directory is unsafe')
        info = (root / path).lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o111:
            raise RuntimeError('review report must be a non-executable regular file')
        if path.startswith('.getzilla/runtime/'):
            if head != reviewed_commit:
                raise RuntimeError('runtime report requires the exact reviewed commit')
            if (_git(root, ['check-ignore', '--quiet', '--', path], allow_failure=True) is None
                    or _git(root, ['ls-files', '-z', '--', path])):
                raise RuntimeError('runtime review report must be ignored and untracked')
            content = _read_regular_bytes(root, path, label='review report')
            if len(content) > 1_048_576:
                raise RuntimeError('review report is too large')
            content.decode('utf-8', 'strict')
            return content
        entries = (_git(root, ['ls-tree', '-z', commit, '--', path]) or b'').split(b'\x00')
        if len(entries) != 2 or not entries[0].startswith(b'100644 blob ') or entries[0].split(b'\t', 1)[-1] != path.encode('utf-8'):
            raise RuntimeError('review report Git entry is not a regular Markdown file')
        content = _read_regular_bytes(root, path, label='review report')
        if len(content) > 1_048_576 or _git_blob(root, commit, path, required=True) != content:
            raise RuntimeError('review report differs from frozen Git tree or is too large')
        content.decode('utf-8', 'strict')
        return content

    report = _safe_path(report)
    report_bytes = regular_report(report, head)
    from .continuity import context_binding, legacy_evidence_allowed, scope_gaps
    context_claim = {}
    if not legacy_evidence_allowed(route) or reviewed_context is not None:
        marker_lines = [line for line in report_bytes.decode('utf-8', 'strict').splitlines()
                        if 'reviewed-context-digest:' in line]
        if (not isinstance(reviewed_context, str) or not re.fullmatch(r'[0-9a-f]{64}', reviewed_context) or
                marker_lines != ['reviewed-context-digest: ' + reviewed_context]):
            raise ValueError('reviewed context requires one exact report marker and matching --reviewed-context')
        if reviewed_context != context_binding(root, route)['digest'] or scope_gaps(root, route):
            raise ValueError('reviewed context is stale or has unresolved scope; obtain a fresh independent report')
        context_claim['reviewed_context'] = reviewed_context
    if report.startswith('.getzilla/runtime/'):
        tree = (_git(root, ['rev-parse', head + '^{tree}']) or b'').decode('ascii').strip()
        return {'contract': 'getzilla.review-source/runtime-v1', 'route_id': route_id, **context_claim,
                'change_id': active.get('change_id') if isinstance(active, dict) else None,
                'report_namespace': report.rsplit('/', 1)[0], 'report_paths': [report],
                'reviewed_commit': reviewed_commit, 'reviewed_tree': tree,
                'frozen_commit': head, 'frozen_tree': tree,
                'report_sha256': hashlib.sha256(report_bytes).hexdigest()}
    raw = _git(root, ['diff', '--name-status', '-z', '--no-renames', reviewed_commit, head, '--']) or b''
    fields = raw.split(b'\x00')
    if fields[-1] != b'' or (len(fields) - 1) % 2:
        raise RuntimeError('review delta inventory is malformed')
    changed = []
    for index in range(0, len(fields) - 1, 2):
        status, raw_path = fields[index:index + 2]
        if status not in (b'A', b'M'):
            raise RuntimeError('review delta contains deletion, rename or unsupported status')
        path = raw_path.decode('utf-8', 'strict')
        regular_report(path, head)
        if status == b'M':
            old_entry = _git(root, ['ls-tree', '-z', reviewed_commit, '--', path]) or b''
            if not old_entry.startswith(b'100644 blob '):
                raise RuntimeError('review delta changes an unsafe prior report entry')
        changed.append(path)
    return {
        'contract': 'getzilla.review-source/v1',
        **context_claim,
        'route_id': route_id,
        'report_namespace': report.rsplit('/', 1)[0],
        'reviewed_commit': reviewed_commit,
        'reviewed_tree': (_git(root, ['rev-parse', reviewed_commit + '^{tree}']) or b'').decode('ascii').strip(),
        'frozen_commit': head,
        'frozen_tree': (_git(root, ['rev-parse', head + '^{tree}']) or b'').decode('ascii').strip(),
        'report_paths': sorted(changed),
        'report_sha256': hashlib.sha256(report_bytes).hexdigest(),
    }
