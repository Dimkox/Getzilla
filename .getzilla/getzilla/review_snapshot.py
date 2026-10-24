"""Review snapshots that do not pile up (#168, step 5).

A reviewer probes a private copy of the exact candidate commit. `create` makes that copy as a
detached Git worktree under the main worktree's `.getzilla/runtime/snapshots` (mode 0700), so it
shares the object store instead of copying it, and writes an owner marker next to it. `remove`
deletes it again once the report is returned. Edits inside a snapshot are reviewer probes and are
discarded on purpose; reports never live in a snapshot.

`remove` acts only on a direct child of that folder (no symlink on the way) whose marker names the
commit the worktree is still detached at. Anything else is kept.
"""
from __future__ import annotations

import json
import os
import secrets
import time
from pathlib import Path
from typing import Any

from .resource_inventory import RUNTIME
from .worktree_safety import WorktreeError, _git, list_worktrees

SNAPSHOTS = RUNTIME + '/snapshots'
SCHEMA = 'getzilla-review-snapshot-v1'


def _base(root: Path) -> Path:
    """The snapshots folder of the main worktree; refuses a link anywhere from `.getzilla` down."""
    main = Path(list_worktrees(root)[0]['path'])
    current = main
    for part in Path(SNAPSHOTS).parts:
        current = current / part
        if current.is_symlink():
            raise WorktreeError(f'{current} is a symlink')
    return current


def create(root: Path, revision: str) -> Path:
    commit = _git(root, 'rev-parse', '--verify', '--end-of-options', revision + '^{commit}').decode().strip()
    base = _base(root)
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(base, 0o700)
    name = f'{commit[:12]}-{secrets.token_hex(3)}'
    path = base / name
    marker = base / f'{name}.json'
    marker.write_text(json.dumps({'schema_version': SCHEMA, 'commit': commit, 'created_at': time.time(),
                                  'pid': os.getpid()}) + '\n', encoding='utf-8', newline='\n')
    try:
        _git(root, 'worktree', 'add', '--quiet', '--detach', str(path), commit)
    except WorktreeError:
        marker.unlink(missing_ok=True)
        raise
    return path


def _marker(base: Path, name: str) -> dict[str, Any] | None:
    try:
        data = json.loads((base / f'{name}.json').read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and data.get('schema_version') == SCHEMA else None


def remove(root: Path, path: str) -> dict[str, Any]:
    """Remove one snapshot made by `create`. Safe to repeat; anything not ours is kept."""
    base = _base(root)
    target = Path(os.path.abspath(path))
    if target.parent != Path(os.path.abspath(base)) or target.name.endswith('.json'):
        return {'path': path, 'result': 'kept', 'reason': 'not a direct child of .getzilla/runtime/snapshots'}
    if target.is_symlink() or Path(os.path.realpath(target)).parent != Path(os.path.realpath(base)):
        return {'path': path, 'result': 'kept', 'reason': 'the snapshot path is a symlink'}  # remove would follow it
    marker = _marker(base, target.name)
    entry = next((item for item in list_worktrees(root)
                  if os.path.abspath(item['path']) == str(target)), None)
    if entry is None:
        if marker is not None and not os.path.lexists(target):
            (base / f'{target.name}.json').unlink(missing_ok=True)
            return {'path': path, 'result': 'absent'}
        return {'path': path, 'result': 'kept', 'reason': 'not a registered snapshot worktree'}
    if marker is None:
        return {'path': path, 'result': 'kept', 'reason': 'no owner marker'}
    if not entry.get('detached') or entry.get('head') != marker.get('commit') or entry.get('locked'):
        return {'path': path, 'result': 'kept', 'reason': 'not detached at the marked commit, or locked'}
    try:
        _git(root, 'worktree', 'remove', '--force', str(target))
    except WorktreeError as exc:
        return {'path': path, 'result': 'error', 'error': str(exc)}
    (base / f'{target.name}.json').unlink(missing_ok=True)
    return {'path': path, 'result': 'removed', 'commit': marker['commit']}
