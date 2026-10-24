"""Which Getzilla worktrees can go, and a guarded removal that keeps unique work (#168, story 4).

A worktree is removable only when all of these hold: it sits under `.getzilla/runtime/worktrees`,
Git has it unlocked, it has no tracked, staged or untracked change, every ignored file in it is
reproducible output, its HEAD is reachable from a remote-tracking ref, and no process works in it.
Any check that cannot run keeps the worktree. Removal inspects again right before it acts and uses
`git worktree remove` without --force, which itself refuses a tree with changes or untracked files.
Remote-tracking refs are read as they are; nothing here fetches, pushes or deletes a branch.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

from .resource_inventory import RUNTIME, classify

WORKTREES = RUNTIME + '/worktrees'
DISPOSABLE_PARTS = frozenset({'__pycache__', '.pytest_cache', '.ruff_cache', '.mypy_cache'})
MAX_IGNORED_FILES = 10_000
MAX_LISTED = 20
TIMEOUT = 60


class WorktreeError(RuntimeError):
    pass


def _git(cwd: Path, *args: str) -> bytes:
    try:
        done = subprocess.run(['git', '-C', str(cwd), *args], capture_output=True, timeout=TIMEOUT, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise WorktreeError(f'git {args[0]}: {type(exc).__name__}') from exc
    if done.returncode != 0:
        detail = done.stderr.decode('utf-8', errors='replace').strip()[:200]
        raise WorktreeError(f'git {args[0]} exited {done.returncode}: {detail}')
    return done.stdout


def list_worktrees(root: Path) -> list[dict[str, Any]]:
    """`git worktree list --porcelain -z` as dicts: path, head, branch and the flags Git reports."""
    entries: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    for field in _git(root, 'worktree', 'list', '--porcelain', '-z').split(b'\0'):
        if not field:
            if current:
                entries.append(current)
                current = {}
            continue
        key, _, value = field.decode('utf-8', errors='surrogateescape').partition(' ')
        if key == 'worktree':
            current = {'path': value}
        elif key in {'HEAD', 'branch'}:
            current[key.lower()] = value
        elif key in {'detached', 'bare', 'locked', 'prunable'}:
            current[key] = value or True
    if current:
        entries.append(current)
    return entries


def _disposable(worktree: Path, relative: str) -> bool:
    if DISPOSABLE_PARTS & set(Path(relative).parts) or relative.endswith('.pyc'):
        return True
    return classify(worktree, worktree / relative) == 'ephemeral'


def _valuable_ignored(worktree: Path, ignored: list[str]) -> list[str]:
    """Ignored files that are not reproducible output; a file Git lists as a folder is opened up."""
    found: list[str] = []
    seen = 0
    for relative in ignored:
        if _disposable(worktree, relative.rstrip('/')):
            continue
        folder = worktree / relative
        if not (relative.endswith('/') and folder.is_dir() and not folder.is_symlink()):
            found.append(relative)
        else:
            for base, dirs, files in os.walk(folder):
                links = [name for name in dirs if os.path.islink(os.path.join(base, name))]  # walk lists them as folders
                dirs[:] = [name for name in dirs if name not in DISPOSABLE_PARTS and name not in links]
                for name in [*files, *links]:
                    seen += 1
                    if seen > MAX_IGNORED_FILES:
                        return [*found, f'(more than {MAX_IGNORED_FILES} ignored files; not all checked)']
                    inner = os.path.relpath(os.path.join(base, name), worktree).replace(os.sep, '/')
                    if not _disposable(worktree, inner):
                        found.append(inner)
        if len(found) >= MAX_LISTED:
            break
    return found[:MAX_LISTED]


def _status(worktree: Path) -> tuple[int, int, list[str]]:
    raw = _git(worktree, 'status', '--porcelain=v1', '-z', '--untracked-files=all', '--ignored=matching')
    fields = raw.split(b'\0')
    changed = untracked = 0
    ignored: list[str] = []
    index = 0
    while index < len(fields):
        field = fields[index].decode('utf-8', errors='surrogateescape')
        index += 1
        if not field:
            continue
        code, path = field[:2], field[3:]
        if code == '??':
            untracked += 1
        elif code == '!!':
            ignored.append(path)
        else:
            changed += 1
            if code[0] in 'RC':
                index += 1  # the original path of a rename or copy follows
    return changed, untracked, ignored


def _in_use(path: Path) -> bool | None:
    """True when this or another process works inside `path`; None when that cannot be checked."""
    target = os.path.realpath(path)

    def inside(value: str) -> bool:
        return value == target or value.startswith(target.rstrip(os.sep) + os.sep)

    if inside(os.path.realpath(os.getcwd())):
        return True
    processes = Path('/proc')
    if not (processes / 'self' / 'cwd').exists():
        return None
    for entry in processes.iterdir():
        if entry.name.isdigit():
            try:
                if inside(os.readlink(entry / 'cwd')):
                    return True
            except OSError:
                continue
    return False


def inspect(root: Path, entry: dict[str, Any], main: str) -> dict[str, Any]:
    """`main` is the main worktree (Git lists it first); task worktrees live under its runtime folder."""
    path = Path(entry['path'])
    report: dict[str, Any] = {'path': str(path), 'branch': entry.get('branch'), 'head': entry.get('head'),
                              'detached': bool(entry.get('detached')), 'removable': False, 'reasons': []}
    reasons: list[str] = report['reasons']
    base = Path(os.path.realpath(Path(main) / WORKTREES))
    real = Path(os.path.realpath(path))
    if base not in real.parents:
        reasons.append('outside .getzilla/runtime/worktrees')
    if real == Path(os.path.realpath(root)):
        reasons.append('the current worktree')
    for flag, text in (('bare', 'bare repository'), ('locked', 'locked by git worktree lock'),
                       ('prunable', 'missing on disk; `git worktree prune` handles it')):
        if entry.get(flag):
            reasons.append(text)
    if reasons:
        return report
    try:
        changed, untracked, ignored = _status(path)
        valuable = _valuable_ignored(path, ignored)
        local_only = bool(_git(path, 'rev-list', '--max-count=1', 'HEAD', '--not', '--remotes').strip())
    except (WorktreeError, OSError) as exc:
        reasons.append(f'check failed: {exc}')
        return report
    report.update(changed=changed, untracked=untracked, valuable_ignored=valuable, local_only_commits=local_only)
    if changed:
        reasons.append(f'{changed} tracked or staged change(s)')
    if untracked:
        reasons.append(f'{untracked} untracked file(s)')
    if valuable:
        reasons.append('ignored files that are not reproducible: ' + ', '.join(valuable[:5]))
    if local_only:
        reasons.append('commits not on any remote-tracking ref')
    busy = _in_use(path)
    if busy is None:
        reasons.append('cannot check for running processes on this platform')
    elif busy:
        reasons.append('a process works in it')
    report['removable'] = not reasons
    return report


def plan(root: Path) -> dict[str, Any]:
    entries = list_worktrees(root)
    reports = [inspect(root, entry, entries[0]['path']) for entry in entries]
    return {'schema_version': 'getzilla-worktree-plan-v1', 'worktrees': reports,
            'removable': sum(item['removable'] for item in reports), 'kept': sum(not item['removable'] for item in reports)}


def remove(root: Path, path: str) -> dict[str, Any]:
    """Inspect `path` again and remove it only if it is still removable. Safe to repeat."""
    wanted = os.path.realpath(path)
    entries = list_worktrees(root)
    entry = next((item for item in entries if os.path.realpath(item['path']) == wanted), None)
    if entry is None:
        return {'path': path, 'result': 'absent'}
    report = inspect(root, entry, entries[0]['path'])
    if not report['removable']:
        return {**report, 'result': 'kept'}
    try:
        _git(root, 'worktree', 'remove', entry['path'])
    except WorktreeError as exc:
        return {**report, 'result': 'error', 'error': str(exc)}
    return {**report, 'result': 'removed'}
