"""Read-only inventory of Getzilla resources and the guard every later cleanup must pass (#168).

Each `.getzilla/runtime` entry gets one class: `protected` (state, approvals, receipts, evidence,
worktrees), `ephemeral` (output Getzilla can recreate) or `unknown`. Unknown is never disposable.
A `..` part, a linked `.getzilla` or runtime folder, or a symlink below it makes the entry unknown.
The inventory does not read a linked `.getzilla` or runtime folder at all and reports itself incomplete.
Nothing in this module deletes. `disposable()` is a path check, not a lock: a deleting caller must
re-check each part through held directory descriptors (`O_NOFOLLOW`, `dir_fd`) and must skip
entries a live run still owns, such as `par/<stamp>-<pid>` while that pid runs.
"""
from __future__ import annotations

import os
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any

RUNTIME = '.getzilla/runtime'
PROTECTED = frozenset({
    '.agents.guard', '.gitignore', '.gitkeep', 'active-change.json', 'active-route.json', 'agent-state.json',
    'approvals.json', 'audit', 'changes', 'checkpoints', 'evidence', 'handoff.json', 'hook-events.jsonl',
    'last-fingerprint.json', 'last-session-end.json', 'metrics.jsonl', 'owner-autonomy', 'parallel-guard.json',
    'path-hints.json', 'receipts', 'reviews', 'routes', 'sessions', 'startup-capacity.json', 'stop-attempts.json',
    'tool-denials.json', 'workflow-cas',
    # Git safety checks for worktrees arrive with their own deletion story; until then they stay.
    'worktrees',
})
EPHEMERAL = frozenset({'par'})  # parallel-runner logs; `getzilla par` recreates them on every run
# Temporary directories Getzilla creates in the system temp folder. They carry no owner record yet,
# so a live run cannot be told from a crashed one: they are inventoried as unknown.
TEMP_PREFIXES = ('grok-core-parallel-', 'grok-named-smoke-', 'grok-trust-tests-', 'grok-legacy-coverage-',
                 'getzilla-', 'adaptive-architecture-object-', 'adaptive-line-stat-')
MAX_ENTRIES = 200_000
# A folder that holds all three is a copy of a Getzilla repository, most often a review snapshot.
COPY_MARKERS = frozenset({'AGENTS.md', 'scripts', 'engineering'})
COPY_ROOTS = ('archive', 'scratch', 'reviews')
MAX_COPY_DEPTH = 4


def classify(root: Path, path: Path) -> str:
    """The class of `path`; anything outside the runtime folder, odd or linked is `unknown`."""
    if '..' in Path(path).parts:
        return 'unknown'  # `link/..` collapses as text but the OS resolves it through the link
    runtime = Path(os.path.abspath(root / RUNTIME))
    target = Path(os.path.abspath(path))
    if target == runtime:
        return 'protected'
    if runtime not in target.parents:
        return 'unknown'
    for folder in (runtime.parent, runtime):
        try:
            if stat.S_ISLNK(os.lstat(folder).st_mode):
                return 'unknown'
        except OSError:
            return 'unknown'
    current = runtime
    for part in target.relative_to(runtime).parts:
        current = current / part
        try:
            if stat.S_ISLNK(os.lstat(current).st_mode):
                return 'unknown'
        except FileNotFoundError:
            break
        except OSError:
            return 'unknown'
    top = target.relative_to(runtime).parts[0]
    if top in PROTECTED or (top.startswith('.') and top.endswith('.lock')):  # state.runtime_lock files
        return 'protected'
    return 'ephemeral' if top in EPHEMERAL else 'unknown'


def disposable(root: Path, path: Path) -> bool:
    """True only for ephemeral entries. Deletion code calls this immediately before it deletes."""
    return classify(root, path) == 'ephemeral'


def measure(path: Path, budget: int = MAX_ENTRIES) -> dict[str, Any]:
    """Apparent bytes and entry count without following links; `complete` is False past the budget."""
    try:
        info = os.lstat(path)
    except OSError:
        return {'bytes': 0, 'entries': 0, 'complete': False}
    size, entries, complete = info.st_size, 1, True
    if not stat.S_ISDIR(info.st_mode):
        return {'bytes': size, 'entries': entries, 'complete': True}
    pending = [str(path)]
    while pending:
        try:
            with os.scandir(pending.pop()) as listing:
                for item in listing:
                    if entries >= budget:
                        return {'bytes': size, 'entries': entries, 'complete': False}
                    entries += 1
                    try:
                        size += item.stat(follow_symlinks=False).st_size
                        if item.is_dir(follow_symlinks=False):
                            pending.append(item.path)
                    except OSError:
                        complete = False
        except OSError:
            complete = False
    return {'bytes': size, 'entries': entries, 'complete': complete}


def _linked_runtime(root: Path) -> bool:
    """A linked `.getzilla` or runtime folder points the inventory at another tree: it is not read."""
    return os.path.islink(root / '.getzilla') or os.path.islink(root / RUNTIME)


def repository_copies(root: Path, depth: int = MAX_COPY_DEPTH,
                      budget: int = MAX_ENTRIES) -> tuple[list[dict[str, Any]], bool]:
    """Repository copies under the runtime folders agents write snapshots to, and whether the search
    and every size are complete. One entry budget covers the search and all sizes. Links are not
    followed, and a copy is not searched for nested copies. The copies stay `unknown`: nothing proves
    them disposable."""
    runtime = root / RUNTIME
    found: list[dict[str, Any]] = []
    if _linked_runtime(root):
        return found, False
    complete = True
    for top in COPY_ROOTS:
        if os.path.islink(runtime / top):
            complete = False
            continue
        if not (runtime / top).is_dir():
            continue
        pending = [(runtime / top, 0)]
        while pending:
            folder, level = pending.pop()
            try:
                with os.scandir(folder) as listing:
                    entries = list(listing)
                names = {entry.name for entry in entries}
                children = [Path(entry.path) for entry in entries if entry.is_dir(follow_symlinks=False)]
            except OSError:
                complete = False
                continue
            if COPY_MARKERS <= names:  # its own entries are counted once, by its size
                size = measure(folder, budget)
                budget -= size['entries']
                complete = complete and size['complete']
                found.append({'path': folder.relative_to(root).as_posix(), **size})
                continue
            budget -= len(entries)
            if budget < 0:
                return sorted(found, key=lambda item: item['path']), False
            if level < depth:
                pending.extend((child, level + 1) for child in children)
    return sorted(found, key=lambda item: item['path']), complete


def _disk(path: Path) -> dict[str, int] | None:
    try:
        usage = shutil.disk_usage(path)
    except OSError:
        return None
    return {'total': usage.total, 'used': usage.used, 'free': usage.free}


def inventory(root: Path, temp_dir: Path | None = None) -> dict[str, Any]:
    """Every runtime entry and every Getzilla-named temp directory, with class and measured size."""
    runtime = root / RUNTIME
    temp = Path(temp_dir or tempfile.gettempdir())
    resources: list[dict[str, Any]] = []
    linked = _linked_runtime(root)
    try:
        names = [] if linked else sorted(os.listdir(runtime))
    except OSError:
        names = []
    for name in names:
        path = runtime / name
        resources.append({'location': 'runtime', 'name': name, 'class': classify(root, path), **measure(path)})
    try:
        temp_names = sorted(name for name in os.listdir(temp) if name.startswith(TEMP_PREFIXES))
    except OSError:
        temp_names = []
    for name in temp_names:
        resources.append({'location': 'temp', 'name': name, 'class': 'unknown', **measure(temp / name)})
    totals: dict[str, dict[str, int]] = {}
    for item in resources:
        group = totals.setdefault(item['class'], {'resources': 0, 'bytes': 0})
        group['resources'] += 1
        group['bytes'] += item['bytes']
    copies, copies_complete = repository_copies(root)
    return {'schema_version': 'getzilla-resource-inventory-v1', 'runtime': str(runtime), 'temp': str(temp),
            'resources': resources, 'totals': totals, 'repository_copies': copies,
            'complete': copies_complete and all(item['complete'] for item in resources),
            'disk': {'runtime': _disk(runtime if runtime.exists() else root), 'temp': _disk(temp)},
            'deleted': 0}
