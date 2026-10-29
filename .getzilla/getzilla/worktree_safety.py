"""Which Getzilla worktrees can go, and a guarded removal that keeps unique work (#168, story 4).

A worktree is removable only when all of these hold: it sits under the main worktree's
`.getzilla/runtime/worktrees` (no folder on that path is a symlink), Git has it unlocked, no rebase,
merge, cherry-pick, revert or bisect is in progress, it has no tracked, staged or untracked change,
no file carries an assume-unchanged bit and no file that exists carries a skip-worktree bit (Git
hides edits to both), every ignored file in it is reproducible output, every commit its HEAD,
per-worktree refs and HEAD reflog reach is also reachable from a remote-tracking ref, and no
process has its working folder inside it. Any check that cannot run keeps the worktree.

Removal inspects again right before it acts and uses `git worktree remove` without --force. Git
deletes ignored files without asking, so a file written after that last inspection is lost; the
window is one process scan plus one Git call. Remote-tracking refs are read as they are: after a
`fetch --prune` drops a ref, commits that only it reached count as local and the worktree stays.
Nothing here fetches, pushes or deletes a branch.
"""
from __future__ import annotations

import os
import stat
import subprocess
import time
from pathlib import Path
from typing import Any

from .resource_inventory import RUNTIME, classify

WORKTREES = RUNTIME + '/worktrees'
IN_PROGRESS = ('rebase-merge', 'rebase-apply', 'MERGE_HEAD', 'CHERRY_PICK_HEAD', 'REVERT_HEAD', 'BISECT_LOG', 'sequencer')
MAX_IGNORED_FILES = 10_000
MAX_REFLOG = 2_000
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
    path = worktree / relative
    kind = classify(worktree, path)
    if kind == 'protected' or not stat.S_ISREG(path.lstat().st_mode):
        return False
    # Cache directory names do not establish ownership of their contents. Keep the existing
    # ordinary bytecode exemption only after protection and file-type checks.
    return relative.endswith('.pyc') or kind == 'ephemeral'


def _valuable_ignored(worktree: Path, ignored: list[str]) -> list[str]:
    """Ignored files that are not reproducible output; a file Git lists as a folder is opened up."""
    found: list[str] = []
    seen = 0
    for relative in ignored:
        if _disposable(worktree, relative):
            continue
        folder = worktree / relative
        if not (relative.endswith('/') and folder.is_dir() and not folder.is_symlink()):
            found.append(relative)
        else:
            for base, dirs, files in os.walk(folder):
                links = [name for name in dirs if os.path.islink(os.path.join(base, name))]  # walk lists them as folders
                dirs[:] = [name for name in dirs if name not in links]
                for name in [*files, *links]:
                    seen += 1
                    if seen > MAX_IGNORED_FILES:
                        return [*found[:MAX_LISTED - 1], f'(more than {MAX_IGNORED_FILES} ignored files; not all checked)']
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


def _hidden_from_status(worktree: Path) -> list[str]:
    """Tracked files whose edits `git status` cannot see: assume-unchanged, or skip-worktree on disk."""
    hidden: list[str] = []
    for field in _git(worktree, 'ls-files', '-v', '-z').split(b'\0'):
        if len(field) < 3:
            continue
        tag, path = chr(field[0]), field[2:].decode('utf-8', errors='surrogateescape')
        # A sparse checkout marks files it leaves out with S; only a skip-worktree file on disk can hold edits.
        if tag.islower() or (tag == 'S' and os.path.lexists(worktree / path)):
            hidden.append(path)
            if len(hidden) >= MAX_LISTED:
                break
    return hidden


def _in_progress(worktree: Path) -> list[str]:
    git_dir = Path(_git(worktree, 'rev-parse', '--absolute-git-dir').decode('utf-8', errors='surrogateescape').strip())
    return [name for name in IN_PROGRESS if os.path.lexists(git_dir / name)]


def _local_only(worktree: Path) -> bool:
    """True when HEAD, a per-worktree ref or the HEAD reflog reaches a commit no remote-tracking ref has."""
    tips = {'HEAD'}
    refs = _git(worktree, 'for-each-ref', '--format=%(objectname)', 'refs/worktree', 'refs/bisect')
    tips.update(refs.decode().split())
    reflog = _git(worktree, 'reflog', 'show', '--format=%H', f'-n{MAX_REFLOG + 1}', 'HEAD', '--').decode().split()
    if len(reflog) > MAX_REFLOG:
        return True  # not every entry can be checked; keep the worktree
    tips.update(reflog)
    return bool(_git(worktree, 'rev-list', '--max-count=1', *sorted(tips), '--not', '--remotes').strip())


def _started_at(entry: Path) -> float | None:
    """Process start time in epoch seconds from the world-readable /proc stat files."""
    try:
        fields = (entry / 'stat').read_text(encoding='utf-8', errors='surrogateescape').rsplit(')', 1)[1].split()
        boot = next(float(line.split()[1]) for line in Path('/proc/stat').read_text(encoding='ascii').splitlines()
                    if line.startswith('btime '))
        return boot + int(fields[19]) / os.sysconf('SC_CLK_TCK')
    except (OSError, ValueError, IndexError, StopIteration):
        return None


def _created_at(worktree: Path) -> float | None:
    """When Git registered the worktree, or None when that is not known.

    `git worktree add` writes `commondir` and `gitdir`; move and repair rewrite only `gitdir`, so the
    earlier of the two mtimes is used. A time in the future (the clock stepped back) is not trusted.
    """
    try:
        git_dir = Path(_git(worktree, 'rev-parse', '--absolute-git-dir').decode('utf-8', errors='surrogateescape').strip())
        created = min(os.stat(git_dir / 'gitdir').st_mtime, os.stat(git_dir / 'commondir').st_mtime)
    except (WorktreeError, OSError):
        return None
    return None if created > time.time() + 2 else created


def _in_use(path: Path, created: float | None = None) -> bool | None:
    """True when this or another process works inside `path`; None when that cannot be checked.

    A process of ours that hides its working folder (ssh-agent, a CI runner, a container init) counts
    as unknown only when it started after the worktree was created; an older process cannot have been
    started for it. Only the working folder is checked, not open files; other users' hidden processes
    are skipped.
    """
    target = os.path.realpath(path)

    def inside(value: str) -> bool:
        return value == target or value.startswith(target.rstrip(os.sep) + os.sep)

    if inside(os.path.realpath(os.getcwd())):
        return True
    processes = Path('/proc')
    if not (processes / 'self' / 'cwd').exists():
        return None
    unknown = False
    uid = os.getuid()
    for entry in processes.iterdir():
        if entry.name.isdigit():
            try:
                if inside(os.readlink(entry / 'cwd')):
                    return True
            except (FileNotFoundError, ProcessLookupError):
                continue  # the process ended
            except OSError:
                try:
                    if entry.stat().st_uid != uid:
                        continue
                except OSError:
                    continue
                started = _started_at(entry)
                if created is None or started is None or started >= created - 2:  # 2 s for clock tick rounding
                    unknown = True
    return None if unknown else False


def inspect(root: Path, entry: dict[str, Any], main: str) -> dict[str, Any]:
    """`main` is the main worktree (Git lists it first); task worktrees live under its runtime folder."""
    path = Path(entry['path'])
    report: dict[str, Any] = {'path': str(path), 'branch': entry.get('branch'), 'head': entry.get('head'),
                              'detached': bool(entry.get('detached')), 'removable': False, 'reasons': []}
    reasons: list[str] = report['reasons']
    if classify(Path(main), Path(main) / WORKTREES) != 'protected':
        reasons.append('the worktrees folder or a folder above it is a symlink')
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
        operations = _in_progress(path)
        changed, untracked, ignored = _status(path)
        hidden = _hidden_from_status(path)
        valuable = _valuable_ignored(path, ignored)
        local_only = _local_only(path)
    except (WorktreeError, OSError, subprocess.SubprocessError, UnicodeDecodeError) as exc:
        reasons.append(f'check failed: {exc}')
        return report
    report.update(changed=changed, untracked=untracked, hidden_from_status=hidden, valuable_ignored=valuable,
                  local_only_commits=local_only, in_progress=operations)
    if operations:
        reasons.append('operation in progress: ' + ', '.join(operations))
    if changed:
        reasons.append(f'{changed} tracked or staged change(s)')
    if untracked:
        reasons.append(f'{untracked} untracked file(s)')
    if hidden:
        reasons.append('files with assume-unchanged or skip-worktree bits: ' + ', '.join(hidden[:5]))
    if valuable:
        reasons.append('ignored files that are not reproducible: ' + ', '.join(valuable[:5]))
    if local_only:
        reasons.append('commits not on any remote-tracking ref')
    busy = _in_use(path, _created_at(path))
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
