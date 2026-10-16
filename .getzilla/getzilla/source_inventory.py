"""Read-only inventory of a folder without Git (Zero-Git ingestion, step INVENTORIED).

The walk never follows links, never writes to the source, never imports or runs client code
and never keeps file contents: each regular file is opened through the identity its directory
entry had, hashed in a stream, and re-checked after the read. Limits and unreadable inputs are
blockers, never a silently truncated or skipped file.
"""
from __future__ import annotations

import fnmatch
import hashlib
import os
import stat
from pathlib import Path

from . import fsx
from .source_models import Exclusion, FilesystemCapabilities, Finding, IngestPolicy, SourceEntry, SourceInventory
from .source_paths import probe_filesystem, validate_paths

_CHUNK = 1024 * 1024
_READ_FLAGS = os.O_RDONLY | fsx.O_NOFOLLOW | fsx.O_NONBLOCK | fsx.O_CLOEXEC | fsx.O_NOCTTY


class _Stop(Exception):
    """A global limit was hit: the walk ends and the inventory is incomplete."""


def effective_executable_mode(policy: IngestPolicy) -> str:
    # Windows has no executable bit: the portable policy manifest is the only evidence there.
    return 'policy-manifest' if fsx.WINDOWS else policy.executable_mode


def excluded_by(path: str, policy: IngestPolicy) -> str | None:
    """The policy pattern that excludes `path` (or one of its parent directories)."""
    parts = path.split('/')
    candidates = ['/'.join(parts[:depth]) for depth in range(1, len(parts) + 1)]
    for pattern in sorted(policy.exclude):
        bare = pattern.rstrip('/')
        for candidate in candidates:
            if fnmatch.fnmatchcase(candidate, bare) or fnmatch.fnmatchcase(candidate, pattern):
                return pattern
    return None


def read_regular_file(parent: fsx.DirHandle, name: str, expected: os.stat_result, limit: int) -> tuple[bytes | None, str, int, str | None]:
    """Hash one regular file opened through its directory entry; return (content-or-None, sha, size, problem).

    Content is returned only when `limit` allows buffering; inventory passes keep=False semantics
    by discarding it. A file replaced or changed during the read is a problem, not a new file.
    """
    try:
        descriptor = fsx.open_at(parent, name, _READ_FLAGS)
    except PermissionError:
        return None, '', 0, 'UNREADABLE'
    except OSError:
        return None, '', 0, 'SOURCE_CHANGED_DURING_READ'
    try:
        before = os.fstat(descriptor)
        # Inode numbers are reused at once on Linux, so a file replaced between the directory
        # lookup and the open can keep (dev, ino): size and timestamps must match too.
        if (not stat.S_ISREG(before.st_mode)
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (expected.st_dev, expected.st_ino, expected.st_size, expected.st_mtime_ns)
                or (not fsx.WINDOWS and before.st_ctime_ns != expected.st_ctime_ns)):
            return None, '', 0, 'SOURCE_CHANGED_DURING_READ'
        if before.st_size > limit:
            return None, '', before.st_size, 'FILE_TOO_LARGE'
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, _CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                return None, '', total, 'FILE_TOO_LARGE'
            digest.update(chunk)
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (total != before.st_size or (after.st_size, after.st_mtime_ns, after.st_ino)
                != (before.st_size, before.st_mtime_ns, before.st_ino)):
            return None, '', total, 'SOURCE_CHANGED_DURING_READ'
        return b''.join(chunks), digest.hexdigest(), total, None
    finally:
        os.close(descriptor)


def inventory_source(root: Path, policy: IngestPolicy, capabilities: FilesystemCapabilities | None = None) -> SourceInventory:
    capabilities = capabilities or probe_filesystem(root)
    executable_mode = effective_executable_mode(policy)
    executable_paths = set(policy.executable_paths)
    entries: list[SourceEntry] = []
    excluded: list[Exclusion] = []
    blockers: list[Finding] = []
    empty = 0
    totals = {'files': 0, 'bytes': 0}
    try:
        root_handle = fsx.open_dir(root)
    except OSError:
        return SourceInventory((), (), (Finding(path='.', reason_code='SOURCE_ROOT_UNREADABLE_OR_LINK'),), capabilities)
    stack: list[tuple[fsx.DirHandle, str, int]] = [(root_handle, '', 0)]
    try:
        while stack:
            handle, prefix, depth = stack.pop()
            try:
                names = sorted(fsx.listdir(handle))
            except OSError:
                blockers.append(Finding(path=prefix.rstrip('/') or '.', reason_code='UNREADABLE_DIRECTORY'))
                fsx.close_dir(handle)
                continue
            if not names:
                empty += 1
            children: list[tuple[fsx.DirHandle, str, int]] = []
            for name in names:
                relative = f'{prefix}{name}'
                if name == '.git':
                    blockers.append(Finding(path=relative, reason_code='GIT_PRESENT' if not prefix else 'NESTED_GIT'))
                    continue
                pattern = excluded_by(relative, policy)
                if pattern is not None:
                    excluded.append(Exclusion(path=relative, reason_code='POLICY_EXCLUDED', policy_ref=f'exclude:{pattern}'))
                    continue
                try:
                    info = fsx.lstat_at(handle, name)
                except PermissionError:
                    blockers.append(Finding(path=relative, reason_code='UNREADABLE'))
                    continue
                except OSError:
                    blockers.append(Finding(path=relative, reason_code='SOURCE_CHANGED_DURING_READ'))
                    continue
                if fsx.is_link(info):
                    blockers.append(Finding(path=relative, reason_code='LINK_OR_REPARSE_POINT'))
                elif stat.S_ISDIR(info.st_mode):
                    if depth + 1 > policy.max_depth:
                        blockers.append(Finding(path=relative, reason_code='DEPTH_LIMIT'))
                        continue
                    try:
                        child = fsx.open_dir_at(handle, name)
                    except OSError:
                        blockers.append(Finding(path=relative, reason_code='UNREADABLE_DIRECTORY'))
                        continue
                    children.append((child, relative + '/', depth + 1))
                elif stat.S_ISREG(info.st_mode):
                    if getattr(info, 'st_nlink', 1) > 1:
                        blockers.append(Finding(path=relative, reason_code='HARDLINK_SHARED_IDENTITY'))
                        continue
                    totals['files'] += 1
                    if totals['files'] > policy.max_files:
                        blockers.append(Finding(path=relative, reason_code='LIMIT_FILES'))
                        raise _Stop
                    _content, digest, size, problem = read_regular_file(handle, name, info, policy.max_file_bytes)
                    del _content
                    if problem:
                        blockers.append(Finding(path=relative, reason_code=problem))
                        continue
                    totals['bytes'] += size
                    if totals['bytes'] > policy.max_total_bytes:
                        blockers.append(Finding(path=relative, reason_code='LIMIT_TOTAL_BYTES'))
                        raise _Stop
                    executable = (relative in executable_paths if executable_mode == 'policy-manifest'
                                  else bool(stat.S_IMODE(info.st_mode) & 0o111))
                    entries.append(SourceEntry(path=relative, executable=executable, size=size, sha256=digest))
                else:
                    blockers.append(Finding(path=relative, reason_code='SPECIAL_FILE'))
            fsx.close_dir(handle)
            stack.extend(reversed(children))
    except _Stop:
        pass
    finally:
        for handle, _prefix, _depth in stack:
            fsx.close_dir(handle)
    paths = validate_paths(entry.path for entry in entries)
    blockers.extend(paths.blockers)
    entries.sort(key=lambda entry: entry.path.encode('utf-8'))
    blockers.sort(key=lambda item: (item.path, item.reason_code))
    excluded.sort(key=lambda item: item.path)
    return SourceInventory(tuple(entries), tuple(excluded), tuple(blockers), capabilities, empty_directories=empty)
