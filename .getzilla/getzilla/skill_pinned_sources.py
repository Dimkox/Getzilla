"""Read bounded owned bytes from an exact upstream Git pin, without checkout execution."""
from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass
from pathlib import Path

from .architecture import ArchitectureError
from .architecture_diff import _git_command, _git_environment, _run_capped
from .component_state import path_parts

MAX_FILE_BYTES = 2097152
MAX_TOTAL_BYTES = 16777216
MAX_FILES = 4096
MAX_COMMIT_BYTES = 131072


@dataclass(frozen=True)
class PinnedTree:
    commit: str
    files: tuple[tuple[str, bytes], ...]
    semantic_safety_qualified: bool = False


def read_pinned_tree(root: Path, commit: str, *, prefixes=('skills/', 'LICENSE')) -> PinnedTree:
    if type(commit) is not str or not re.fullmatch(r'[a-f0-9]{40}', commit):
        raise ValueError('FULL_PIN_REQUIRED')
    if (type(prefixes) is not tuple or not 1 <= len(prefixes) <= 16
            or any(type(item) is not str or len(item) > 240 for item in prefixes)):
        raise ValueError('PINNED_PREFIX_BOUNDS')
    for prefix in prefixes:
        path_parts(prefix.rstrip('/'))
    deadline = time.monotonic() + 30
    env = _git_environment()
    env.update(GIT_NO_LAZY_FETCH='1', GIT_NO_REPLACE_OBJECTS='1')

    def git(arguments, limit, stdin=None):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError('PINNED_READ_DEADLINE')
        try:
            code, out, _error = _run_capped(
                _git_command(['-c', 'protocol.allow=never', *arguments], safe_directory=root),
                cwd=root, env=env, stdout_limit=limit, stderr_limit=1024,
                timeout=min(10, remaining), stdin_data=stdin)
        except (ArchitectureError, OSError) as exc:
            raise ValueError('PINNED_SOURCE_UNAVAILABLE') from exc
        if code:
            raise ValueError('PINNED_SOURCE_UNAVAILABLE')
        return out

    top = git(['rev-parse', '--show-toplevel'], 4096)
    if Path(top.decode('utf-8').strip()).resolve() != root.resolve():
        raise ValueError('PINNED_SOURCE_ROOT_MISMATCH')
    commit_bytes = git(['cat-file', 'commit', commit], MAX_COMMIT_BYTES)
    # Check bytes ourselves as well as disabling Git replacement refs.
    actual = hashlib.sha1(b'commit ' + str(len(commit_bytes)).encode() + b'\0' + commit_bytes,
                          usedforsecurity=False).hexdigest()
    if actual != commit:
        raise ValueError('PINNED_COMMIT_HASH_MISMATCH')
    raw = git(['ls-tree', '-r', '-z', '--full-tree', commit, '--', *prefixes], 1048576)
    records = raw.split(b'\0')
    if records[-1] != b'' or not 1 < len(records) <= MAX_FILES + 1:
        raise ValueError('PINNED_INVENTORY_BOUNDS')
    entries = []
    seen = set()
    for record in records[:-1]:
        try:
            metadata, raw_name = record.split(b'\t', 1)
            mode, kind, oid = metadata.split(b' ')
            name = raw_name.decode('utf-8')
            path_parts(name)
        except (ValueError, UnicodeError) as exc:
            raise ValueError('UNSAFE_PINNED_ENTRY') from exc
        if (mode not in (b'100644', b'100755') or kind != b'blob' or not re.fullmatch(b'[a-f0-9]{40}', oid)
                or name in seen or len(name) > 512 or len(name.split('/')) > 32
                or not any(name == prefix or name.startswith(prefix.rstrip('/') + '/') for prefix in prefixes)):
            raise ValueError('UNSAFE_PINNED_ENTRY')
        seen.add(name)
        entries.append((name, oid))
    request = b''.join(oid + b'\n' for _, oid in entries)
    output = git(['cat-file', '--batch'], MAX_TOTAL_BYTES + len(entries) * 128, request)
    offset, total, files = 0, 0, []
    for name, oid in entries:
        end = output.find(b'\n', offset)
        if end < 0:
            raise ValueError('PINNED_BLOB_TRUNCATED')
        header = output[offset:end].split(b' ')
        if len(header) != 3 or header[:2] != [oid, b'blob'] or not header[2].isdigit():
            raise ValueError('PINNED_BLOB_HEADER')
        size = int(header[2])
        total += size
        if size > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
            raise ValueError('PINNED_BLOB_BOUNDS')
        offset = end + 1
        content = output[offset:offset + size]
        if len(content) != size or output[offset + size:offset + size + 1] != b'\n':
            raise ValueError('PINNED_BLOB_TRUNCATED')
        actual = hashlib.sha1(b'blob ' + str(size).encode() + b'\0' + content, usedforsecurity=False).hexdigest().encode()
        if actual != oid:
            raise ValueError('PINNED_BLOB_HASH_MISMATCH')
        files.append((name, content))
        offset += size + 1
    if offset != len(output):
        raise ValueError('PINNED_BLOB_TRAILING_DATA')
    return PinnedTree(commit, tuple(files))
