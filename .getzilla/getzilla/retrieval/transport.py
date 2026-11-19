"""Explicit plaintext subprocess transport; no source discovery or permissions.

The caller supplies ordinary text and an explicit local argv. This is not native
source/sink admission and cannot turn an unadmitted packet into an admitted one.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import tempfile

from .budget import RetrievalError

MAX_TEXT_BYTES = 262144


def deliver_text(text, argv, *, transport, scratch=None, timeout=30):
    if transport not in {'stdin', 'file'}:
        raise RetrievalError('unsupported_transport')
    if (type(text) is not str or len(text.encode('utf-8')) > MAX_TEXT_BYTES
            or type(argv) is not list or not argv or any(type(a) is not str or '\x00' in a for a in argv)
            or type(timeout) not in {int, float} or not 0 < timeout <= 60):
        raise RetrievalError('context_bytes_exceeded' if type(text) is str and len(text.encode('utf-8')) > MAX_TEXT_BYTES
                             else 'invalid_transport_request')
    try:
        if transport == 'stdin':
            if any('{context_file}' in arg for arg in argv):
                raise RetrievalError('unsupported_transport')
            return subprocess.run(argv, input=text.encode('utf-8'), timeout=timeout, check=False).returncode
        if scratch is None or sum(arg.count('{context_file}') for arg in argv) != 1:
            raise RetrievalError('unsupported_transport')
        parent = Path(os.path.abspath(scratch))
        current = Path(parent.anchor)
        for part in parent.parts[1:]:
            current /= part
            if current.is_symlink():
                raise RetrievalError('unsafe_transport_scratch')
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = parent.stat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
                or hasattr(os, 'geteuid') and info.st_uid != os.geteuid()):
            raise RetrievalError('unsafe_transport_scratch')
        # Unique private subdirectory prevents concurrent invocations from sharing
        # a prompt file. TemporaryDirectory removes it even on client failure.
        with tempfile.TemporaryDirectory(prefix='context-', dir=parent) as directory:
            path = Path(directory) / 'context.txt'
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'wb') as output:
                output.write(text.encode('utf-8'))
            command = [arg.replace('{context_file}', str(path)) for arg in argv]
            return subprocess.run(command, stdin=subprocess.DEVNULL, timeout=timeout, check=False).returncode
    except (OSError, subprocess.TimeoutExpired):
        raise RetrievalError('transport_unavailable') from None
