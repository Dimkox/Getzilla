"""Exact reviewed BuildKit distribution; ephemeral runtime only, no system install.

Release API asset digest and size are part of the selected producer source.
Caller JSON is never a tool pin authority. Only three regular archive members
can become executables; BuildKit takes its own private copy before execution.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import platform
import re
import tarfile
import time

from .security_artifacts import read_file
from .security_oci import canonical

VERSION = '0.35.0'
ARCHIVE_SIZE = 94617951
ARCHIVE_SHA256 = '37b3befbed28fb72a44d72bf42362c268610386c42feafa27cb45ee0b531369c'
URL = f'https://github.com/moby/buildkit/releases/download/v{VERSION}/buildkit-v{VERSION}.linux-amd64.tar.gz'
TOOLS = frozenset({'buildkitd', 'buildctl', 'buildkit-runc'})


def extract_tools(archive, destination):
    destination = Path(destination)
    destination.mkdir(mode=0o700)
    found, total, count = {}, 0, 0
    with tarfile.open(fileobj=archive, mode='r|gz') if hasattr(archive, 'read') else tarfile.open(archive, 'r|gz') as stream:
        for member in stream:
            count += 1
            total += member.size
            if count > 1000 or member.size < 0 or total > 512 * 1024 * 1024:
                raise ValueError('BuildKit archive exceeds finite member/expanded-byte bound')
            if member.isdir() and member.name.rstrip('/') == 'bin':
                continue
            if not member.isfile() or not re.fullmatch(r'bin/[A-Za-z0-9._-]+', member.name):
                raise ValueError('BuildKit archive has a link or unsafe member')
            name = member.name.removeprefix('bin/')
            if name not in TOOLS:
                continue
            if name in found or not 0 < member.size <= 128 * 1024 * 1024:
                raise ValueError('BuildKit tool is duplicate or outside finite byte bound')
            source = stream.extractfile(member)
            if source is None:
                raise ValueError('BuildKit tool member unavailable')
            measured = hashlib.sha256()
            fd = os.open(destination / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o500)
            copied = 0
            with source, os.fdopen(fd, 'wb') as target:
                while copied < member.size:
                    value = source.read(min(65536, member.size - copied))
                    if not value:
                        raise ValueError('BuildKit tool member is truncated')
                    target.write(value)
                    measured.update(value)
                    copied += len(value)
            found[name] = dict(path=str(destination / name), sha256=measured.hexdigest())
    if set(found) != TOOLS:
        raise ValueError('BuildKit distribution lacks required fixed tools')
    return found


def archive_bytes(path):
    path = Path(path)
    raw = read_file(path.parent, path.name, ARCHIVE_SIZE)
    if len(raw) != ARCHIVE_SIZE or hashlib.sha256(raw).hexdigest() != ARCHIVE_SHA256:
        raise ValueError('BuildKit distribution differs from selected producer source pin')
    return raw


def provision(destination):
    """Execute only on the selected ephemeral runner, before the guarded job."""
    from .security_image_registry import BoundedHTTP
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ValueError('pinned BuildKit provisioning requires ephemeral Linux x86_64')
    destination = Path(destination).absolute()
    destination.mkdir(mode=0o700)  # Existing state refuses; no overwrite/retry.
    uid, gid = int(os.environ.get('SUDO_UID', os.getuid())), int(os.environ.get('SUDO_GID', os.getgid()))
    if os.geteuid() == 0:
        os.chown(destination, uid, gid)  # Runner can remove its private regular artifacts after the job.
    archive = destination / 'buildkit.tar.gz'
    _, raw = BoundedHTTP(deadline=time.monotonic() + 65).get(URL, {}, ARCHIVE_SIZE)
    if len(raw) != ARCHIVE_SIZE or hashlib.sha256(raw).hexdigest() != ARCHIVE_SHA256:
        raise ValueError('bounded pinned BuildKit download incomplete')
    fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
    body = dict(schema_version=1, version=VERSION, archive=str(archive), sha256=ARCHIVE_SHA256, bytes=ARCHIVE_SIZE)
    fd = os.open(destination / 'toolchain.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(canonical(body))
    return body
