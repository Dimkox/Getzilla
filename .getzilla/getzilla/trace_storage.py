"""Read-only OS-owner custody for the classic local journal, not customer ACLs."""
from __future__ import annotations

import os
import stat
import threading
from pathlib import Path


class ReadUnavailable(ValueError):
    def __init__(self):
        super().__init__('local observations unavailable')


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class LocalRead:
    """A live kernel-CWD anchor and retained, checked descendant descriptors."""
    def __init__(self, root):
        self.root = os.path.abspath(os.fspath(root))
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.owner_thread = threading.current_thread()
        self.uid = os.geteuid() if hasattr(os, 'geteuid') else None
        self.handles = []
        self.closed = False
        try:
            if os.name != 'posix' or self.uid is None or os.getuid() != self.uid:
                raise ReadUnavailable()
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            descriptor = os.open('.', flags)
            info = os.fstat(descriptor)
            self.handles.append((descriptor, _identity(info), None, None))
            self._directory(info)
            if os.getcwd() != self.root or os.path.realpath(self.root) != self.root:
                raise ReadUnavailable()
            self.check()
        except (OSError, ValueError):
            self.close()
            raise ReadUnavailable() from None

    def _directory(self, info, private=False):
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.uid
                or info.st_mode & 0o022 or private and stat.S_IMODE(info.st_mode) != 0o700):
            raise ReadUnavailable()

    def check(self):
        if (self.closed or os.getpid() != self.pid or threading.get_ident() != self.thread
                or threading.current_thread() is not self.owner_thread):
            raise ReadUnavailable()
        try:
            if os.geteuid() != self.uid or os.getuid() != self.uid:
                raise ReadUnavailable()
            anchor = self.handles[0]
            if _identity(os.stat(self.root, follow_symlinks=False)) != anchor[1]:
                raise ReadUnavailable()
            for descriptor, identity, parent, name in self.handles:
                if _identity(os.fstat(descriptor)) != identity:
                    raise ReadUnavailable()
                if parent is not None and _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != identity:
                    raise ReadUnavailable()
        except OSError:
            raise ReadUnavailable() from None

    def check_root(self, root):
        if os.path.abspath(os.fspath(root)) != self.root:
            raise ReadUnavailable()
        self.check()

    def open_regular(self, relative, maximum):
        if relative not in {'.getzilla/runtime/metrics.jsonl', '.getzilla/runtime/path-hints.json',
                            '.getzilla/runtime/parallel-guard.json'}:
            raise ReadUnavailable()
        self.check()
        parent = self.handles[0][0]
        parts = relative.split('/')
        try:
            for name in parts[:-1]:
                descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                info = os.fstat(descriptor)
                self.handles.append((descriptor, _identity(info), parent, name))
                self._directory(info, private=name == 'runtime')
                parent = descriptor
            descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
            info = os.fstat(descriptor)
            self.handles.append((descriptor, _identity(info), parent, parts[-1]))
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.uid or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > maximum):
                raise ReadUnavailable()
            self.check()
            return descriptor
        except OSError:
            raise ReadUnavailable() from None

    def read(self, relative, maximum):
        descriptor = self.open_regular(relative, maximum)
        try:
            chunks, size = [], 0
            while True:
                self.check()
                chunk = os.read(descriptor, min(65536, maximum + 1 - size))
                self.check()
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > maximum:
                    raise ReadUnavailable()
            self.check()
            return b''.join(chunks)
        except OSError:
            raise ReadUnavailable() from None

    def git_location(self):
        self.check()
        descriptor = self.handles[0][0]
        address = Path(f'/proc/self/fd/{descriptor}')
        try:
            if _identity(address.stat()) != self.handles[0][1]:
                raise ReadUnavailable()
        except OSError:
            raise ReadUnavailable() from None
        return address, (descriptor,)

    def close(self):
        if self.closed:
            return
        self.closed = True
        for descriptor, identity, _, _ in reversed(self.handles):
            try:
                # Cleanup is not admission: a changed owned file must close.
                # Same-process hostile reopen of the SAME inode is outside
                # this local reader's proof; no OFD/OS isolation is asserted.
                current = os.fstat(descriptor)
                if (current.st_dev, current.st_ino, current.st_uid, stat.S_IFMT(current.st_mode)) == (
                        identity[0], identity[1], identity[2], stat.S_IFMT(identity[3])):
                    os.close(descriptor)
            except OSError:
                pass
        self.handles.clear()

    def __enter__(self):
        self.check()
        return self

    def __exit__(self, *_):
        self.close()
