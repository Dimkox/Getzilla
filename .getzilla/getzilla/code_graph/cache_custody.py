"""Bound, owned cache names. Namespace checks are not an OS isolation boundary."""
from __future__ import annotations

import contextlib
import errno
import os
import stat
import sys
import time
from pathlib import Path

from .. import fsx
from .models import GraphError


class CacheCustody:
    def __init__(self, path: Path, *, create: bool, private_parent: int | None = None):
        self.private_parent = private_parent
        self.path = Path(fsx.system_canonical(path))
        self.stack = contextlib.ExitStack()
        self.descriptor = None
        self.missing = False
        try:
            self._parents()
            root = self.stack.enter_context(fsx.ReadOnlyBoundRoot(Path(self.path.anchor)))
            relative = self.path.relative_to(self.path.anchor).as_posix()
            try:
                self.parent, self.name, self.check_parent = self.stack.enter_context(
                    root._parent(relative, create=create and private_parent is None, before_write=self._parents))
            except FileNotFoundError:
                if private_parent is not None:
                    raise GraphError('CACHE_PATH_CHANGED')
                self.missing = True
                return
            self._parents()
            if private_parent is not None and not os.path.samestat(os.fstat(private_parent), os.fstat(self.parent)):
                raise GraphError('CACHE_PATH_CHANGED')
            self.created = False
            try:
                info = fsx.lstat_at(self.parent, self.name)
            except FileNotFoundError:
                if not create:
                    self.missing = True
                    return
                self._create()
            else:
                self._file(info)
                self.descriptor = fsx.open_at(self.parent, self.name,
                    (os.O_RDWR if create else os.O_RDONLY) | fsx.O_NOFOLLOW | fsx.O_NONBLOCK | fsx.O_CLOEXEC)
                self.identity = (info.st_dev, info.st_ino)
            self.check()
        except (OSError, fsx.ComponentStateError) as error:
            self.close()
            raise GraphError('CACHE_PATH_UNSAFE') from error
        except BaseException:
            self.close()
            raise

    def _parents(self):
        uid = os.getuid() if hasattr(os, 'getuid') else None
        for parent in (self.path.parent, *self.path.parent.parents):
            try:
                info = parent.lstat()
            except FileNotFoundError:
                continue
            if fsx.is_link(info) or not stat.S_ISDIR(info.st_mode):
                raise GraphError('CACHE_PATH_UNSAFE')
            if uid is not None:
                trusted_sticky = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
                if (info.st_uid not in (0, uid) or info.st_mode & 0o022 and not trusted_sticky
                        or parent == self.path.parent and info.st_uid != uid):
                    raise GraphError('CACHE_PATH_UNSAFE')

    def _file(self, info):
        if (fsx.is_link(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or self.private_parent is not None and stat.S_IMODE(info.st_mode) != 0o600
                or hasattr(os, 'getuid') and (info.st_uid != os.getuid() or info.st_mode & 0o022)):
            raise GraphError('CACHE_PATH_UNSAFE')

    def _create(self):
        self.check_parent()
        self._parents()
        for suffix in ('-wal', '-shm', '-journal'):
            try:
                fsx.lstat_at(self.parent, self.name + suffix)
            except FileNotFoundError:
                continue
            raise GraphError('CACHE_SIDECAR_UNRECOGNIZED')
        self.descriptor = fsx.open_at(self.parent, self.name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | fsx.O_NOFOLLOW | fsx.O_CLOEXEC, 0o600)
        info = os.fstat(self.descriptor)
        self.identity = (info.st_dev, info.st_ino)
        self.created = True

    def check(self):
        if self.missing:
            return
        try:
            self.check_parent()
            self._parents()
            named = fsx.lstat_at(self.parent, self.name)
            opened = os.fstat(self.descriptor)
            self._file(named)
            self._file(opened)
            if (named.st_dev, named.st_ino) != self.identity or (opened.st_dev, opened.st_ino) != self.identity:
                raise GraphError('CACHE_PATH_CHANGED')
            for suffix in ('-wal', '-shm', '-journal'):
                try:
                    self._file(fsx.lstat_at(self.parent, self.name + suffix))
                except FileNotFoundError:
                    pass
        except (OSError, fsx.ComponentStateError) as error:
            raise GraphError('CACHE_PATH_UNSAFE') from error

    def header(self):
        self.check()
        os.lseek(self.descriptor, 0, os.SEEK_SET)
        value = os.read(self.descriptor, 16)
        self.check()
        return value

    @contextlib.contextmanager
    def locked(self, *, exclusive=True):
        self.check()
        # Darwin arbitrates flock against SQLite's byte-range locks on the same
        # inode. Serialize cooperating caches on their retained parent there.
        lock_descriptor = self.parent if sys.platform == 'darwin' else self.descriptor
        deadline = time.monotonic() + 30
        while True:
            try:
                fsx.lock_file(lock_descriptor, exclusive=exclusive, blocking=False)
                break
            except OSError as error:
                if error.errno not in (errno.EACCES, errno.EAGAIN):
                    raise
                if time.monotonic() >= deadline:
                    raise GraphError('CACHE_BUSY') from error
                time.sleep(.01)
        try:
            self.check()
            yield
        finally:
            fsx.unlock_file(lock_descriptor)

    def close(self):
        if self.descriptor is not None:
            os.close(self.descriptor)
            self.descriptor = None
        self.stack.close()
