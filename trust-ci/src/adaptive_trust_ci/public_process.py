"""Explicit Linux delegated-cgroup envelope for protected producer descendants.

A process group is insufficient: trusted scanners may create nested sessions.
This profile refuses absent delegation; it makes no claim about arbitrary code
with permission to move itself into a different delegated cgroup.
"""

from __future__ import annotations
import ctypes
import os
from pathlib import Path
import secrets
import sys
import time


def _cgroup2(descriptor):
    if sys.platform != "linux" or ctypes.sizeof(ctypes.c_long) != 8:
        return False
    buffer = ctypes.create_string_buffer(256)
    library = ctypes.CDLL(None, use_errno=True)
    if library.fstatfs(descriptor, ctypes.byref(buffer)) != 0:
        return False
    return ctypes.c_long.from_buffer(buffer).value == 0x63677270


def _create_leaf(path):
    path.mkdir(mode=0o700)


def _remove_leaf(path):
    path.rmdir()


class ProducerCleanupUnknown(ValueError):
    """The owned kernel group did not yield a confirmed empty observation."""


class ProducerEnvelope:
    def __init__(self, root, deadline, *, clock=time.monotonic):
        self.root, self.deadline, self.clock = Path(root), deadline, clock
        self.descriptors, self.path, self.identity = {}, None, None
        self.closed, self.empty_confirmed = False, False
        try:
            if (
                not self.root.is_absolute()
                or ".." in self.root.parts
                or self.clock() >= deadline
                or sys.platform != "linux"
                or not hasattr(os, "O_NOFOLLOW")
            ):
                raise ValueError("producer-cgroup-unavailable")
            descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            self.descriptors["root"] = descriptor
            info = os.fstat(descriptor)
            self.root_identity = (info.st_dev, info.st_ino)
            if info.st_uid != os.getuid() or info.st_mode & 0o022 or not _cgroup2(descriptor):
                raise ValueError("producer-cgroup-delegation-required")
            if (
                self._path_read(self.root / "cgroup.type").strip() != b"domain"
                or b"pids" not in self._path_read(self.root / "cgroup.controllers").split()
                or b"pids" not in self._path_read(self.root / "cgroup.subtree_control").split()
            ):
                raise ValueError("producer-cgroup-controller-required")
            self._root_bound()
            entries = list(self.root.iterdir())
            if len(entries) > 256 or any(entry.name.startswith('producer-') for entry in entries):
                raise ProducerCleanupUnknown('producer-prior-group-unresolved')
            self.path = self.root / ("producer-" + secrets.token_hex(16))
            _create_leaf(self.path)
            leaf = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            self.descriptors["leaf"] = leaf
            self.identity = (os.fstat(leaf).st_dev, os.fstat(leaf).st_ino)
            self._root_bound()
            for name, flags in (
                ("cgroup.procs", os.O_RDWR),
                ("cgroup.events", os.O_RDONLY),
                ("cgroup.kill", os.O_WRONLY),
                ("pids.max", os.O_RDWR),
            ):
                self.descriptors[name] = os.open(self.path / name, flags | os.O_NOFOLLOW | os.O_CLOEXEC)
            if self._read("cgroup.procs").strip() or self._populated():
                raise ValueError("producer-cgroup-not-empty")
            self._write("pids.max", b"128")
            if self._read("pids.max").strip() != b"128":
                raise ValueError("producer-cgroup-pid-cap-unconfirmed")
        except BaseException:
            self.close()
            raise

    def _root_bound(self):
        info = self.root.lstat()
        current = os.fstat(self.descriptors['root'])
        if ((info.st_dev, info.st_ino) != self.root_identity
                or (current.st_dev, current.st_ino) != self.root_identity
                or info.st_uid != os.getuid() or info.st_mode & 0o022):
            raise ValueError('producer-cgroup-root-changed')

    @staticmethod
    def _path_read(path):
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            value = os.read(descriptor, 4097)
            if len(value) > 4096:
                raise ValueError("producer-cgroup-control-bound")
            return value
        finally:
            os.close(descriptor)

    def _read(self, name):
        descriptor = self.descriptors[name]
        os.lseek(descriptor, 0, os.SEEK_SET)
        value = os.read(descriptor, 4097)
        if len(value) > 4096:
            raise ValueError("producer-cgroup-control-bound")
        return value

    def _write(self, name, value):
        descriptor = self.descriptors[name]
        os.lseek(descriptor, 0, os.SEEK_SET)
        if os.write(descriptor, value) != len(value):
            raise ValueError("producer-cgroup-control-write")

    def _populated(self):
        rows = self._read("cgroup.events").splitlines()
        values = [row.split() for row in rows if row.startswith(b"populated ")]
        if len(values) != 1 or values[0] not in ([b"populated", b"0"], [b"populated", b"1"]):
            raise ValueError("producer-cgroup-population-unavailable")
        return values[0][1] == b"1"

    def attach(self, process):
        # The fixed child waits for stdin. No work/payload is sent until this
        # kernel membership observation confirms the exact newly spawned PID.
        if self.closed or type(process.pid) is not int or process.pid <= 0 or self.clock() >= self.deadline:
            raise ValueError("producer-cgroup-attach-refused")
        self._root_bound()
        self._write("cgroup.procs", str(process.pid).encode("ascii"))
        members = self._read("cgroup.procs").split()
        if members != [str(process.pid).encode("ascii")]:
            raise ValueError("producer-cgroup-membership-unconfirmed")

    def close(self):
        if self.closed:
            return
        problem = None
        try:
            if "cgroup.kill" in self.descriptors:
                self._write("cgroup.kill", b"1")
                while self._populated():
                    if self.clock() >= self.deadline:
                        raise ProducerCleanupUnknown("producer-cgroup-cleanup-unconfirmed")
                    time.sleep(min(0.005, max(0, self.deadline - self.clock())))
                if self._read("cgroup.procs").strip():
                    raise ProducerCleanupUnknown("producer-cgroup-cleanup-unconfirmed")
                self.empty_confirmed = True
            elif self.path is not None:
                # No child could be attached before construction completed.
                self.empty_confirmed = True
            if self.path is not None:
                info = self.path.lstat()
                if self.identity is not None and (info.st_dev, info.st_ino) != self.identity:
                    raise ValueError("producer-cgroup-path-changed")
                _remove_leaf(self.path)
        except (OSError, ValueError) as error:
            problem = error
        finally:
            for descriptor in self.descriptors.values():
                os.close(descriptor)
            self.descriptors.clear()
            self.closed = True
        if problem is not None:
            raise ProducerCleanupUnknown("producer-cgroup-cleanup-unconfirmed") from problem

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
        if not self.empty_confirmed:
            raise ProducerCleanupUnknown("producer-cgroup-cleanup-unconfirmed")
