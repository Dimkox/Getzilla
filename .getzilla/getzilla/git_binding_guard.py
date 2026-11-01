"""Private, finite Linux history guard for Git output admission.

This is not a mount-namespace boundary. Only the locally qualified overlayfs
backend is enabled. All other acquisition outcomes retain strict Git binding.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass, field
import os
from pathlib import Path
import platform
import stat
import struct
import sys
import threading
import time

from . import fsx
from .architecture import ArchitectureError

MAX_DIRECTORIES = 256
MAX_ENTRIES = 4096
MAX_EVENTS = 8192
MAX_EVENT_BYTES = 1_048_576
MAX_DRAIN_READS = 32
SETUP_SECONDS = 5.0
OPERATION_SECONDS = 120.0
_OVERLAYFS = 0x794C7630
_MODIFY = 0x00000002
_ATTRIB = 0x00000004
_CLOSE_WRITE = 0x00000008
_MOVED_FROM = 0x00000040
_MOVED_TO = 0x00000080
_CREATE = 0x00000100
_DELETE = 0x00000200
_DELETE_SELF = 0x00000400
_MOVE_SELF = 0x00000800
_UNMOUNT = 0x00002000
_OVERFLOW = 0x00004000
_IGNORED = 0x00008000
_ONLYDIR = 0x01000000
_MASK_ADD = 0x20000000
_ISDIR = 0x40000000
_CHILD_EVENTS = _MODIFY | _ATTRIB | _CLOSE_WRITE | _MOVED_FROM | _MOVED_TO | _CREATE | _DELETE
_SELF_EVENTS = _DELETE_SELF | _MOVE_SELF | _UNMOUNT | _IGNORED
_WATCH_MASK = _CHILD_EVENTS | _SELF_EVENTS
_EVENT = struct.Struct("=iIII")


class GuardUnavailable(Exception):
    """Only a setup capability/configuration result, never an invalidation."""


class _StatFS(ctypes.Structure):
    # Linux x86-64 statfs ABI. Other ABIs are deliberately unqualified.
    _fields_ = [
        ("kind", ctypes.c_long), ("block_size", ctypes.c_long),
        ("blocks", ctypes.c_ulong), ("free_blocks", ctypes.c_ulong),
        ("available_blocks", ctypes.c_ulong), ("files", ctypes.c_ulong),
        ("free_files", ctypes.c_ulong), ("filesystem_id", ctypes.c_int * 2),
        ("name_length", ctypes.c_long), ("fragment_size", ctypes.c_long),
        ("flags", ctypes.c_long), ("spare", ctypes.c_long * 4),
    ]


def _native_api():
    if (sys.platform != "linux" or fsx.WINDOWS or platform.machine() != "x86_64"
            or ctypes.sizeof(ctypes.c_long) != 8):
        raise GuardUnavailable("platform")
    try:
        library = ctypes.CDLL(None, use_errno=True)
        library.inotify_init1.argtypes = [ctypes.c_int]
        library.inotify_init1.restype = ctypes.c_int
        library.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        library.inotify_add_watch.restype = ctypes.c_int
        library.fstatfs.argtypes = [ctypes.c_int, ctypes.POINTER(_StatFS)]
        library.fstatfs.restype = ctypes.c_int
        return library
    except (AttributeError, OSError):
        raise GuardUnavailable("backend") from None


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


@dataclass
class _Directory:
    descriptor: int
    identity: tuple[int, ...]
    watch: int
    parent: Path | None
    label: str


@dataclass
class _Watch:
    identity: tuple[int, int]
    label: str
    names: dict[bytes, str] = field(default_factory=dict)
    history: set[bytes] = field(default_factory=set)
    all_names: str | None = None


class LinuxGitGuard:
    """Own all descriptors and retain name history until the operation ends."""

    mode = "linux-inotify-overlayfs-v1"

    def __init__(self) -> None:
        self._api = _native_api()
        self._descriptor = -1
        self._directories: dict[Path, _Directory] = {}
        self._watches: dict[int, _Watch] = {}
        self._files: dict[Path, tuple[tuple[int, ...] | None, str]] = {}
        self._started = time.monotonic()
        self._owner = threading.get_ident()
        self._sealed = False
        self._failure: str | None = None
        self._event_count = 0
        self._event_bytes = 0
        self._entry_count = 0
        # Finish fallible Python setup before acquiring the native resource.
        self._descriptor = self._api.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        if self._descriptor < 0:
            raise GuardUnavailable("backend-resources")

    def _fail(self, label: str = "path ancestor", reason: str = "changed") -> None:
        if self._failure is None:
            self._failure = f"Git {label} binding {reason}"
        raise ArchitectureError(self._failure, code="git") from None

    def _active(self) -> None:
        if self._failure is not None:
            self._fail()
        if self._descriptor < 0 or self._owner != threading.get_ident():
            self._fail(reason="guard is unavailable")
        budget = OPERATION_SECONDS if self._sealed else SETUP_SECONDS
        if time.monotonic() - self._started >= budget:
            self._fail(reason="guard limit exceeded")

    def remaining(self) -> float:
        self._active()
        budget = OPERATION_SECONDS if self._sealed else SETUP_SECONDS
        return max(0.001, budget - (time.monotonic() - self._started))

    def _qualified(self, descriptor: int) -> None:
        result = _StatFS()
        if self._api.fstatfs(descriptor, ctypes.byref(result)) != 0:
            raise GuardUnavailable("filesystem")
        if result.kind != _OVERLAYFS:
            raise GuardUnavailable("filesystem")

    def _watch(self, descriptor: int, identity: tuple[int, ...], label: str) -> int:
        self._qualified(descriptor)
        watch = self._api.inotify_add_watch(
            self._descriptor, os.fsencode(f"/proc/self/fd/{descriptor}"),
            _WATCH_MASK | _ONLYDIR | _MASK_ADD,
        )
        if watch < 0:
            self.check()
            raise GuardUnavailable("watch-resources")
        existing = self._watches.get(watch)
        if existing is None:
            self._watches[watch] = _Watch(identity[:2], label)
        elif existing.identity != identity[:2]:
            self._fail(label)
        elif existing.label == "path ancestor":
            existing.label = label
        return watch

    def _add_directory(self, path: Path, parent: Path | None, label: str) -> None:
        self._active()
        if self._sealed or len(self._directories) >= MAX_DIRECTORIES:
            self._fail(label, "guard limit exceeded")
        descriptor = -1
        try:
            if parent is None:
                descriptor = fsx.open_dir(path, flags=os.O_NONBLOCK | os.O_CLOEXEC)
            else:
                descriptor = fsx.open_dir_at(self._directories[parent].descriptor, path.name,
                                             flags=os.O_NONBLOCK | os.O_CLOEXEC)
            opened = fsx.fstat_dir(descriptor)
            if not stat.S_ISDIR(opened.st_mode) or fsx.is_link(opened):
                raise GuardUnavailable("path-alias")
            identity = _identity(opened)
            watch = self._watch(descriptor, identity, label)
            self._directories[path] = _Directory(descriptor, identity, watch, parent, label)
            descriptor = -1  # ownership moved into the graph
            self._validate_directory(path, self._directories[path])
            self._drain()
        except OSError:
            self.check()
            raise GuardUnavailable("path-coverage") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _protect(self, directory: Path, name: str, label: str) -> None:
        record = self._directories[directory]
        watch = self._watches[record.watch]
        encoded = os.fsencode(name)
        previous = watch.names.get(encoded)
        if previous is None or previous == "path ancestor":
            watch.names[encoded] = label
        if encoded in watch.history:
            self._fail(watch.names[encoded])
        self._drain()

    def directory(self, path: Path, label: str) -> Path:
        """Walk every supplied component before normalizing '..'; never follow links."""
        self._active()
        if not path.is_absolute():
            raise GuardUnavailable("path-alias")
        current = Path("/")
        if current not in self._directories:
            self._add_directory(current, None, "path ancestor")
        for name in path.parts[1:]:
            if name == "..":
                current = current.parent
                continue
            self._protect(current, name, "path ancestor")
            child = current / name
            if child not in self._directories:
                self._add_directory(child, current, "path ancestor")
            else:
                self._validate_directory(child, self._directories[child])
            current = child
        record = self._directories[current]
        if record.label == "path ancestor":
            record.label = label
        watch = self._watches[record.watch]
        if watch.label == "path ancestor":
            watch.label = label
        if record.parent is not None:
            self._protect(record.parent, current.name, label)
        self._drain()
        return current

    def protect(self, directory: Path, name: str, label: str) -> None:
        self._active()
        if directory not in self._directories or name in {"", ".", ".."} or "/" in name:
            self._fail(label, "guard is incomplete")
        self._protect(directory, name, label)

    def file(self, path: Path, label: str) -> os.stat_result | None:
        """Protect an exact present/absent regular name and retain strict identity."""
        self.protect(path.parent, path.name, label)
        try:
            info = fsx.lstat_at(self._directories[path.parent].descriptor, path.name)
        except FileNotFoundError:
            info = None
        except OSError:
            self._fail(label, "is unavailable")
        if info is not None and (not stat.S_ISREG(info.st_mode) or fsx.is_link(info)):
            raise GuardUnavailable("path-alias")
        identity = None if info is None else _identity(info)
        previous = self._files.get(path)
        if previous is not None and previous[0] != identity:
            self._fail(label)
        self._files[path] = identity, label
        self._drain()
        return info

    def tree(self, path: Path, label: str) -> tuple[Path, ...]:
        """A bounded closed selector subtree: all changes, including new names, fail."""
        self.protect(path.parent, path.name, label)
        try:
            info = fsx.lstat_at(self._directories[path.parent].descriptor, path.name)
        except FileNotFoundError:
            self._files[path] = None, label
            return ()
        if not stat.S_ISDIR(info.st_mode) or fsx.is_link(info):
            raise GuardUnavailable("path-alias")
        current = self.directory(path, label)
        watch = self._watches[self._directories[current].watch]
        if watch.history:
            self._fail(label)
        watch.all_names = label
        self._drain()
        files: list[Path] = []
        with fsx.scandir(self._directories[current].descriptor) as entries:
            for entry in entries:
                self._entry_count += 1
                self._active()
                if self._entry_count > MAX_ENTRIES:
                    self._fail(label, "guard limit exceeded")
                child = current / entry.name
                if entry.is_dir(follow_symlinks=False):
                    files.extend(self.tree(child, label))
                else:
                    self.file(child, label)
                    files.append(child)
        self._drain()
        return tuple(files)

    def _validate_directory(self, path: Path, record: _Directory) -> None:
        try:
            opened = fsx.fstat_dir(record.descriptor)
            named = (path.lstat() if record.parent is None else
                     fsx.lstat_at(self._directories[record.parent].descriptor, path.name))
        except OSError:
            self._fail(record.label, "is unavailable")
        if (fsx.is_link(named) or not stat.S_ISDIR(named.st_mode)
                or _identity(opened)[:3] != record.identity[:3]
                or _identity(named)[:3] != record.identity[:3]):
            self._fail(record.label)

    def _consume(self, data: bytes) -> None:
        offset = 0
        self._event_bytes += len(data)
        if not data or self._event_bytes > MAX_EVENT_BYTES:
            self._fail(reason="guard limit exceeded")
        while offset < len(data):
            self._active()
            if len(data) - offset < _EVENT.size:
                self._fail(reason="guard event is invalid")
            watch_id, mask, _cookie, size = _EVENT.unpack_from(data, offset)
            offset += _EVENT.size
            self._event_count += 1
            if self._event_count > MAX_EVENTS:
                self._fail(reason="guard limit exceeded")
            if mask & _OVERFLOW:
                self._fail(reason="guard overflowed")
            if (size > 4096 or offset + size > len(data) or size % 4
                    or mask & ~(_WATCH_MASK | _ISDIR) or not mask & _WATCH_MASK):
                self._fail(reason="guard event is invalid")
            watch = self._watches.get(watch_id)
            if watch is None:
                self._fail(reason="guard event is invalid")
            raw_name = data[offset:offset + size]
            offset += size
            if mask & _SELF_EVENTS:
                self._fail(watch.label)
            if not size:
                self._fail(watch.label)
            name, separator, padding = raw_name.partition(b"\0")
            if (not separator or not name or name in {b".", b".."}
                    or b"/" in name or padding.strip(b"\0")):
                self._fail(reason="guard event is invalid")
            watch.history.add(name)
            label = watch.names.get(name) or watch.all_names
            if label is not None:
                self._fail(label)

    def _drain(self) -> None:
        self._active()
        for _ in range(MAX_DRAIN_READS):
            self._active()
            try:
                data = os.read(self._descriptor, 65_536)
            except BlockingIOError:
                return
            except InterruptedError:
                continue
            except OSError:
                self._fail(reason="guard read failed")
            self._consume(data)
        self._fail(reason="guard limit exceeded")

    def check(self) -> None:
        self._drain()
        for path, record in self._directories.items():
            self._validate_directory(path, record)
        for path, (identity, label) in self._files.items():
            try:
                info = fsx.lstat_at(self._directories[path.parent].descriptor, path.name)
            except FileNotFoundError:
                if identity is None:
                    continue
                self._fail(label, "is unavailable")
            except OSError:
                self._fail(label, "is unavailable")
            if fsx.is_link(info) or _identity(info) != identity:
                self._fail(label)
        self._drain()

    def seal(self) -> None:
        self.check()
        self._sealed = True

    def covers(self, path: Path, identity: tuple[int, ...]) -> bool:
        self._active()
        record = self._directories.get(path)
        return record is not None and record.identity[:3] == identity[:3]

    def key(self) -> tuple[object, ...]:
        self._active()
        return (
            self.mode,
            tuple(sorted((str(path), record.identity[:3]) for path, record in self._directories.items())),
            tuple(sorted((str(path), identity) for path, (identity, _label) in self._files.items())),
        )

    def close(self) -> None:
        descriptor, self._descriptor = self._descriptor, -1
        failed = False
        if descriptor >= 0:
            try:
                os.close(descriptor)  # removes all watches without rearm/reset
            except OSError:
                failed = True
        for record in self._directories.values():
            try:
                os.close(record.descriptor)
            except OSError:
                failed = True
        self._directories.clear()
        self._watches.clear()
        self._files.clear()
        if failed and self._failure is None:
            self._fail(reason="guard cleanup failed")
