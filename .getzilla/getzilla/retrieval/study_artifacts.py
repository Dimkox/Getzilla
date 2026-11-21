"""Held read-only exact artifact inventory; custody, never execution authority."""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import stat
import time

from .budget import RetrievalError
from .contracts import digest, hex_digest
from .evaluation_inputs import checked_relative


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class HeldArtifacts:
    """Acquisition has a finite I/O deadline; check() is lifetime-neutral custody.

The execution/operation/source owners enforce their own original deadlines.
Metadata snapshots never extend or replace any of those permits.
"""
    def __init__(self, root, files, *, deadline=None, _verify_hash=True):
        self._stack = ExitStack()
        self._bindings = []
        self._directories = []
        self._closed = False
        self.hashes_verified = _verify_hash
        self._deadline = time.monotonic() + 180 if deadline is None else deadline
        self._opened = 0
        try:
            self._tick()
            import resource
            limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
            present = len(os.listdir('/proc/self/fd'))
            self._fd_headroom = (8256 if limit == resource.RLIM_INFINITY
                                 else max(0, limit - present - 64))
            root = Path(root)
            if (not root.is_absolute() or '..' in root.parts or type(files) is not tuple
                    or not 1 <= len(files) <= 4096):
                raise RetrievalError('artifact_inventory_unavailable')
            expected = {}
            for item in files:
                if (type(item) is not tuple or len(item) != 3 or type(item[1]) is not int
                        or not 0 <= item[1] <= 3_000_000_000 or not hex_digest(item[2])):
                    raise RetrievalError('artifact_inventory_unavailable')
                checked_relative(item[0])
                if item[0] in expected:
                    raise RetrievalError('artifact_inventory_unavailable')
                expected[item[0]] = item[1:]
            if sum(row[0] for row in expected.values()) > 12 * 1024**3:
                raise RetrievalError('artifact_inventory_unavailable')
            directory = self._open(root.anchor, directory=True)
            for component in root.parts[1:]:
                directory = self._child(directory, component, directory=True)
            observed = set()
            pending = [(directory, '')]
            entries = 0
            while pending:
                parent, prefix = pending.pop()
                self._tick()
                names = os.listdir(parent)
                self._directories.append((parent, frozenset(names)))
                entries += len(names)
                if entries > 8192:
                    raise RetrievalError('artifact_inventory_unavailable')
                for name in sorted(names):
                    self._tick()
                    path = prefix + name
                    info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        pending.append((self._child(parent, name, directory=True), path + '/'))
                        continue
                    if path not in expected or path in observed:
                        raise RetrievalError('artifact_inventory_unavailable')
                    descriptor = self._child(parent, name, directory=False)
                    size, digest = expected[path]
                    if os.fstat(descriptor).st_size != size:
                        raise RetrievalError('artifact_bytes_mismatch')
                    if _verify_hash:
                        hasher, count = hashlib.sha256(), 0
                        while True:
                            self._tick()
                            part = os.read(descriptor, min(65536, size - count + 1))
                            if not part:
                                break
                            count += len(part)
                            if count > size:
                                raise RetrievalError('artifact_bytes_mismatch')
                            hasher.update(part)
                        if count != size or hasher.hexdigest() != digest:
                            raise RetrievalError('artifact_bytes_mismatch')
                    observed.add(path)
            if observed != set(expected):
                raise RetrievalError('artifact_inventory_unavailable')
            self.check()
        except BaseException as error:
            self.close()
            if isinstance(error, (OSError, TypeError, AttributeError, ImportError)):
                raise RetrievalError('artifact_custody_unavailable') from None
            raise

    def _tick(self):
        if time.monotonic() >= self._deadline:
            raise RetrievalError('artifact_deadline')

    def _open(self, path, *, directory):
        self._fd_budget()
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                             | os.O_NONBLOCK | (os.O_DIRECTORY if directory else 0))
        self._stack.callback(os.close, descriptor)
        self._opened += 1
        self._qualified(os.fstat(descriptor), directory)
        return descriptor

    @staticmethod
    def _qualified(info, directory):
        if (info.st_uid not in {0, os.getuid()} or info.st_mode & 0o022
                or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
                or not directory and info.st_nlink != 1):
            raise RetrievalError('artifact_custody_unavailable')

    def _child(self, parent, name, *, directory):
        self._fd_budget()
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                             | os.O_NONBLOCK | (os.O_DIRECTORY if directory else 0), dir_fd=parent)
        self._stack.callback(os.close, descriptor)
        self._opened += 1
        after = os.fstat(descriptor)
        self._qualified(after, directory)
        if _identity(before) != _identity(after):
            raise RetrievalError('artifact_custody_unavailable')
        # Ancestor directory membership can change independently. Its identity
        # is held; exact entry sets are checked separately inside this inventory.
        identity = _identity(after)[:5] if directory else _identity(after)
        self._bindings.append((parent, name, descriptor, identity, directory))
        return descriptor

    def _fd_budget(self):
        if self._opened >= self._fd_headroom:
            raise RetrievalError('artifact_file_descriptor_budget')

    def check(self):
        if self._closed:
            raise RetrievalError('artifact_custody_unavailable')
        try:
            for parent, name, descriptor, identity, directory in self._bindings:
                current = _identity(os.fstat(descriptor))
                named = _identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
                if directory:
                    current, named = current[:5], named[:5]
                if current != identity or named != identity:
                    raise RetrievalError('artifact_custody_unavailable')
            for descriptor, entries in self._directories:
                if frozenset(os.listdir(descriptor)) != entries:
                    raise RetrievalError('artifact_inventory_unavailable')
        except OSError:
            raise RetrievalError('artifact_custody_unavailable') from None

    def close(self):
        self._closed = True
        self._stack.close()

    def __enter__(self):
        self.check()
        return self

    def __exit__(self, *_arguments):
        self.close()


_SNAPSHOT_ISSUER = object()


class StudyExportSnapshot:
    """Held metadata facts, explicitly not streamed integrity or execution consent."""
    __slots__ = ('_issuer', '_held', '_binding_digest')

    def __init__(self, issuer, held, binding_digest):
        if issuer is not _SNAPSHOT_ISSUER:
            raise TypeError('held export facts only')
        self._issuer, self._held = issuer, held
        self._binding_digest = binding_digest

    @property
    def binding_digest(self):
        return self._binding_digest

    @property
    def hashes_verified(self):
        return False

    def close(self):
        self._held.close()

    def __reduce_ex__(self, protocol):
        raise TypeError('held export facts cannot be serialized')


def snapshot_study_export(root, relative_root, expected_files):
    checked_relative(relative_root)
    target = Path(root) / relative_root
    try:
        outer, leaf = target.parent.lstat(), target.lstat()
        if (stat.S_IMODE(outer.st_mode) != 0o700 or outer.st_uid != os.getuid()
                or not stat.S_ISDIR(outer.st_mode) or stat.S_IMODE(leaf.st_mode) != 0o555
                or not stat.S_ISDIR(leaf.st_mode) or leaf.st_uid != os.getuid()):
            raise RetrievalError('study_export_dac_unavailable')
        held = HeldArtifacts(target, expected_files, _verify_hash=False)
        try:
            for descriptor, _ in held._directories:
                info = os.fstat(descriptor)
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o555:
                    raise RetrievalError('study_export_dac_unavailable')
            for _, _, descriptor, _, directory in held._bindings:
                if not directory:
                    info = os.fstat(descriptor)
                    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o444:
                        raise RetrievalError('study_export_dac_unavailable')
            binding = digest({'path': str(target), 'expected_files': expected_files,
                'entries': [[sorted(entries)] for _, entries in held._directories],
                'identities': [list(identity) for _, _, _, identity, _ in held._bindings]})
            return StudyExportSnapshot(_SNAPSHOT_ISSUER, held, binding)
        except BaseException:
            held.close()
            raise
    except OSError:
        raise RetrievalError('study_export_unavailable') from None


def check_study_export(snapshot):
    if (type(snapshot) is not StudyExportSnapshot
            or getattr(snapshot, '_issuer', None) is not _SNAPSHOT_ISSUER):
        raise RetrievalError('study_export_unavailable')
    snapshot._held.check()
