"""Private trace metadata I/O pinned to the actual native project CWD.

This is an OS-owner storage boundary, not customer authentication or a sandbox.
No caller-supplied FD or serialized identity can construct the native resource.
"""
from __future__ import annotations

import hashlib
import asyncio
import contextvars
import os
import secrets
import stat
import subprocess
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from . import fsx

_CREATION = object()
MAX_IO = 64 * 1024 * 1024
MAX_ENTRIES = 8192
_LEASE_CONTEXT = contextvars.ContextVar('native_trace_guards', default=())
_LIVE_GUARDS = {}


def _task():
    try:
        return asyncio.current_task()
    except RuntimeError:
        return None


def _resource(descriptor):
    info = os.fstat(descriptor)
    return info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink


class _GuardLease:
    """Only the actual runtime-lock manager creates and retires this resource."""
    def __init__(self, root, name, primary, marker, native_identity=None):
        self._primary = primary
        self._marker = marker
        self._guard_resource = _resource(primary)
        self._marker_resource = _resource(marker)
        try:
            self.root_identity = native_identity if native_identity is not None else _identity(os.stat(root, follow_symlinks=False))
        except OSError:
            # Existing nontrace lock semantics do not depend on path discovery.
            # The native resource still needs fork cleanup, but cannot qualify
            # an anchored trace when its root identity was not observed.
            self.root_identity = None
        self._keeper = os.dup(primary)
        try:
            os.set_inheritable(self._keeper, False)
            # Private OFD position marker permits safe cleanup if the duplicate
            # is accidentally closed. It never qualifies lock reuse by itself,
            # changes no file bytes, and is not a grant/serialized capability.
            self._offset = secrets.randbelow(1 << 30)+1
            os.lseek(primary, self._offset, os.SEEK_SET)
        except BaseException:
            os.close(self._keeper)
            raise
        self.name = name
        self.pid, self.uid = os.getpid(), os.getuid()
        self.thread, self.ident, self.task = threading.current_thread(), threading.get_ident(), _task()
        self.generation = object()
        self.active = True
        self.fork_closed = False
        _LIVE_GUARDS[self] = self.generation
        self._context_token = _LEASE_CONTEXT.set((*_LEASE_CONTEXT.get(), self))

    def _same_ofd(self):
        try:
            # A negative lifetime filter prevents a probe from acquiring a lock
            # on an independently reopened descriptor. This marker cannot
            # admit reuse: both actual kernel probes below remain mandatory.
            if not (self._generation_owned(self._primary) and self._generation_owned(self._keeper)):
                return False
            if (_resource(self._primary) != self._guard_resource
                    or _resource(self._keeper) != self._guard_resource):
                return False
            # No second independently opened lock. The private duplicate keeps
            # this OFD locked, so a reused independent primary cannot pass.
            fsx.lock_file(self._keeper, exclusive=True, blocking=False)
            fsx.lock_file(self._primary, exclusive=True, blocking=False)
            return True
        except OSError:
            return False

    def _generation_owned(self, descriptor):
        try:
            return (_resource(descriptor) == self._guard_resource
                    and os.lseek(descriptor, 0, os.SEEK_CUR) == self._offset)
        except OSError:
            return False

    def invalidate(self):
        self.active = False
        _LIVE_GUARDS.pop(self, None)
        _LEASE_CONTEXT.reset(self._context_token)

    def close(self):
        if self.fork_closed or os.getpid() != self.pid:
            return
        owned = self._same_ofd() or self._generation_owned(self._primary)
        try:
            if owned:
                fsx.unlock_file(self._primary)
                os.close(self._primary)
        finally:
            try:
                if self._generation_owned(self._keeper):
                    os.close(self._keeper)
            except OSError:
                pass


def retain_guard(root, name, primary, marker, *, native_identity=None):
    """Private entry used only after runtime_lock actually acquired both locks."""
    if os.name != 'posix' or fsx.WINDOWS:
        return None
    return _GuardLease(root, name, primary, marker, native_identity)


def held_guard(anchor, name):
    """Require live ownership in this exact execution context, not a copied flag."""
    anchor.check()
    for lease in reversed(_LEASE_CONTEXT.get()):
        if lease.root_identity != anchor.identity or lease.name != name:
            continue
        if (not lease.active or _LIVE_GUARDS.get(lease) is not lease.generation
                or lease.pid != os.getpid() or lease.uid != os.getuid() or os.getuid() != os.geteuid()
                or lease.thread is not threading.current_thread() or lease.ident != threading.get_ident()
                or lease.task is not _task() or not lease._same_ofd()):
            raise ValueError('native_trace_guard_unavailable')
        relative = f'.getzilla/runtime/.{name}.guard.lock'
        with anchor.file(relative) as (descriptor, _):
            if _resource(descriptor) != lease._guard_resource:
                raise ValueError('native_trace_guard_changed')
        return lease
    raise ValueError('native_trace_guard_unavailable')


def _fork_child():
    leases = tuple(_LIVE_GUARDS)
    _LIVE_GUARDS.clear()
    _LEASE_CONTEXT.set(())
    for lease in leases:
        lease.active = False
        lease.fork_closed = True
        # Inherited OFDs belong to the still-live parent. NEVER LOCK_UN here.
        for descriptor, expected in ((lease._primary, lease._guard_resource),
                                     (lease._keeper, lease._guard_resource),
                                     (lease._marker, lease._marker_resource)):
            try:
                if (_resource(descriptor) == expected and
                        (descriptor == lease._marker or lease._generation_owned(descriptor))):
                    os.close(descriptor)
            except OSError:
                pass


if hasattr(os, 'register_at_fork'):
    os.register_at_fork(after_in_child=_fork_child)


@contextmanager
def _pid_marker(anchor, name, deadline):
    """Anonymous lifetime marker; the existing named kernel guard serializes.

    Never create, remove or repair a PID pathname. Legacy contenders acquire
    the same kernel guard before their own PID marker protocol.
    """
    anchor.check()
    owner_pid = os.getpid()
    if name not in {'task-transition','route'} or time.monotonic() >= deadline:
        raise ValueError('native_trace_marker_unavailable')
    descriptor,writer = os.pipe()
    os.close(writer)
    os.set_inheritable(descriptor,False)
    identity = _resource(descriptor)
    try:
        yield descriptor
    finally:
        if os.getpid() == owner_pid:
            try:
                if _resource(descriptor) == identity:
                    os.close(descriptor)
            except OSError:
                pass


@contextmanager
def native_lock(anchor, name, timeout):
    """The existing retained kernel guard plus an anonymous lifetime marker."""
    if name not in {'task-transition', 'route'} or timeout < 0:
        raise ValueError('native_trace_lock_unavailable')
    deadline = time.monotonic()+timeout
    relative = f'.getzilla/runtime/.{name}.guard.lock'
    lease, locked = None, False
    with anchor.parent(relative, create=True) as (parent, leaf):
        descriptor = fsx.open_at(parent, leaf, os.O_CREAT | os.O_RDWR | fsx.O_NOFOLLOW | fsx.O_CLOEXEC | fsx.O_NONBLOCK, 0o600)
        try:
            anchor._regular(os.fstat(descriptor), limit=128)
            if _identity(os.fstat(descriptor)) != _identity(fsx.lstat_at(parent, leaf)):
                raise ValueError('native_trace_guard_changed')
            while True:
                try:
                    fsx.lock_file(descriptor, exclusive=True, blocking=False)
                    locked = True
                    break
                except BlockingIOError:
                    remaining = deadline-time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('native_trace_lock_timeout')
                    time.sleep(min(0.01, remaining))
            with _pid_marker(anchor, name, deadline) as marker:
                lease = retain_guard(None, name, descriptor, marker, native_identity=anchor.identity)
                try:
                    yield
                finally:
                    if os.getpid() == lease.pid:
                        lease.invalidate()
        finally:
            if lease is not None:
                lease.close()
            else:
                try:
                    if locked:
                        fsx.unlock_file(descriptor)
                finally:
                    os.close(descriptor)


def _identity(info):
    return info.st_dev, info.st_ino


class _NativeRoot:
    def __init__(self, creation, root, descriptor):
        if creation is not _CREATION:
            raise ValueError('native_trace_root_required')
        self.workspace = str(root)
        self._fd = descriptor
        self._pid = os.getpid()
        self._uid = os.getuid()
        self.identity = _identity(os.fstat(descriptor))
        self._bytes = 0
        self._entries = 0
        self._closed = False
        self._parents = {}

    def check(self):
        if self._closed or os.getpid() != self._pid or os.getuid() != self._uid or os.geteuid() != self._uid:
            raise ValueError('native_trace_root_expired')
        info = os.fstat(self._fd)
        if (not stat.S_ISDIR(info.st_mode) or _identity(info) != self.identity
                or info.st_uid != self._uid or info.st_mode & 0o022):
            raise ValueError('private_observation_directory_required')

    def charge(self, *, size=0, entries=1):
        self._bytes += size
        self._entries += entries
        if self._bytes > MAX_IO or self._entries > MAX_ENTRIES:
            raise ValueError('trace_io_limit')

    def check_cwd(self):
        self.check()
        if _identity(os.stat('.', follow_symlinks=False)) != self.identity:
            raise ValueError('native_trace_cwd_changed')

    def check_root(self, root):
        self.check()
        if os.path.abspath(root) != self.workspace:
            raise ValueError('native_trace_project_mismatch')

    def root_info(self):
        self.check()
        return os.fstat(self._fd)

    def duplicate_root_fd(self):
        """Internal reader adapter: the actual caller owns and closes this dup.

        The descriptor is never serialized or accepted as an authority claim.
        Callers retain this live native object for lifetime/root revalidation.
        """
        self.check()
        descriptor = os.dup(self._fd)
        try:
            os.set_inheritable(descriptor, False)
            self.check()
            if _identity(os.fstat(descriptor)) != self.identity:
                raise ValueError('native_trace_root_changed')
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    @property
    def binding(self):
        self.check()
        raw = f'{self.identity[0]}:{self.identity[1]}'.encode()
        return {name: hashlib.sha256(name.encode()+b':'+raw).hexdigest()
                for name in ('repository_digest', 'workspace_digest')}

    def git_source(self):
        """Use the same admitted owned-FD graph as other native Git facts."""
        from .architecture_diff import _GitOperation, _git, ArchitectureError
        self.check_cwd()
        try:
            with _GitOperation(Path(self.workspace),native_anchor=self,_budget_seconds=0.5) as scope:
                output = _git(Path(self.workspace),['show','--no-patch','--no-show-signature',
                              '--no-notes','--format=%H%n%T','HEAD'],limit=256,_scope=scope)
        except (OSError, ArchitectureError, subprocess.SubprocessError):
            raise ValueError('native_trace_source_unavailable') from None
        values = (output or b'').strip().decode('ascii').splitlines()
        head, tree = values if len(values) == 2 else ('', '')
        self.check_cwd()
        if (len(head) not in {40, 64} or len(tree) != len(head)
                or any(character not in '0123456789abcdef' for character in head+tree)):
            raise ValueError('native_trace_source_unavailable')
        return {'head': head, 'tree': tree}

    @contextmanager
    def parent(self, relative, *, private=True, source=False, create=False):
        self.check()
        relative = Path(relative)
        if relative.is_absolute() or not relative.parts or any(part in {'', '.', '..'} for part in relative.parts):
            raise ValueError('unsafe_trace_path')
        handles = [os.dup(self._fd)]
        names = []
        try:
            for index, name in enumerate(relative.parts[:-1]):
                self.charge()
                if create:
                    try:
                        fsx.mkdir_at(handles[-1], name, 0o700)
                    except FileExistsError:
                        pass
                child = fsx.open_dir_at(handles[-1], name, flags=fsx.O_CLOEXEC)
                handles.append(child)
                info = os.fstat(child)
                # Source directories permit normal repository modes. Restricted
                # runtime descendants are private; .getzilla itself may be0755.
                restricted = private and not source and index >= 1
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self._uid
                        or info.st_mode & 0o022
                        or restricted and stat.S_IMODE(info.st_mode) != 0o700):
                    raise ValueError('private_observation_directory_required')
                names.append((handles[-2], name, _identity(info), restricted))
            self._validate_names(names)
            self._parents[handles[-1]] = names
            yield handles[-1], relative.name
            self._validate_names(names)
        finally:
            self._parents.pop(handles[-1], None)
            for handle in reversed(handles):
                os.close(handle)

    def _validate_names(self, names):
        self.check()
        for parent, name, expected, private in names:
            info = fsx.lstat_at(parent, name)
            if (not stat.S_ISDIR(info.st_mode) or _identity(info) != expected or info.st_uid != self._uid
                    or info.st_mode & 0o022 or private and stat.S_IMODE(info.st_mode) != 0o700):
                raise ValueError('trace_directory_changed')

    def check_parent(self, parent):
        if parent not in self._parents:
            raise ValueError('native_trace_parent_required')
        self._validate_names(self._parents[parent])

    def _regular(self, info, *, private=True, source=False, public_source=False, limit=1_048_576):
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != self._uid or info.st_nlink != 1
                or info.st_size > limit or info.st_mode & 0o022
                or not source and info.st_mode & 0o111
                or private and not source and stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError('private_observation_file_required')
        if public_source and stat.S_IMODE(info.st_mode) not in {0o444,0o644,0o555,0o755}:
            raise ValueError('public_source_file_required')

    @contextmanager
    def file(self, relative, *, writable=False, private=True, source=False, public_source=False, limit=1_048_576):
        if public_source:
            if writable:
                raise ValueError('public_source_read_only')
            source = True
        with self.parent(relative, private=private, source=source) as (parent, name):
            flags = os.O_RDWR | os.O_APPEND if writable else os.O_RDONLY
            descriptor = fsx.open_at(parent, name, flags | fsx.O_NOFOLLOW | fsx.O_NONBLOCK | fsx.O_CLOEXEC)
            try:
                info = os.fstat(descriptor)
                self._regular(info, private=private, source=source, public_source=public_source, limit=limit)
                if _identity(fsx.lstat_at(parent, name)) != _identity(info):
                    raise ValueError('trace_file_changed')
                yield descriptor, parent
                after = os.fstat(descriptor)
                self._regular(after, private=private, source=source, public_source=public_source, limit=limit)
                if not writable and (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise ValueError('trace_file_changed')
                if _identity(fsx.lstat_at(parent, name)) != _identity(info):
                    raise ValueError('trace_file_changed')
            finally:
                os.close(descriptor)

    def _source_unchanged(self, descriptor, parent, name, expected, limit):
        self.check_parent(parent)
        opened = os.fstat(descriptor)
        named = fsx.lstat_at(parent,name)
        self._regular(opened, source=True, public_source=True, limit=limit)
        self._regular(named, source=True, public_source=True, limit=limit)
        def identity(info):
            return (info.st_dev,info.st_ino,info.st_uid,info.st_mode,info.st_nlink,
                    info.st_size,info.st_mtime_ns,info.st_ctime_ns)
        if identity(opened) != identity(expected) or identity(named) != identity(expected):
            raise ValueError('public_source_changed')

    def read(self, relative, limit=1_048_576, *, private=True, source=False, public_source=False):
        allocated = None
        if not source and not public_source:
            from .native_state_snapshot import metadata_limit,decode
            allocated = metadata_limit(relative)
            if allocated is not None:
                limit = min(limit,allocated)
        with self.file(relative, private=private, source=source, public_source=public_source, limit=limit) as (descriptor, parent):
            chunks, size = [], 0
            expected = os.fstat(descriptor) if public_source else None
            while True:
                if public_source:
                    self._source_unchanged(descriptor,parent,Path(relative).name,expected,limit)
                chunk = os.read(descriptor, min(65536, limit + 1-size))
                self.charge(size=len(chunk))
                if public_source:
                    self._source_unchanged(descriptor,parent,Path(relative).name,expected,limit)
                if not chunk:
                    raw = b''.join(chunks)
                    if allocated is not None:
                        return decode(raw,limit=limit)
                    return raw
                size += len(chunk)
                if size > limit:
                    raise ValueError('trace_io_limit')
                chunks.append(chunk)

    def stat(self, relative, *, private=True, source=False):
        """Named metadata from the same resource; no root-hint path reopening."""
        with self.parent(relative, private=private, source=source) as (parent,name):
            info = fsx.lstat_at(parent,name)
            if stat.S_ISDIR(info.st_mode):
                if (info.st_uid != self._uid or info.st_mode & 0o022
                        or private and not source and stat.S_IMODE(info.st_mode) != 0o700):
                    raise ValueError('private_observation_directory_required')
            else:
                self._regular(info,private=private,source=source)
            self.check_parent(parent)
            return info

    def exists(self, relative, *, private=True, source=False):
        try:
            with self.parent(relative, private=private, source=source) as (parent, name):
                info = fsx.lstat_at(parent, name)
                if fsx.is_link(info):
                    raise ValueError('unsafe_trace_path')
                return True
        except FileNotFoundError:
            return False

    def write(self, relative, raw):
        from .native_state_snapshot import metadata_limit,write
        limit = metadata_limit(relative)
        if limit is None:
            raise ValueError('native_trace_metadata_path_unsupported')
        if not isinstance(raw, bytes) or len(raw) > limit:
            raise ValueError('trace_io_limit')
        with self.parent(relative, create=True) as (parent, name):
            write(parent,name,raw,limit=limit,check=lambda:self.check_parent(parent),charge=self.charge)

    def unlink(self, relative):
        # POSIX pathname deletion cannot condition on an expected inode.
        # Refuse before touching a leaf, rather than claim a recheck is CAS.
        raise ValueError('native_trace_unlink_unsupported')


@contextmanager
def native_root(root):
    if (os.name != 'posix' or not hasattr(os, 'register_at_fork') or os.getuid() != os.geteuid()
            or not isinstance(root, (Path, str))):
        raise ValueError('native_trace_root_unavailable')
    descriptor = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    anchor = None
    try:
        absolute = os.path.abspath(os.fspath(root))
        # Path operations compare the hint only. They never select descendant I/O.
        named = os.stat(absolute, follow_symlinks=False)
        current = os.fstat(descriptor)
        if (not stat.S_ISDIR(named.st_mode) or _identity(named) != _identity(current)
                or os.getcwd() != absolute or os.path.realpath(absolute) != absolute):
            raise ValueError('native_trace_root_mismatch')
        anchor = _NativeRoot(_CREATION, absolute, descriptor)
        anchor.check()
        yield anchor
    finally:
        if anchor is not None:
            anchor._closed = True
        os.close(descriptor)
