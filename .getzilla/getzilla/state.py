from __future__ import annotations

import os
import copy
import json
import errno
import re
import secrets
import stat
import sys
import time
import urllib.parse
import contextvars
from contextlib import contextmanager
from functools import wraps
from datetime import datetime, timedelta as timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from . import fsx
from .util import (
    dump_json as dump_json,
    git_head,
    git_output,
    load_json,
    now_utc,
    runtime_dir,
    tree_fingerprint,
)

APPROVAL_SCOPES = {'production', 'external-write', 'protected-path'}
APPROVAL_SOURCES = {'standing-user-consent', 'explicit-user-consent'}
# A protected-path grant authorizes writing its exact files, so their own content is not part of
# its tree binding; legacy grants retain their original HEAD binding.
GRANTED_RESOURCES_BINDING = 'tree-except-granted-resources'
BRANCH_RESOURCES_BINDING = 'branch-and-exact-resources'
SCOPE_ACTIONS = {
    'production': {
        'git-push-branch',
        'git-push-tag',
        'pull-request-merge',
        'docker-push',
        'npm-publish',
        'github-release',
    },
    'external-write': {'external-write'},
    'protected-path': {'protected-path-write'},
}


def _windows_process_alive(pid: int) -> bool:
    """``OpenProcess`` probe: Windows ``os.kill(pid, 0)`` would send CTRL_C_EVENT."""
    import ctypes
    from ctypes import wintypes

    if pid > 0xFFFFFFFF:
        return False
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        # ERROR_ACCESS_DENIED: the process exists but belongs to someone else
        # (the PermissionError case below); anything else means it is gone.
        return ctypes.get_last_error() == 5
    try:
        code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            return True
        return code.value == 259  # STILL_ACTIVE
    finally:
        kernel32.CloseHandle(handle)


def _process_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if fsx.WINDOWS:
        return _windows_process_alive(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _release_lock_file(lock: Path) -> None:
    """Remove a released lock file; Windows retries a reader's brief share lock."""
    attempts = 20 if fsx.WINDOWS else 1
    for attempt in range(attempts):
        try:
            lock.unlink()
            return
        except FileNotFoundError:
            return
        except PermissionError:
            # A concurrent _stale_lock reader holds the file open without
            # FILE_SHARE_DELETE; POSIX unlink never fails this way.
            if attempt + 1 >= attempts:
                raise
            time.sleep(0.05)


LOCK_WRITE_GRACE_SECONDS = 2.0


def _stale_lock(lock: Path) -> bool:
    try:
        raw = lock.read_text(encoding='utf-8').strip()
        pid = int(raw)
    except OSError:
        return True
    except ValueError:
        if raw:
            return True  # malformed content is never a live holder
        # The holder creates the file and only then writes its pid: a young empty lock is held.
        try:
            return time.time() - lock.stat().st_mtime > LOCK_WRITE_GRACE_SECONDS
        except OSError:
            return True
    return not _process_alive(pid)


def _lock_identity(lock: Path) -> tuple[int, int, int, bytes]:
    info = lock.stat()
    try:
        content = lock.read_bytes()
    except FileNotFoundError:
        raise
    except OSError:
        content = b''
    return info.st_ino, info.st_dev, info.st_mtime_ns, content


def _wait_for_lock(lock: Path, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError(f'could not acquire runtime lock: {lock}')
    time.sleep(min(0.05, remaining))


def _open_lock_guard(guard: Path) -> int:
    parent = fsx.open_dir(guard.parent)
    descriptor: int | None = None
    try:
        # Concurrent first creation can return ENOENT from Darwin openat(O_CREAT).
        # Retry only that leaf syscall, with the same parent and admission flags.
        attempts = 3 if sys.platform == 'darwin' else 1
        for attempt in range(attempts):
            try:
                descriptor = fsx.open_at(parent, guard.name,
                                         os.O_CREAT | os.O_RDWR | fsx.O_BINARY | fsx.O_NOINHERIT
                                         | fsx.O_NOFOLLOW | fsx.O_NONBLOCK, 0o600)
                break
            except FileNotFoundError:
                if attempt + 1 == attempts:
                    raise
        opened = os.fstat(descriptor)
        named = fsx.lstat_at(parent, guard.name)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or fsx.is_link(named)
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)):
            raise OSError(errno.EINVAL, 'runtime lock guard must be a single-link regular file', str(guard))
        return descriptor
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise
    finally:
        fsx.close_dir(parent)


@contextmanager
def _pid_lock(lock: Path, deadline: float, *, allow_immediate: bool) -> Iterator[None]:
    """Legacy marker, always acquired and released under the retained guard."""
    fd: int | None = None
    first_attempt = allow_immediate
    while fd is None:
        if not first_attempt and time.monotonic() >= deadline:
            raise TimeoutError(f'could not acquire runtime lock: {lock}')
        first_attempt = False
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY | fsx.O_BINARY | fsx.O_NOINHERIT, 0o600)
        except FileExistsError:
            try:
                judged = _lock_identity(lock)
            except FileNotFoundError:
                continue
            if _stale_lock(lock):
                try:
                    # Another waiter may have removed the stale lock and taken a fresh one meanwhile:
                    # remove only the file that was judged (#215). The pid content tells a fresh lock
                    # apart even when a freed inode comes back with the same coarse mtime.
                    if _lock_identity(lock) != judged:
                        continue
                    lock.unlink()
                    continue
                except FileNotFoundError:
                    continue
            _wait_for_lock(lock, deadline)
        except PermissionError:
            # Windows refuses to create a name whose previous file is still
            # delete-pending; that is contention, not a missing permission.
            if not fsx.WINDOWS:
                raise
            _wait_for_lock(lock, deadline)
    owner_pid = os.getpid()
    try:
        os.write(fd, f'{owner_pid}\n'.encode())
        yield fd
    finally:
        if os.getpid() == owner_pid:
            os.close(fd)
            _release_lock_file(lock)


@contextmanager
def runtime_lock(root: Path, name: str = 'state', timeout: float = 5.0, *, anchor=None) -> Iterator[None]:
    if anchor is not None:
        anchor.check_root(root)
        from .trace_storage import native_lock
        with native_lock(anchor, name, timeout):
            yield
        return
    deadline = time.monotonic() + timeout
    lock = runtime_dir(root) / f'.{name}.lock'
    # Never unlink this file: every opener must lock the same retained inode.
    # The extra suffix also avoids agent_lifecycle's enclosing .agents.guard.
    guard = lock.with_name(f'.{name}.guard.lock')
    descriptor = _open_lock_guard(guard)
    locked = False
    contended = False
    lease = None
    try:
        while True:
            if contended and time.monotonic() >= deadline:
                raise TimeoutError(f'could not acquire runtime lock: {lock}')
            try:
                fsx.lock_file(descriptor, exclusive=True, blocking=False)
                locked = True
                break
            except OSError as error:
                if not (isinstance(error, BlockingIOError)
                        or (fsx.WINDOWS and error.errno in {errno.EACCES, errno.EDEADLK})):
                    raise
                contended = True
                _wait_for_lock(lock, deadline)
        # Only an uncontended acquisition gets the timeout=0 immediate attempt.
        # A retry must still have budget when it reaches the PID stage.
        with _pid_lock(lock, deadline, allow_immediate=not contended) as marker:
            from .trace_storage import retain_guard
            lease = retain_guard(root, name, descriptor, marker)
            try:
                yield
            finally:
                if lease is not None and os.getpid() == lease.pid:
                    lease.invalidate()
    finally:
        try:
            if lease is not None:
                lease.close()
            elif locked:
                # Windows needs an explicit unlock before close. Do it on POSIX
                # too, keeping the guard held through removal of the PID marker.
                fsx.unlock_file(descriptor)
        finally:
            if lease is None:
                os.close(descriptor)


def active_route_path(root: Path) -> Path:
    return root / '.getzilla/runtime/active-route.json'


_UNBOUND = object()
_SESSION: contextvars.ContextVar = contextvars.ContextVar('getzilla_session', default=_UNBOUND)
_TRANSITIONS: contextvars.ContextVar[tuple[str, ...]] = contextvars.ContextVar('getzilla_transitions', default=())
_SESSION_ID = re.compile(r'[A-Za-z0-9._-]{1,128}')
_ROUTE_ID = re.compile(r'[A-Za-z0-9_-]{1,128}')


def bind_session(session_id: str | None) -> None:
    """Route reads in this process belong to ``session_id``; hooks bind it from their payload (#80)."""
    valid = isinstance(session_id, str) and session_id != 'manual' and _SESSION_ID.fullmatch(session_id)
    _SESSION.set(session_id if valid else None)


def current_session() -> str | None:
    selected = _SESSION.get()
    if selected is _UNBOUND:
        selected = os.environ.get('GETZILLA_SESSION_ID') or os.environ.get('CLAUDE_CODE_SESSION_ID')
    return selected if isinstance(selected, str) and selected != 'manual' and _SESSION_ID.fullmatch(selected) else None


def _runtime(root: Path) -> Path:
    return root / '.getzilla/runtime'


def _safe_parents(root: Path, relative: Path) -> tuple[list[fsx.DirHandle], list[tuple]]:
    handles = [fsx.open_dir(root, flags=fsx.O_CLOEXEC)]
    identities = []
    try:
        for name in relative.parts:
            if name in {'', '.', '..'}:
                raise ValueError('unsafe-state-path')
            try:
                fsx.mkdir_at(handles[-1], name, 0o700)
            except FileExistsError:
                pass
            child = fsx.open_dir_at(handles[-1], name, flags=fsx.O_CLOEXEC)
            info = fsx.fstat_dir(child)
            identities.append((handles[-1], name, info.st_dev, info.st_ino))
            handles.append(child)
        return handles, identities
    except BaseException:
        for handle in reversed(handles):
            fsx.close_dir(handle)
        raise


def durable_json(root: Path, path: Path, value: Any, *, anchor=None) -> None:
    """Publish through pinned no-follow directories, with file and directory durability."""
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('utf-8')
    durable_bytes(root, path, raw, anchor=anchor)


def durable_bytes(root: Path, path: Path, raw: bytes, *, anchor=None) -> None:
    relative = path.relative_to(root)
    if anchor is not None:
        anchor.check_root(root)
        anchor.write(relative, raw)
        return
    handles, identities = _safe_parents(root, relative.parent)
    temporary = '.task-' + secrets.token_hex(16) + '.tmp'
    created = False
    try:
        from .native_state_snapshot import metadata_limit,write as write_snapshot
        limit = metadata_limit(relative)
        if limit is not None:
            def check_snapshot_parents():
                for parent,name,device,inode in identities:
                    info = fsx.lstat_at(parent,name)
                    if fsx.is_link(info) or (info.st_dev,info.st_ino) != (device,inode):
                        raise ValueError('state-directory-changed')
            if fsx.effective_uid() is None:
                # No POSIX owner/private-mode proof exists on this backend.
                # Keep only the old unframed workflow behavior. This bounded
                # format probe returns no contents or reader/ACL authority.
                from .package_status import read_package_file
                from .native_state_snapshot import HEADER,decode
                decode(raw,limit=limit)
                try:
                    fsx.lstat_at(handles[-1],relative.name)
                except FileNotFoundError:
                    pass
                else:
                    existing = read_package_file(root,relative.as_posix(),limit=limit)
                    if HEADER in existing:
                        raise ValueError('native_state_snapshot_platform_unsupported')
                    decode(existing,limit=limit)  # Also rejects partial/ambiguous framing.
                    check_snapshot_parents()
            elif write_snapshot(handles[-1],relative.name,raw,limit=limit,
                                check=check_snapshot_parents,framed_only=True):
                return
        descriptor = fsx.open_at(handles[-1], temporary,
                                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | fsx.O_NOFOLLOW | fsx.O_CLOEXEC, 0o600)
        created = True
        with os.fdopen(descriptor, 'wb') as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        for parent, name, device, inode in identities:
            info = fsx.lstat_at(parent, name)
            if fsx.is_link(info) or (info.st_dev, info.st_ino) != (device, inode):
                raise ValueError('state-directory-changed')
        try:
            info = fsx.lstat_at(handles[-1], relative.name)
        except FileNotFoundError:
            pass
        else:
            if fsx.is_link(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('unsafe-state-target')
        fsx.replace_at(handles[-1], temporary, handles[-1], relative.name)
        created = False
        fsx.fsync_dir(handles[-1])
    finally:
        if created:
            fsx.unlink_at(handles[-1], temporary)
        for handle in reversed(handles):
            fsx.close_dir(handle)


@contextmanager
def task_transition(root: Path, *, anchor=None, timeout=5.0) -> Iterator[None]:
    """Outer lock order: task transition, route, agents/approvals. Never hold over tools."""
    if anchor is not None:
        anchor.check_root(root)
    key = anchor.workspace if anchor is not None else str(root.resolve())
    active = _TRANSITIONS.get()
    if anchor is not None and key in active:
        from .trace_storage import held_guard
        held_guard(anchor, 'task-transition')
        yield
        return
    if key in active:
        yield
        return
    if anchor is None:
        handles, _ = _safe_parents(root, Path('.getzilla/runtime'))
        for handle in reversed(handles):
            fsx.close_dir(handle)
    with runtime_lock(root, 'task-transition', timeout=timeout, anchor=anchor):
        token = _TRANSITIONS.set((*active, key))
        try:
            yield
        finally:
            _TRANSITIONS.reset(token)


def serialized_task(function):
    @wraps(function)
    def wrapped(root: Path, *args, **kwargs):
        with task_transition(root, anchor=kwargs.get('anchor')):
            return function(root, *args, **kwargs)
    return wrapped


def _route_document(root: Path, path: Path, *, limit: int = 1_048_576, anchor=None) -> dict[str, Any]:
    from .package_status import read_package_file
    from .spec import _pairs_object, _reject_constant
    if anchor is not None:
        anchor.check_root(root)
    raw = (anchor.read(path.relative_to(root).as_posix(), limit) if anchor is not None
           else read_package_file(root, path.relative_to(root).as_posix(), limit=limit))
    from .native_state_snapshot import metadata_limit,decode
    allocated = metadata_limit(path.relative_to(root))
    if allocated is not None:
        raw = decode(raw,limit=min(limit,allocated))
    value = json.loads(raw, object_pairs_hook=_pairs_object, parse_constant=_reject_constant)
    if not isinstance(value, dict):
        raise ValueError('invalid-route-document')
    return value


def canonical_route(root: Path, route_id: str, *, anchor=None) -> dict[str, Any]:
    from .continuity import validate_route
    if not isinstance(route_id, str) or not _ROUTE_ID.fullmatch(route_id):
        raise ValueError('invalid-route-id')
    route = _route_document(root, _runtime(root) / 'routes' / f'{route_id}.json', anchor=anchor)
    if route.get('route_id') != route_id:
        raise ValueError('canonical-route-mismatch')
    validate_route(root, route, anchor=anchor)
    return route


def _present(root, path, anchor=None):
    if anchor is not None:
        anchor.check_root(root)
    return anchor.exists(path.relative_to(root)) if anchor is not None else path.exists() or path.is_symlink()


def discovered_route(root: Path, *, anchor=None) -> dict[str, Any] | None:
    """Read-only global discovery never changes session or grants mutation authority."""
    from .continuity import has_task_context, validate_route
    path = _runtime(root) / 'active-route.json'
    if not _present(root, path, anchor):
        return None
    try:
        locator = _route_document(root, path, anchor=anchor)
        route_id = locator.get('route_id')
        if not isinstance(route_id, str) or not _ROUTE_ID.fullmatch(route_id):
            return None
        canonical = _runtime(root) / 'routes' / f'{route_id}.json'
        if _present(root, canonical, anchor):
            return canonical_route(root, route_id, anchor=anchor)
        if not has_task_context(locator):
            validate_route(root, locator, anchor=anchor)
            return locator
    except (OSError, ValueError):
        return None
    return None


def route_authority_present(root: Path, *, anchor=None) -> bool:
    paths = [_runtime(root) / 'active-route.json']
    session = current_session()
    if session:
        paths.append(_session_pointer(root, session))
    return any(_present(root, path, anchor) for path in paths)


def require_route_owner(root: Path, route: dict[str, Any] | None = None, *, anchor=None) -> dict[str, Any]:
    from .continuity import has_task_context
    route = get_active_route(root, anchor=anchor) if route is None else route
    if not route:
        raise ValueError('task authority unavailable; use explicit --session with --continue or --new-task')
    if has_task_context(route) and current_session() != route.get('session_id'):
        raise ValueError('task owner required; use explicit --session with --continue or --new-task')
    if anchor is not None and canonical_route(root, route['route_id'], anchor=anchor) != route:
        raise ValueError('canonical task context changed')
    return route


def _session_pointer(root: Path, session_id: str) -> Path:
    return _runtime(root) / 'sessions' / f'{session_id}.json'


def get_active_route(root: Path, *, anchor=None) -> dict[str, Any] | None:
    from .continuity import has_task_context
    session = current_session()
    if session:
        path = _session_pointer(root, session)
        if _present(root, path, anchor):
            try:
                pointer = _route_document(root, path, limit=4096, anchor=anchor)
                route = canonical_route(root, pointer.get('route_id'), anchor=anchor)
                fields = {'route_id', 'session_id', 'logical_task_id', 'authority_epoch'} if has_task_context(route) else {'route_id', 'session_id'}
                if set(pointer) != fields or pointer.get('session_id') != session or route.get('session_id') != session:
                    return None
                if has_task_context(route) and (
                    type(pointer.get('authority_epoch')) is not int or
                    pointer['authority_epoch'] != route['authority_epoch'] or
                    pointer['logical_task_id'] != route['logical_task_id']
                ):
                    return None
                return route
            except (OSError, ValueError, TypeError):
                return None
    route = discovered_route(root, anchor=anchor)
    if route and session and route.get('session_id') != session:
        legacy_owner = route.get('session_id')
        if has_task_context(route) or (isinstance(legacy_owner, str) and legacy_owner != 'manual' and _SESSION_ID.fullmatch(legacy_owner)):
            return None
    return route


CLOSED_CHANGE_STATUSES = frozenset({'released', 'archived', 'cancelled'})


class ActiveChangeConflict(RuntimeError):
    """A new route would orphan the open change package bound to another route."""

    def __init__(self, change_id: str, change_route_id: str, route_id: str) -> None:
        self.change_id = change_id
        self.change_route_id = change_route_id
        self.route_id = route_id
        super().__init__(
            f'open change package {change_id} is bound to route {change_route_id}; '
            f'refusing to activate route {route_id}. Finish or cancel the change first.'
        )


def open_change_binding(root: Path, *, anchor=None) -> tuple[str, str] | None:
    """Return (change_id, route_id) of the active change package while it is still open."""
    change = get_active_change(root, anchor=anchor)
    if change is None:
        return None
    change_id, rel = change.get('change_id'), change.get('path')
    if not isinstance(change_id, str) or not isinstance(rel, str) or not rel:
        raise ValueError('selected change pointer is malformed')
    from .workflow_storage import valid_package_path
    package = root / rel if anchor is not None else (root / rel).resolve()
    if not valid_package_path(rel, change_id) or anchor is None and not package.is_relative_to(root.resolve()):
        raise ValueError('selected change path is unsafe')
    state = _route_document(root, root / rel / 'state.json', anchor=anchor)
    route_id = state.get('route_id')
    if not isinstance(route_id, str) or not _ROUTE_ID.fullmatch(route_id):
        raise ValueError('selected change state is malformed')
    from .continuity import validate_package_state
    validate_package_state(state, {'route_id': route_id}, change_id)
    if state['status'] in CLOSED_CHANGE_STATUSES:
        return None
    return change_id, route_id


def _publish_route_projections(root: Path, route: dict[str, Any], *, anchor=None) -> None:
    from .continuity import has_task_context
    session = route.get('session_id')
    if isinstance(session, str) and session != 'manual' and _SESSION_ID.fullmatch(session):
        pointer = {'route_id': route['route_id'], 'session_id': session}
        if has_task_context(route):
            pointer.update(logical_task_id=route['logical_task_id'], authority_epoch=route['authority_epoch'])
        durable_json(root, _session_pointer(root, session), pointer, anchor=anchor)
    durable_json(root, active_route_path(root), route, anchor=anchor)
    if has_task_context(route) and route.get('change_id') is None:
        selected = get_active_change(root, anchor=anchor)
        if selected is not None:
            if open_change_binding(root, anchor=anchor) is not None:
                raise ValueError('open package cannot be detached by route projection')
            if anchor is not None:
                if get_active_change(root, anchor=anchor) != selected:
                    raise ValueError('package pointer changed before projection repair')
                anchor.unlink('.getzilla/runtime/active-change.json')
                return
            handles, _ = _safe_parents(root, Path('.getzilla/runtime'))
            try:
                if get_active_change(root) != selected:
                    raise ValueError('package pointer changed before projection repair')
                fsx.unlink_at(handles[-1], 'active-change.json')
                fsx.fsync_dir(handles[-1])
            finally:
                for handle in reversed(handles):
                    fsx.close_dir(handle)


@serialized_task
def _commit_route(root: Path, route: dict[str, Any], *, expected: dict[str, Any] | None,
                  observation_only: bool = False, native_claim=None, anchor=None, lock_timeout=5.0) -> dict[str, Any]:
    from .continuity import validate_route
    if observation_only:
        if expected is None or native_claim is not None:
            raise ValueError('observation metadata requires canonical authority')
        require_route_owner(root, expected, anchor=anchor)
        allowed = {'observation_publication', 'observation_capture_failed', 'state_revision', 'updated_at'}
        if ({key: value for key, value in route.items() if key not in allowed}
                != {key: value for key, value in expected.items() if key not in allowed}
                or route.get('state_revision') != expected.get('state_revision', -1)+1):
            raise ValueError('observation metadata cannot change task authority')
        from .observation_privacy import local_identity
        local_identity(root, anchor=anchor)
    validate_route(root, route, anchor=anchor)
    with runtime_lock(root, 'route', anchor=anchor, timeout=lock_timeout):
        path = _runtime(root) / 'routes' / f"{route['route_id']}.json"
        exists = _present(root, path, anchor)
        actual = canonical_route(root, route['route_id'], anchor=anchor) if exists else None
        if actual != expected:
            raise ValueError('route changed before atomic update')
        if (actual is not None and 'execution_store_required' in actual
                and route.get('execution_store_required') != actual['execution_store_required']):
            raise ValueError('canonical execution store requirement is monotone')
        if actual and (actual.get('context') or {}).get('version') == 2 and (
                (route.get('context') or {}).get('version') != 2 or
                (route['context'].get('intake') or {}).get('required') is not True):
            raise ValueError('required intake cannot be downgraded')
        if ('sprint' in route or 'observation_publication' in route) and not observation_only:
            from .sprint_lifecycle import prepare_transition
            try:
                route = prepare_transition(root, copy.deepcopy(route), actual, native_claim=native_claim, anchor=anchor)
            except (OSError, ValueError, RuntimeError, TypeError, KeyError):
                if actual is None or not ('sprint' in actual or 'observation_publication' in actual):
                    raise ValueError('native_sprint_capture_unavailable') from None
                route['observation_capture_failed'] = True
        durable_json(root, path, route, anchor=anchor)
        if not observation_only:
            _publish_route_projections(root, route, anchor=anchor)
    return copy.deepcopy(route)


@serialized_task
def set_active_route(root: Path, route: dict[str, Any]) -> None:
    from .continuity import has_task_context
    route = copy.deepcopy(route)
    if has_task_context(route):
        require_route_owner(root, route)
    path = _runtime(root) / 'routes' / f"{route['route_id']}.json"
    existing = canonical_route(root, route['route_id']) if path.exists() or path.is_symlink() else None
    if existing is not None and existing != route and (has_task_context(existing) or has_task_context(route)):
        raise ValueError('use a task transition to update canonical authority')
    if existing is None:
        if has_task_context(route):
            from .continuity import _ensure_idle
            _ensure_idle(root)
            for locator in (active_route_path(root), _session_pointer(root, route['session_id'])):
                if locator.exists() or locator.is_symlink():
                    selected = _route_document(root, locator)
                    if selected.get('route_id') == route['route_id']:
                        raise ValueError('canonical task authority is missing; restore the original record, never recreate it')
        binding = open_change_binding(root)
        if binding and binding[1] != route['route_id']:
            raise ActiveChangeConflict(binding[0], binding[1], route['route_id'])
    _commit_route(root, route, expected=existing)
    if existing is None:
        from .metrics_journal import record_route
        record_route(root, route)


@serialized_task
def update_route(root: Path, *, expected_route: dict[str, Any] | None = None, **updates: Any) -> dict[str, Any] | None:
    from .continuity import has_task_context
    route = get_active_route(root)
    if not route:
        if route_authority_present(root):
            require_route_owner(root)
        return None
    require_route_owner(root, route)
    if ('execution_store_required' in updates
            and updates['execution_store_required'] != route.get('execution_store_required')):
        raise ValueError('execution store binding requires explicit provisioning')
    if expected_route is not None and route != expected_route:
        raise ValueError('route changed before atomic update')
    if has_task_context(route) and updates.get('status') in {'completed', 'cancelled', 'released', 'archived'}:
        from .continuity import assert_finishable
        assert_finishable(root, route, cancel=updates['status'] == 'cancelled')
    immutable = {'route_id', 'task', 'logical_task_id', 'origin_session_id', 'session_id', 'workspace',
                 'task_context_version', 'authority_epoch', 'state_revision', 'context', 'handoff',
                 'intent_state', 'sprint', 'observation_publication'}
    if has_task_context(route) and any(key in updates and updates[key] != route.get(key) for key in immutable | {'change_id'}):
        raise ValueError('immutable task authority requires an explicit task transition')
    changed = copy.deepcopy(route)
    changed.update(updates)
    changed['updated_at'] = now_utc()
    if has_task_context(route):
        changed['state_revision'] += 1
    return _commit_route(root, changed, expected=route)


@serialized_task
def arm_execution_store(root: Path, *, expected_route: dict[str, Any], generation: str) -> dict[str, Any]:
    """Arm only an existing durable store; this identity carries no stop progress."""
    from . import execution_store
    route = require_route_owner(root)
    if route != expected_route:
        raise ValueError('route changed before execution provisioning')
    registry = execution_store.load_registry(root)
    control = registry.get('controls', {}).get(route['route_id'])
    if (registry.get('schema_version') != 2 or registry.get('generation') != generation
            or not control or control['logical_task_id'] != route['logical_task_id']):
        raise ValueError('durable execution store is unavailable')
    binding = {'version': 1, 'generation': generation}
    if route.get('execution_store_required') == binding:
        return route
    if 'execution_store_required' in route:
        raise ValueError('canonical execution store requirement is monotone')
    updated = copy.deepcopy(route)
    updated['execution_store_required'] = binding
    updated['state_revision'] += 1
    updated['updated_at'] = now_utc()
    return _commit_route(root, updated, expected=route)


def agent_state_path(root: Path) -> Path:
    return root / '.getzilla/runtime/agent-state.json'


def get_agent_state(root: Path) -> dict[str, Any]:
    data = load_json(agent_state_path(root), {'active': {}, 'history': []})
    return data if isinstance(data, dict) else {'active': {}, 'history': []}


def record_agent_start(root: Path, agent_id: str, agent_type: str, *,
                       now: datetime | None = None, generation: str | None = None,
                       requirement_ids: tuple[str, ...] | None = None) -> dict[str, Any]:
    from .agent_lifecycle import start_agent
    scope = {} if requirement_ids is None else {'requirement_ids': requirement_ids}
    return start_agent(root, agent_id, agent_type, now=now, generation=generation, **scope)


def record_agent_stop(root: Path, agent_id: str, agent_type: str, *, generation: str | None = None,
                      now: datetime | None = None, final: bool = False) -> bool:
    """Record a stop once. Returns True on the first stop, False if already stopped."""
    from .agent_lifecycle import stop_agent
    return stop_agent(root, agent_id, agent_type, generation=generation, now=now, final=final)


def active_write_agents(root: Path, write_roles: set[str]) -> list[str]:
    state = get_agent_state(root)
    return [
        data.get('agent_type', '')
        for data in state.get('active', {}).values()
        if data.get('agent_type') in write_roles
    ]


def approvals_path(root: Path) -> Path:
    return runtime_dir(root) / 'approvals.json'


def _repository_identity(root: Path) -> str:
    from .git_platforms import parse_remote

    remote = git_output(root, 'config', '--get', 'remote.origin.url') or ''
    identity = parse_remote(remote)
    if identity is not None and identity.provider == 'github':
        return identity.repository  # Preserve existing valid GitHub grant bindings.
    if identity is not None and identity.provider == 'entire':
        return identity.resource  # Host and /et versus /gh must remain in the binding.
    raise RuntimeError('remote.origin.url must identify a supported GitHub or Entire repository without credentials')


def _grant_repository_identity(root: Path, scope: str) -> str:
    """Local grants have a separate identity; remote target checks stay remote-only."""
    try:
        return _repository_identity(root)
    except RuntimeError:
        if scope not in {'protected-path', 'external-write'} or \
                git_output(root, 'config', '--get', 'remote.origin.url') is not None:
            raise
        from .local_grant_identity import repository_identity
        return repository_identity(root)


def _active_change_id(root: Path) -> str | None:
    change = get_active_change(root) or {}
    value = change.get('change_id')
    from .continuity import has_task_context
    route = get_active_route(root)
    if route and has_task_context(route):
        from .workflow_storage import valid_package_path
        if value != route.get('change_id'):
            raise ValueError('grant package identity does not match canonical task')
        if value is not None:
            if not valid_package_path(change.get('path'), value):
                raise ValueError('grant package path is invalid')
            package = _route_document(root, root / change['path'] / 'state.json')
            from .continuity import validate_package_state
            validate_package_state(package, route, value)
    return str(value) if value else None


_GRANT_PATTERN_CHARACTERS = re.compile(r'[*?\[\]{}]')
# Category names the policy used to emit: one grant for them authorized every target (#53 review).
_CATEGORY_RESOURCES = frozenset({
    'github-api', 'github-pull-request-review', 'github-pr-review', 'direct-http-write',
    'github-api:unparsed', 'github-pr-review:unparsed',
})
_GITHUB_TARGET = re.compile(r'^(github-pr-review:)?([\w.-]+/[\w.-]+)(#\S+)$')
_CONTROL_PLANE_DIRECTORIES = frozenset({
    '.agents', '.grok', '.qwen', '.claude', '.codex', '.gemini', '.getzilla', '.github', 'trust-ci',
})



def _normalize_grant_resource(scope: str, raw: str) -> str:
    """One exact grant resource; wildcard patterns are forbidden by AGENTS.md (issue #38).

    Protected paths must be plain repository-relative file paths. External and
    production resources name one exact target: a URL (``?`` query allowed), an MCP
    tool, ``github-api:<METHOD> <host>/<endpoint>``, ``github-pr-review:<owner>/<repo>#<n>``,
    a branch or tag, ``<owner>/<repo>#<n>`` for a merge, or an image/package reference.
    """
    resource = raw.replace('\\', '/').strip()
    patterns = _GRANT_PATTERN_CHARACTERS if scope == 'protected-path' else re.compile(r'[*\[\]]')
    if patterns.search(resource) or any(ord(char) < 32 or ord(char) == 127 for char in resource):
        raise ValueError(
            f'{scope} grants require exact resources; wildcard pattern {resource!r} is forbidden'
        )
    if resource in _CATEGORY_RESOURCES or resource.endswith((':', '#')):
        raise ValueError(f'{scope} grants require an exact target, not the category {resource!r}')
    if scope == 'protected-path':
        while resource.startswith('./'):
            resource = resource[2:]
        # Percent-encoding can smuggle traversal (%2e%2e) or separators past the split
        # checks below; a grant path must be a literal, not an encoded one (review P53-5).
        if urllib.parse.unquote(resource) != resource:
            raise ValueError(
                f'protected-path grants must be literal paths, not percent-encoded: {raw!r}'
            )
        parts = resource.split('/')
        if (
            not resource
            or resource.startswith(('/', '~'))
            or ':' in resource
            or any(part in {'', '.', '..'} or part.endswith(('.', ' ')) for part in parts)
        ):
            raise ValueError(
                f'protected-path grants require an exact repository-relative file path, not {raw!r}'
            )
        # A bare control-plane directory would authorize nothing useful under exact-match,
        # but refuse it so a grant always names a file, never a whole engine directory.
        if resource in _CONTROL_PLANE_DIRECTORIES:
            raise ValueError(
                f'protected-path grants must name a file inside {resource!r}, not the directory'
            )
        return resource
    match = _GITHUB_TARGET.match(resource)
    if match:
        # GitHub owner/repository names are case-insensitive; the policy compares them lower-cased.
        return f'{match.group(1) or ""}{match.group(2).lower()}{match.group(3)}'
    if scope == 'production':
        return resource.removeprefix('refs/heads/').removeprefix('refs/tags/')
    return resource


class GrantExtensionError(ValueError):
    """Fixed diagnostic; never a request to mint a replacement grant."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _grant_digest(value: Any) -> str:
    import hashlib
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def _grant_time(value: Any) -> datetime:
    if type(value) is not str or len(value) > 40:
        raise ValueError('invalid grant timestamp')
    result = datetime.fromisoformat(value)
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError('invalid grant timestamp')
    return result


_EXTENSION_FIELDS = {'schema_version', 'kind', 'request_id', 'parent_id',
                     'parent_record_sha256', 'request_sha256'}
_FORMER_FIELDS = {'schema_version', 'source', 'repository', 'route_id', 'logical_task_id', 'authority_epoch',
                  'owner_session_id', 'session_id', 'change_id', 'binding', 'git_branch', 'anchor_commit',
                  'git_head', 'grant_binding_digest', 'resources', 'created_at'}
_SUPERSESSION_FIELDS = {'schema_version', 'kind', 'status', 'id', 'parent_record_sha256', 'former',
                       'request_id', 'request_sha256', 'successor_id', 'successor_record_sha256',
                       'superseded_at', 'expires_at'}


def _grant_hex(value: Any, width: int) -> bool:
    return type(value) is str and re.fullmatch('[0-9a-f]{' + str(width) + '}', value) is not None


def _extension_metadata(value: Any) -> None:
    if (type(value) is not dict or set(value) != _EXTENSION_FIELDS or type(value['schema_version']) is not int
            or value['schema_version'] != 1
            or value['kind'] != 'exact-protected-path-extension'
            or not _grant_hex(value['request_id'], 32) or not _grant_hex(value['parent_id'], 16)
            or not all(_grant_hex(value[key], 64) for key in ('parent_record_sha256', 'request_sha256'))):
        raise ValueError('unsupported extension metadata')


def approval_record_kind(value: Any) -> str:
    """Closed non-authority history, ordinary v2 authority, or inactive legacy."""
    if type(value) is not dict:
        raise ValueError('unsupported grant record')
    if type(value.get('schema_version')) is int and value['schema_version'] == 2:
        if 'kind' in value or 'status' in value:
            raise ValueError('unsupported grant kind or status')
        if 'extension' in value:
            _extension_metadata(value['extension'])
            if value.get('scope') != 'protected-path' or value.get('binding') != BRANCH_RESOURCES_BINDING:
                raise ValueError('unsupported extension scope')
        return 'active'
    if type(value.get('schema_version')) is int and value['schema_version'] == 3:
        if (set(value) != _SUPERSESSION_FIELDS or value['kind'] != 'protected-path-grant-supersession-v1'
                or value['status'] != 'superseded' or not _grant_hex(value['id'], 16)
                or not _grant_hex(value['successor_id'], 16) or not _grant_hex(value['request_id'], 32)
                or not all(_grant_hex(value[key], 64) for key in
                           ('parent_record_sha256', 'request_sha256', 'successor_record_sha256'))):
            raise ValueError('unsupported grant supersession')
        former = value['former']
        if (type(former) is not dict or set(former) != _FORMER_FIELDS
                or type(former['schema_version']) is not int or former['schema_version'] != 2
                or former['binding'] != BRANCH_RESOURCES_BINDING or former['source'] not in APPROVAL_SOURCES
                or type(former['authority_epoch']) is not int or former['authority_epoch'] < 0
                or not _grant_hex(former['grant_binding_digest'], 64)
                or former['anchor_commit'] != former['git_head']
                or type(former['git_head']) is not str
                or not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', former['git_head'])
                or any(type(former[key]) is not str or not former[key] or len(former[key]) > 1024
                       for key in ('repository', 'route_id', 'logical_task_id', 'owner_session_id', 'session_id', 'git_branch'))
                or former['change_id'] is not None and type(former['change_id']) is not str):
            raise ValueError('unsupported former grant binding')
        if _extension_resources(former['resources']) != former['resources']:
            raise ValueError('noncanonical former resources')
        for timestamp in (value['superseded_at'], value['expires_at'], former['created_at']):
            _grant_time(timestamp)
        return 'supersession'
    if type(value.get('schema_version')) is int and value['schema_version'] == 1 and 'kind' not in value and 'status' not in value:
        return 'inactive'
    raise ValueError('unsupported grant record')


def _read_approvals(root: Path, binding) -> tuple[Any, list[dict[str, Any]]]:
    from .spec import _pairs_object, _reject_constant
    snapshot = binding.read('.getzilla/runtime/approvals.json', limit=1_048_576)
    if snapshot is None:
        return None, []
    try:
        rows = json.loads(snapshot.content, object_pairs_hook=_pairs_object, parse_constant=_reject_constant)
        if type(rows) is not list or len(rows) > 200:
            raise ValueError('unsupported approval store')
        identifiers = [row.get('id') for row in rows if type(row) is dict]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError('duplicate approval identifier')
        for row in rows:
            approval_record_kind(row)
        validate_approval_history(rows)
        return snapshot, rows
    except (ValueError, TypeError, RecursionError) as error:
        raise ValueError('unsupported approval store') from error


def validate_approval_history(rows: list[dict]) -> None:
    """Check retained links without requiring pruned history or following successors for authority."""
    for row in rows:
        approval_record_kind(row)
    for row in rows:
        if approval_record_kind(row) != 'supersession':
            continue
        successors = [candidate for candidate in rows if candidate.get('id') == row['successor_id']]
        if not successors:
            continue
        if len(successors) != 1:
            raise ValueError('ambiguous supersession link')
        successor = successors[0]
        kind = approval_record_kind(successor)
        if kind == 'supersession':
            digest = successor['parent_record_sha256']
        elif kind == 'active':
            digest = _grant_digest(successor)
            if successor.get('extension') != {
                'schema_version': 1, 'kind': 'exact-protected-path-extension',
                'request_id': row['request_id'], 'parent_id': row['id'],
                'parent_record_sha256': row['parent_record_sha256'], 'request_sha256': row['request_sha256'],
            }:
                raise ValueError('conflicting supersession metadata')
        else:
            raise ValueError('conflicting supersession kind')
        if digest != row['successor_record_sha256']:
            raise ValueError('conflicting supersession digest')


def _extension_resources(resources: Any) -> list[str]:
    if type(resources) not in (list, tuple) or not 1 <= len(resources) <= 1024:
        raise ValueError('invalid extension resources')
    if any(type(value) is not str or len(value.encode('utf-8')) > 4096 for value in resources):
        raise ValueError('invalid extension resources')
    if sum(len(value.encode('utf-8')) for value in resources) > 262144:
        raise ValueError('invalid extension resources')
    return sorted({_normalize_grant_resource('protected-path', value) for value in resources})


def add_approval(
    root: Path,
    scope: str,
    reason: str,
    ttl_minutes: int = 15,
    *,
    actions: list[str] | tuple[str, ...] | set[str] | None = None,
    resources: list[str] | tuple[str, ...] | set[str] | None = None,
    source: str = 'standing-user-consent',
) -> dict[str, Any]:
    """Bind protected edits to a branch/file set; other actions retain exact source binding."""
    from .grant_authoring import add_approval
    return add_approval(root, scope, reason, ttl_minutes, actions=actions, resources=resources, source=source)


def _extension_context(root: Path) -> tuple[dict, dict]:
    from .grant_authoring import _extension_context
    return _extension_context(root)


def _extension_parent_shape(parent: dict) -> None:
    from .grant_authoring import _extension_parent_shape
    return _extension_parent_shape(parent)


def _extension_current(root: Path, parent: dict, context: dict, route: dict,
                       *, combined: list[str] | None = None) -> str:
    # Revalidate the captured record without consulting a store that may now contain its tombstone.
    from .grant_authoring import _extension_current
    return _extension_current(root, parent, context, route, combined=combined)


def _extension_result(status: str, code: str, grant: dict | None = None) -> dict[str, Any]:
    from .grant_authoring import _extension_result
    return _extension_result(status, code, grant)


def extend_protected_path_approval(
    root: Path, parent_id: str, request_id: str, reason: str, ttl_minutes: int = 15, *,
    actions: list[str] | tuple[str, ...], resources: list[str] | tuple[str, ...],
    source: str = 'standing-user-consent',
) -> dict[str, Any]:
    """Replace one current protected grant with an explicitly delegated strict superset.

    One store publication contains both the non-authority history and the ordinary successor.
    A request ID is only an idempotency key; it does not supply consent or recover revoked authority.
    """
    from .grant_authoring import extend_protected_path_approval
    return extend_protected_path_approval(root, parent_id, request_id, reason, ttl_minutes, actions=actions, resources=resources, source=source)


def _extend_protected_path_approval(
    root: Path, parent_id: str, request_id: str, reason: str, ttl_minutes: int, *,
    actions: list[str] | tuple[str, ...], resources: list[str] | tuple[str, ...], source: str,
) -> dict[str, Any]:
    from .grant_authoring import _extend_protected_path_approval
    return _extend_protected_path_approval(root, parent_id, request_id, reason, ttl_minutes, actions=actions, resources=resources, source=source)


@serialized_task
def has_valid_approval(
    root: Path,
    scope: str,
    *,
    action: str | None = None,
    resource: str | None = None,
) -> bool:
    """Recheck exact task/epoch/owner and all existing source, resource and TTL fences."""
    route = get_active_route(root)
    if route:
        try:
            require_route_owner(root, route)
        except ValueError:
            return False
    elif route_authority_present(root):
        return False
    route = route or {}
    if scope in {'production', 'external-write'} and action:
        from .human_gates import gate_block_reason

        # Production human gates decide per action; the grant itself binds the exact target.
        if gate_block_reason(root, scope, action, resource if scope == 'external-write' else None):
            return False
    from .fsx import ReadOnlyBoundRoot
    try:
        with ReadOnlyBoundRoot(root) as binding:
            _snapshot, approvals = _read_approvals(root, binding)
    except (OSError, ValueError):
        return False
    try:
        repository = _grant_repository_identity(root, scope)
    except RuntimeError:
        return False
    local_repository = repository.startswith('local-git-v1:')
    if local_repository and not current_session():
        return False
    head = git_head(root)
    if not head:
        return False
    try:
        change_id = _active_change_id(root)
    except (ValueError, OSError):
        return False
    bindings = {
        'repository': repository,
        'route_id': route.get('route_id'),
        'change_id': change_id,
        'git_head': head,
    }
    now = datetime.now(timezone.utc)
    normalized_resource = resource.replace('\\', '/') if resource else None
    for approval in approvals:
        if approval_record_kind(approval) != 'active':
            continue
        query = {**bindings, '_query': (scope, action, normalized_resource)}
        if _approval_matches(root, approval, route, query, head, now, strict='extension' in approval):
            return True
    return False


def _approval_matches(root: Path, approval: dict, route: dict, bindings: dict, head: str,
                      now: datetime, *, strict: bool = False) -> bool:
    from .continuity import has_task_context, legacy_evidence_allowed, task_identity
    scope, action, normalized_resource = bindings['_query']
    if (bindings.get('repository', '').startswith('local-git-v1:')
            and approval.get('session_id') != current_session()):
        return False
    try:
        expires = datetime.fromisoformat(str(approval['expires_at']))
    except (KeyError, TypeError, ValueError):
        return False
    if expires < now:
        return False
    if approval.get('schema_version') != 2:
        return False
    if approval.get('authorization') != 'delegated-local-grant':
        return False
    if approval.get('scope') != scope:
        return False
    branch_bound = scope == 'protected-path' and approval.get('binding') == BRANCH_RESOURCES_BINDING
    continuity_fields = {'logical_task_id', 'authority_epoch', 'owner_session_id'}
    if continuity_fields.intersection(approval):
        if (not continuity_fields.issubset(approval) or type(approval.get('authority_epoch')) is not int or
                approval['logical_task_id'] != task_identity(route) or
                approval['authority_epoch'] != route.get('authority_epoch', 0) or
                approval['owner_session_id'] != route.get('session_id')):
            return False
    elif has_task_context(route) and (
            not legacy_evidence_allowed(route) or route.get('origin_session_id') != route.get('session_id')):
        return False
    if any(approval.get(key) != value for key, value in bindings.items() if key != '_query'
           if not (branch_bound and key == 'git_head')):
        return False
    grant_binding_digest = approval.get('grant_binding_digest')
    legacy_tree_fingerprint = approval.get('tree_fingerprint')
    if grant_binding_digest is not None and legacy_tree_fingerprint is not None:
        return False
    binding = approval.get('binding')
    if binding is None:
        expected_digest = tree_fingerprint(root)
    elif branch_bound:
        anchor = approval.get('anchor_commit')
        branch = git_output(root, 'symbolic-ref', '--quiet', 'HEAD')
        if (not branch or branch != approval.get('git_branch')
                or not isinstance(anchor, str) or not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', anchor)
                or anchor != approval.get('git_head')
                or git_output(root, 'merge-base', '--is-ancestor', anchor, head) is None):
            return False
        try:
            expected_digest = tree_fingerprint(root, approval.get('resources') or [], anchor=anchor,
                                               **({'strict': True} if strict else {}))
        except (OSError, ValueError):
            return False
    elif binding == GRANTED_RESOURCES_BINDING and approval.get('scope') == 'protected-path':
        expected_digest = tree_fingerprint(root, approval.get('resources') or [])
    else:
        return False
    if (grant_binding_digest or legacy_tree_fingerprint) != expected_digest:
        return False
    if action and action not in set(approval.get('actions') or []):
        return False
    # Exact equality only: a stored pattern (legacy or hand-edited) never widens a grant.
    resources = {str(item).replace('\\', '/') for item in approval.get('resources') or []}
    if normalized_resource is not None and normalized_resource not in resources:
        return False
    return True


def approval_mismatch(root: Path, scope: str, *, action: str, resource: str | None) -> str:
    """Why no recorded grant covers this action: a hint for the refusal, never an authorization.

    An agent that recorded a grant and was refused again needs the reason, not a bare repeat.
    """
    from .fsx import ReadOnlyBoundRoot
    try:
        with ReadOnlyBoundRoot(root) as binding:
            _snapshot, approvals = _read_approvals(root, binding)
    except (OSError, ValueError):
        return ''
    now = datetime.now(timezone.utc)
    head = git_head(root) or ''
    route = (get_active_route(root) or {}).get('route_id')
    normalized = resource.replace('\\', '/') if resource else None
    reasons: list[str] = []
    for approval in approvals:
        if approval_record_kind(approval) != 'active' or approval.get('authorization') != 'delegated-local-grant':
            continue
        try:
            if datetime.fromisoformat(str(approval['expires_at'])) < now:
                continue
        except (KeyError, TypeError, ValueError):
            continue
        actions = set(approval.get('actions') or [])
        resources = {str(item).replace('\\', '/') for item in approval.get('resources') or []}
        if action not in actions and (normalized is None or normalized not in resources):
            continue
        if approval.get('scope') != scope:
            reasons.append(f'a grant for it was recorded with scope {approval.get("scope")}, but this needs scope {scope}')
        elif action not in actions:
            reasons.append(f'the {scope} grant names actions {sorted(actions)}, not {action}')
        elif normalized is not None and normalized not in resources:
            reasons.append(f'the {scope} grant for {action} names {sorted(resources)}, not {normalized}')
        elif approval.get('route_id') != route:
            reasons.append('the grant belongs to a different task route or owner; select the exact task with --session and --continue')
        elif approval.get('git_head') != head:
            reasons.append(f'the grant is bound to commit {str(approval.get("git_head"))[:12]}, '
                           f'but HEAD is now {head[:12]}')
        else:
            reasons.append('the grant no longer matches the change, the work tree or this repository')
    if not reasons:
        return ''
    return (f' A recorded grant does not cover it: {reasons[-1]}. Another grant is not consent for this one: '
            f'only with the owner\'s delegation for exactly `--action {action}`'
            + (f' and `--resource {normalized}`' if normalized else '') + ' record that grant, then retry once.')


def active_change_path(root: Path) -> Path:
    return root / '.getzilla/runtime/active-change.json'


@serialized_task
def set_active_change(root: Path, data: dict[str, Any]) -> None:
    from .continuity import has_task_context
    route = get_active_route(root)
    if not route and route_authority_present(root):
        raise ValueError('task authority unavailable; cannot change its package projection')
    if route and has_task_context(route):
        require_route_owner(root, route)
        if route.get('change_id') != data.get('change_id'):
            raise ValueError('package projection does not match canonical task attachment')
    durable_json(root, active_change_path(root), data)


def get_active_change(root: Path, *, anchor=None) -> dict[str, Any] | None:
    path = active_change_path(root)
    if not _present(root, path, anchor):
        return None
    return _route_document(root, path, limit=4096, anchor=anchor)


def stop_attempts_path(root: Path) -> Path:
    return runtime_dir(root) / 'stop-attempts.json'


def _stop_attempts(root: Path) -> dict[str, Any]:
    path = stop_attempts_path(root)
    if not path.exists() and not path.is_symlink():
        return {}
    return _route_document(root, path, limit=262144)


def increment_stop_attempt(root: Path, route_id: str, *, observation: str | None = None) -> int:
    with runtime_lock(root, 'stop'):
        data = _stop_attempts(root)
        previous = data.get(route_id, 0)
        if isinstance(previous, dict):
            if (set(previous) != {'observation', 'attempts'} or not isinstance(previous['observation'], str)
                    or not re.fullmatch(r'[0-9a-f]{64}', previous['observation'])):
                raise ValueError('invalid stop retry state')
            count = previous['attempts']
        else:
            count = previous
        if type(count) is not int or not 0 <= count <= 1_000_000:
            raise ValueError('invalid stop retry count')
        if observation is not None:
            if not isinstance(observation, str) or not re.fullmatch(r'[0-9a-f]{64}', observation):
                raise ValueError('invalid stop observation')
            if isinstance(previous, dict) and previous['observation'] != observation:
                count = 0
        value = min(count + 1, 1_000_000)
        data[route_id] = {'observation': observation, 'attempts': value} if observation is not None else value
        durable_json(root, stop_attempts_path(root), data)
        return value


def reset_stop_attempt(root: Path, route_id: str) -> None:
    with runtime_lock(root, 'stop'):
        data = _stop_attempts(root)
        if route_id in data:
            data.pop(route_id)
            durable_json(root, stop_attempts_path(root), data)
