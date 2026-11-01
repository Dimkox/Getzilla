from __future__ import annotations

import os
import copy
import json
import errno
import re
import secrets
import stat
import time
import urllib.parse
import contextvars
from contextlib import contextmanager
from functools import wraps
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from . import fsx
from .util import (
    dump_json,
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
        descriptor = fsx.open_at(parent, guard.name,
                                 os.O_CREAT | os.O_RDWR | fsx.O_BINARY | fsx.O_NOINHERIT
                                 | fsx.O_NOFOLLOW | fsx.O_NONBLOCK, 0o600)
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
    try:
        os.write(fd, f'{os.getpid()}\n'.encode())
        yield
    finally:
        os.close(fd)
        _release_lock_file(lock)


@contextmanager
def runtime_lock(root: Path, name: str = 'state', timeout: float = 5.0) -> Iterator[None]:
    deadline = time.monotonic() + timeout
    lock = runtime_dir(root) / f'.{name}.lock'
    # Never unlink this file: every opener must lock the same retained inode.
    # The extra suffix also avoids agent_lifecycle's enclosing .agents.guard.
    guard = lock.with_name(f'.{name}.guard.lock')
    descriptor = _open_lock_guard(guard)
    locked = False
    contended = False
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
        with _pid_lock(lock, deadline, allow_immediate=not contended):
            yield
    finally:
        try:
            if locked:
                # Windows needs an explicit unlock before close. Do it on POSIX
                # too, keeping the guard held through removal of the PID marker.
                fsx.unlock_file(descriptor)
        finally:
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


def durable_json(root: Path, path: Path, value: Any) -> None:
    """Publish through pinned no-follow directories, with file and directory durability."""
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('utf-8')
    durable_bytes(root, path, raw)


def durable_bytes(root: Path, path: Path, raw: bytes) -> None:
    relative = path.relative_to(root)
    handles, identities = _safe_parents(root, relative.parent)
    temporary = '.task-' + secrets.token_hex(16) + '.tmp'
    created = False
    try:
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
def task_transition(root: Path) -> Iterator[None]:
    """Outer lock order: task transition, route, agents/approvals. Never hold over tools."""
    key = str(root.resolve())
    active = _TRANSITIONS.get()
    if key in active:
        yield
        return
    handles, _ = _safe_parents(root, Path('.getzilla/runtime'))
    for handle in reversed(handles):
        fsx.close_dir(handle)
    with runtime_lock(root, 'task-transition'):
        token = _TRANSITIONS.set((*active, key))
        try:
            yield
        finally:
            _TRANSITIONS.reset(token)


def serialized_task(function):
    @wraps(function)
    def wrapped(root: Path, *args, **kwargs):
        with task_transition(root):
            return function(root, *args, **kwargs)
    return wrapped


def _route_document(root: Path, path: Path, *, limit: int = 1_048_576) -> dict[str, Any]:
    from .package_status import read_package_file
    from .spec import _pairs_object, _reject_constant
    raw = read_package_file(root, path.relative_to(root).as_posix(), limit=limit)
    value = json.loads(raw, object_pairs_hook=_pairs_object, parse_constant=_reject_constant)
    if not isinstance(value, dict):
        raise ValueError('invalid-route-document')
    return value


def canonical_route(root: Path, route_id: str) -> dict[str, Any]:
    from .continuity import validate_route
    if not isinstance(route_id, str) or not _ROUTE_ID.fullmatch(route_id):
        raise ValueError('invalid-route-id')
    route = _route_document(root, _runtime(root) / 'routes' / f'{route_id}.json')
    if route.get('route_id') != route_id:
        raise ValueError('canonical-route-mismatch')
    validate_route(root, route)
    return route


def discovered_route(root: Path) -> dict[str, Any] | None:
    """Read-only global discovery never changes session or grants mutation authority."""
    from .continuity import has_task_context, validate_route
    path = _runtime(root) / 'active-route.json'
    if not path.exists() and not path.is_symlink():
        return None
    try:
        locator = _route_document(root, path)
        route_id = locator.get('route_id')
        if not isinstance(route_id, str) or not _ROUTE_ID.fullmatch(route_id):
            return None
        canonical = _runtime(root) / 'routes' / f'{route_id}.json'
        if canonical.exists() or canonical.is_symlink():
            return canonical_route(root, route_id)
        if not has_task_context(locator):
            validate_route(root, locator)
            return locator
    except (OSError, ValueError):
        return None
    return None


def route_authority_present(root: Path) -> bool:
    paths = [_runtime(root) / 'active-route.json']
    session = current_session()
    if session:
        paths.append(_session_pointer(root, session))
    return any(path.exists() or path.is_symlink() for path in paths)


def require_route_owner(root: Path, route: dict[str, Any] | None = None) -> dict[str, Any]:
    from .continuity import has_task_context
    route = get_active_route(root) if route is None else route
    if not route:
        raise ValueError('task authority unavailable; use explicit --session with --continue or --new-task')
    if has_task_context(route) and current_session() != route.get('session_id'):
        raise ValueError('task owner required; use explicit --session with --continue or --new-task')
    return route


def _session_pointer(root: Path, session_id: str) -> Path:
    return _runtime(root) / 'sessions' / f'{session_id}.json'


def get_active_route(root: Path) -> dict[str, Any] | None:
    from .continuity import has_task_context
    session = current_session()
    if session:
        path = _session_pointer(root, session)
        if path.exists() or path.is_symlink():
            try:
                pointer = _route_document(root, path, limit=4096)
                route = canonical_route(root, pointer.get('route_id'))
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
    route = discovered_route(root)
    if route and session and route.get('session_id') != session:
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


def open_change_binding(root: Path) -> tuple[str, str] | None:
    """Return (change_id, route_id) of the active change package while it is still open."""
    change = get_active_change(root)
    if change is None:
        return None
    change_id, rel = change.get('change_id'), change.get('path')
    if not isinstance(change_id, str) or not isinstance(rel, str) or not rel:
        raise ValueError('selected change pointer is malformed')
    from .workflow_storage import valid_package_path
    package = (root / rel).resolve()
    if not valid_package_path(rel, change_id) or not package.is_relative_to(root.resolve()):
        raise ValueError('selected change path is unsafe')
    state = _route_document(root, root / rel / 'state.json')
    if state.get('change_id') != change_id or not isinstance(state.get('route_id'), str) or not state.get('status'):
        raise ValueError('selected change state is malformed')
    if state.get('status') in CLOSED_CHANGE_STATUSES:
        return None
    route_id = state.get('route_id')
    return (change_id, route_id) if isinstance(route_id, str) and route_id else None


def _publish_route_projections(root: Path, route: dict[str, Any]) -> None:
    from .continuity import has_task_context
    session = route.get('session_id')
    if isinstance(session, str) and session != 'manual' and _SESSION_ID.fullmatch(session):
        pointer = {'route_id': route['route_id'], 'session_id': session}
        if has_task_context(route):
            pointer.update(logical_task_id=route['logical_task_id'], authority_epoch=route['authority_epoch'])
        durable_json(root, _session_pointer(root, session), pointer)
    durable_json(root, active_route_path(root), route)


@serialized_task
def _commit_route(root: Path, route: dict[str, Any], *, expected: dict[str, Any] | None) -> dict[str, Any]:
    from .continuity import validate_route
    validate_route(root, route)
    with runtime_lock(root, 'route'):
        path = _runtime(root) / 'routes' / f"{route['route_id']}.json"
        exists = path.exists() or path.is_symlink()
        actual = canonical_route(root, route['route_id']) if exists else None
        if actual != expected:
            raise ValueError('route changed before atomic update')
        durable_json(root, path, route)
        _publish_route_projections(root, route)
    return copy.deepcopy(route)


@serialized_task
def set_active_route(root: Path, route: dict[str, Any]) -> None:
    from .continuity import has_task_context
    route = copy.deepcopy(route)
    if has_task_context(route):
        require_route_owner(root, route)
    path = _runtime(root) / 'routes' / f"{route['route_id']}.json"
    existing = canonical_route(root, route['route_id']) if path.exists() or path.is_symlink() else None
    if existing is not None and existing != route:
        raise ValueError('use a task transition to update canonical authority')
    if existing is None:
        binding = open_change_binding(root)
        if binding and binding[1] != route['route_id']:
            raise ActiveChangeConflict(binding[0], binding[1], route['route_id'])
    _commit_route(root, route, expected=existing)
    if existing is None:
        from .route_metrics import record_route
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
    if expected_route is not None and route != expected_route:
        raise ValueError('route changed before atomic update')
    immutable = {'route_id', 'task', 'logical_task_id', 'origin_session_id', 'session_id', 'workspace',
                 'task_context_version', 'authority_epoch', 'state_revision', 'context', 'handoff'}
    if has_task_context(route) and any(key in updates and updates[key] != route.get(key) for key in immutable | {'change_id'}):
        raise ValueError('immutable task authority requires an explicit task transition')
    changed = copy.deepcopy(route)
    changed.update(updates)
    changed['updated_at'] = now_utc()
    if has_task_context(route):
        changed['state_revision'] += 1
    return _commit_route(root, changed, expected=route)


def agent_state_path(root: Path) -> Path:
    return root / '.getzilla/runtime/agent-state.json'


def get_agent_state(root: Path) -> dict[str, Any]:
    data = load_json(agent_state_path(root), {'active': {}, 'history': []})
    return data if isinstance(data, dict) else {'active': {}, 'history': []}


def record_agent_start(root: Path, agent_id: str, agent_type: str, *,
                       now: datetime | None = None, generation: str | None = None) -> dict[str, Any]:
    from .agent_lifecycle import start_agent
    return start_agent(root, agent_id, agent_type, now=now, generation=generation)


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


def _active_change_id(root: Path) -> str | None:
    change = get_active_change(root) or {}
    value = change.get('change_id')
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


@serialized_task
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
    from .continuity import normalize_route, task_identity
    route = get_active_route(root)
    if route:
        route = normalize_route(root, route)
        require_route_owner(root, route)
    elif route_authority_present(root):
        raise ValueError('task authority unavailable; cannot issue an unrouted grant')
    route = route or {}
    normalized_scope = scope.strip()
    normalized_reason = reason.strip()
    normalized_source = source.strip()
    if normalized_scope not in APPROVAL_SCOPES:
        raise ValueError(f'unsupported approval scope: {scope}')
    if not normalized_reason:
        raise ValueError('approval reason must not be empty')
    if normalized_source not in APPROVAL_SOURCES:
        raise ValueError(f'unsupported approval source: {source}')
    if isinstance(ttl_minutes, bool) or not 1 <= ttl_minutes <= 1440:
        raise ValueError('ttl_minutes must be between 1 and 1440')

    normalized_actions = sorted({str(item).strip() for item in (actions or []) if str(item).strip()})
    if not normalized_actions:
        raise ValueError('at least one explicit delegated action is required')
    unsupported = set(normalized_actions) - SCOPE_ACTIONS[normalized_scope]
    if unsupported:
        raise ValueError(f'actions are outside scope {normalized_scope}: {sorted(unsupported)}')

    normalized_resources = sorted({
        _normalize_grant_resource(normalized_scope, str(item)) for item in (resources or []) if str(item).strip()
    })
    if normalized_scope == 'production' and (not normalized_resources or '' in normalized_resources):
        raise ValueError(
            'production grants require exact nonblank resources; for example '
            '--action git-push-branch --resource fix/x'
        )
    if normalized_scope in {'external-write', 'protected-path'} and not normalized_resources:
        raise ValueError(f'{normalized_scope} grants require explicit resources')

    from .human_gates import gate_block_reason

    if normalized_scope == 'external-write':
        for resource in normalized_resources:
            gate_reason = gate_block_reason(root, normalized_scope, 'external-write', resource)
            if gate_reason:
                raise ValueError(gate_reason)
    else:
        for action in normalized_actions:
            gate_reason = gate_block_reason(root, normalized_scope, action)
            if gate_reason:
                raise ValueError(gate_reason)

    head = git_head(root)
    if not head:
        raise RuntimeError('an exact Git HEAD is required for delegated approval')
    branch = git_output(root, 'symbolic-ref', '--quiet', 'HEAD')
    if normalized_scope == 'protected-path' and not branch:
        raise ValueError('a named Git branch is required for protected-path approval')
    now = datetime.now(timezone.utc)
    approval = {
        'schema_version': 2,
        'id': secrets.token_hex(8),
        'authorization': 'delegated-local-grant',
        'source': normalized_source,
        'scope': normalized_scope,
        'actions': normalized_actions,
        'resources': normalized_resources,
        'reason': normalized_reason,
        'repository': _repository_identity(root),
        'route_id': route.get('route_id'),
        'logical_task_id': task_identity(route),
        'authority_epoch': route.get('authority_epoch', 0),
        'owner_session_id': route.get('session_id'),
        'change_id': _active_change_id(root),
        'git_head': head,
        **({'binding': BRANCH_RESOURCES_BINDING, 'git_branch': branch, 'anchor_commit': head,
            'session_id': current_session()}
           if normalized_scope == 'protected-path' else {}),
        'grant_binding_digest': tree_fingerprint(
            root, normalized_resources if normalized_scope == 'protected-path' else (),
            anchor=head if normalized_scope == 'protected-path' else None,
        ),
        'created_at': now.isoformat(timespec='seconds'),
        'expires_at': (now + timedelta(minutes=ttl_minutes)).isoformat(timespec='seconds'),
    }
    with runtime_lock(root, 'approvals'):
        approvals = load_json(approvals_path(root), [])
        if not isinstance(approvals, list):
            approvals = []
        approvals.append(approval)
        dump_json(approvals_path(root), approvals[-200:])
    from .route_metrics import record
    record(root, 'grant', approval.get('route_id'), event_id='grant:' + approval['id'], scope=approval['scope'])
    return approval


@serialized_task
def has_valid_approval(
    root: Path,
    scope: str,
    *,
    action: str | None = None,
    resource: str | None = None,
) -> bool:
    """Recheck exact task/epoch/owner and all existing source, resource and TTL fences."""
    from .continuity import has_task_context, legacy_evidence_allowed, task_identity
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
    approvals = load_json(approvals_path(root), [])
    if not isinstance(approvals, list):
        return False
    try:
        repository = _repository_identity(root)
    except RuntimeError:
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
    current_binding_digest = tree_fingerprint(root)
    now = datetime.now(timezone.utc)
    kept: list[dict[str, Any]] = []
    matched = False
    normalized_resource = resource.replace('\\', '/') if resource else None
    for approval in approvals:
        try:
            expires = datetime.fromisoformat(str(approval['expires_at']))
        except (KeyError, TypeError, ValueError):
            continue
        if expires < now:
            continue
        kept.append(approval)
        if approval.get('schema_version') != 2:
            continue
        if approval.get('authorization') != 'delegated-local-grant':
            continue
        if approval.get('scope') != scope:
            continue
        branch_bound = scope == 'protected-path' and approval.get('binding') == BRANCH_RESOURCES_BINDING
        continuity_fields = {'logical_task_id', 'authority_epoch', 'owner_session_id'}
        if continuity_fields.intersection(approval):
            if (not continuity_fields.issubset(approval) or type(approval.get('authority_epoch')) is not int or
                    approval['logical_task_id'] != task_identity(route) or
                    approval['authority_epoch'] != route.get('authority_epoch', 0) or
                    approval['owner_session_id'] != route.get('session_id')):
                continue
        elif has_task_context(route) and (
                not legacy_evidence_allowed(route) or route.get('origin_session_id') != route.get('session_id')):
            continue
        if any(approval.get(key) != value for key, value in bindings.items()
               if not (branch_bound and key == 'git_head')):
            continue
        grant_binding_digest = approval.get('grant_binding_digest')
        legacy_tree_fingerprint = approval.get('tree_fingerprint')
        if grant_binding_digest is not None and legacy_tree_fingerprint is not None:
            continue
        binding = approval.get('binding')
        if binding is None:
            expected_digest = current_binding_digest
        elif branch_bound:
            anchor = approval.get('anchor_commit')
            branch = git_output(root, 'symbolic-ref', '--quiet', 'HEAD')
            if (not branch or branch != approval.get('git_branch')
                    or not isinstance(anchor, str) or not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', anchor)
                    or anchor != approval.get('git_head')
                    or git_output(root, 'merge-base', '--is-ancestor', anchor, head) is None):
                continue
            try:
                expected_digest = tree_fingerprint(root, approval.get('resources') or [], anchor=anchor)
            except (OSError, ValueError):
                continue
        elif binding == GRANTED_RESOURCES_BINDING and approval.get('scope') == 'protected-path':
            expected_digest = tree_fingerprint(root, approval.get('resources') or [])
        else:
            continue
        if (grant_binding_digest or legacy_tree_fingerprint) != expected_digest:
            continue
        if action and action not in set(approval.get('actions') or []):
            continue
        # Exact equality only: a stored pattern (legacy or hand-edited) never widens a grant.
        resources = {str(item).replace('\\', '/') for item in approval.get('resources') or []}
        if normalized_resource is not None and normalized_resource not in resources:
            continue
        matched = True
    return matched


def approval_mismatch(root: Path, scope: str, *, action: str, resource: str | None) -> str:
    """Why no recorded grant covers this action: a hint for the refusal, never an authorization.

    An agent that recorded a grant and was refused again needs the reason, not a bare repeat.
    """
    approvals = load_json(approvals_path(root), [])
    if not isinstance(approvals, list):
        return ''
    now = datetime.now(timezone.utc)
    head = git_head(root) or ''
    route = (get_active_route(root) or {}).get('route_id')
    normalized = resource.replace('\\', '/') if resource else None
    reasons: list[str] = []
    for approval in approvals:
        if not isinstance(approval, dict) or approval.get('authorization') != 'delegated-local-grant':
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
            reasons.append('the grant was recorded under an earlier route (each prompt starts a new one)')
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
    if route and has_task_context(route):
        require_route_owner(root, route)
        if route.get('change_id') != data.get('change_id'):
            raise ValueError('package projection does not match canonical task attachment')
    durable_json(root, active_change_path(root), data)


def get_active_change(root: Path) -> dict[str, Any] | None:
    path = active_change_path(root)
    if not path.exists() and not path.is_symlink():
        return None
    return _route_document(root, path, limit=4096)


def stop_attempts_path(root: Path) -> Path:
    return runtime_dir(root) / 'stop-attempts.json'


def increment_stop_attempt(root: Path, route_id: str) -> int:
    with runtime_lock(root, 'stop'):
        data = load_json(stop_attempts_path(root), {})
        if not isinstance(data, dict):
            data = {}
        value = int(data.get(route_id, 0)) + 1
        data[route_id] = value
        dump_json(stop_attempts_path(root), data)
        return value


def reset_stop_attempt(root: Path, route_id: str) -> None:
    with runtime_lock(root, 'stop'):
        data = load_json(stop_attempts_path(root), {})
        if isinstance(data, dict):
            data.pop(route_id, None)
            dump_json(stop_attempts_path(root), data)
