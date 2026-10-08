from __future__ import annotations

import os
import re
import secrets
import time
from contextlib import contextmanager
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


def _stale_lock(lock: Path) -> bool:
    try:
        raw = lock.read_text(encoding='utf-8').strip()
        pid = int(raw)
    except (OSError, ValueError):
        return True
    return not _process_alive(pid)


@contextmanager
def runtime_lock(root: Path, name: str = 'state', timeout: float = 5.0) -> Iterator[None]:
    lock = runtime_dir(root) / f'.{name}.lock'
    deadline = time.monotonic() + timeout
    fd: int | None = None
    while fd is None:
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY | fsx.O_BINARY | fsx.O_NOINHERIT, 0o600)
        except FileExistsError:
            if _stale_lock(lock):
                try:
                    lock.unlink()
                    continue
                except FileNotFoundError:
                    continue
                except OSError:
                    pass
            if time.monotonic() >= deadline:
                raise TimeoutError(f'could not acquire runtime lock: {lock}')
            time.sleep(0.05)
        except PermissionError:
            # Windows refuses to create a name whose previous file is still
            # delete-pending; that is contention, not a missing permission.
            if not fsx.WINDOWS:
                raise
            if time.monotonic() >= deadline:
                raise TimeoutError(f'could not acquire runtime lock: {lock}')
            time.sleep(0.05)
    try:
        os.write(fd, f'{os.getpid()}\n'.encode())
        yield
    finally:
        os.close(fd)
        _release_lock_file(lock)


def active_route_path(root: Path) -> Path:
    return root / '.getzilla/runtime/active-route.json'


def get_active_route(root: Path) -> dict[str, Any] | None:
    data = load_json(active_route_path(root))
    return data if isinstance(data, dict) else None


def set_active_route(root: Path, route: dict[str, Any]) -> None:
    with runtime_lock(root, 'route'):
        dump_json(active_route_path(root), route)
        route_dir = runtime_dir(root) / 'routes'
        route_dir.mkdir(parents=True, exist_ok=True)
        dump_json(route_dir / f"{route['route_id']}.json", route)


def update_route(root: Path, **updates: Any) -> dict[str, Any] | None:
    with runtime_lock(root, 'route'):
        route = get_active_route(root)
        if not route:
            return None
        route.update(updates)
        route['updated_at'] = now_utc()
        dump_json(active_route_path(root), route)
        dump_json(runtime_dir(root) / 'routes' / f"{route['route_id']}.json", route)
        return route


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
    remote = git_output(root, 'config', '--get', 'remote.origin.url') or ''
    match = re.search(r'(?:github\.com[:/])([^/\s]+/[^/\s]+?)(?:\.git)?$', remote.strip())
    if not match:
        raise RuntimeError('remote.origin.url must identify a GitHub owner/repository')
    return match.group(1).removesuffix('.git')


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
        return resource
    match = _GITHUB_TARGET.match(resource)
    if match:
        # GitHub owner/repository names are case-insensitive; the policy compares them lower-cased.
        return f'{match.group(1) or ""}{match.group(2).lower()}{match.group(3)}'
    if scope == 'production':
        return resource.removeprefix('refs/heads/').removeprefix('refs/tags/')
    return resource


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
    """Materialize an explicitly delegated local grant for one exact repository tree."""
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
    route = get_active_route(root) or {}
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
        'change_id': _active_change_id(root),
        'git_head': head,
        'grant_binding_digest': tree_fingerprint(root),
        'created_at': now.isoformat(timespec='seconds'),
        'expires_at': (now + timedelta(minutes=ttl_minutes)).isoformat(timespec='seconds'),
    }
    with runtime_lock(root, 'approvals'):
        approvals = load_json(approvals_path(root), [])
        if not isinstance(approvals, list):
            approvals = []
        approvals.append(approval)
        dump_json(approvals_path(root), approvals[-200:])
    return approval


def has_valid_approval(
    root: Path,
    scope: str,
    *,
    action: str | None = None,
    resource: str | None = None,
) -> bool:
    """Validate a delegated grant against the current route, repository, HEAD and tree."""
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
    route = get_active_route(root) or {}
    bindings = {
        'repository': repository,
        'route_id': route.get('route_id'),
        'change_id': _active_change_id(root),
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
        if any(approval.get(key) != value for key, value in bindings.items()):
            continue
        grant_binding_digest = approval.get('grant_binding_digest')
        legacy_tree_fingerprint = approval.get('tree_fingerprint')
        if grant_binding_digest is not None and legacy_tree_fingerprint is not None:
            continue
        if (grant_binding_digest or legacy_tree_fingerprint) != current_binding_digest:
            continue
        if action and action not in set(approval.get('actions') or []):
            continue
        # Exact equality only: a stored pattern (legacy or hand-edited) never widens a grant.
        resources = {str(item).replace('\\', '/') for item in approval.get('resources') or []}
        if normalized_resource is not None and normalized_resource not in resources:
            continue
        matched = True
    if len(kept) != len(approvals):
        dump_json(approvals_path(root), kept)
    return matched


def active_change_path(root: Path) -> Path:
    return root / '.getzilla/runtime/active-change.json'


def set_active_change(root: Path, data: dict[str, Any]) -> None:
    dump_json(active_change_path(root), data)


def get_active_change(root: Path) -> dict[str, Any] | None:
    data = load_json(active_change_path(root))
    return data if isinstance(data, dict) else None


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
