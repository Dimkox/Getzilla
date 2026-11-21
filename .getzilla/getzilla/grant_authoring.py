"""Explicit grant authoring; ordinary state readers do not load this owner.

State retains the canonical task lock, context, errors, mutable approval data,
clock and grant readers. This leaf uses those normal state helpers directly.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from . import state


@state.serialized_task
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
    route = state.get_active_route(root)
    if route:
        route = normalize_route(root, route)
        state.require_route_owner(root, route)
    elif state.route_authority_present(root):
        raise ValueError('task authority unavailable; cannot issue an unrouted grant')
    route = route or {}
    normalized_scope = scope.strip()
    normalized_reason = reason.strip()
    normalized_source = source.strip()
    if normalized_scope not in state.APPROVAL_SCOPES:
        raise ValueError(f'unsupported approval scope: {scope}')
    if not normalized_reason:
        raise ValueError('approval reason must not be empty')
    if normalized_source not in state.APPROVAL_SOURCES:
        raise ValueError(f'unsupported approval source: {source}')
    if isinstance(ttl_minutes, bool) or not 1 <= ttl_minutes <= 1440:
        raise ValueError('ttl_minutes must be between 1 and 1440')

    normalized_actions = sorted({str(item).strip() for item in (actions or []) if str(item).strip()})
    if not normalized_actions:
        raise ValueError('at least one explicit delegated action is required')
    unsupported = set(normalized_actions) - state.SCOPE_ACTIONS[normalized_scope]
    if unsupported:
        raise ValueError(f'actions are outside scope {normalized_scope}: {sorted(unsupported)}')

    normalized_resources = sorted({
        state._normalize_grant_resource(normalized_scope, str(item)) for item in (resources or []) if str(item).strip()
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

    head = state.git_head(root)
    if not head:
        raise RuntimeError('an exact Git HEAD is required for delegated approval')
    branch = state.git_output(root, 'symbolic-ref', '--quiet', 'HEAD')
    if normalized_scope == 'protected-path' and not branch:
        raise ValueError('a named Git branch is required for protected-path approval')
    repository = state._grant_repository_identity(root, normalized_scope)
    local_repository = repository.startswith('local-git-v1:')
    if local_repository and not state.current_session():
        raise ValueError('an explicit caller session is required for local delegated approval')
    now = state.datetime.now(state.timezone.utc)
    approval = {
        'schema_version': 2,
        'id': state.secrets.token_hex(8),
        'authorization': 'delegated-local-grant',
        'source': normalized_source,
        'scope': normalized_scope,
        'actions': normalized_actions,
        'resources': normalized_resources,
        'reason': normalized_reason,
        'repository': repository,
        'route_id': route.get('route_id'),
        'logical_task_id': task_identity(route),
        'authority_epoch': route.get('authority_epoch', 0),
        'owner_session_id': route.get('session_id'),
        'change_id': state._active_change_id(root),
        'git_head': head,
        **({'session_id': state.current_session()} if local_repository else {}),
        **({'binding': state.BRANCH_RESOURCES_BINDING, 'git_branch': branch, 'anchor_commit': head,
            'session_id': state.current_session()}
           if normalized_scope == 'protected-path' else {}),
        'grant_binding_digest': state.tree_fingerprint(
            root, normalized_resources if normalized_scope == 'protected-path' else (),
            anchor=head if normalized_scope == 'protected-path' else None,
        ),
        'created_at': now.isoformat(timespec='seconds'),
        'expires_at': (now + state.timedelta(minutes=ttl_minutes)).isoformat(timespec='seconds'),
    }
    with state.runtime_lock(root, 'approvals'):
        from .component_state import BoundRoot
        with BoundRoot(root) as binding:
            _snapshot, approvals = state._read_approvals(root, binding)
        approvals.append(approval)
        state.dump_json(state.approvals_path(root), approvals[-200:])
    from .metrics_journal import record
    record(root, 'grant', approval.get('route_id'), event_id='grant:' + approval['id'], scope=approval['scope'])
    return approval


def _extension_context(root: Path) -> tuple[dict, dict]:
    from .continuity import context_binding, has_task_context, scope_gaps, task_identity
    try:
        route = state.require_route_owner(root)
        head = state.git_head(root)
        branch = state.git_output(root, 'symbolic-ref', '--quiet', 'HEAD')
        if (not has_task_context(route) or not head or not branch or not state.current_session()
                or scope_gaps(root, route)):
            raise ValueError('unqualified context')
        return route, {
            'repository': state._grant_repository_identity(root, 'protected-path'), 'route_id': route['route_id'],
            'logical_task_id': task_identity(route), 'authority_epoch': route['authority_epoch'],
            'owner_session_id': route['session_id'], 'session_id': state.current_session(),
            'change_id': state._active_change_id(root), 'git_head': head, 'git_branch': branch,
            'scope_binding': context_binding(root, route),
        }
    except (KeyError, OSError, RuntimeError, ValueError):
        raise state.GrantExtensionError('EXTENSION_AUTHORITY_MISMATCH') from None


def _extension_parent_shape(parent: dict) -> None:
    fields = state._FORMER_FIELDS | {'id', 'authorization', 'scope', 'actions', 'reason', 'expires_at'}
    if (set(parent) not in (fields, fields | {'extension'})
            or state.approval_record_kind(parent) != 'active'
            or parent.get('authorization') != 'delegated-local-grant'
            or parent.get('scope') != 'protected-path'
            or parent.get('actions') != ['protected-path-write']
            or parent.get('binding') != state.BRANCH_RESOURCES_BINDING
            or parent.get('source') not in state.APPROVAL_SOURCES
            or not state._grant_hex(parent.get('id'), 16)
            or not state._grant_hex(parent.get('grant_binding_digest'), 64)
            or type(parent.get('authority_epoch')) is not int
            or parent['authority_epoch'] < 0
            or any(type(parent.get(key)) is not str or not parent[key]
                   for key in ('repository', 'route_id', 'logical_task_id', 'owner_session_id',
                               'session_id', 'git_branch', 'reason'))
            or parent.get('change_id') is not None and type(parent['change_id']) is not str
            or type(parent.get('anchor_commit')) is not str
            or not state.re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', parent['anchor_commit'])
            or parent.get('git_head') != parent['anchor_commit']):
        raise state.GrantExtensionError('UNSUPPORTED_EXTENSION_BINDING')
    try:
        if state._extension_resources(parent['resources']) != parent['resources']:
            raise ValueError('noncanonical resources')
        created, expires = state._grant_time(parent['created_at']), state._grant_time(parent['expires_at'])
        if not created < expires or expires - created > state.timedelta(days=1):
            raise ValueError('unqualified lifetime')
    except (KeyError, TypeError, ValueError):
        raise state.GrantExtensionError('UNSUPPORTED_EXTENSION_BINDING') from None


def _extension_current(root: Path, parent: dict, context: dict, route: dict,
                       *, combined: list[str] | None = None) -> str:
    # Revalidate the captured record without consulting a store that may now contain its tombstone.
    if any(parent[key] != context[key] for key in context if key not in {'git_head', 'scope_binding'}):
        raise state.GrantExtensionError('EXTENSION_AUTHORITY_MISMATCH')
    now = state.datetime.now(state.timezone.utc)
    if not state._grant_time(parent['created_at']) <= now < state._grant_time(parent['expires_at']):
        raise state.GrantExtensionError('EXTENSION_PARENT_NOT_CURRENT')
    if state.git_output(root, 'merge-base', '--is-ancestor', parent['anchor_commit'], context['git_head']) is None:
        raise state.GrantExtensionError('EXTENSION_PARENT_NOT_CURRENT')
    try:
        old_digest = state.tree_fingerprint(root, parent['resources'], anchor=parent['anchor_commit'], strict=True)
        digest = (state.tree_fingerprint(root, combined, anchor=parent['anchor_commit'], strict=True)
                  if combined is not None else old_digest)
    except (OSError, ValueError):
        raise state.GrantExtensionError('EXTENSION_SOURCE_UNQUALIFIED') from None
    if old_digest != parent['grant_binding_digest']:
        raise state.GrantExtensionError('EXTENSION_PARENT_NOT_CURRENT')
    return digest


def _extension_result(status: str, code: str, grant: dict | None = None) -> dict[str, Any]:
    return {'status': status, 'code': code, 'grant': grant,
            'inspection_required': status == 'unknown', 'retryable': False}


def extend_protected_path_approval(
    root: Path, parent_id: str, request_id: str, reason: str, ttl_minutes: int = 15, *,
    actions: list[str] | tuple[str, ...], resources: list[str] | tuple[str, ...],
    source: str = 'standing-user-consent',
) -> dict[str, Any]:
    """Replace one current protected grant with an explicitly delegated strict superset.

    One store publication contains both the non-authority history and the ordinary successor.
    A request ID is only an idempotency key; it does not supply consent or recover revoked authority.
    """
    try:
        return state._extend_protected_path_approval(
            root, parent_id, request_id, reason, ttl_minutes, actions=actions, resources=resources, source=source)
    except state.GrantExtensionError:
        raise
    except (OSError, ValueError):
        raise state.GrantExtensionError('EXTENSION_STORE_UNQUALIFIED') from None


@state.serialized_task
def _extend_protected_path_approval(
    root: Path, parent_id: str, request_id: str, reason: str, ttl_minutes: int, *,
    actions: list[str] | tuple[str, ...], resources: list[str] | tuple[str, ...], source: str,
) -> dict[str, Any]:
    from .component_state import BoundRoot
    if (type(actions) not in (list, tuple) or len(actions) != 1
            or type(actions[0]) is not str or actions[0] != 'protected-path-write'):
        raise state.GrantExtensionError('UNSUPPORTED_EXTENSION_SCOPE')
    try:
        if (not state._grant_hex(parent_id, 16) or not state._grant_hex(request_id, 32)
                or type(reason) is not str or not reason.strip() or len(reason.encode('utf-8', 'strict')) > 1024
                or type(ttl_minutes) is not int or not 1 <= ttl_minutes <= 1440
                or type(source) is not str or source not in state.APPROVAL_SOURCES):
            raise ValueError('invalid request')
        full_set = state._extension_resources(resources)
    except (UnicodeError, TypeError, ValueError):
        raise state.GrantExtensionError('INVALID_EXTENSION_REQUEST') from None
    request_digest = state._grant_digest({'parent_id': parent_id, 'request_id': request_id,
                                   'reason': reason.strip(), 'ttl_minutes': ttl_minutes,
                                   'actions': ['protected-path-write'], 'resources': full_set, 'source': source})
    route, context = state._extension_context(root)
    with state.runtime_lock(root, 'approvals'), BoundRoot(root) as binding:
        try:
            snapshot, rows = state._read_approvals(root, binding)
        except (OSError, ValueError):
            raise state.GrantExtensionError('EXTENSION_STORE_UNQUALIFIED') from None
        parents = [row for row in rows if row.get('id') == parent_id]
        if len(parents) != 1:
            raise state.GrantExtensionError('EXTENSION_STORE_UNQUALIFIED')
        parent = parents[0]
        requests = [row for row in rows if row.get('request_id') == request_id
                    or type(row.get('extension')) is dict and row['extension'].get('request_id') == request_id]
        if requests:
            if any((row.get('request_sha256') if state.approval_record_kind(row) == 'supersession'
                    else row['extension']['request_sha256']) != request_digest for row in requests):
                raise state.GrantExtensionError('EXTENSION_REQUEST_CONFLICT')
            if state.approval_record_kind(parent) != 'supersession' or parent['request_id'] != request_id:
                raise state.GrantExtensionError('EXTENSION_REPLAY_NOT_CURRENT')
            successors = [row for row in rows if row.get('id') == parent['successor_id']]
            if len(successors) != 1:
                raise state.GrantExtensionError('EXTENSION_REPLAY_NOT_CURRENT')
            successor = successors[0]
            if (state.approval_record_kind(successor) != 'active'
                    or state._grant_digest(successor) != parent['successor_record_sha256']
                    or successor.get('extension') != {
                        'schema_version': 1, 'kind': 'exact-protected-path-extension', 'request_id': request_id,
                        'parent_id': parent_id, 'parent_record_sha256': parent['parent_record_sha256'],
                        'request_sha256': request_digest}):
                raise state.GrantExtensionError('EXTENSION_REPLAY_NOT_CURRENT')
            state._extension_parent_shape(successor)
            try:
                state._extension_current(root, successor, context, route)
                if state._extension_context(root)[1] != context or binding.read('.getzilla/runtime/approvals.json') != snapshot:
                    raise ValueError('changed replay')
            except (OSError, ValueError):
                raise state.GrantExtensionError('EXTENSION_REPLAY_NOT_CURRENT') from None
            return state._extension_result('replayed', 'EXTENSION_REPLAYED', successor)
        if state.approval_record_kind(parent) != 'active':
            raise state.GrantExtensionError('EXTENSION_REPLAY_NOT_CURRENT')
        state._extension_parent_shape(parent)
        if not set(parent['resources']) < set(full_set):
            raise state.GrantExtensionError('INVALID_EXTENSION_REQUEST')
        digest = state._extension_current(root, parent, context, route, combined=full_set)
        now = state.datetime.now(state.timezone.utc)
        child = {**parent, 'id': state.secrets.token_hex(8), 'source': source, 'reason': reason.strip(),
                 'resources': full_set, 'grant_binding_digest': digest,
                 'created_at': now.isoformat(timespec='microseconds'),
                 'expires_at': min(state._grant_time(parent['expires_at']), now + state.timedelta(minutes=ttl_minutes)).isoformat(timespec='microseconds'),
                 'extension': {'schema_version': 1, 'kind': 'exact-protected-path-extension',
                               'request_id': request_id, 'parent_id': parent_id,
                               'parent_record_sha256': state._grant_digest(parent), 'request_sha256': request_digest}}
        if any(row.get('id') == child['id'] for row in rows):
            raise state.GrantExtensionError('EXTENSION_STORE_UNQUALIFIED')
        tombstone = {'schema_version': 3, 'kind': 'protected-path-grant-supersession-v1', 'status': 'superseded',
                     'id': parent_id, 'parent_record_sha256': state._grant_digest(parent),
                     'former': {key: parent[key] for key in state._FORMER_FIELDS},
                     'request_id': request_id, 'request_sha256': request_digest,
                     'successor_id': child['id'], 'successor_record_sha256': state._grant_digest(child),
                     'superseded_at': now.isoformat(timespec='microseconds'), 'expires_at': parent['expires_at']}
        updated = [tombstone if row is parent else row for row in rows] + [child]
        if len(updated) > 200:
            raise state.GrantExtensionError('EXTENSION_STORE_UNQUALIFIED')
        content = (state.json.dumps(updated, ensure_ascii=True, indent=2, allow_nan=False) + '\n').encode()
        if len(content) > 1_048_576:
            raise state.GrantExtensionError('EXTENSION_STORE_UNQUALIFIED')

        def check() -> None:
            current_route, current_context = state._extension_context(root)
            if current_context != context:
                raise state.GrantExtensionError('EXTENSION_CAS_CONFLICT')
            if state._extension_current(root, parent, context, current_route, combined=full_set) != digest:
                raise state.GrantExtensionError('EXTENSION_CAS_CONFLICT')

        # On failure, observe once. Never roll back, remint, or make a second publication.
        try:
            binding.write('.getzilla/runtime/approvals.json', content, 0o600, expected=snapshot, before_publish=check)
        except (OSError, ValueError):
            pass
        try:
            observed = binding.read('.getzilla/runtime/approvals.json', limit=1_048_576)
        except (OSError, ValueError):
            observed = None
        if observed is not None and observed.content == content:
            try:
                current_route, current_context = state._extension_context(root)
                if current_context != context:
                    raise ValueError('context changed')
                state._extension_current(root, child, context, current_route)
                if binding.read('.getzilla/runtime/approvals.json') != observed:
                    raise ValueError('successor revoked')
            except (OSError, ValueError):
                return state._extension_result('committed_not_current', 'EXTENSION_COMMITTED_NOT_CURRENT')
            return state._extension_result('created', 'EXTENSION_CREATED', child)
        if observed == snapshot:
            return state._extension_result('refused', 'EXTENSION_NOT_PUBLISHED')
        return state._extension_result('unknown', 'EXTENSION_PUBLICATION_UNVERIFIED')
