"""Canonical continuity authoring leaf; imported only by explicit writer entry points.

The public owner retains canonical readonly helpers, state locks and mutable modules.
This module does not supply another store or change scope, epoch, grant or receipt semantics.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from . import continuity


def normalize_route(root: Path, route: dict[str, Any] | None = None) -> dict[str, Any]:
    route = route or continuity.state.get_active_route(root)
    if not route:
        return continuity.state.require_route_owner(root)
    if continuity.has_task_context(route):
        continuity.validate_route(root, route)
        return continuity.state.require_route_owner(root, route)
    session = continuity.state.current_session()
    legacy_owner = route.get('session_id')
    identified_owner = isinstance(legacy_owner, str) and legacy_owner != 'manual' and continuity.state._SESSION_ID.fullmatch(legacy_owner)
    if not session or identified_owner and legacy_owner != session:
        raise ValueError('legacy task needs explicit matching --session and --continue')
    if not isinstance(route.get('task'), str):
        raise ValueError('legacy original task is unavailable; recover its original bytes before migration')
    identity = continuity.task_identity(route)
    workers = continuity._active_workers(root)
    if any(record['route_id'] != route['route_id'] or record['task_id'] != identity for record in workers.values()):
        raise ValueError('legacy worker identity is inconsistent; restart without retagging workers')
    updated = continuity.copy.deepcopy(route)
    updated.update(task_context_version=1, logical_task_id=identity, origin_session_id=route.get('session_id') or 'legacy-unbound',
                   session_id=session, authority_epoch=0, state_revision=0, workspace=str(root.resolve()),
                   context=continuity.new_context(legacy=True))
    binding = continuity.state.open_change_binding(root)
    if binding:
        if binding[1] != route['route_id'] or route.get('change_id') not in (None, binding[0]):
            raise ValueError('legacy selected package conflicts with task authority; explicit recovery required')
        active = continuity.state.get_active_change(root)
        selected = continuity.state._route_document(root, root / active['path'] / 'state.json')
        continuity.validate_package_state(selected, route, binding[0])
        # Freeze the pre-attachment lifecycle identity first. Never retag workers.
        updated['change_id'] = binding[0]
    path = root / '.getzilla/runtime/routes' / f"{route['route_id']}.json"
    expected = route if path.exists() or path.is_symlink() else None
    return continuity.state._commit_route(root, updated, expected=expected)


def _changed(route: dict[str, Any], *, scope: bool = False) -> dict[str, Any]:
    result = continuity.copy.deepcopy(route)
    result['state_revision'] += 1
    result['updated_at'] = continuity.now_utc()
    if scope:
        result['context']['revision'] += 1
        result['context']['legacy_compatible'] = False
    return result


def _passive(text: str) -> bool:
    from .router import is_system_notice, should_reuse_active_route
    value = text.strip()
    return not value or is_system_notice(value) or should_reuse_active_route(value)


def _union_assessment(root: Path, route: dict[str, Any], text: str) -> None:
    from .router import build_route, RISK_ORDER
    assessed = build_route(root, text, route['session_id'], base_commit_override=route.get('base_commit'),
                           base_fingerprint_override=route.get('base_fingerprint')).to_dict()
    if RISK_ORDER.get(assessed['risk'], 0) > RISK_ORDER.get(route['risk'], 0):
        route['risk'] = assessed['risk']
    if assessed.get('delivery_lane') == 'full':
        route['delivery_lane'] = 'full'
    for field in ('domains', 'task_domains', 'workflow_skills', 'analysis_agents', 'review_agents',
                  'allowed_agents', 'quality_profiles', 'required_evidence', 'human_gates'):
        route[field] = list(dict.fromkeys([*route.get(field, []), *assessed.get(field, [])]))
    if not route.get('write_agent') and assessed.get('write_agent'):
        route['write_agent'] = assessed['write_agent']
    if route.get('write_agent'):
        route['allowed_agents'] = list(dict.fromkeys([*route['allowed_agents'], route['write_agent']]))
    # Intake keeps existing obligations, but the old exact-diff assessment no
    # longer establishes readiness for the expanded scope.
    route['risk_assessment'] = {'schema_version': 1, 'status': 'provisional'}


def submit(root: Path, text: str, session_id: str | None = None, *, new_task: bool = False,
           continue_route: str | None = None, expected_epoch: int | None = None,
           expected_revision: int | None = None, event_id: str | None = None,
           request_id: str | None = None) -> dict[str, Any] | None:
    """Only an explicit new task or exact handoff changes task ownership/identity."""
    if session_id is not None:
        continuity.state.bind_session(session_id)
    session = continuity.state.current_session()
    if not session:
        raise ValueError('explicit --session is required; use --continue or --new-task')
    if not isinstance(text, str) or event_id is not None and not continuity._identifier(event_id):
        raise ValueError('invalid task intake')
    if request_id is not None and not continuity._identifier(request_id):
        raise ValueError('invalid handoff request identity')
    if new_task and continue_route is not None:
        raise ValueError('new-task and continue are mutually exclusive')
    if continue_route is not None:
        route = continuity.state.canonical_route(root, continue_route)
        if route.get('status') in continuity.TERMINAL:
            raise ValueError('cannot continue a terminal task; use explicit --new-task')
        if not continuity.has_task_context(route):
            prior_owner = route.get('session_id')
            if (isinstance(prior_owner, str) and prior_owner != 'manual' and continuity.state._SESSION_ID.fullmatch(prior_owner)
                    and prior_owner != session):
                raise ValueError('legacy foreign task cannot be silently adopted')
            route = continuity.normalize_route(root, route)
        if route['session_id'] != session:
            if not continuity._integer(expected_epoch) or not continuity._integer(expected_revision) or not continuity._identifier(request_id):
                raise ValueError('handoff requires exact --expected-epoch, --expected-revision and --request-id')
            if (route['authority_epoch'], route['state_revision']) != (expected_epoch, expected_revision):
                raise ValueError('stale task handoff')
            continuity._ensure_idle(root)
            updated = continuity._changed(route)
            updated['handoff'] = {'request_id': request_id, 'from_session': route['session_id'], 'to_session': session,
                                  'from_epoch': expected_epoch, 'from_revision': expected_revision}
            updated['session_id'] = session
            updated['authority_epoch'] += 1
            updated['context']['legacy_compatible'] = False
            route = continuity.state._commit_route(root, updated, expected=route)
        elif expected_epoch is not None or expected_revision is not None:
            prior = route.get('handoff') or {}
            if (prior.get('from_epoch'), prior.get('from_revision')) == (expected_epoch, expected_revision) and prior.get('request_id') != request_id:
                raise ValueError('handoff request identity collision')
            if prior.get('from_epoch') != expected_epoch or prior.get('from_revision') != expected_revision:
                if (route['authority_epoch'], route['state_revision']) != (expected_epoch, expected_revision):
                    raise ValueError('stale task continuation')
            continuity.state._publish_route_projections(root, route)
        else:
            continuity.state._publish_route_projections(root, route)
    else:
        route = continuity.state.get_active_route(root)
    if new_task or route is None or route.get('status') in continuity.TERMINAL:
        if not new_task and continuity.state.route_authority_present(root) and route is None:
            raise ValueError('task authority unavailable; use explicit --continue ROUTE_ID or --new-task')
        if continuity._passive(text):
            return route
        if (not new_task and route is not None and route.get('status') in continuity.TERMINAL
                and re.match(r'\s*(?:continue|resume|продолжай(?:те)?|продолжи(?:те)?)\s+', text, re.IGNORECASE)):
            raise ValueError('the selected task is closed; use --new-task with the full scope')
        continuity._ensure_idle(root)
        binding = continuity.state.open_change_binding(root)
        if binding:
            raise continuity.state.ActiveChangeConflict(binding[0], binding[1], 'new-task')
        from .router import build_route
        raw = text.encode('utf-8')
        overflow = len(raw) > continuity.MAX_ORIGINAL_BYTES
        route = build_route(root, 'Original task NOT admitted: scope_sync_required.' if overflow else text, session).to_dict()
        if overflow:
            route['context']['revision'] = 1
            route['context']['rejected'] = continuity._rejection(raw, event_id, 'original-bytes')
        continuity.state.set_active_route(root, route)
        if overflow:
            raise ValueError('scope_sync_required: original task exceeds UTF-8 byte limit; resupply exact bytes')
        return route
    route = continuity.normalize_route(root, route)
    continuity.state.require_route_owner(root, route)
    if continuity._passive(text):
        return continuity._sync_gate_projection(root, route)
    raw = text.encode('utf-8')
    value_digest = continuity.hashlib.sha256(raw).hexdigest()
    context = route['context']
    replay = [*context['pending'], *((context.get('last_ack') or {}).get('acknowledged', []))]
    for item in replay:
        if event_id is not None and item.get('event_id') == event_id:
            if item.get('digest') != value_digest or item.get('bytes') != len(raw):
                raise ValueError('event identity collision')
            return continuity._sync_gate_projection(root, route)
    if context['rejected'] is not None:
        rejected = context['rejected']
        if event_id is not None and rejected.get('event_id') == event_id and rejected['digest'] != value_digest:
            raise ValueError('event identity collision')
        can_retry = (rejected['reason'] in {'queue-count', 'queue-bytes'} and rejected['digest'] == value_digest
                     and rejected['bytes'] == len(raw) and len(raw) <= continuity.MAX_ITEM_BYTES
                     and len(context['pending']) < continuity.MAX_PENDING and context['pending_bytes'] + len(raw) <= continuity.MAX_PENDING_BYTES
                     and (rejected['event_id'] is None or rejected['event_id'] == event_id))
        if not can_retry:
            raise ValueError('scope_sync_required: a NOT-admitted input needs explicit exact resolution')
    reason = ('item-bytes' if len(raw) > continuity.MAX_ITEM_BYTES else 'queue-count' if len(context['pending']) >= continuity.MAX_PENDING
              else 'queue-bytes' if context['pending_bytes'] + len(raw) > continuity.MAX_PENDING_BYTES else None)
    updated = continuity._changed(route, scope=True)
    if reason:
        updated['context']['rejected'] = continuity._rejection(raw, event_id, reason)
    else:
        updated['context']['rejected'] = None
        updated['context']['pending'].append({'id': 'scope-' + continuity.secrets.token_hex(12), 'event_id': event_id,
                                              'text': text, 'digest': value_digest, 'bytes': len(raw), 'at': continuity.now_utc()})
        updated['context']['pending_bytes'] += len(raw)
        continuity._union_assessment(root, updated, text)
    result = continuity.state._commit_route(root, updated, expected=route)
    result = continuity._sync_gate_projection(root, result)
    if reason:
        raise ValueError('scope_sync_required: input NOT admitted; prior scope retained')
    return result


def _rejection(raw: bytes, event_id: str | None, reason: str) -> dict[str, Any]:
    return {'id': 'rejected-' + continuity.secrets.token_hex(12), 'event_id': event_id,
            'digest': continuity.hashlib.sha256(raw).hexdigest(), 'bytes': len(raw), 'reason': reason, 'at': continuity.now_utc()}


def _sync_gate_projection(root: Path, route: dict[str, Any]) -> dict[str, Any]:
    if not route.get('change_id'):
        return route
    from .change import start_change, transition
    from .human_gates import route_gate_digest
    from .workflow_storage import RUNTIME_CHANGES, valid_package_path
    selected = continuity.state.get_active_change(root)
    if (not isinstance(selected, dict) or selected.get('change_id') != route['change_id'] or
            not valid_package_path(selected.get('path'), route['change_id'])):
        raise ValueError('scope projection requires the selected canonical package')
    runtime = f"{RUNTIME_CHANGES}/{route['change_id']}"
    if selected['path'] != runtime:
        # The native start/recovery path copies historical packages. Never
        # rewrite the tracked history to repair a runtime projection.
        start_change(root)
        selected = continuity.state.get_active_change(root)
        if not selected or selected.get('path') != runtime:
            raise ValueError('scope projection requires a runtime package')
    path = root / selected['path']
    value = continuity.state._route_document(root, path / 'state.json')
    continuity.validate_package_state(value, route, route['change_id'])
    snapshot = continuity.state._route_document(root, path / 'route.json')
    if snapshot.get('route_id') != route['route_id']:
        raise ValueError('package route snapshot conflicts with scope projection')
    gates = route.get('human_gates', [])
    gate_digest = route_gate_digest(route['route_id'], gates)
    # A partial write remains a declaration mismatch and grants no authority.
    # Exact intake replay repairs either projection without duplicating scope.
    if snapshot.get('human_gates') != gates:
        snapshot['human_gates'] = gates
        continuity.state.durable_json(root, path / 'route.json', snapshot)
    if value.get('human_gates') != gates or value.get('human_gates_digest') != gate_digest:
        value['human_gates'] = gates
        value['human_gates_digest'] = gate_digest
        continuity.state.durable_json(root, path / 'state.json', value)
    context = route['context']
    if (context['pending'] or context['rejected']) and (
            value['status'] in {'verifying', 'reviewing', 'ready'} or
            value['status'] == 'implementing' and route.get('status') in {'verifying', 'reviewing', 'ready'}):
        if context.get('version') == 2:
            # The old stage is historical while scope is pending. Do not enter
            # implementing to invalidate evidence: the actual intake admission
            # consumers already refuse old cuts and preserve the queued input.
            return route
        transition(root, route['change_id'], 'implementing', 'scope synchronization required')
        return continuity.state.canonical_route(root, route['route_id'])
    return route


def attach_package(root: Path, route: dict[str, Any], change_id: str, path: Path) -> dict[str, Any]:
    route = continuity.normalize_route(root, route)
    if route.get('change_id') not in (None, change_id):
        raise ValueError('task already has another package')
    record = continuity.state._route_document(root, path / 'state.json')
    if record.get('route_id') != route['route_id'] or record.get('change_id') != change_id:
        raise ValueError('package identity conflicts with canonical task')
    current = continuity.state.canonical_route(root, route['route_id'])
    if current != route:
        raise ValueError('route changed before package attachment')
    if route.get('change_id') is None:
        updated = continuity._changed(route)
        updated['change_id'] = change_id
        route = continuity.state._commit_route(root, updated, expected=route)
    continuity.state.set_active_change(root, {'change_id': change_id, 'path': path.relative_to(root).as_posix()})
    return route


def _request_schema(request: Any) -> None:
    required = {'version', 'operation_id', 'route_id', 'logical_task_id', 'authority_epoch', 'revision',
                'spec_digest', 'requirements_digest', 'items'}
    if (not isinstance(request, dict) or set(request) - required - {'resolve_rejected'} or
            not required.issubset(request) or type(request['version']) is not int or request['version'] != 1 or
            not all(continuity._identifier(request[key]) for key in ('operation_id', 'route_id', 'logical_task_id')) or
            not all(continuity._integer(request[key]) for key in ('authority_epoch', 'revision')) or
            not all(continuity._hex(request[key]) for key in ('spec_digest', 'requirements_digest')) or
            not isinstance(request['items'], dict) or len(request['items']) > continuity.MAX_PENDING + 1):
        raise ValueError('invalid closed scope acknowledgment request')
    for identifier, targets in request['items'].items():
        if (not continuity._identifier(identifier) or not isinstance(targets, list) or not 1 <= len(targets) <= 32 or
                any(not continuity._identifier(target) for target in targets) or len(set(targets)) != len(targets)):
            raise ValueError('invalid typed scope mapping')


def _resolution(root: Path, value: Any, rejected: dict | None, targets: set[str]) -> dict | None:
    if value is None:
        return None
    if not rejected or not isinstance(value, dict):
        raise ValueError('no rejected input matches this resolution')
    allowed = {'id', 'action', 'text', 'text_path', 'targets', 'user_event_id', 'decision'}
    if set(value) - allowed or value.get('id') != rejected['id'] or ('text' in value) == ('text_path' in value):
        raise ValueError('invalid rejected-input resolution')
    if 'text_path' in value:
        from .package_status import read_package_file
        raw = read_package_file(root, value['text_path'], 8 * 1024 * 1024)
        raw.decode('utf-8', 'strict')
    elif isinstance(value['text'], str):
        raw = value['text'].encode('utf-8')
    else:
        raise ValueError('resolution requires exact UTF-8 input bytes')
    if len(raw) != rejected['bytes'] or continuity.hashlib.sha256(raw).hexdigest() != rejected['digest']:
        raise ValueError('rejected-input bytes do not match')
    metadata = {key: value[key] for key in value if key not in {'text', 'text_path'}}
    if value.get('action') == 'incorporated':
        mapped = value.get('targets')
        if (not isinstance(mapped, list) or not 1 <= len(mapped) <= 32 or
                any(not isinstance(item, str) or item not in targets for item in mapped) or
                set(value) & {'user_event_id', 'decision'}):
            raise ValueError('incorporation needs existing typed targets')
    elif value.get('action') == 'withdrawn':
        if (not continuity._identifier(value.get('user_event_id')) or not isinstance(value.get('decision'), str) or
                not value['decision'].strip() or len(value['decision'].encode('utf-8')) > 4096 or 'targets' in value):
            raise ValueError('withdrawal requires a current explicit user decision and event identity')
    else:
        raise ValueError('resolution action must be incorporated or withdrawn')
    return {**metadata, 'digest': rejected['digest'], 'bytes': rejected['bytes']}


def ack_scope(root: Path, request: dict[str, Any]) -> dict[str, Any]:
    continuity._request_schema(request)
    route = continuity.normalize_route(root)
    continuity.state.require_route_owner(root, route)
    for field in ('route_id', 'logical_task_id', 'authority_epoch'):
        if request[field] != route[field]:
            raise ValueError('scope acknowledgment task/epoch mismatch')
    documents = continuity.package_documents(root, route, durable=True)
    if documents is None:
        raise ValueError('scope acknowledgment requires a typed package')
    from .workflow_storage import RUNTIME_CHANGES
    if documents['path'] != f"{RUNTIME_CHANGES}/{route['change_id']}":
        raise ValueError('historical package is read-only; run scripts/getzilla_change.py start to copy it into runtime')
    for field in ('spec_digest', 'requirements_digest'):
        if request[field] != documents[field]:
            raise ValueError('scope acknowledgment document digest mismatch')
    context = route['context']
    previous = context['last_ack']
    transaction_digest = continuity.digest(request)
    mirror = documents['state'].get('scope_ack')
    if previous and previous.get('operation_id') == request['operation_id']:
        if previous['transaction_digest'] != transaction_digest or mirror != previous:
            raise ValueError('scope acknowledgment replay collision or missing transaction mirror')
        if request.get('resolve_rejected'):
            proof = previous.get('rejected_resolution')
            continuity._resolution(root, request['resolve_rejected'], proof, continuity._typed_targets(documents['spec']))
        return route
    if request['revision'] != context['revision']:
        raise ValueError('stale scope acknowledgment revision')
    targets = continuity._typed_targets(documents['spec'])
    items = request['items']
    pending = {item['id']: item for item in context['pending']}
    if any(identifier != 'original' and identifier not in pending for identifier in items):
        raise ValueError('scope acknowledgment names an unknown item')
    if any(target not in targets for mapped in items.values() for target in mapped):
        raise ValueError('scope acknowledgment names an unknown typed target')
    if 'original' not in items and not previous:
        raise ValueError('original task must receive explicit typed synchronization')
    original = items.get('original') or (previous or {}).get('items', {}).get('original')
    if not original or any(target not in targets for target in original):
        raise ValueError('original scope mapping must name current typed targets')
    resolution = continuity._resolution(root, request.get('resolve_rejected'), context['rejected'], targets)
    updated = continuity._changed(route, scope=True)
    updated['context']['pending'] = [item for item in context['pending'] if item['id'] not in items]
    updated['context']['pending_bytes'] = sum(item['bytes'] for item in updated['context']['pending'])
    if resolution:
        updated['context']['rejected'] = None
    acknowledged = [{key: item[key] for key in ('id', 'event_id', 'digest', 'bytes')}
                    for item in context['pending'] if item['id'] in items]
    ack = {'version': 1, 'operation_id': request['operation_id'], 'transaction_digest': transaction_digest,
           'route_id': route['route_id'], 'logical_task_id': route['logical_task_id'],
           'authority_epoch': route['authority_epoch'], 'previous_revision': context['revision'],
           'revision': updated['context']['revision'], 'spec_digest': documents['spec_digest'],
           'requirements_digest': documents['requirements_digest'], 'items': {'original': original, **items},
           'acknowledged': acknowledged, 'rejected_resolution': resolution}
    if mirror is not None and mirror != previous and mirror != ack:
        raise ValueError('another package-first scope transaction is pending; retry it exactly')
    if continuity.package_documents(root, route, durable=True) != documents:
        raise ValueError('scope documents changed before acknowledgment publication')
    package_state = continuity.copy.deepcopy(documents['state'])
    package_state['scope_ack'] = ack
    continuity.state.durable_json(root, root / documents['path'] / 'state.json', package_state)
    check = continuity.package_documents(root, route, durable=True)
    if (check['spec_digest'], check['requirements_digest']) != (documents['spec_digest'], documents['requirements_digest']):
        raise ValueError('scope documents changed during acknowledgment publication')
    updated['context']['last_ack'] = ack
    return continuity.state._commit_route(root, updated, expected=route)


def update_intent(root: Path, request: dict[str, Any]) -> dict[str, Any]:
    from .task_intent import update_intent as transition_intent
    return transition_intent(root, request)


def finish_task(root: Path, *, cancel: bool = False) -> dict[str, Any]:
    route = continuity.normalize_route(root)
    continuity.assert_finishable(root, route, cancel=cancel)
    return continuity.state.update_route(root, status='cancelled' if cancel else 'completed')
