"""Canonical unfinished-task context and bounded, explicitly synchronized scope.

The route owns intake and identity. The typed package owns acceptance criteria.
Neither discovery nor intake acknowledgments confer approval or verification.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import secrets
from pathlib import Path
from typing import Any

from . import state
from .util import now_utc

MAX_PENDING = 16
MAX_ITEM_BYTES = 8192
MAX_PENDING_BYTES = 65536
MAX_ORIGINAL_BYTES = 65536
MAX_CONTEXT_BYTES = 16384
TERMINAL = frozenset({'completed', 'released', 'archived', 'cancelled'})
_MODERN = frozenset({'task_context_version', 'logical_task_id', 'origin_session_id',
                     'authority_epoch', 'state_revision', 'workspace', 'context', 'handoff'})
_ID = re.compile(r'[A-Za-z0-9_.:/-]{1,128}\Z')
_HEX = re.compile(r'[0-9a-f]{64}\Z')


def digest(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def has_task_context(route: dict[str, Any]) -> bool:
    return bool(_MODERN.intersection(route))


def new_context(*, legacy: bool = False) -> dict[str, Any]:
    return {'version': 1, 'revision': 0, 'pending': [], 'pending_bytes': 0,
            'rejected': None, 'last_ack': None, 'legacy_compatible': legacy}


def task_identity(route: dict[str, Any]) -> str:
    from .agent_lifecycle import _task_identity
    source = route.get('logical_task_id') if has_task_context(route) else (
        route['change_id'] if 'change_id' in route else route.get('session_id', route.get('route_id') or 'unrouted'))
    return _task_identity(source)


def _integer(value: Any) -> bool:
    return type(value) is int and 0 <= value < 2**53


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and bool(_ID.fullmatch(value))


def _hex(value: Any) -> bool:
    return isinstance(value, str) and bool(_HEX.fullmatch(value))


def validate_route(root: Path, route: dict[str, Any]) -> None:
    if not isinstance(route, dict) or not isinstance(route.get('task'), str):
        raise ValueError('invalid task envelope')
    if not has_task_context(route):
        return
    if type(route.get('task_context_version')) is not int or route['task_context_version'] != 1:
        raise ValueError('unsupported task context version; explicit recovery required')
    if (not _identifier(route.get('logical_task_id')) or not _identifier(route.get('origin_session_id')) or
            not _identifier(route.get('session_id')) or route['session_id'] == 'manual' or
            route.get('workspace') != str(root.resolve()) or
            not _integer(route.get('authority_epoch')) or not _integer(route.get('state_revision'))):
        raise ValueError('invalid task identity, workspace or authority epoch')
    context = route.get('context')
    if (not isinstance(context, dict) or set(context) != set(new_context()) or
            type(context['version']) is not int or context['version'] != 1 or
            not _integer(context['revision']) or type(context['legacy_compatible']) is not bool or
            not isinstance(context['pending'], list) or len(context['pending']) > MAX_PENDING):
        raise ValueError('invalid task context')
    total, ids, events = 0, set(), set()
    for item in context['pending']:
        if (not isinstance(item, dict) or set(item) != {'id', 'event_id', 'text', 'digest', 'bytes', 'at'} or
                not _identifier(item['id']) or item['id'] in ids or not isinstance(item['text'], str) or
                not isinstance(item['at'], str) or
                item['event_id'] is not None and not _identifier(item['event_id'])):
            raise ValueError('invalid pending scope item')
        raw = item['text'].encode('utf-8')
        if (not raw or len(raw) > MAX_ITEM_BYTES or type(item['bytes']) is not int or item['bytes'] != len(raw) or
                item['digest'] != hashlib.sha256(raw).hexdigest()):
            raise ValueError('pending scope integrity mismatch')
        if item['event_id'] is not None:
            if item['event_id'] in events:
                raise ValueError('duplicate pending event')
            events.add(item['event_id'])
        ids.add(item['id'])
        total += len(raw)
    if type(context['pending_bytes']) is not int or context['pending_bytes'] != total or total > MAX_PENDING_BYTES:
        raise ValueError('invalid pending scope byte count')
    rejected = context['rejected']
    if rejected is not None and (
        not isinstance(rejected, dict) or set(rejected) != {'id', 'event_id', 'digest', 'bytes', 'reason', 'at'} or
        not _identifier(rejected['id']) or not _hex(rejected['digest']) or
        not _integer(rejected['bytes']) or rejected['bytes'] == 0 or
        rejected['reason'] not in {'item-bytes', 'queue-count', 'queue-bytes', 'original-bytes'} or
        not isinstance(rejected['at'], str) or rejected['event_id'] is not None and not _identifier(rejected['event_id'])
    ):
        raise ValueError('invalid rejected scope latch')
    ack = context['last_ack']
    if ack is not None and (not isinstance(ack, dict) or not _hex(ack.get('transaction_digest')) or
                            not _integer(ack.get('revision')) or ack['revision'] > context['revision']):
        raise ValueError('invalid acknowledged scope transaction')
    if route.get('handoff') is not None:
        handoff = route['handoff']
        if (not isinstance(handoff, dict) or set(handoff) != {'from_session', 'to_session', 'from_epoch', 'from_revision'} or
                not all(_identifier(handoff[key]) for key in ('from_session', 'to_session')) or
                not all(_integer(handoff[key]) for key in ('from_epoch', 'from_revision')) or
                handoff['to_session'] != route['session_id'] or handoff['from_epoch'] + 1 != route['authority_epoch']):
            raise ValueError('invalid handoff transaction')


def _active_workers(root: Path) -> dict[str, Any]:
    path = state.agent_state_path(root)
    if not path.exists() and not path.is_symlink():
        return {}
    try:
        ledger = state._route_document(root, path)
        active = ledger['active']
        if not isinstance(active, dict) or not isinstance(ledger.get('history'), list):
            raise ValueError('malformed worker ledger')
        for identifier, record in active.items():
            if (not _identifier(identifier) or not isinstance(record, dict) or
                    any(not _identifier(record.get(key)) for key in ('route_id', 'task_id', 'generation', 'agent_type')) or
                    record.get('workspace') != str(root.resolve()) or
                    record.get('lifecycle') not in {'running', 'interrupt-requested', 'interrupted'}):
                raise ValueError('malformed worker identity')
        return active
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise ValueError('worker state is unavailable; diagnose and explicitly restart the original instance') from error


@state.serialized_task
def normalize_route(root: Path, route: dict[str, Any] | None = None) -> dict[str, Any]:
    route = route or state.get_active_route(root)
    if not route:
        return state.require_route_owner(root)
    if has_task_context(route):
        validate_route(root, route)
        return state.require_route_owner(root, route)
    session = state.current_session()
    if not session or route.get('session_id') not in {'manual', session}:
        raise ValueError('legacy task needs explicit matching --session and --continue')
    identity = task_identity(route)
    workers = _active_workers(root)
    if any(record['route_id'] != route['route_id'] or record['task_id'] != identity for record in workers.values()):
        raise ValueError('legacy worker identity is inconsistent; restart without retagging workers')
    updated = copy.deepcopy(route)
    updated.update(task_context_version=1, logical_task_id=identity, origin_session_id=route.get('session_id') or session,
                   session_id=session, authority_epoch=0, state_revision=0, workspace=str(root.resolve()),
                   context=new_context(legacy=True))
    path = root / '.getzilla/runtime/routes' / f"{route['route_id']}.json"
    expected = route if path.exists() or path.is_symlink() else None
    return state._commit_route(root, updated, expected=expected)


def _changed(route: dict[str, Any], *, scope: bool = False) -> dict[str, Any]:
    result = copy.deepcopy(route)
    result['state_revision'] += 1
    result['updated_at'] = now_utc()
    if scope:
        result['context']['revision'] += 1
        result['context']['legacy_compatible'] = False
    return result


def _passive(text: str) -> bool:
    from .router import is_system_notice, should_reuse_active_route
    value = text.strip()
    return not value or is_system_notice(value) or should_reuse_active_route(value)


def _ensure_idle(root: Path) -> None:
    if _active_workers(root):
        raise ValueError('active or interrupted worker prevents task handoff; finish the original instance first')


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
    if route.get('write_agent'):
        route['allowed_agents'] = list(dict.fromkeys([*route['allowed_agents'], route['write_agent']]))


@state.serialized_task
def submit(root: Path, text: str, session_id: str | None = None, *, new_task: bool = False,
           continue_route: str | None = None, expected_epoch: int | None = None,
           expected_revision: int | None = None, event_id: str | None = None,
           request_id: str | None = None) -> dict[str, Any] | None:
    """Only an explicit new task or exact handoff changes task ownership/identity."""
    if session_id is not None:
        state.bind_session(session_id)
    session = state.current_session()
    if not session:
        raise ValueError('explicit --session is required; use --continue or --new-task')
    if not isinstance(text, str) or event_id is not None and not _identifier(event_id):
        raise ValueError('invalid task intake')
    if request_id is not None and not _identifier(request_id):
        raise ValueError('invalid handoff request identity')
    if new_task and continue_route is not None:
        raise ValueError('new-task and continue are mutually exclusive')
    if continue_route is not None:
        route = state.canonical_route(root, continue_route)
        if not has_task_context(route):
            if route.get('session_id') not in {'manual', session}:
                raise ValueError('legacy foreign task cannot be silently adopted')
            route = normalize_route(root, route)
        if route['session_id'] != session:
            if not _integer(expected_epoch) or not _integer(expected_revision):
                raise ValueError('handoff requires exact --expected-epoch and --expected-revision')
            if (route['authority_epoch'], route['state_revision']) != (expected_epoch, expected_revision):
                raise ValueError('stale task handoff')
            _ensure_idle(root)
            updated = _changed(route)
            updated['handoff'] = {'from_session': route['session_id'], 'to_session': session,
                                  'from_epoch': expected_epoch, 'from_revision': expected_revision}
            updated['session_id'] = session
            updated['authority_epoch'] += 1
            updated['context']['legacy_compatible'] = False
            route = state._commit_route(root, updated, expected=route)
        elif expected_epoch is not None or expected_revision is not None:
            prior = route.get('handoff') or {}
            if prior.get('from_epoch') != expected_epoch or prior.get('from_revision') != expected_revision:
                if (route['authority_epoch'], route['state_revision']) != (expected_epoch, expected_revision):
                    raise ValueError('stale task continuation')
            state._publish_route_projections(root, route)
        else:
            state._publish_route_projections(root, route)
    else:
        route = state.get_active_route(root)
    if new_task or route is None or route.get('status') in TERMINAL:
        if not new_task and state.route_authority_present(root) and route is None:
            raise ValueError('task authority unavailable; use explicit --continue ROUTE_ID or --new-task')
        if _passive(text):
            return route
        _ensure_idle(root)
        binding = state.open_change_binding(root)
        if binding:
            raise state.ActiveChangeConflict(binding[0], binding[1], 'new-task')
        from .router import build_route
        raw = text.encode('utf-8')
        overflow = len(raw) > MAX_ORIGINAL_BYTES
        route = build_route(root, 'Original task NOT admitted: scope_sync_required.' if overflow else text, session).to_dict()
        if overflow:
            route['context']['revision'] = 1
            route['context']['rejected'] = _rejection(raw, event_id, 'original-bytes')
        state.set_active_route(root, route)
        if overflow:
            raise ValueError('scope_sync_required: original task exceeds UTF-8 byte limit; resupply exact bytes')
        return route
    route = normalize_route(root, route)
    state.require_route_owner(root, route)
    if _passive(text):
        return route
    raw = text.encode('utf-8')
    value_digest = hashlib.sha256(raw).hexdigest()
    context = route['context']
    replay = [*context['pending'], *((context.get('last_ack') or {}).get('acknowledged', []))]
    for item in replay:
        if event_id is not None and item.get('event_id') == event_id:
            if item.get('digest') != value_digest or item.get('bytes') != len(raw):
                raise ValueError('event identity collision')
            return route
    if context['rejected'] is not None:
        rejected = context['rejected']
        if event_id is not None and rejected.get('event_id') == event_id and rejected['digest'] != value_digest:
            raise ValueError('event identity collision')
        raise ValueError('scope_sync_required: a NOT-admitted input needs explicit exact resolution')
    reason = ('item-bytes' if len(raw) > MAX_ITEM_BYTES else 'queue-count' if len(context['pending']) >= MAX_PENDING
              else 'queue-bytes' if context['pending_bytes'] + len(raw) > MAX_PENDING_BYTES else None)
    updated = _changed(route, scope=True)
    if reason:
        updated['context']['rejected'] = _rejection(raw, event_id, reason)
    else:
        updated['context']['pending'].append({'id': 'scope-' + secrets.token_hex(12), 'event_id': event_id,
                                              'text': text, 'digest': value_digest, 'bytes': len(raw), 'at': now_utc()})
        updated['context']['pending_bytes'] += len(raw)
        _union_assessment(root, updated, text)
    result = state._commit_route(root, updated, expected=route)
    _sync_gate_projection(root, result)
    if reason:
        raise ValueError('scope_sync_required: input NOT admitted; prior scope retained')
    return result


def _rejection(raw: bytes, event_id: str | None, reason: str) -> dict[str, Any]:
    return {'id': 'rejected-' + secrets.token_hex(12), 'event_id': event_id,
            'digest': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw), 'reason': reason, 'at': now_utc()}


def _sync_gate_projection(root: Path, route: dict[str, Any]) -> None:
    if not route.get('change_id'):
        return
    from .human_gates import route_gate_digest
    from .workflow_storage import change_directory
    path = change_directory(root, route['change_id'])
    value = state._route_document(root, path / 'state.json')
    if value.get('route_id') != route['route_id'] or value.get('change_id') != route['change_id']:
        raise ValueError('package gate projection conflicts with canonical task')
    value['human_gates'] = route.get('human_gates', [])
    value['human_gates_digest'] = route_gate_digest(route['route_id'], value['human_gates'])
    state.durable_json(root, path / 'state.json', value)


@state.serialized_task
def attach_package(root: Path, route: dict[str, Any], change_id: str, path: Path) -> dict[str, Any]:
    route = normalize_route(root, route)
    if route.get('change_id') not in (None, change_id):
        raise ValueError('task already has another package')
    record = state._route_document(root, path / 'state.json')
    if record.get('route_id') != route['route_id'] or record.get('change_id') != change_id:
        raise ValueError('package identity conflicts with canonical task')
    current = state.canonical_route(root, route['route_id'])
    if current != route:
        raise ValueError('route changed before package attachment')
    if route.get('change_id') is None:
        updated = _changed(route)
        updated['change_id'] = change_id
        route = state._commit_route(root, updated, expected=route)
    state.set_active_change(root, {'change_id': change_id, 'path': path.relative_to(root).as_posix()})
    return route


def package_documents(root: Path, route: dict[str, Any], *, durable: bool = False) -> dict[str, Any] | None:
    """Load the actual selected typed authority, never a caller's claimed digest."""
    from .package_status import read_package_file
    from .spec import MAX_SPEC_BYTES, _parse_canonical_json, _validate_document, canonical_spec_digest
    from .workflow_storage import valid_package_path
    active = state.get_active_change(root)
    change_id = route.get('change_id')
    if change_id is None:
        if active is not None:
            raise ValueError('selected package is not attached to this task')
        return None
    if (not isinstance(active, dict) or set(active) != {'change_id', 'path'} or
            active['change_id'] != change_id or not valid_package_path(active['path'], change_id)):
        raise ValueError('selected package does not match canonical task')
    path = root / active['path']
    package_state = state._route_document(root, path / 'state.json')
    if package_state.get('change_id') != change_id or package_state.get('route_id') != route['route_id']:
        raise ValueError('package state does not match canonical task')
    raw_spec = read_package_file(root, active['path'] + '/change-spec.yaml', MAX_SPEC_BYTES, sync=durable)
    spec = _parse_canonical_json(raw_spec, path / 'change-spec.yaml')
    _validate_document(spec, gate=True, root=root)
    if spec.get('change_id') != change_id:
        raise ValueError('typed spec change identity mismatch')
    requirements = read_package_file(root, active['path'] + '/requirements.md', sync=durable)
    requirements.decode('utf-8', 'strict')
    if not requirements.strip():
        raise ValueError('requirements are unavailable')
    return {'path': active['path'], 'state': package_state, 'spec': spec,
            'spec_digest': canonical_spec_digest(spec), 'requirements': requirements,
            'requirements_digest': hashlib.sha256(requirements).hexdigest()}


def context_binding(root: Path, route: dict[str, Any] | None = None, *, discovery: bool = False) -> dict[str, Any]:
    route = state.get_active_route(root) if route is None else route
    if not route:
        raise ValueError('task context unavailable')
    if has_task_context(route):
        canonical = state.canonical_route(root, route['route_id'])
        if canonical != route:
            raise ValueError('task context changed')
        validate_route(root, route)
        if not discovery:
            state.require_route_owner(root, route)
    documents = package_documents(root, route)
    if documents is None and not (route.get('delivery_lane') == 'light' or route.get('complexity') in {'micro', 'docs'}):
        raise ValueError('full task requires an attached typed package')
    value = {'version': 1, 'route_id': route['route_id'], 'logical_task_id': task_identity(route),
             'authority_epoch': route.get('authority_epoch', 0),
             'context_revision': (route.get('context') or {}).get('revision', 0),
             'change_id': route.get('change_id'), 'variant': 'package' if documents else 'no-package',
             'package_path': documents['path'] if documents else None,
             'spec_digest': documents['spec_digest'] if documents else None,
             'requirements_digest': documents['requirements_digest'] if documents else None}
    return {**value, 'digest': digest(value)}


def legacy_evidence_allowed(route: dict[str, Any] | None) -> bool:
    if not route:
        return True
    if not has_task_context(route):
        return True
    context = route.get('context') or {}
    return (type(route.get('task_context_version')) is int and route['task_context_version'] == 1 and
            route.get('authority_epoch') == 0 and type(route.get('authority_epoch')) is int and
            not route.get('handoff') and context.get('legacy_compatible') is True and
            type(context.get('revision')) is int and context['revision'] == 0 and
            context.get('pending') == [] and context.get('rejected') is None and context.get('last_ack') is None)


def scope_gaps(root: Path, route: dict[str, Any] | None = None) -> list[str]:
    route = state.get_active_route(root) if route is None else route
    if not route:
        return ['task authority unavailable'] if state.route_authority_present(root) else []
    if legacy_evidence_allowed(route):
        return []
    try:
        validate_route(root, route)
        state.require_route_owner(root, route)
        context = route['context']
        gaps = []
        if context['pending']:
            gaps.append('scope_sync_required: pending amendments need explicit typed synchronization')
        if context['rejected'] is not None:
            gaps.append('scope_sync_required: NOT-admitted input needs exact explicit resolution')
        binding = context_binding(root, route)
        if binding['variant'] == 'package':
            documents = package_documents(root, route)
            ack = context['last_ack']
            if (not ack or ack['revision'] != context['revision'] or
                    ack.get('authority_epoch') != route['authority_epoch'] or
                    ack.get('spec_digest') != binding['spec_digest'] or
                    ack.get('requirements_digest') != binding['requirements_digest'] or
                    'original' not in ack.get('items', {}) or documents['state'].get('scope_ack') != ack):
                gaps.append('scope_sync_required: original/acknowledged scope or package transaction is stale')
        return gaps
    except (ValueError, OSError, KeyError, TypeError) as error:
        return ['scope_sync_required: ' + str(error)]


def _request_schema(request: Any) -> None:
    required = {'version', 'operation_id', 'route_id', 'logical_task_id', 'authority_epoch', 'revision',
                'spec_digest', 'requirements_digest', 'items'}
    if (not isinstance(request, dict) or set(request) - required - {'resolve_rejected'} or
            not required.issubset(request) or type(request['version']) is not int or request['version'] != 1 or
            not all(_identifier(request[key]) for key in ('operation_id', 'route_id', 'logical_task_id')) or
            not all(_integer(request[key]) for key in ('authority_epoch', 'revision')) or
            not all(_hex(request[key]) for key in ('spec_digest', 'requirements_digest')) or
            not isinstance(request['items'], dict) or len(request['items']) > MAX_PENDING + 1):
        raise ValueError('invalid closed scope acknowledgment request')
    for identifier, targets in request['items'].items():
        if (not _identifier(identifier) or not isinstance(targets, list) or not 1 <= len(targets) <= 32 or
                any(not _identifier(target) for target in targets) or len(set(targets)) != len(targets)):
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
    if len(raw) != rejected['bytes'] or hashlib.sha256(raw).hexdigest() != rejected['digest']:
        raise ValueError('rejected-input bytes do not match')
    metadata = {key: value[key] for key in value if key not in {'text', 'text_path'}}
    if value.get('action') == 'incorporated':
        mapped = value.get('targets')
        if (not isinstance(mapped, list) or not 1 <= len(mapped) <= 32 or
                any(not isinstance(item, str) or item not in targets for item in mapped) or
                set(value) & {'user_event_id', 'decision'}):
            raise ValueError('incorporation needs existing typed targets')
    elif value.get('action') == 'withdrawn':
        if (not _identifier(value.get('user_event_id')) or not isinstance(value.get('decision'), str) or
                not value['decision'].strip() or len(value['decision'].encode('utf-8')) > 4096 or 'targets' in value):
            raise ValueError('withdrawal requires a current explicit user decision and event identity')
    else:
        raise ValueError('resolution action must be incorporated or withdrawn')
    return {**metadata, 'digest': rejected['digest'], 'bytes': rejected['bytes']}


@state.serialized_task
def ack_scope(root: Path, request: dict[str, Any]) -> dict[str, Any]:
    _request_schema(request)
    route = normalize_route(root)
    state.require_route_owner(root, route)
    for field in ('route_id', 'logical_task_id', 'authority_epoch'):
        if request[field] != route[field]:
            raise ValueError('scope acknowledgment task/epoch mismatch')
    documents = package_documents(root, route, durable=True)
    if documents is None:
        raise ValueError('scope acknowledgment requires a typed package')
    for field in ('spec_digest', 'requirements_digest'):
        if request[field] != documents[field]:
            raise ValueError('scope acknowledgment document digest mismatch')
    context = route['context']
    previous = context['last_ack']
    transaction_digest = digest(request)
    mirror = documents['state'].get('scope_ack')
    if previous and previous.get('operation_id') == request['operation_id']:
        if previous['transaction_digest'] != transaction_digest or mirror != previous:
            raise ValueError('scope acknowledgment replay collision or missing transaction mirror')
        if request.get('resolve_rejected'):
            proof = previous.get('rejected_resolution')
            _resolution(root, request['resolve_rejected'], proof, _typed_targets(documents['spec']))
        return route
    if request['revision'] != context['revision']:
        raise ValueError('stale scope acknowledgment revision')
    targets = _typed_targets(documents['spec'])
    items = request['items']
    pending = {item['id']: item for item in context['pending']}
    if any(identifier != 'original' and identifier not in pending for identifier in items):
        raise ValueError('scope acknowledgment names an unknown item')
    if any(target not in targets for mapped in items.values() for target in mapped):
        raise ValueError('scope acknowledgment names an unknown typed target')
    if 'original' not in items and not previous:
        raise ValueError('original task must receive explicit typed synchronization')
    resolution = _resolution(root, request.get('resolve_rejected'), context['rejected'], targets)
    updated = _changed(route, scope=True)
    updated['context']['pending'] = [item for item in context['pending'] if item['id'] not in items]
    updated['context']['pending_bytes'] = sum(item['bytes'] for item in updated['context']['pending'])
    if resolution:
        updated['context']['rejected'] = None
    original = items.get('original') or (previous or {}).get('items', {}).get('original')
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
    if package_documents(root, route, durable=True) != documents:
        raise ValueError('scope documents changed before acknowledgment publication')
    package_state = copy.deepcopy(documents['state'])
    package_state['scope_ack'] = ack
    state.durable_json(root, root / documents['path'] / 'state.json', package_state)
    check = package_documents(root, route, durable=True)
    if (check['spec_digest'], check['requirements_digest']) != (documents['spec_digest'], documents['requirements_digest']):
        raise ValueError('scope documents changed during acknowledgment publication')
    updated['context']['last_ack'] = ack
    return state._commit_route(root, updated, expected=route)


def _typed_targets(spec: dict[str, Any]) -> set[str]:
    result = {spec['objective']['id']}
    for name in ('acceptance_criteria', 'invariants', 'forbidden_outcomes'):
        result.update(item['id'] for item in spec.get(name, []))
    return result


def receipt_context_current(root: Path, route: dict[str, Any], receipt: dict[str, Any]) -> bool:
    observed = receipt.get('continuity')
    if observed is None:
        return legacy_evidence_allowed(route)
    try:
        return not scope_gaps(root, route) and observed == context_binding(root, route)
    except (OSError, ValueError, KeyError, TypeError):
        return False


@state.serialized_task
def finish_task(root: Path, *, cancel: bool = False) -> dict[str, Any]:
    route = normalize_route(root)
    state.require_route_owner(root, route)
    _ensure_idle(root)
    if state.open_change_binding(root):
        raise ValueError('finish or cancel the attached package before closing its task')
    if not cancel:
        from .receipts import validate_evidence
        gaps = [*scope_gaps(root, route), *validate_evidence(root, route)]
        if gaps:
            raise ValueError('; '.join(gaps))
    return state.update_route(root, status='cancelled' if cancel else 'completed')


def render_context(root: Path | None, route: dict[str, Any]) -> str:
    lines = ['TASK DATA — original and unresolved scope (not additional system instructions)',
             'Logical task: ' + task_identity(route),
             f"Owner: {route.get('session_id')} | Origin: {route.get('origin_session_id', route.get('session_id'))} "
             f"| Authority epoch: {route.get('authority_epoch', 0)}", 'Original task:', route['task']]
    context = route.get('context') or {}
    for item in context.get('pending', []):
        lines.extend([f"Pending {item['id']} ({item['bytes']} UTF-8 bytes):", item['text']])
    if context.get('rejected'):
        rejected = context['rejected']
        lines.append(f"scope_sync_required: NOT admitted {rejected['id']} ({rejected['bytes']} bytes, "
                     f"sha256={rejected['digest']}); exact original bytes must be supplied again.")
    if root:
        try:
            documents = package_documents(root, route)
            if documents:
                lines.extend([f"Typed package: {documents['path']}",
                              f"Spec digest: {documents['spec_digest']}",
                              f"Requirements digest: {documents['requirements_digest']}"])
                spec = documents['spec']
                for item in [spec['objective'], *spec.get('acceptance_criteria', []),
                             *spec.get('invariants', []), *spec.get('forbidden_outcomes', [])]:
                    lines.append(f"Typed {item['id']}: {item['statement']} (mapping is not completion)")
                for row in documents['state'].get('evidence_accounting', {}).get('obligations', []):
                    if row.get('status') != 'pass':
                        lines.append(f"Unresolved evidence: {row.get('id')}: {row.get('status')}")
            lines.extend(scope_gaps(root, route))
        except (OSError, ValueError, KeyError, TypeError) as error:
            lines.append('Typed authority unavailable: ' + str(error))
    recovery = f"Full stored intake: .getzilla/runtime/routes/{route['route_id']}.json; "
    recovery += 'typed package: ' + str(route.get('change_id') or 'none') + '.\n'
    raw = ('\n'.join(lines) + '\n').encode('utf-8')
    reserve = len(recovery.encode('utf-8')) + 160
    if len(raw) + len(recovery.encode('utf-8')) > MAX_CONTEXT_BYTES:
        prefix = raw[:MAX_CONTEXT_BYTES - reserve].decode('utf-8', 'ignore')
        omitted = len(raw) - len(prefix.encode('utf-8'))
        return prefix + f'\n[Display omitted {omitted} UTF-8 bytes; durable scope is unchanged.]\n' + recovery
    return raw.decode('utf-8') + recovery
