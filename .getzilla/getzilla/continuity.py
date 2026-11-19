"""Canonical unfinished-task context and bounded, explicitly synchronized scope.

The route owns intake and identity. The typed package owns acceptance criteria.
Neither discovery nor intake acknowledgments confer approval or verification.
"""
from __future__ import annotations

import copy as copy
import hashlib
import json
import re
import secrets as secrets
from pathlib import Path
from typing import Any

from . import state
from .util import now_utc as now_utc

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


def _typed_mapping(items: Any) -> bool:
    return (isinstance(items, dict) and 1 <= len(items) <= MAX_PENDING + 1 and
            all(_identifier(identifier) and isinstance(targets, list) and 1 <= len(targets) <= 32 and
                all(_identifier(target) for target in targets) and len(set(targets)) == len(targets)
                for identifier, targets in items.items()))


def _validate_ack(route: dict[str, Any], ack: Any) -> None:
    fields = {'version', 'operation_id', 'transaction_digest', 'route_id', 'logical_task_id',
              'authority_epoch', 'previous_revision', 'revision', 'spec_digest', 'requirements_digest',
              'items', 'acknowledged', 'rejected_resolution'}
    if (not isinstance(ack, dict) or set(ack) != fields or type(ack['version']) is not int or ack['version'] != 1 or
            not _identifier(ack['operation_id']) or
            any(not _hex(ack[key]) for key in ('transaction_digest', 'spec_digest', 'requirements_digest')) or
            ack['route_id'] != route['route_id'] or ack['logical_task_id'] != route['logical_task_id'] or
            any(not _integer(ack[key]) for key in ('authority_epoch', 'previous_revision', 'revision')) or
            ack['authority_epoch'] > route['authority_epoch'] or
            ack['revision'] != ack['previous_revision'] + 1 or ack['revision'] > route['context']['revision'] or
            not _typed_mapping(ack['items']) or 'original' not in ack['items'] or
            not isinstance(ack['acknowledged'], list) or len(ack['acknowledged']) > MAX_PENDING):
        raise ValueError('invalid acknowledged scope transaction')
    ids, events = set(), set()
    for item in ack['acknowledged']:
        if (not isinstance(item, dict) or set(item) != {'id', 'event_id', 'digest', 'bytes'} or
                not _identifier(item['id']) or item['id'] == 'original' or item['id'] in ids or
                not _hex(item['digest']) or type(item['bytes']) is not int or not 1 <= item['bytes'] <= MAX_ITEM_BYTES or
                item['event_id'] is not None and (not _identifier(item['event_id']) or item['event_id'] in events)):
            raise ValueError('invalid acknowledged scope replay proof')
        ids.add(item['id'])
        if item['event_id'] is not None:
            events.add(item['event_id'])
    if set(ack['items']) != {'original', *ids}:
        raise ValueError('acknowledged scope mapping and replay proof differ')
    resolution = ack['rejected_resolution']
    if resolution is not None:
        common = {'id', 'action', 'digest', 'bytes'}
        if (not isinstance(resolution, dict) or not _identifier(resolution.get('id')) or
                not _hex(resolution.get('digest')) or not _integer(resolution.get('bytes')) or resolution['bytes'] == 0):
            raise ValueError('invalid rejected scope resolution proof')
        if resolution.get('action') == 'incorporated':
            if set(resolution) != common | {'targets'} or not _typed_mapping({'rejected': resolution['targets']}):
                raise ValueError('invalid rejected scope incorporation proof')
        elif resolution.get('action') == 'withdrawn':
            if (set(resolution) != common | {'user_event_id', 'decision'} or
                    not _identifier(resolution['user_event_id']) or not isinstance(resolution['decision'], str) or
                    not resolution['decision'].strip() or len(resolution['decision'].encode('utf-8')) > 4096):
                raise ValueError('invalid rejected scope withdrawal proof')
        else:
            raise ValueError('invalid rejected scope resolution action')


def validate_route(root: Path, route: dict[str, Any], *, anchor=None) -> None:
    if not isinstance(route, dict):
        raise ValueError('invalid task envelope')
    if 'intent_state' in route:
        from .task_intent import validate_intent
        validate_intent(route['intent_state'])
    if not has_task_context(route):
        if 'task' in route and not isinstance(route['task'], str):
            raise ValueError('invalid legacy task text')
        return
    if not isinstance(route.get('task'), str):
        raise ValueError('invalid original task text')
    if 'execution_store_required' in route:
        binding = route['execution_store_required']
        if (not isinstance(binding, dict) or set(binding) != {'version', 'generation'}
                or type(binding['version']) is not int or binding['version'] != 1
                or not isinstance(binding['generation'], str)
                or not re.fullmatch(r'[0-9a-f]{32}', binding['generation'])):
            raise ValueError('invalid canonical execution store binding')
    if type(route.get('task_context_version')) is not int or route['task_context_version'] != 1:
        raise ValueError('unsupported task context version; explicit recovery required')
    origin = route.get('origin_session_id')
    if (not _identifier(route.get('logical_task_id')) or not isinstance(origin, str) or
            not 1 <= len(origin) <= 128 or not re.fullmatch(r'[\w.:/-]+', origin) or
            not _identifier(route.get('session_id')) or route['session_id'] == 'manual' or
            route.get('workspace') != (anchor.workspace if anchor is not None else str(root.resolve())) or
            not _integer(route.get('authority_epoch')) or not _integer(route.get('state_revision'))):
        raise ValueError('invalid task identity, workspace or authority epoch')
    context = route.get('context')
    intake_v2 = isinstance(context, dict) and type(context.get('version')) is int and context['version'] == 2
    if (not isinstance(context, dict) or set(context) != set(new_context()) | ({'intake'} if intake_v2 else set()) or
            type(context['version']) is not int or context['version'] not in {1, 2} or
            not _integer(context['revision']) or type(context['legacy_compatible']) is not bool or
            not isinstance(context['pending'], list) or len(context['pending']) > MAX_PENDING):
        raise ValueError('invalid task context')
    if intake_v2:
        from .intake_publication import validate_protocol_metadata
        validate_protocol_metadata(context['intake'])
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
    if ack is not None:
        _validate_ack(route, ack)
    if route.get('handoff') is not None:
        handoff = route['handoff']
        if (not isinstance(handoff, dict) or set(handoff) != {'request_id', 'from_session', 'to_session', 'from_epoch', 'from_revision'} or
                not _identifier(handoff['request_id']) or
                not all(_identifier(handoff[key]) for key in ('from_session', 'to_session')) or
                not all(_integer(handoff[key]) for key in ('from_epoch', 'from_revision')) or
                handoff['to_session'] != route['session_id'] or handoff['from_epoch'] + 1 != route['authority_epoch']):
            raise ValueError('invalid handoff transaction')


def _active_workers(root: Path, *, anchor=None) -> dict[str, Any]:
    path = state.agent_state_path(root)
    if not state._present(root, path, anchor):
        return {}
    try:
        ledger = state._route_document(root, path, anchor=anchor)
        active = ledger['active']
        if not isinstance(active, dict) or not isinstance(ledger.get('history'), list):
            raise ValueError('malformed worker ledger')
        for identifier, record in active.items():
            if (not _identifier(identifier) or not isinstance(record, dict) or
                    any(not _identifier(record.get(key)) for key in ('route_id', 'task_id', 'generation', 'agent_type')) or
                    record.get('workspace') != (anchor.workspace if anchor is not None else str(root.resolve())) or
                    record.get('lifecycle') not in {'running', 'interrupt-requested', 'interrupted'}):
                raise ValueError('malformed worker identity')
        return active
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise ValueError('worker state is unavailable; diagnose and explicitly restart the original instance') from error


@state.serialized_task
def normalize_route(root: Path, route: dict[str, Any] | None=None) -> dict[str, Any]:
    from . import continuity_authoring as authoring
    return authoring.normalize_route(root, route)


def _changed(route: dict[str, Any], *, scope: bool=False) -> dict[str, Any]:
    from . import continuity_authoring as authoring
    return authoring._changed(route, scope=scope)


def _passive(text: str) -> bool:
    from . import continuity_authoring as authoring
    return authoring._passive(text)


def _ensure_idle(root: Path, *, anchor=None) -> None:
    if _active_workers(root, anchor=anchor):
        raise ValueError('active or interrupted worker prevents task handoff; finish the original instance first')


def _union_assessment(root: Path, route: dict[str, Any], text: str) -> None:
    from . import continuity_authoring as authoring
    return authoring._union_assessment(root, route, text)


@state.serialized_task
def submit(root: Path, text: str, session_id: str | None=None, *, new_task: bool=False, continue_route: str | None=None, expected_epoch: int | None=None, expected_revision: int | None=None, event_id: str | None=None, request_id: str | None=None) -> dict[str, Any] | None:
    """Only an explicit new task or exact handoff changes task ownership/identity."""
    from . import continuity_authoring as authoring
    return authoring.submit(root, text, session_id, new_task=new_task, continue_route=continue_route, expected_epoch=expected_epoch, expected_revision=expected_revision, event_id=event_id, request_id=request_id)


def _rejection(raw: bytes, event_id: str | None, reason: str) -> dict[str, Any]:
    from . import continuity_authoring as authoring
    return authoring._rejection(raw, event_id, reason)


def _sync_gate_projection(root: Path, route: dict[str, Any]) -> dict[str, Any]:
    from . import continuity_authoring as authoring
    return authoring._sync_gate_projection(root, route)


@state.serialized_task
def attach_package(root: Path, route: dict[str, Any], change_id: str, path: Path) -> dict[str, Any]:
    from . import continuity_authoring as authoring
    return authoring.attach_package(root, route, change_id, path)


def validate_package_state(value: dict[str, Any], route: dict[str, Any], change_id: str) -> None:
    from .package_status import STAGES, _timestamp
    if (type(value.get('schema_version')) is not int or value['schema_version'] != 1 or
            not isinstance(value.get('status'), str) or value['status'] not in STAGES or
            value.get('change_id') != change_id or value.get('route_id') != route['route_id'] or
            not isinstance(value.get('history'), list) or any(not isinstance(row, dict) for row in value['history'])):
        raise ValueError('invalid selected package state envelope or identity')
    checkpoints = value.get('checkpoints', [])
    if (not isinstance(checkpoints, list) or len(checkpoints) > 2 or
            any(not isinstance(row, dict) or not isinstance(row.get('kind'), str) or
                row['kind'] not in {'initial', 'implementation'} or
                row.get('route_id') != route['route_id'] or row.get('change_id') != change_id or
                not _timestamp(row.get('observed_at')) for row in checkpoints) or
            len({row['kind'] for row in checkpoints}) != len(checkpoints)):
        raise ValueError('invalid selected package checkpoints')


def package_documents(root: Path, route: dict[str, Any], *, durable: bool = False,
                       gate: bool = True, anchor=None, draft: bool = False) -> dict[str, Any] | None:
    """Load the actual selected typed authority, never a caller's claimed digest."""
    from .package_status import read_package_file
    from .spec import MAX_SPEC_BYTES, _parse_canonical_json, _validate_document, canonical_spec_digest
    from .workflow_storage import valid_package_path
    active = state.get_active_change(root, anchor=anchor)
    change_id = route.get('change_id')
    if change_id is None:
        if active is not None:
            raise ValueError('selected package is not attached to this task')
        return None
    if (not isinstance(active, dict) or set(active) != {'change_id', 'path'} or
            active['change_id'] != change_id or not valid_package_path(active['path'], change_id)):
        raise ValueError('selected package does not match canonical task')
    path = root / active['path']
    package_state = state._route_document(root, path / 'state.json', anchor=anchor)
    validate_package_state(package_state, route, change_id)
    raw_spec = (anchor.read(active['path'] + '/change-spec.yaml', MAX_SPEC_BYTES) if anchor is not None
                else read_package_file(root, active['path'] + '/change-spec.yaml', MAX_SPEC_BYTES, sync=durable))
    spec = _parse_canonical_json(raw_spec, path / 'change-spec.yaml')
    # Enabled intake can consistently observe an incomplete typed draft. Its
    # actual pre-code consumers require current semantic readiness separately.
    # The explicit draft observation is also used only to bootstrap that ingress.
    intake = (route.get('context') or {}).get('version') == 2
    _validate_document(spec, gate=gate and not (draft or intake), root=root, anchor=anchor)
    if spec.get('change_id') != change_id:
        raise ValueError('typed spec change identity mismatch')
    requirements = (anchor.read(active['path'] + '/requirements.md', 1_048_576) if anchor is not None
                    else read_package_file(root, active['path'] + '/requirements.md', sync=durable))
    requirements.decode('utf-8', 'strict')
    if not requirements.strip():
        raise ValueError('requirements are unavailable')
    return {'path': active['path'], 'state': package_state, 'spec': spec,
            'spec_digest': canonical_spec_digest(spec), 'requirements': requirements,
            'requirements_digest': hashlib.sha256(requirements).hexdigest()}


def context_binding(root: Path, route: dict[str, Any] | None = None, *, discovery: bool = False, anchor=None) -> dict[str, Any]:
    """Capture a bounded, revalidated observation; this is not a filesystem snapshot.

    No diagnostic read creates a lock or state file. Two equal document reads
    bracketed by canonical-route checks refuse observed concurrent changes.
    Publication still compares the captured binding under task_transition.
    """
    route = state.get_active_route(root, anchor=anchor) if route is None else route
    if not route:
        raise ValueError('task context unavailable')
    if has_task_context(route):
        canonical = state.canonical_route(root, route['route_id'], anchor=anchor)
        if canonical != route:
            raise ValueError('task context changed')
        validate_route(root, route, anchor=anchor)
        if not discovery:
            state.require_route_owner(root, route, anchor=anchor)
    documents = package_documents(root, route, anchor=anchor)
    if documents is None and not (route.get('risk') == 'low' and (
            route.get('delivery_lane') == 'light' or route.get('complexity') == 'micro')):
        raise ValueError('full task requires an attached typed package')
    if has_task_context(route) and state.canonical_route(root, route['route_id'], anchor=anchor) != route:
        raise ValueError('task context changed during capture')
    if package_documents(root, route, anchor=anchor) != documents:
        raise ValueError('task context documents changed during capture')
    if has_task_context(route):
        if state.canonical_route(root, route['route_id'], anchor=anchor) != route:
            raise ValueError('task context changed during capture')
        if not discovery and state.get_active_route(root, anchor=anchor) != route:
            raise ValueError('selected task context changed during capture')
    value = {'version': 1, 'route_id': route['route_id'], 'logical_task_id': task_identity(route),
             'authority_epoch': route.get('authority_epoch', 0),
             'context_revision': (route.get('context') or {}).get('revision', 0),
             'change_id': route.get('change_id'), 'variant': 'package' if documents else 'no-package',
             'package_path': documents['path'] if documents else None,
             'spec_digest': documents['spec_digest'] if documents else None,
             'requirements_digest': documents['requirements_digest'] if documents else None}
    if 'intent_state' in route:
        value.update(version=2, intent_digest=digest(route['intent_state']))
    if 'execution_store_required' in route:
        value['execution_store_required'] = route['execution_store_required']
    if (route.get('context') or {}).get('version') == 2:
        value.update(version=2, intake_protocol={'version': 1, 'required': True})
    return {**value, 'digest': digest(value)}


def unavailable_authority_notice(root: Path) -> str:
    if not state.route_authority_present(root):
        return ''
    return ('Task authority unavailable; scope remains unresolved. Inspect the canonical records under '
            '.getzilla/runtime/routes/ and repair the original state; use exact --continue ROUTE_ID '
            '--session SESSION. Global discovery cannot authorize mutation.')


def legacy_evidence_allowed(route: dict[str, Any] | None) -> bool:
    if not route:
        return True
    if 'intent_state' in route:
        return False
    if not has_task_context(route):
        return True
    context = route.get('context') or {}
    required = _MODERN - {'handoff'}
    return (required.issubset(route) and isinstance(route.get('task'), str) and
            _identifier(route.get('logical_task_id')) and _identifier(route.get('session_id')) and
            isinstance(route.get('origin_session_id'), str) and isinstance(route.get('workspace'), str) and
            _integer(route.get('state_revision')) and isinstance(context, dict) and set(context) == set(new_context()) and
            type(context.get('version')) is int and context['version'] == 1 and
            type(route.get('task_context_version')) is int and route['task_context_version'] == 1 and
            route.get('authority_epoch') == 0 and type(route.get('authority_epoch')) is int and
            not route.get('handoff') and context.get('legacy_compatible') is True and
            type(context.get('revision')) is int and context['revision'] == 0 and
            context.get('pending') == [] and type(context.get('pending_bytes')) is int and context['pending_bytes'] == 0 and
            context.get('rejected') is None and context.get('last_ack') is None)


def scope_gaps(root: Path, route: dict[str, Any] | None = None, *, anchor=None) -> list[str]:
    route = state.get_active_route(root, anchor=anchor) if route is None else route
    if not route:
        return ['task authority unavailable'] if state.route_authority_present(root, anchor=anchor) else []
    if legacy_evidence_allowed(route):
        return []
    try:
        validate_route(root, route, anchor=anchor)
        state.require_route_owner(root, route, anchor=anchor)
        context = route['context']
        gaps = []
        if context['pending']:
            gaps.append('scope_sync_required: pending amendments need explicit typed synchronization')
        if context['rejected'] is not None:
            gaps.append('scope_sync_required: NOT-admitted input needs exact explicit resolution')
        binding = context_binding(root, route, anchor=anchor)
        if binding['variant'] == 'package':
            documents = package_documents(root, route, anchor=anchor)
            ack = context['last_ack']
            if (not ack or ack['revision'] != context['revision'] or
                    ack.get('authority_epoch') != route['authority_epoch'] or
                    ack.get('spec_digest') != binding['spec_digest'] or
                    ack.get('requirements_digest') != binding['requirements_digest'] or
                    'original' not in ack.get('items', {}) or documents['state'].get('scope_ack') != ack or
                    any(target not in _typed_targets(documents['spec']) for mapped in ack['items'].values() for target in mapped)):
                gaps.append('scope_sync_required: original/acknowledged scope or package transaction is stale')
        from .task_intent import intent_gaps
        return [*gaps, *intent_gaps(root, route)]
    except (ValueError, OSError, KeyError, TypeError) as error:
        return ['scope_sync_required: ' + str(error)]


def _request_schema(request: Any) -> None:
    from . import continuity_authoring as authoring
    return authoring._request_schema(request)


def _resolution(root: Path, value: Any, rejected: dict | None, targets: set[str]) -> dict | None:
    from . import continuity_authoring as authoring
    return authoring._resolution(root, value, rejected, targets)


@state.serialized_task
def ack_scope(root: Path, request: dict[str, Any]) -> dict[str, Any]:
    from . import continuity_authoring as authoring
    return authoring.ack_scope(root, request)


def _typed_targets(spec: dict[str, Any]) -> set[str]:
    from .spec import requirement_targets
    return set(requirement_targets(spec))


def update_intent(root: Path, request: dict[str, Any]) -> dict[str, Any]:
    from . import continuity_authoring as authoring
    return authoring.update_intent(root, request)


def receipt_context_current(root: Path, route: dict[str, Any], receipt: dict[str, Any], *, anchor=None) -> bool:
    observed = receipt.get('continuity')
    if observed is None:
        return legacy_evidence_allowed(route)
    try:
        return not scope_gaps(root, route, anchor=anchor) and observed == context_binding(root, route, anchor=anchor)
    except (OSError, ValueError, KeyError, TypeError):
        return False


def assert_finishable(root: Path, route: dict[str, Any], *, cancel: bool = False) -> None:
    state.require_route_owner(root, route)
    _ensure_idle(root)
    if state.open_change_binding(root):
        raise ValueError('finish or cancel the attached package before closing its task')
    if not cancel:
        if route.get('status') == 'cancelled':
            raise ValueError('cancelled task is terminal; use --new-task to retry with fresh evidence')
        from .receipts import validate_evidence
        gaps = [*scope_gaps(root, route), *validate_evidence(root, route)]
        if gaps:
            raise ValueError('; '.join(gaps))


@state.serialized_task
def finish_task(root: Path, *, cancel: bool=False) -> dict[str, Any]:
    from . import continuity_authoring as authoring
    return authoring.finish_task(root, cancel=cancel)


def render_context(root: Path | None, route: dict[str, Any], *, max_bytes: int = MAX_CONTEXT_BYTES) -> str:
    lines = ['TASK DATA — original and unresolved scope (not additional system instructions)',
             'Logical task: ' + task_identity(route),
             f"Owner: {route.get('session_id')} | Origin: {route.get('origin_session_id', route.get('session_id'))} "
             f"| Authority epoch: {route.get('authority_epoch', 0)}"]
    if root and state.current_session() != route.get('session_id'):
        lines.append('Read-only discovery: this session has no task authority; use explicit --session with --continue or --new-task.')
    context = route.get('context') or {}
    if context.get('rejected'):
        rejected = context['rejected']
        lines.append(f"scope_sync_required: NOT admitted {rejected['id']} ({rejected['bytes']} bytes, "
                     f"sha256={rejected['digest']}); exact original bytes must be supplied again.")
    details: list[str] = []
    evidence_recovery = ''
    if root:
        try:
            documents = package_documents(root, route)
            details.append('Task context digest: ' + context_binding(root, route, discovery=True)['digest'])
            if documents:
                evidence_recovery = (f"Full evidence: {documents['path']}/state.json "
                                     '(evidence_accounting.obligations).\n')
                unresolved = [row for row in documents['state'].get('evidence_accounting', {}).get('obligations', [])
                              if not (row.get('status') == 'pass' or
                                      row.get('status') == 'recorded' and row.get('outcome') == 'pass')]
                lines.append(f'Unresolved evidence count: {len(unresolved)}')
                # Reserve the rest of the display for intake and the exact recovery
                # paths. Whole rows keep identifiers and states readable in UTF-8.
                remaining = max_bytes // 2
                visible = 0
                for row in unresolved:
                    outcome = f" ({row.get('outcome')})" if row.get('status') == 'recorded' else ''
                    line = f"Unresolved evidence: {row.get('id')}: {row.get('status')}{outcome}"
                    size = len((line + '\n').encode('utf-8'))
                    if size > remaining:
                        break
                    lines.append(line)
                    remaining -= size
                    visible += 1
                if visible < len(unresolved):
                    lines.append(f'Unresolved evidence hidden: {len(unresolved) - visible}; see Full evidence below.')
                details.extend([f"Typed package: {documents['path']}",
                                f"Spec digest: {documents['spec_digest']}",
                                f"Requirements digest: {documents['requirements_digest']}"])
                spec = documents['spec']
                for item in [spec['objective'], *spec.get('acceptance_criteria', []),
                             *spec.get('invariants', []), *spec.get('forbidden_outcomes', [])]:
                    details.append(f"Typed {item['id']}: {item['statement']} (mapping is not completion)")
            lines.extend(scope_gaps(root, route))
        except (OSError, ValueError, KeyError, TypeError) as error:
            lines.append('Typed authority unavailable: ' + str(error))
    lines.extend(['Original task:', route.get('task', 'Original task unavailable in this legacy record; inspect the original package.')])
    for item in context.get('pending', []):
        lines.extend([f"Pending {item['id']} ({item['bytes']} UTF-8 bytes):", item['text']])
    for question in (route.get('intent_state') or {}).get('questions', []):
        answer = question['answer']
        lines.append(f"Human question {question['id']} for {', '.join(question['targets'])}: {question['question']}")
        if answer:
            lines.append(f"Human response ({answer.get('resolution', 'answered')}; {answer['source_ref']}): {answer['text']}")
        else:
            lines.append('Unresolved: ask the human before the affected implementation; independent work may continue.')
    lines.extend(details)
    recovery = f"Full stored intake: .getzilla/runtime/routes/{route['route_id']}.json; "
    recovery += 'typed package: ' + str(route.get('change_id') or 'none') + '.\n' + evidence_recovery
    raw = ('\n'.join(lines) + '\n').encode('utf-8')
    reserve = len(recovery.encode('utf-8')) + 160
    if len(raw) + len(recovery.encode('utf-8')) > max_bytes:
        prefix = raw[:max(0, max_bytes - reserve)].decode('utf-8', 'ignore')
        omitted = len(raw) - len(prefix.encode('utf-8'))
        return prefix + f'\n[Display omitted {omitted} UTF-8 bytes; durable scope is unchanged.]\n' + recovery
    return raw.decode('utf-8') + recovery
