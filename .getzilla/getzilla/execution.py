"""Retry-safe local attempt contract. No production executor or external-write backend."""
from __future__ import annotations

import copy
from dataclasses import InitVar, dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import time
from typing import Any, Protocol

from . import continuity, state
from . import execution_store as store
from .execution_output import normalize_output, RESPONSE_BYTES, utf8_tail
from .package_status import _git_read, read_package_file
from .spec import _bounded_walk
from .util import tree_fingerprint

_ISSUER = object()
_CONSTRUCTION_TOKEN = object()
_UNCERTAIN: set[tuple[str, str]] = set()
_LIVE: dict[tuple[str, str], tuple[Any, float, str]] = {}
_CANCEL_LIVE: dict[tuple[str, str], float] = {}
_CANCEL_UNCERTAIN: set[tuple[str, str]] = set()
_ID = re.compile(r'[A-Za-z0-9:._-]{1,128}')


class ExecutionError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class Clock:
    monotonic = staticmethod(time.monotonic)
    sleep = staticmethod(time.sleep)

    @staticmethod
    def utcnow():
        return datetime.now(timezone.utc)


SYSTEM_CLOCK = Clock()


@dataclass(frozen=True)
class CallerContext:
    workspace: str
    session_id: str
    route_id: str
    logical_task_id: str
    authority_epoch: int
    agent_id: str | None
    agent_generation: str | None
    _observation_id: str | None
    _issuer: object = field(repr=False)
    _construction_token: InitVar[object]

    def __post_init__(self, _construction_token):
        if self._issuer is not _ISSUER or _construction_token is not _CONSTRUCTION_TOKEN:
            raise ExecutionError('execution_forbidden')


@dataclass(frozen=True)
class SubmitRequest:
    intent_key: str
    arguments: Any
    hard_timeout_seconds: int
    label: str = 'tool'
    operation_id: str | None = None
    mcp_request_id: str | None = None
    remote_task_id: str | None = None


@dataclass(frozen=True)
class AdmittedRequest:
    intent_key: str = field(repr=False)
    argument_bytes: bytes = field(repr=False)
    hard_timeout_seconds: int
    label: str
    operation_id: str | None
    mcp_request_id: str | None
    remote_task_id: str | None

    @property
    def arguments(self):
        # Every consumer owns its decoded payload; caller references cannot alter admission.
        return json.loads(self.argument_bytes)


@dataclass(frozen=True)
class Admission:
    execution_id: str
    execution_generation: str
    revision: int
    token: str = field(repr=False)

    def consume(self, root: Path, request: AdmittedRequest):
        return _consume_dispatch(root, self, request)


@dataclass(frozen=True)
class CancelAdmission:
    execution_id: str
    execution_generation: str
    request_id: str
    token: str = field(repr=False)

    def consume(self, root: Path):
        return _consume_cancel(root, self)


class ExecutionBackend(Protocol):
    kind: str
    external_mutations: bool
    cooperative_admission: bool

    def dispatch(self, root: Path, admission: Admission, request: AdmittedRequest) -> dict | None: ...
    def cancel(self, root: Path, admission: CancelAdmission) -> bool: ...


def _digest(value):
    _bounded_walk(value)
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()
    if len(raw) > 65536:
        raise ExecutionError('request_too_large')
    return hashlib.sha256(raw).hexdigest()


def _snapshot(request: SubmitRequest):
    try:
        _bounded_walk(request.arguments)
        raw = json.dumps(request.arguments, sort_keys=True, ensure_ascii=False,
                         separators=(',', ':'), allow_nan=False).encode()
        if len(raw) > 65536:
            raise ExecutionError('request_too_large')
        # Validate the very bytes retained for dispatch, rather than retain mutable aliases.
        _bounded_walk(json.loads(raw))
        return AdmittedRequest(request.intent_key, raw, request.hard_timeout_seconds, request.label,
                               request.operation_id, request.mcp_request_id, request.remote_task_id)
    except (TypeError, ValueError, RuntimeError, UnicodeError, RecursionError) as error:
        raise ExecutionError('invalid_submit') from error


def _request_digest(request: AdmittedRequest, kind: str):
    return _digest({'arguments': request.arguments, 'backend': kind, 'timeout': request.hard_timeout_seconds,
                    'label': request.label, 'operation_id': request.operation_id, 'remote_task_id': request.remote_task_id})


def _agent(root, agent_id):
    try:
        return continuity._active_workers(root)[agent_id]
    except (KeyError, OSError, ValueError) as error:
        raise ExecutionError('actor_unavailable') from error


def trusted_caller(root: Path, *, agent_id: str | None = None, execution_id: str | None = None) -> CallerContext:
    """Calling adapters bind the native session first; principal text is never an input."""
    root = root.resolve(strict=True)
    session = state.current_session()
    if not session:
        raise ExecutionError('actor_unavailable')
    saved = None
    if execution_id is not None:
        saved = _find(store.load_registry(root), execution_id)
        if saved['owner']['workspace'] != str(root) or saved['owner']['session_id'] != session:
            raise ExecutionError('execution_forbidden')
        _owner_current(root, saved)
        route = state.canonical_route(root, saved['owner']['route_id'])
    else:
        try:
            route = state.require_route_owner(root)
        except ValueError as error:
            raise ExecutionError('actor_unavailable') from error
        route = state.canonical_route(root, route['route_id'])
    if not session or session != route.get('session_id') or not continuity.has_task_context(route):
        raise ExecutionError('actor_unavailable')
    generation = None
    if agent_id is not None:
        agent = _agent(root, agent_id)
        if (agent['route_id'] != route['route_id'] or agent['task_id'] != continuity.task_identity(route)
                or agent.get('authority_epoch', 0) != route['authority_epoch']):
            raise ExecutionError('actor_unavailable')
        generation = agent['generation']
        if saved is not None and (saved['owner']['agent_id'] != agent_id
                                  or saved['owner']['agent_generation'] != generation):
            raise ExecutionError('execution_forbidden')
    fields = dict(workspace=str(root), session_id=session, route_id=route['route_id'],
                  logical_task_id=continuity.task_identity(route), authority_epoch=route['authority_epoch'],
                  agent_id=agent_id, agent_generation=generation, _observation_id=execution_id, _issuer=_ISSUER)
    return CallerContext(**fields, _construction_token=_CONSTRUCTION_TOKEN)


def _caller(root, caller):
    if (type(caller) is not CallerContext or caller._issuer is not _ISSUER
            or caller.workspace != str(root.resolve()) or caller.session_id != state.current_session()):
        raise ExecutionError('execution_forbidden')
    try:
        route = state.canonical_route(root, caller.route_id)
        if (route['session_id'] != caller.session_id or route['authority_epoch'] != caller.authority_epoch
                or continuity.task_identity(route) != caller.logical_task_id):
            raise ExecutionError('execution_forbidden')
        if caller.agent_id:
            agent = _agent(root, caller.agent_id)
            if (agent['generation'] != caller.agent_generation or agent['route_id'] != caller.route_id
                    or agent['task_id'] != caller.logical_task_id
                    or agent.get('authority_epoch', 0) != caller.authority_epoch):
                raise ExecutionError('execution_forbidden')
        return route
    except (OSError, ValueError, KeyError) as error:
        if isinstance(error, ExecutionError):
            raise
        raise ExecutionError('execution_forbidden') from error


def _authorize(root, caller, record):
    _caller(root, caller)
    if caller._observation_id is not None and caller._observation_id != record['execution_id']:
        raise ExecutionError('execution_forbidden')
    owner = record['owner']
    if any(owner[key] != value for key, value in (
        ('workspace', caller.workspace), ('session_id', caller.session_id),
    )):
        raise ExecutionError('execution_forbidden')
    # The observed attempt's canonical owner controls ACL, never the selected task pointer.
    _owner_route(root, record)
    if caller.agent_id and (owner['agent_id'] != caller.agent_id or owner['agent_generation'] != caller.agent_generation):
        raise ExecutionError('execution_forbidden')


def _owner_route(root, record):
    owner = record['owner']
    try:
        route = state.canonical_route(root, owner['route_id'])
        if (route['session_id'] != owner['session_id'] or route['authority_epoch'] != owner['authority_epoch']
                or continuity.task_identity(route) != owner['logical_task_id']):
            raise ExecutionError('event_fenced')
    except (KeyError, OSError, ValueError) as error:
        raise ExecutionError('execution_forbidden') from error


def _owner_current(root, record):
    _owner_route(root, record)
    owner = record['owner']
    try:
        if owner['agent_id']:
            agent = _agent(root, owner['agent_id'])
            if (agent['generation'] != owner['agent_generation'] or agent['route_id'] != owner['route_id']
                    or agent['task_id'] != owner['logical_task_id']
                    or agent.get('authority_epoch', 0) != owner['authority_epoch']):
                raise ExecutionError('event_fenced')
    except (KeyError, OSError, ValueError) as error:
        raise ExecutionError('event_fenced') from error


def _source(root, route):
    """Bounded content observation, not an immutable checkout or PASS receipt."""
    entries = []
    total = 0
    pending = [root]
    while pending:
        folder = pending.pop()
        with os.scandir(folder) as listing:
            for entry in sorted(listing, key=lambda item: item.name):
                path = Path(entry.path)
                relative = path.relative_to(root).as_posix()
                if entry.name in {'.git', '__pycache__', '.pytest_cache'} or relative == '.getzilla/runtime':
                    continue
                if (entry.name == '.env' or entry.name.startswith('.env.') or entry.name in {'.ssh', 'id_rsa'}
                        or path.suffix.lower() in {'.pem', '.key'}):
                    raise ExecutionError('source_inventory_unavailable')
                if len(entries) + len(pending) >= 4096:
                    raise ExecutionError('source_inventory_unavailable')
                if entry.is_symlink():
                    entries.append((relative, 'link', hashlib.sha256(os.fsencode(os.readlink(path))).hexdigest()))
                elif entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                elif entry.is_file(follow_symlinks=False):
                    raw = read_package_file(root, relative, limit=2 * 1024 * 1024)
                    total += len(raw)
                    if total > 16 * 1024 * 1024:
                        raise ExecutionError('source_inventory_unavailable')
                    entries.append((relative, entry.stat(follow_symlinks=False).st_mode, hashlib.sha256(raw).hexdigest()))
                else:
                    raise ExecutionError('source_inventory_unavailable')
    inventory = hashlib.sha256(json.dumps(sorted(entries), ensure_ascii=True).encode()).hexdigest()
    code, top = _git_read(root, ['rev-parse', '--show-toplevel'])
    head, dirty = None, False
    if code == 0 and Path(os.fsdecode(top).strip()).resolve() == root:
        code, head_raw = _git_read(root, ['rev-parse', 'HEAD'])
        head = head_raw.decode('ascii').strip() if code == 0 else None
        code, status = _git_read(root, ['status', '--porcelain=v1', '-z', '--untracked-files=all'])
        if code != 0 or head is None or not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', head):
            raise ExecutionError('source_inventory_unavailable')
        dirty = bool(status)
    binding = continuity.context_binding(root, route, discovery=True)['digest']
    native = tree_fingerprint(root) if head is not None else None
    return {'git_head': head, 'tree_fingerprint': native,
            'fingerprint': hashlib.sha256((str(head) + str(native) + inventory).encode()).hexdigest(),
            'dirty': dirty, 'inventory_digest': inventory, 'context_digest': binding, 'evidence_links': []}


def _view(root, record):
    result = copy.deepcopy({key: value for key, value in record.items() if key != 'output'})
    result['output'] = normalize_output(None if record['expired'] else record['output'])
    result.pop('backend')  # backend token digests are never part of the observation surface
    result.pop('event_receipts')
    if result['cancel_claim'] is not None:
        result['cancel_claim'].pop('token_digest')
    if (str(root.resolve()), record['execution_id']) in _CANCEL_UNCERTAIN:
        result['cancel_claim']['state'] = 'unknown'
        if record['execution_status'] not in store.TERMINAL:
            result.update(cleanup_status='unconfirmed', operation_outcome='unknown')
    result['evidence_authority'] = False
    result['observation_status'] = 'expired' if record['expired'] else 'ready'
    live = _LIVE.get((str(root.resolve()), record['execution_id']))
    result['live_continuity'] = bool(live and live[2] == record['execution_generation'])
    if record['execution_status'] not in store.TERMINAL and not result['live_continuity']:
        result['observation_status'] = 'recovery_unknown'
    result['deadline_elapsed'] = bool(live and live[0].monotonic() >= live[1])
    if (str(root.resolve()), record['execution_id']) in _UNCERTAIN:
        result.update(observation_status='persistence_unknown', execution_status='orphaned',
                      operation_outcome='unknown', cleanup_status='unconfirmed', terminal_reason='persistence_unknown')
    while len(json.dumps(result, ensure_ascii=False).encode()) > RESPONSE_BYTES:
        preview = result['output']['preview'].encode()
        if not preview:
            raise ExecutionError('execution_view_too_large')
        result['output'].update(preview=utf8_tail(preview, len(preview) // 2),
                                preview_truncated=True, truncated=True, complete_output=False)
    return result


def _find(registry, execution_id):
    if not isinstance(execution_id, str) or not re.fullmatch(r'[0-9a-f]{32}', execution_id):
        raise ExecutionError('execution_not_found')
    try:
        return registry['records'][execution_id]
    except KeyError as error:
        raise ExecutionError('execution_not_found') from error


def get(root: Path, caller: CallerContext, execution_id: str):
    _caller(root, caller)
    record = _find(store.load_registry(root), execution_id)
    _authorize(root, caller, record)
    return _view(root, record)


def _backend(backend):
    if backend is None:
        raise ExecutionError('unsupported_backend')
    if getattr(backend, 'external_mutations', None) is not False:
        raise ExecutionError('external_backend_unqualified')
    if not isinstance(backend.kind, str) or not _ID.fullmatch(backend.kind):
        raise ExecutionError('unsupported_backend')
    if getattr(backend, 'cooperative_admission', None) is not True:
        raise ExecutionError('unsupported_admission_fence')
    return backend.kind


def _dispatch_ready(root, record):
    live = _LIVE.get((str(root.resolve()), record['execution_id']))
    if (not live or live[2] != record['execution_generation'] or live[0].monotonic() >= live[1]
            or record['execution_status'] != 'running' or record['dispatch_claim'] != 'pending'):
        raise ExecutionError('admission_fenced')
    _owner_current(root, record)


@state.serialized_task
def _consume_dispatch(root, admission, request):
    if type(request) is not AdmittedRequest:
        raise ExecutionError('unsupported_admission_fence')
    def consume(registry):
        record = _find(registry, admission.execution_id)
        _dispatch_ready(root, record)
        if (record['execution_generation'] != admission.execution_generation
                or record['revision'] != admission.revision
                or not secrets.compare_digest(record['backend']['token_digest'], hashlib.sha256(admission.token.encode()).hexdigest())
                or _request_digest(request, record['backend']['kind']) != record['input']['request_digest']):
            raise ExecutionError('admission_fenced')
        record.update(dispatch_claim='consumed', revision=record['revision'] + 1)
    registry, _ = store.mutate_registry(root, consume)
    return _view(root, registry['records'][admission.execution_id])


def submit(root: Path, caller: CallerContext, request: SubmitRequest, *, backend: ExecutionBackend | None = None,
           clock: Clock = SYSTEM_CLOCK):
    kind = _backend(backend)
    if (type(caller) is not CallerContext or getattr(caller, '_issuer', None) is not _ISSUER
            or caller._observation_id is not None):
        raise ExecutionError('execution_forbidden')
    if (type(request) is not SubmitRequest or type(request.hard_timeout_seconds) is not int
            or not 1 <= request.hard_timeout_seconds <= 86400 or not isinstance(request.intent_key, str)
            or not 1 <= len(request.intent_key.encode()) <= 1024
            or not re.fullmatch(r'[A-Za-z0-9 ._-]{1,80}', request.label)
            or any(value is not None and (not isinstance(value, str) or not _ID.fullmatch(value))
                   for value in (request.operation_id, request.mcp_request_id, request.remote_task_id))):
        raise ExecutionError('invalid_submit')
    request = _snapshot(request)
    request_digest = _request_digest(request, kind)
    with state.task_transition(root):
        route = _caller(root, caller)
        owner = {'workspace': caller.workspace, 'project': hashlib.sha256(caller.workspace.encode()).hexdigest(),
                 'session_id': caller.session_id, 'route_id': caller.route_id, 'logical_task_id': caller.logical_task_id,
                 'change_id': route.get('change_id'), 'authority_epoch': caller.authority_epoch,
                 'principal_kind': 'agent' if caller.agent_id else 'session',
                 'principal_id': caller.agent_id or caller.session_id, 'agent_id': caller.agent_id,
                 'agent_generation': caller.agent_generation, 'run_id': None}
        intent = _digest([owner['workspace'], owner['principal_kind'], owner['principal_id'],
                          owner['logical_task_id'], request.intent_key])
        token = secrets.token_hex(32)
        now = clock.utcnow()
        started = clock.monotonic()
        if now.tzinfo is None or not math.isfinite(started):
            raise ExecutionError('invalid_clock')
        def allocate(registry):
            existing = registry['intents'].get(intent)
            if existing:
                record = registry['records'][existing]
                _authorize(root, caller, record)
                if record['input']['request_digest'] != request_digest:
                    raise ExecutionError('intent_conflict')
                return existing, False
            if len(registry['records']) >= store.MAX_RECORDS:
                raise store.RegistryError('registry_full')
            execution_id = secrets.token_hex(16)
            record = {
                'schema_version': 1, 'execution_id': execution_id, 'revision': 1,
                'execution_generation': secrets.token_hex(16), 'owner': owner,
                'input': {'intent_digest': intent, 'request_digest': request_digest, 'display': {'label': request.label}},
                'source': _source(root.resolve(), route),
                'deadline': {'submitted_at': now.isoformat(),
                             'hard_deadline_at': (now + timedelta(seconds=request.hard_timeout_seconds)).isoformat(),
                             'duration_seconds': request.hard_timeout_seconds},
                'backend': {'kind': kind, 'token_digest': hashlib.sha256(token.encode()).hexdigest(),
                            'claim': 'committed', 'external_mutations': False},
                'operation_id': request.operation_id, 'mcp_request_id': request.mcp_request_id,
                'remote_task_id': request.remote_task_id, 'execution_status': 'running',
                'cleanup_status': 'not_required', 'operation_outcome': 'not_applicable', 'terminal_reason': None,
                'source_final': None, 'source_changed': False, 'output': None, 'retention_until': None,
                'expired': False, 'event_receipts': {}, 'dispatch_claim': 'pending', 'cancel_claim': None,
            }
            registry['records'][execution_id] = record
            registry['intents'][intent] = execution_id
            return execution_id, True
        registry, (execution_id, dispatch) = store.mutate_registry(root, allocate, create=True)
    record = registry['records'][execution_id]
    if not dispatch:
        return _view(root, record)
    _LIVE[(str(root.resolve()), execution_id)] = (clock, started + request.hard_timeout_seconds,
                                                 record['execution_generation'])
    if clock.monotonic() >= started + request.hard_timeout_seconds:
        def expire_before_dispatch(registry):
            current = _find(registry, execution_id)
            _owner_current(root, current)
            if current['revision'] != record['revision'] or current['execution_status'] != 'running':
                raise ExecutionError('event_fenced')
            current.update(execution_status='timed_out', cleanup_status='not_required',
                           operation_outcome='unknown' if current['operation_id'] else 'not_applicable',
                           terminal_reason='deadline_before_dispatch',
                           retention_until=(clock.utcnow() + timedelta(days=1)).isoformat(),
                           revision=current['revision'] + 1)
        try:
            expired, _ = store.mutate_registry(root, expire_before_dispatch)
            return _view(root, expired['records'][execution_id])
        except store.RegistryError:
            _UNCERTAIN.add((str(root.resolve()), execution_id))
            return _view(root, record)
    admission = Admission(execution_id, record['execution_generation'], record['revision'], token)
    # Check the already-stale unlocked boundary before even entering the cooperative adapter.
    # Its own consumption below remains the linearization point; no lock spans adapter work.
    with state.task_transition(root):
        _dispatch_ready(root, _find(store.load_registry(root), execution_id))
    try:
        result = backend.dispatch(root, admission, request)
    except Exception:
        # A dispatch claim is never repeated, even if the backend threw before returning.
        _UNCERTAIN.add((str(root.resolve()), execution_id))
        try:
            record = _find(store.load_registry(root), execution_id)
        except store.RegistryError:
            pass
        return _view(root, record)
    record = _find(store.load_registry(root), execution_id)
    if record['dispatch_claim'] != 'consumed':
        raise ExecutionError('unsupported_admission_fence')
    if result is not None:
        try:
            return record_event(root, token, execution_id, record['revision'], record['execution_generation'],
                                'dispatch-result', result)
        except store.RegistryError:
            _UNCERTAIN.add((str(root.resolve()), execution_id))
            return _view(root, record)
    return _view(root, record)


@state.serialized_task
def record_event(root, backend_token, execution_id, expected_revision, execution_generation, event_id, event):
    if (not isinstance(backend_token, str) or not re.fullmatch(r'[0-9a-f]{64}', backend_token)
            or not isinstance(event_id, str) or not _ID.fullmatch(event_id) or not isinstance(event, dict)
            or set(event) - {'execution_status', 'terminal_reason', 'cleanup_status', 'operation_outcome', 'output'}
            or event.get('execution_status') not in store.STATUSES):
        raise ExecutionError('invalid_event')
    # The exact event digest precedes lossy normalization, so conflicting replays stay conflicts.
    try:
        raw_event = json.dumps(event, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()
        if len(raw_event) > store.MAX_REGISTRY_BYTES:
            raise ExecutionError('invalid_event')
        digest = hashlib.sha256(raw_event).hexdigest()
    except (ValueError, TypeError, UnicodeError, RecursionError) as error:
        raise ExecutionError('invalid_event') from error
    event = copy.deepcopy(event)
    if 'output' in event:
        event['output'] = normalize_output(event['output'])
    def apply(registry):
        record = _find(registry, execution_id)
        _owner_current(root, record)
        if (not secrets.compare_digest(record['backend']['token_digest'], hashlib.sha256(backend_token.encode()).hexdigest())
                or record['execution_generation'] != execution_generation):
            raise ExecutionError('event_fenced')
        if event_id in record['event_receipts']:
            if record['event_receipts'][event_id] != digest:
                raise ExecutionError('event_conflict')
            return
        live = _LIVE.get((str(root.resolve()), execution_id))
        if not live or live[2] != execution_generation or live[0].monotonic() >= live[1]:
            raise ExecutionError('event_fenced')
        if (type(expected_revision) is not int or record['revision'] != expected_revision
                or record['execution_status'] in store.TERMINAL or len(record['event_receipts']) >= 64
                or record['dispatch_claim'] != 'consumed'):
            raise ExecutionError('event_fenced')
        if record['execution_status'] == 'cancel_requested' and event['execution_status'] == 'running':
            raise ExecutionError('event_fenced')
        record.update(copy.deepcopy(event))
        record['revision'] += 1
        record['event_receipts'][event_id] = digest
        if record['execution_status'] in store.TERMINAL:
            if record['terminal_reason'] is None:
                record['terminal_reason'] = 'backend_' + record['execution_status']
            record['retention_until'] = (live[0].utcnow() + timedelta(days=1)).isoformat()
            try:
                route = state.canonical_route(root, record['owner']['route_id'])
                record['source_final'] = _source(root.resolve(), route)
                record['source_changed'] = record['source_final'] != record['source']
            except (ValueError, OSError):
                record['source_final'] = None
                record['source_changed'] = True
    registry, _ = store.mutate_registry(root, apply)
    return _view(root, registry['records'][execution_id])


def wait(root, caller, execution_id, timeout_seconds, *, clock: Clock = SYSTEM_CLOCK):
    if (type(timeout_seconds) not in {int, float} or not 0 < timeout_seconds <= 30
            or not math.isfinite(timeout_seconds)):
        raise ExecutionError('invalid_wait_timeout')
    end = clock.monotonic() + timeout_seconds
    while True:
        view = get(root, caller, execution_id)
        if view['execution_status'] in store.TERMINAL or view['observation_status'] == 'expired':
            return {'wait_status': 'ready', 'execution': view}
        remaining = end - clock.monotonic()
        if remaining <= 0:
            return {'wait_status': 'wait_expired', 'execution': view}
        clock.sleep(min(.01, remaining))


@state.serialized_task
def restore(root, *, clock: Clock = SYSTEM_CLOCK):
    """Explicit local maintenance, never a process recovery or external reconciliation."""
    session = state.current_session()
    if not session:
        raise ExecutionError('actor_unavailable')
    now = clock.utcnow()
    if now.tzinfo is None:
        raise ExecutionError('invalid_clock')
    counts = {'orphaned': 0, 'expired': 0, 'unchanged': 0, 'unavailable': 0, 'normalized_outputs': 0}
    def maintain(registry):
        for execution_id, record in registry['records'].items():
            if record['owner']['session_id'] != session:
                counts['unavailable'] += 1
                continue
            try:
                _owner_current(root, record)
            except ExecutionError:
                counts['unavailable'] += 1
                continue
            original_revision = record['revision']
            normalized = normalize_output(record['output'])
            output_changed = record['output'] is not None and record['output'] != normalized
            if output_changed:
                record.update(output=normalized, revision=original_revision + 1)
                counts['normalized_outputs'] += 1
            if record['execution_status'] in store.TERMINAL:
                if (not record['expired'] and record['retention_until'] is not None
                        and datetime.fromisoformat(record['retention_until']) <= now):
                    record.update(expired=True, output=None, revision=original_revision + 1)
                    counts['expired'] += 1
                else:
                    if not output_changed:
                        counts['unchanged'] += 1
                continue
            live = _LIVE.get((str(root.resolve()), execution_id))
            if (live and live[0] is clock and live[0].monotonic() < live[1]
                    and (str(root.resolve()), execution_id) not in _UNCERTAIN):
                if not output_changed:
                    counts['unchanged'] += 1
                continue
            record.update(execution_status='orphaned', cleanup_status='unconfirmed',
                          operation_outcome='unknown' if record['operation_id'] else 'not_applicable',
                          terminal_reason='recovery_uncertain', retention_until=(now + timedelta(days=1)).isoformat(),
                          revision=original_revision + 1)
            if record['output'] is not None:
                record['output'] = normalize_output(record['output'])
            counts['orphaned'] += 1
    store.mutate_registry(root, maintain)
    return counts


def _cancel_ready(root, record, admission):
    claim = record['cancel_claim']
    end = _CANCEL_LIVE.get((str(root.resolve()), admission.request_id))
    if (record['execution_status'] in store.TERMINAL or record['execution_generation'] != admission.execution_generation
            or claim is None or claim['request_id'] != admission.request_id or claim['state'] != 'reserved'
            or not secrets.compare_digest(claim['token_digest'], hashlib.sha256(admission.token.encode()).hexdigest())
            or end is None or SYSTEM_CLOCK.monotonic() >= end):
        raise ExecutionError('admission_fenced')
    _owner_current(root, record)


@state.serialized_task
def _consume_cancel(root, admission):
    def consume(registry):
        record = _find(registry, admission.execution_id)
        _cancel_ready(root, record, admission)
        record['cancel_claim']['state'] = 'consumed'
        record['revision'] += 1
    registry, _ = store.mutate_registry(root, consume)
    return _view(root, registry['records'][admission.execution_id])


@state.serialized_task
def _cancel_receipt(root, admission, outcome):
    def save(registry):
        record = _find(registry, admission.execution_id)
        claim = record['cancel_claim']
        if (record['execution_status'] in store.TERMINAL or claim['state'] in {'accepted', 'rejected', 'unknown'}):
            return
        _owner_current(root, record)
        if (record['execution_generation'] != admission.execution_generation or claim['request_id'] != admission.request_id
                or not secrets.compare_digest(claim['token_digest'], hashlib.sha256(admission.token.encode()).hexdigest())):
            raise ExecutionError('admission_fenced')
        if outcome == 'accepted' and claim['state'] != 'consumed':
            raise ExecutionError('unsupported_admission_fence')
        claim['state'] = outcome
        record['revision'] += 1
        if outcome == 'accepted':
            record.update(execution_status='cancel_requested', cleanup_status='pending')
        elif outcome == 'unknown':
            record.update(cleanup_status='unconfirmed', operation_outcome='unknown')
    registry, _ = store.mutate_registry(root, save)
    return _view(root, registry['records'][admission.execution_id])


def cancel(root, caller, execution_id, *, backend=None):
    kind = _backend(backend)
    token, request_id = secrets.token_hex(32), secrets.token_hex(16)
    now, started = SYSTEM_CLOCK.utcnow(), SYSTEM_CLOCK.monotonic()
    with state.task_transition(root):
        def reserve(registry):
            record = _find(registry, execution_id)
            _authorize(root, caller, record)
            if record['execution_status'] in store.TERMINAL or record['cancel_claim'] is not None:
                return False
            if record['backend']['kind'] != kind:
                raise ExecutionError('unsupported_backend')
            record['cancel_claim'] = {'request_id': request_id, 'token_digest': hashlib.sha256(token.encode()).hexdigest(),
                                      'state': 'reserved', 'requested_at': now.isoformat(),
                                      'deadline_at': (now + timedelta(seconds=30)).isoformat()}
            record['revision'] += 1
            return True
        registry, reserved = store.mutate_registry(root, reserve)
    record = registry['records'][execution_id]
    if not reserved:
        return _view(root, record)
    _CANCEL_LIVE[(str(root.resolve()), request_id)] = started + 30
    admission = CancelAdmission(execution_id, record['execution_generation'], request_id, token)
    with state.task_transition(root):
        _cancel_ready(root, _find(store.load_registry(root), execution_id), admission)
    try:
        accepted = backend.cancel(root, admission)
    except Exception:
        accepted = None  # Lost response is uncertain; a reserved request is never resent.
    try:
        return _cancel_receipt(root, admission, 'accepted' if accepted is True else
                               'rejected' if accepted is False else 'unknown')
    except (store.RegistryError, ExecutionError) as error:
        _CANCEL_UNCERTAIN.add((str(root.resolve()), execution_id))
        if isinstance(error, ExecutionError) and error.code == 'unsupported_admission_fence':
            raise
        return _view(root, record)
