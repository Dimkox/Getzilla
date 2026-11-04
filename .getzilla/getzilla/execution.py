"""Retry-safe local attempt contract. No production executor or external-write backend."""
from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
from typing import Any, Protocol

from . import continuity, state
from . import execution_store as store
from .package_status import _git_read, read_package_file
from .spec import _bounded_walk

_ISSUER = object()
_UNCERTAIN: set[tuple[str, str]] = set()
_ID = re.compile(r'[A-Za-z0-9:._-]{1,128}')


class ExecutionError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, init=False)
class CallerContext:
    workspace: str
    session_id: str
    route_id: str
    logical_task_id: str
    authority_epoch: int
    agent_id: str | None
    agent_generation: str | None
    _issuer: object


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
class Admission:
    execution_id: str
    execution_generation: str
    revision: int
    token: str


class ExecutionBackend(Protocol):
    kind: str
    external_mutations: bool

    def dispatch(self, root: Path, admission: Admission, request: SubmitRequest) -> dict | None: ...
    def cancel(self, root: Path, admission: Admission) -> bool: ...


def _digest(value):
    _bounded_walk(value)
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()
    if len(raw) > 65536:
        raise ExecutionError('request_too_large')
    return hashlib.sha256(raw).hexdigest()


def _agent(root, agent_id):
    try:
        return continuity._active_workers(root)[agent_id]
    except (KeyError, OSError, ValueError) as error:
        raise ExecutionError('actor_unavailable') from error


def trusted_caller(root: Path, *, agent_id: str | None = None) -> CallerContext:
    """Calling adapters bind the native session first; principal text is never an input."""
    root = root.resolve(strict=True)
    with state.task_transition(root):
        route = state.require_route_owner(root)
        route = state.canonical_route(root, route['route_id'])
        session = state.current_session()
        if not session or session != route.get('session_id') or not continuity.has_task_context(route):
            raise ExecutionError('actor_unavailable')
        generation = None
        if agent_id is not None:
            agent = _agent(root, agent_id)
            if (agent['route_id'] != route['route_id'] or agent['task_id'] != continuity.task_identity(route)
                    or agent.get('authority_epoch', 0) != route['authority_epoch']):
                raise ExecutionError('actor_unavailable')
            generation = agent['generation']
        value = object.__new__(CallerContext)
        fields = dict(workspace=str(root), session_id=session, route_id=route['route_id'],
                      logical_task_id=continuity.task_identity(route), authority_epoch=route['authority_epoch'],
                      agent_id=agent_id, agent_generation=generation, _issuer=_ISSUER)
        for key, item in fields.items():
            object.__setattr__(value, key, item)
        return value


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
    owner = record['owner']
    if any(owner[key] != value for key, value in (
        ('workspace', caller.workspace), ('session_id', caller.session_id), ('route_id', caller.route_id),
        ('logical_task_id', caller.logical_task_id), ('authority_epoch', caller.authority_epoch),
    )):
        raise ExecutionError('execution_forbidden')
    if caller.agent_id and (owner['agent_id'] != caller.agent_id or owner['agent_generation'] != caller.agent_generation):
        raise ExecutionError('execution_forbidden')


def _owner_current(root, record):
    owner = record['owner']
    try:
        route = state.canonical_route(root, owner['route_id'])
        if (route['session_id'] != owner['session_id'] or route['authority_epoch'] != owner['authority_epoch']
                or continuity.task_identity(route) != owner['logical_task_id']):
            raise ExecutionError('event_fenced')
        if owner['agent_id']:
            agent = _agent(root, owner['agent_id'])
            if (agent['generation'] != owner['agent_generation'] or agent['route_id'] != owner['route_id']
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
                    entries.append((relative, 'file', hashlib.sha256(raw).hexdigest()))
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
    binding = continuity.context_binding(root, route)['digest']
    return {'git_head': head, 'fingerprint': hashlib.sha256((str(head) + inventory).encode()).hexdigest(),
            'dirty': dirty, 'inventory_digest': inventory, 'context_digest': binding, 'evidence_links': []}


def _view(root, record):
    result = copy.deepcopy(record)
    result.pop('backend')  # backend token digests are never part of the observation surface
    result.pop('event_receipts')
    result['evidence_authority'] = False
    result['observation_status'] = 'expired' if record['expired'] else 'ready'
    if (str(root.resolve()), record['execution_id']) in _UNCERTAIN:
        result.update(observation_status='persistence_unknown', execution_status='orphaned',
                      operation_outcome='unknown', cleanup_status='unconfirmed')
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


def submit(root: Path, caller: CallerContext, request: SubmitRequest, *, backend: ExecutionBackend | None = None):
    _backend(backend)
    if (type(request) is not SubmitRequest or type(request.hard_timeout_seconds) is not int
            or not 1 <= request.hard_timeout_seconds <= 86400 or not isinstance(request.intent_key, str)
            or not 1 <= len(request.intent_key.encode()) <= 1024
            or not re.fullmatch(r'[A-Za-z0-9 ._-]{1,80}', request.label)
            or any(value is not None and (not isinstance(value, str) or not _ID.fullmatch(value))
                   for value in (request.operation_id, request.mcp_request_id, request.remote_task_id))):
        raise ExecutionError('invalid_submit')
    request_digest = _digest({'arguments': request.arguments, 'backend': backend.kind,
                              'timeout': request.hard_timeout_seconds, 'label': request.label,
                              'operation_id': request.operation_id, 'mcp_request_id': request.mcp_request_id,
                              'remote_task_id': request.remote_task_id})
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
        now = datetime.now(timezone.utc)
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
                'backend': {'kind': backend.kind, 'token_digest': hashlib.sha256(token.encode()).hexdigest(),
                            'claim': 'committed', 'external_mutations': False},
                'operation_id': request.operation_id, 'mcp_request_id': request.mcp_request_id,
                'remote_task_id': request.remote_task_id, 'execution_status': 'running',
                'cleanup_status': 'not_required', 'operation_outcome': 'not_applicable', 'terminal_reason': None,
                'source_final': None, 'source_changed': False, 'output': None, 'retention_until': None,
                'expired': False, 'event_receipts': {},
            }
            registry['records'][execution_id] = record
            registry['intents'][intent] = execution_id
            return execution_id, True
        registry, (execution_id, dispatch) = store.mutate_registry(root, allocate, create=True)
    record = registry['records'][execution_id]
    if not dispatch:
        return _view(root, record)
    admission = Admission(execution_id, record['execution_generation'], record['revision'], token)
    try:
        result = backend.dispatch(root, admission, request)
    except Exception:
        # A dispatch claim is never repeated, even if the backend threw before returning.
        _UNCERTAIN.add((str(root.resolve()), execution_id))
        return _view(root, record)
    if result is not None:
        try:
            return record_event(root, token, execution_id, record['revision'], record['execution_generation'],
                                'dispatch-result', result)
        except store.RegistryError:
            _UNCERTAIN.add((str(root.resolve()), execution_id))
            return _view(root, record)
    return _view(root, record)


def record_event(root, backend_token, execution_id, expected_revision, execution_generation, event_id, event):
    if (not isinstance(backend_token, str) or not re.fullmatch(r'[0-9a-f]{64}', backend_token)
            or not isinstance(event_id, str) or not _ID.fullmatch(event_id) or not isinstance(event, dict)
            or set(event) - {'execution_status', 'terminal_reason', 'cleanup_status', 'operation_outcome', 'output'}
            or event.get('execution_status') not in store.STATUSES):
        raise ExecutionError('invalid_event')
    digest = _digest(event)
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
        if (type(expected_revision) is not int or record['revision'] != expected_revision
                or record['execution_status'] in store.TERMINAL or len(record['event_receipts']) >= 64):
            raise ExecutionError('event_fenced')
        if record['execution_status'] == 'cancel_requested' and event['execution_status'] == 'running':
            raise ExecutionError('event_fenced')
        record.update(copy.deepcopy(event))
        record['revision'] += 1
        record['event_receipts'][event_id] = digest
        if record['execution_status'] in store.TERMINAL:
            record['retention_until'] = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    registry, _ = store.mutate_registry(root, apply)
    return _view(root, registry['records'][execution_id])


def cancel(root, caller, execution_id, *, backend=None):
    _backend(backend)
    record = _find(store.load_registry(root), execution_id)
    _authorize(root, caller, record)
    if record['execution_status'] in store.TERMINAL or record['execution_status'] == 'cancel_requested':
        return _view(root, record)
    if record['backend']['kind'] != backend.kind:
        raise ExecutionError('unsupported_backend')
    # Contract backends accept the request; this is never a claim of process termination.
    admission = Admission(execution_id, record['execution_generation'], record['revision'], '')
    if backend.cancel(root, admission) is not True:
        raise ExecutionError('cancel_not_accepted')
    def accepted(registry):
        current = _find(registry, execution_id)
        _authorize(root, caller, current)
        if current['revision'] != record['revision'] or current['execution_status'] in store.TERMINAL:
            raise ExecutionError('event_fenced')
        current.update(execution_status='cancel_requested', cleanup_status='pending', revision=current['revision'] + 1)
    registry, _ = store.mutate_registry(root, accepted)
    return _view(root, registry['records'][execution_id])
