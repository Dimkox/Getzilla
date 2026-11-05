"""First-party private files to a registered UDS; stored facts never restore permission.

This local Factory profile does not qualify hooks, model-generated lineage or Core tools.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
from pathlib import Path
import secrets
import threading
import time

from .access_authority import AccessAuthority, AccessError, _closed, _identity, _private, source_key
from .brokers import _allowed_path
from .contracts import canonical_digest, canonical_json
from .result_broker import ResultBroker
from .result_dispatch import DispatchClaim, UdsResultHandoffClient
from .store import PostgresFactoryStore


_BOUNDS = dict(connect_timeout=2, lock_timeout='500ms', statement_timeout='1500ms', transaction_timeout='2s')


def _remaining_bounds(deadline):
    remaining = deadline - time.monotonic()
    if not math.isfinite(remaining) or remaining < .001:
        raise AccessError('access_expired')
    milliseconds = max(1, int(remaining * 1000))
    return dict(connect_timeout=min(2, max(1, math.ceil(remaining))),
                lock_timeout=f'{min(500, milliseconds)}ms',
                statement_timeout=f'{min(1500, milliseconds)}ms',
                transaction_timeout=f'{min(2000, milliseconds)}ms')


@dataclass(frozen=True, repr=False)
class _Source:
    key: tuple
    version: str
    repository: str
    workspace: str
    relative_path: str
    path: Path
    digest: str


class LocalSourceAdapter:
    """Server composition owns locations. Requests cannot name a path or content hash."""

    def __init__(self, bindings):
        if type(bindings) is not list or not 1 <= len(bindings) <= 4096:
            raise AccessError('invalid_source_registration')
        self._sources = {}
        for value in bindings:
            _closed(value, {'key', 'version', 'repository_id', 'workspace_handle',
                            'relative_path', 'file', 'content_digest'})
            key = source_key(value['key'])
            digest = value['content_digest']
            if (key[2] != 'local' or key in self._sources or type(digest) is not str or len(digest) != 64
                    or any(char not in '0123456789abcdef' for char in digest)
                    or type(value['file']) is not str or type(value['relative_path']) is not str):
                raise AccessError('invalid_source_registration')
            path = Path(value['file'])
            if not path.is_absolute() or '..' in path.parts:
                raise AccessError('invalid_source_registration')
            self._sources[key] = _Source(key, _identity(value['version']), _identity(value['repository_id']),
                _identity(value['workspace_handle']), value['relative_path'], path, digest)

    def _read(self, key, context, authority, session, remaining):
        source = self._sources.get(key)
        if (source is None or source.repository != context.repository_id
                or source.workspace != context.workspace_handle):
            raise AccessError('access_denied')
        _allowed_path(source.relative_path, context, 'access_denied')
        wire_key = dict(zip(('tenant', 'project', 'provider', 'site', 'resource'), key))
        if not authority.authorize(session, wire_key, source.version, 'source:read'):
            raise AccessError('access_denied')
        raw, _metadata = _private(source.path, min(262144, remaining))
        if hashlib.sha256(raw).hexdigest() != source.digest:
            raise AccessError('source_unavailable')
        if not authority.authorize(session, wire_key, source.version, 'source:read'):
            raise AccessError('access_denied')
        return raw, (key, source.version, source.digest)


@dataclass(frozen=True, repr=False)
class _Prepared:
    identifier: str
    session: object
    grant: object
    execution_packet: str
    workspace: str
    attempt: str
    destination: str
    lineage: tuple
    envelope: object
    authority: tuple
    binding_wire: str
    binding_digest: str
    deadline: float
    native_capture: _CapturedSources | None = None


@dataclass(frozen=True, repr=False)
class _CapturedSources:
    session: object
    grant: object
    execution_packet: str
    context: object
    attempt: str
    chunks: tuple
    lineage: tuple
    deadline: float
    profile: tuple


@dataclass(repr=False)
class _Entry:
    prepared: _Prepared
    expires: float
    state: str = 'pending'
    request: str | None = None


class _NativeQueue:
    def __init__(self):
        self._lock = threading.Lock()
        self._entries = {}
        self.wakeup = threading.Event()

    def _cut(self, prepared, entry):
        now = time.monotonic()
        with self._lock:
            if now >= prepared.deadline:
                raise AccessError('access_expired')
            if entry is not None:
                if (self._entries.get(prepared.identifier) is not entry or entry.state != 'ready'
                        or now >= entry.expires):
                    raise AccessError('access_expired')
                entry.state = 'dispatch_admitted'
                del self._entries[prepared.identifier]
                return entry
            if (prepared.identifier in self._entries or len(self._entries) >= 64
                    or sum(item.prepared.authority[3] == prepared.authority[3]
                           for item in self._entries.values()) >= 16):
                raise AccessError('access_queue_unavailable')
            result = _Entry(prepared, now + 0.250)
            self._entries[prepared.identifier] = result
            return result

    def _finish_commit(self, entry, request):
        with self._lock:
            if self._entries.get(entry.prepared.identifier) is not entry or entry.state != 'pending':
                raise AccessError('access_queue_unavailable')
            entry.request, entry.state = request, 'ready'
            self.wakeup.set()

    def _abort(self, entry):
        with self._lock:
            self._entries.pop(entry.prepared.identifier, None)
            entry.state = 'blocked'

    def _ready(self):
        with self._lock:
            now = time.monotonic()
            self._entries = {key: entry for key, entry in self._entries.items()
                             if entry.expires > now or entry.state == 'pending'}
            ready = tuple(entry for entry in self._entries.values() if entry.state == 'ready')
            if len(ready) <= 8:
                self.wakeup.clear()
            return ready[:8]


class AccessReleaseService:
    """Trusted co-composition. Its queue has no public restoration or sink callback API."""

    def __init__(self, store, authority, sources, destinations):
        if (type(store) is not PostgresFactoryStore or type(authority) is not AccessAuthority
                or type(sources) is not LocalSourceAdapter or type(destinations) is not dict
                or not 1 <= len(destinations) <= 256
                or any(type(client) is not UdsResultHandoffClient or client._transport is not None
                       or client._timeout > 2 for client in destinations.values())):
            raise AccessError('access_profile_unavailable')
        self._store, self._authority, self._sources = store, authority, sources
        self._destinations = {_identity(key): client for key, client in destinations.items()}
        self._queue, self._prepared, self._lock = _NativeQueue(), {}, threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self.last_error = None

    def _context(self, cursor, grant, packet):
        context = self._store._proposal_context(cursor, grant, packet)
        if 'read_file' not in context.allowed_tools or context.max_output_bytes < 1:
            raise AccessError('access_denied')
        cursor.execute('SELECT factory.access_task_fence_v1(%s,%s,%s,%s,%s)',
            (grant.task_id, grant.run_id, grant.owner, grant.fence, grant.packet_digest))
        return context, str(cursor.fetchone()[0])

    def prepare(self, session, grant, packet, sources, destination):
        if type(destination) is not str or destination not in self._destinations:
            raise AccessError('access_denied')
        captured = self._capture_native_sources(session, grant, packet, sources, time.monotonic() + 2)
        return self._prepare_native_sources(captured, destination, captured.deadline)

    def _native_profile(self):
        # Fixed producer code, not a caller-selected sanitizer or plugin.
        return ('factory.source-text/v1', 'identity/v1', 'access-local-text/v1')

    def _capture_native_sources(self, session, grant, packet, sources, deadline):
        """The same actual producer, retained for the optional trusted-parent bridge."""
        _remaining_bounds(deadline)
        actor = self._authority.actor(session)
        if (actor.kind != 'worker' or actor.actor_id != grant.owner or 'task:execute' not in actor.scopes
                or type(sources) is not list or not 1 <= len(sources) <= 128):
            raise AccessError('access_denied')
        keys = tuple(source_key(item) for item in sources)
        if len(set(keys)) != len(keys):
            raise AccessError('invalid_access_request')
        with self._store._transaction(**_remaining_bounds(deadline)) as cursor:
            context, attempt = self._context(cursor, grant, packet)
        if '*' not in actor.repositories and context.repository_id not in actor.repositories:
            raise AccessError('access_denied')
        chunks, lineage, size = [], [], 0
        for key in keys:
            _remaining_bounds(deadline)
            raw, dependency = self._sources._read(key, context, self._authority, session,
                                                 min(262144, context.max_output_bytes) - size)
            chunks.append(raw)
            lineage.append(dependency)
            size += len(raw)
        _remaining_bounds(deadline)
        return _CapturedSources(session, grant, packet, context, attempt,
                                tuple(chunks), tuple(lineage), deadline, self._native_profile())

    def _revalidate_native_sources(self, captured, context, attempt, deadline):
        if (type(captured) is not _CapturedSources or context != captured.context
                or attempt != captured.attempt or self._native_profile() != captured.profile):
            raise AccessError('access_denied')
        size = 0
        for raw, dependency in zip(captured.chunks, captured.lineage, strict=True):
            _remaining_bounds(min(deadline, captured.deadline))
            current, lineage = self._sources._read(dependency[0], context, self._authority,
                captured.session, min(262144, context.max_output_bytes) - size)
            if current != raw or lineage != dependency:
                raise AccessError('source_unavailable')
            size += len(current)
        _remaining_bounds(min(deadline, captured.deadline))

    def _prepare_native_sources(self, captured, destination, deadline, *, native_revalidate=False):
        if (type(captured) is not _CapturedSources or type(destination) is not str
                or destination not in self._destinations or captured.profile != self._native_profile()):
            raise AccessError('access_denied')
        deadline = min(deadline, captured.deadline)
        _remaining_bounds(deadline)
        session, grant, packet = captured.session, captured.grant, captured.execution_packet
        context, attempt = captured.context, captured.attempt
        chunks, lineage = captured.chunks, captured.lineage
        authority = self._authority.release_binding(session, lineage, destination)
        source_digest = canonical_digest([[list(key), version, digest] for key, version, digest in lineage])
        # The optional native profile represents one existing result stage of
        # this actual checked attempt. Rebinding/restart cannot mint a new
        # source operation to bypass existing result/outbox idempotency.
        identifier = (canonical_digest({'contract': 'factory-native-source-stage/v1',
            'task': grant.task_id, 'run': grant.run_id, 'fence': grant.fence,
            'packet': packet, 'attempt': attempt, 'stage': 'factory.source-text/v1'})
            if native_revalidate else secrets.token_hex(32))
        identity = dict(repository_id=context.repository_id, task_id=grant.task_id, run_id=grant.run_id,
            fence=grant.fence, packet_digest=grant.packet_digest, attempt_id=attempt,
            source_operation='access:' + identifier, source_digest=source_digest)
        # The actual trusted adapter above owns every input and dependency. Reuse the
        # existing sanitizer policy, without changing the default unqualified inspect().
        envelope = ResultBroker(policy_version='access-local-text/v1', max_bytes=min(262144, context.max_output_bytes)).sanitize_candidate(
            channel='native_tool_result', content_type='text/plain', chunks=chunks, identity=identity)
        if envelope.outcome not in {'allow', 'redacted'}:
            raise AccessError('source_unavailable')
        binding = {'contract': 'factory-owned-access-release/v1', 'execution_packet_digest': packet,
            'authority_revision': authority[0], 'permission_digest': authority[1], 'destination_id': destination,
            'destination_revision': authority[2], 'principal_id': authority[3],
            'lineage': [[list(key), version, digest] for key, version, digest in lineage],
            'transform': 'access-local-text/v1', 'payload_digest': envelope.sanitized_payload_digest}
        prepared = _Prepared(identifier, session, grant, packet, context.workspace_handle, attempt,
            destination, lineage, envelope, authority, canonical_json(binding).decode(),
            canonical_digest(binding), deadline, captured if native_revalidate else None)
        with self._lock:
            now = time.monotonic()
            self._prepared = {key: item for key, item in self._prepared.items() if item.deadline > now}
            existing = self._prepared.get(identifier)
            if existing is not None:
                if (existing.binding_digest != prepared.binding_digest
                        or existing.envelope.record_digest != prepared.envelope.record_digest
                        or not (existing.session is session or existing.session == session)):
                    raise AccessError('access_conflict')
                return {'prepared_id': identifier}  # Preserve original bytes and deadline.
            if (len(self._prepared) >= 64 or sum(item.authority[3] == authority[3]
                    for item in self._prepared.values()) >= 16):
                raise AccessError('access_queue_unavailable')
            self._prepared[identifier] = prepared
        return {'prepared_id': identifier}

    def _refresh_native_prepared(self, prepared):
        if prepared.native_capture is None:
            return
        with self._store._transaction(**_remaining_bounds(prepared.deadline)) as cursor:
            context, attempt = self._context(cursor, prepared.grant, prepared.execution_packet)
        # Source reads/custody checks occur OUTSIDE task/SQL/SOURCE locks.
        # The later transaction still rechecks current task and source authority
        # at its actual native queue cut; this is not an atomic filesystem fence.
        self._revalidate_native_sources(prepared.native_capture, context, attempt, prepared.deadline)

    def release(self, session, identifier):
        if type(identifier) is not str or len(identifier) != 64:
            raise AccessError('invalid_access_request')
        with self._lock:
            prepared = self._prepared.get(identifier)
            if prepared is None or prepared.session != session:
                raise AccessError('access_already_used')
            # Claim once before any durable write. Unknown outcomes never auto-replay.
            del self._prepared[identifier]
        entry = None
        try:
            self._refresh_native_prepared(prepared)
            with self._store._transaction(**(_remaining_bounds(prepared.deadline)
                    if prepared.native_capture is not None else _BOUNDS)) as cursor:
                context, attempt = self._context(cursor, prepared.grant, prepared.execution_packet)
                if context.workspace_handle != prepared.workspace or attempt != prepared.attempt:
                    raise AccessError('access_denied')
                record = prepared.envelope
                command = {'contract': 'adaptive-factory.result-admission-command/v1', 'action': 'result_admission',
                    'actor_id': prepared.grant.owner, 'idempotency_key': identifier,
                    'envelope_digest': record.record_digest, 'correlation_id': 'access:' + identifier}
                cursor.execute('SELECT factory.admit_result_v1(%s,%s,%s,%s,%s,%s,%s)',
                    (canonical_json(record.to_dict()).decode(), record.record_digest, prepared.grant.owner,
                     identifier, canonical_digest(command), canonical_json(command).decode(), 'access:' + identifier))
                cursor.execute('SELECT factory.stage_access_release_v1(%s,%s,%s,%s)',
                    (record.record_digest, prepared.grant.owner, prepared.binding_wire, prepared.binding_digest))
                request = cursor.fetchone()[0].strip()
                entry = self._authority._queue_cut(prepared, self._queue)
            # The context manager has verified COMMIT and released every database lock.
            self._queue._finish_commit(entry, request)
        except BaseException:
            if entry is not None:
                self._queue._abort(entry)
            raise
        return {'status': 'queued', 'operation_id': 'factory-result:' + request}

    def run_once(self):
        count = 0
        for entry in self._queue._ready():
            if self._stop.is_set():
                self._queue._abort(entry)
                continue
            prepared = entry.prepared
            token = secrets.token_hex(32)
            try:
                self._refresh_native_prepared(prepared)
                with self._store._transaction(**(_remaining_bounds(prepared.deadline)
                        if prepared.native_capture is not None else _BOUNDS)) as cursor:
                    context, attempt = self._context(cursor, prepared.grant, prepared.execution_packet)
                    if context.workspace_handle != prepared.workspace or attempt != prepared.attempt:
                        raise AccessError('access_denied')
                    cursor.execute('SELECT factory.claim_access_release_v1(%s,%s,%s,%s)',
                        (entry.request, prepared.binding_digest, prepared.grant.owner, token))
                    self._authority._queue_cut(prepared, self._queue, entry)
                # COMMIT is verified. All task/stop/SOURCE locks are released before UDS.
                record = prepared.envelope
                claim = DispatchClaim(entry.request, 'factory-result:' + entry.request, record.record_digest,
                    record.repository_id, record.task_id, record.run_id, record.fence, record.packet_digest,
                    record.attempt_id, token, 'factory-protected-dispatcher', 'claimed', record.to_dict())
                outcome = self._destinations[prepared.destination].dispatch(claim)
                with self._store._transaction(**_BOUNDS) as cursor:
                    cursor.execute('SELECT factory.observe_access_release_v1(%s,%s,%s,%s)',
                        (entry.request, token, outcome.state, outcome.observation_digest))
                count += 1
            except Exception as error:
                # No repost. A transport/commit ambiguity requires existing operation observation.
                self.last_error = type(error).__name__
            finally:
                self._queue._abort(entry)
        return count

    def start(self):
        if self._thread is not None:
            raise AccessError('access_profile_unavailable')
        from .result_dispatch import ResultDispatcher
        dispatcher = ResultDispatcher(None, next(iter(self._destinations.values())),
            dispatcher_id='factory-protected-dispatcher', poll_seconds=0.05, protected_service=self)
        self._thread = threading.Thread(target=self._run, args=(dispatcher,),
                                        name='factory-protected-dispatch', daemon=True)
        self._thread.start()

    def _run(self, dispatcher):
        while not self._stop.is_set():
            self._queue.wakeup.wait(0.05)
            dispatcher.run_once()

    def close(self):
        self._stop.set()
        self._queue.wakeup.set()
        if self._thread is not None:
            self._thread.join(3)
