"""First-party private files to a registered UDS; stored facts never restore permission.

This local Factory profile does not qualify hooks, model-generated lineage or Core tools.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
import math
from pathlib import Path
import secrets
import threading
import time
import weakref

from .access_authority import AccessAuthority, AccessError, _identity, _private, source_key
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
    classification: str = 'unknown'


class LocalSourceAdapter:
    """Server composition owns locations. Requests cannot name a path or content hash."""

    def __init__(self, bindings):
        if type(bindings) is not list or not 1 <= len(bindings) <= 4096:
            raise AccessError('invalid_source_registration')
        self._sources = {}
        for value in bindings:
            required = {'key', 'version', 'repository_id', 'workspace_handle',
                        'relative_path', 'file', 'content_digest'}
            if type(value) is not dict or set(value) not in (required, required | {'classification'}):
                raise AccessError('invalid_source_registration')
            classification = value.get('classification', 'unknown')
            if type(classification) is not str or classification not in {'public', 'internal', 'personal', 'secret', 'unknown'}:
                raise AccessError('invalid_source_registration')
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
                _identity(value['workspace_handle']), value['relative_path'], path, digest, classification)

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
    consumed: bool = False
    native_payload: object | None = None
    native_destination: object | None = None


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
    classifications: tuple = ()
    retrieval_query: object | None = None
    capture_clock: tuple | None = None


@dataclass(repr=False)
class _Entry:
    prepared: _Prepared
    expires: float
    state: str = 'pending'
    request: str | None = None


@dataclass(frozen=True, repr=False)
class _Retired:
    """Only bounded replay/accounting facts; no source or prepared payload."""
    identifier: str
    authority: tuple
    deadline: float
    consumed: bool = True
    native_capture: None = None


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

    def _discard(self, identifier):
        with self._lock:
            for key, entry in tuple(self._entries.items()):
                if entry.prepared.identifier == identifier:
                    old = entry.prepared
                    entry.prepared = _Retired(old.identifier, old.authority, old.deadline)
                    entry.state = 'blocked'
                    del self._entries[key]

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

    def __init__(self, store, authority, sources, destinations, *, payload_profile=None, retrieval_profile=None):
        if (type(store) is not PostgresFactoryStore or type(authority) is not AccessAuthority
                or type(sources) is not LocalSourceAdapter or type(destinations) is not dict
                or not 1 <= len(destinations) <= 256
                or any(type(client) is not UdsResultHandoffClient or client._transport is not None
                       or client._timeout > 2 for client in destinations.values())):
            raise AccessError('access_profile_unavailable')
        if payload_profile is not None and retrieval_profile is not None:
            raise AccessError('access_profile_unavailable')
        self._retrieval_enabled = retrieval_profile is not None
        self._automatic_retention = retrieval_profile == 'factory.ephemeral-retrieval162/v1'
        self._retention_receiver_ref = self._retention_destination = None
        self._retention_last_scan = 0.0
        if retrieval_profile is not None:
            try:
                from .retrieval_access import RetrievalProfile
                payload_profile = RetrievalProfile(retrieval_profile)
            except (ImportError, ValueError, TypeError):
                raise AccessError('access_profile_unavailable') from None
        elif payload_profile is not None:
            try:
                from .payload_access import PayloadProfile
                payload_profile = PayloadProfile(payload_profile)
            except (ImportError, ValueError, TypeError):
                raise AccessError('access_profile_unavailable') from None
        self._payload_profile = payload_profile
        self._retrieval_hosts = weakref.WeakSet() if self._retrieval_enabled else None
        self._store, self._authority, self._sources = store, authority, sources
        self._destinations = {_identity(key): client for key, client in destinations.items()}
        self._queue, self._prepared, self._lock = _NativeQueue(), {}, threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self.last_error = None

    def _attach_retrieval_host(self, host):
        from .native_access import FactoryNativeAccessHost
        if (not self._retrieval_enabled or type(host) is not FactoryNativeAccessHost
                or host._service is not self or len(self._retrieval_hosts) >= 8):
            raise AccessError('access_profile_unavailable')
        self._retrieval_hosts.add(host)

    def _retire_dependencies(self, digests, *, cancel_all=False):
        complete = True
        for host in tuple(self._retrieval_hosts or ()):
            complete = host._retire_dependencies(digests, cancel_all=cancel_all) and complete
        with self._lock:
            identifiers = tuple(key for key, value in self._prepared.items() if type(value) is _Prepared
                and (cancel_all or any(canonical_digest([list(source), version, digest]) in digests
                    for source, version, digest in value.lineage)))
        for identifier in identifiers:
            self._retire_retrieval(identifier)
        return complete

    def _attach_retention_receiver(self, receiver, destination):
        from .retrieval_receiver import OwnedRetrievalReceiver
        if (not self._automatic_retention or type(receiver) is not OwnedRetrievalReceiver
                or receiver._retention_profile != 'factory.ephemeral-retrieval162/v1'
                or destination not in self._destinations):
            raise AccessError('access_profile_unavailable')
        client = self._destinations[destination]
        client._revalidate_socket()
        if (receiver.path != client._socket_path or receiver._identity != client._socket_identity
                or not secrets.compare_digest(receiver._credential, client._token)):
            raise AccessError('access_profile_unavailable')
        self._retention_receiver_ref, self._retention_destination = weakref.ref(receiver), destination

    def _retention_receiver(self, destination):
        receiver = None if self._retention_receiver_ref is None else self._retention_receiver_ref()
        if (receiver is None or receiver._server is None or receiver._thread is None
                or not receiver._thread.is_alive() or destination != self._retention_destination
                or receiver._service_ref is None or receiver._service_ref() is not self):
            raise AccessError('access_profile_unavailable')
        client = self._destinations[destination]
        client._revalidate_socket()
        if client._socket_identity != receiver._identity:
            raise AccessError('access_profile_unavailable')
        return receiver

    def _expire_owned_memory(self):
        if not self._automatic_retention:
            return False
        return self._retire_dependencies((), cancel_all=True)

    def retire_retrieval(self, session, envelope_digest, *, reason):
        from .retrieval_retention import retire
        return retire(self, session, envelope_digest, reason=reason)

    def observe_retrieval_retirement(self, session, envelope_digest):
        from .retrieval_retention import observe
        return observe(self, session, envelope_digest)

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
        original = ('factory.source-text/v1', 'identity/v1', 'access-local-text/v1')
        if self._payload_profile is None:
            return original
        identity = (*original, self._payload_profile.name, self._payload_profile.policy.identity,
            canonical_digest([[list(key), item.version, item.digest, item.classification]
                              for key, item in sorted(self._sources._sources.items())]))
        if self._automatic_retention:
            receiver = self._retention_receiver(self._retention_destination)
            return (*identity, receiver._epoch)
        return identity

    def _capture_retrieval_sources(self, session, grant, packet, query, deadline):
        """Candidate filters come from this task and current destination authority."""
        from .retrieval_access import RetrievalQuery
        if (not self._retrieval_enabled or type(query) is not RetrievalQuery
                or query.destination not in self._destinations):
            raise AccessError('access_denied')
        _remaining_bounds(deadline)
        with self._store._transaction(**_remaining_bounds(deadline)) as cursor:
            context, attempt = self._context(cursor, grant, packet)
        capture_clock = None
        if self._automatic_retention:
            receiver = self._retention_receiver(query.destination)
            deadline, capture_clock = receiver._reserve(self, context, attempt, deadline)
        self._authority._live()
        self._authority._credential_live(session)
        with self._authority._source:
            snapshot, _actor, _principal = self._authority._current(session)
            destination = snapshot.destinations.get(query.destination)
            if destination is None or destination['repository_id'] != context.repository_id:
                raise AccessError('access_denied')
            partition = destination['tenant_id'], destination['project_id']
        keys = []
        for key, source in sorted(self._sources._sources.items()):
            _remaining_bounds(deadline)
            if (key[:2] != partition or source.repository != context.repository_id
                    or source.workspace != context.workspace_handle):
                continue
            wire = dict(zip(('tenant', 'project', 'provider', 'site', 'resource'), key))
            if not self._authority.authorize(session, wire, source.version, 'source:read'):
                continue
            try:
                self._authority.release_binding(session, ((key, source.version, source.digest),), query.destination)
            except AccessError as error:
                if str(error) == 'access_denied':
                    continue
                raise
            self._payload_profile.classification(source.classification)
            _allowed_path(source.relative_path, context, 'access_denied')
            if not source.relative_path.endswith('.py'):
                raise AccessError('source_unavailable')
            keys.append(wire)
            if len(keys) > 128:
                raise AccessError('source_unavailable')
        if not keys:
            raise AccessError('source_unavailable')
        return self._capture_native_sources(session, grant, packet, keys, deadline,
            retrieval_query=query, capture_clock=capture_clock)

    def _capture_native_sources(self, session, grant, packet, sources, deadline, *, retrieval_query=None, capture_clock=None):
        """The same actual producer, retained for the optional trusted-parent bridge."""
        _remaining_bounds(deadline)
        if self._retrieval_enabled != (retrieval_query is not None):
            raise AccessError('access_denied')
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
        classifications = ()
        if self._payload_profile is not None:
            # Class comes from this actual registered source owner, never query DTOs.
            classifications = tuple(self._sources._sources[key].classification
                                    if key in self._sources._sources else 'unknown' for key in keys)
            for classification in classifications:
                self._payload_profile.classification(classification)
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
                                tuple(chunks), tuple(lineage), deadline, self._native_profile(), classifications,
                                retrieval_query, capture_clock)

    def _revalidate_native_sources(self, captured, context, attempt, deadline):
        if (type(captured) is not _CapturedSources or context != captured.context
                or attempt != captured.attempt or self._native_profile() != captured.profile):
            raise AccessError('access_denied')
        if self._payload_profile is not None:
            current_classes = tuple(self._sources._sources[item[0]].classification
                                    if item[0] in self._sources._sources else 'unknown' for item in captured.lineage)
            if current_classes != captured.classifications:
                raise AccessError('source_unavailable')
            for classification in current_classes:
                self._payload_profile.classification(classification)
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
        if captured.retrieval_query is not None and captured.retrieval_query.destination != destination:
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
            'packet': packet, 'attempt': attempt, 'stage':
            'factory.source-text/v1' if captured.retrieval_query is None else 'factory.retrieval162/v1'})
            if native_revalidate or self._payload_profile is not None else secrets.token_hex(32))
        identity = dict(repository_id=context.repository_id, task_id=grant.task_id, run_id=grant.run_id,
            fence=grant.fence, packet_digest=grant.packet_digest, attempt_id=attempt,
            source_operation='access:' + identifier, source_digest=source_digest)
        native_payload = None
        if self._payload_profile is not None:
            native_payload = self._prepare_payload(captured, deadline)
            chunks = (native_payload.payload,)
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
            'transform': 'access-local-text/v1' + (':' + native_payload.binding_stamp if native_payload else ''),
            'payload_digest': envelope.sanitized_payload_digest}
        prepared = _Prepared(identifier, session, grant, packet, context.workspace_handle, attempt,
            destination, lineage, envelope, authority, canonical_json(binding).decode(),
            canonical_digest(binding), deadline, captured if native_revalidate or native_payload is not None else None,
            native_payload=native_payload,
            native_destination=self._destinations[destination] if native_payload is not None else None)
        self._verify_native_payload(prepared)
        if self._automatic_retention:
            self._retention_receiver(destination)._pin_prepared(self, prepared)
        with self._lock:
            now = time.monotonic()
            # Native entries retain this service's original bounded stage intent,
            # including expiry/consumption. Capacity pressure refuses rather than
            # renewing its target/deadline. Durable replay remains the existing
            # result-command/outbox constraint, including across process restart.
            self._prepared = {key: item for key, item in self._prepared.items()
                              if type(item) is _Retired or item.native_capture is not None or item.deadline > now}
            existing = self._prepared.get(identifier)
            if existing is not None:
                if existing.consumed or now >= existing.deadline:
                    raise AccessError('access_already_used')
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

    def _prepare_payload(self, captured, deadline):
        if self._retrieval_enabled:
            return self._payload_profile.prepare(captured, self._sources._sources,
                min(262144, captured.context.max_output_bytes), deadline)
        return self._payload_profile.prepare(captured.chunks, captured.lineage, captured.classifications,
            min(262144, captured.context.max_output_bytes), deadline)

    def _retire_retrieval(self, identifier):
        """Drop owned ephemeral derivatives; durable outbox is a separate owner."""
        with self._lock:
            prepared = self._prepared.get(identifier)
            if (type(prepared) is not _Prepared or prepared.native_capture is None
                    or prepared.native_capture.retrieval_query is None):
                return
            self._prepared[identifier] = _Retired(identifier, prepared.authority, prepared.deadline)
        self._queue._discard(identifier)

    def _discard_retrieval_capture(self, captured):
        with self._lock:
            identifiers = tuple(key for key, item in self._prepared.items()
                if type(item) is _Prepared and item.native_capture is captured)
        for identifier in identifiers:
            self._retire_retrieval(identifier)

    def _expire_retrieval(self):
        with self._lock:
            identifiers = tuple(key for key, item in self._prepared.items()
                if type(item) is _Prepared and item.deadline <= time.monotonic())
        for identifier in identifiers:
            self._retire_retrieval(identifier)

    def _verify_native_payload(self, prepared):
        if self._payload_profile is None:
            if prepared.native_payload is not None:
                raise AccessError('access_denied')
            return
        from .payload_access import PreparedPayload
        proof = prepared.native_payload
        capture = prepared.native_capture
        if type(proof) is not PreparedPayload or type(capture) is not _CapturedSources:
            raise AccessError('access_denied')
        if capture.profile != self._native_profile():
            raise AccessError('access_denied')
        if self._destinations.get(prepared.destination) is not prepared.native_destination:
            raise AccessError('access_denied')
        grant, context = capture.grant, capture.context
        expected_scope = dict(repository_id=context.repository_id, task_id=grant.task_id,
            run_id=grant.run_id, fence=grant.fence, packet_digest=grant.packet_digest,
            attempt_id=capture.attempt, source_operation='access:' + prepared.identifier,
            source_digest=canonical_digest([[list(key), version, digest] for key, version, digest in capture.lineage]),
            channel='native_tool_result', content_type='text/plain', policy_version='access-local-text/v1')
        if any(getattr(prepared.envelope, key) != value for key, value in expected_scope.items()):
            raise AccessError('access_denied')
        current = self._prepare_payload(capture, min(prepared.deadline, capture.deadline))
        binding = json.loads(prepared.binding_wire)
        expected_binding = {'contract': 'factory-owned-access-release/v1',
            'execution_packet_digest': prepared.execution_packet,
            'authority_revision': prepared.authority[0], 'permission_digest': prepared.authority[1],
            'destination_id': prepared.destination, 'destination_revision': prepared.authority[2],
            'principal_id': prepared.authority[3],
            'lineage': [[list(key), version, digest] for key, version, digest in capture.lineage],
            'transform': 'access-local-text/v1:' + proof.binding_stamp,
            'payload_digest': prepared.envelope.sanitized_payload_digest}
        if (binding != expected_binding or canonical_digest(binding) != prepared.binding_digest
                or canonical_json(binding).decode() != prepared.binding_wire
                or current != proof or prepared.envelope.sanitized_payload.encode('utf-8') != proof.payload
                or prepared.envelope.sanitized_payload_digest != canonical_digest(proof.payload.decode('utf-8'))
                or json.loads(prepared.binding_wire)['transform'] != 'access-local-text/v1:' + proof.binding_stamp):
            raise AccessError('access_denied')

    def _refresh_native_prepared(self, prepared):
        if prepared.native_capture is None:
            return
        with self._store._transaction(**_remaining_bounds(prepared.deadline)) as cursor:
            context, attempt = self._context(cursor, prepared.grant, prepared.execution_packet)
        # Source reads/custody checks occur OUTSIDE task/SQL/SOURCE locks.
        # The later transaction still rechecks current task and source authority
        # at its actual native queue cut; this is not an atomic filesystem fence.
        self._revalidate_native_sources(prepared.native_capture, context, attempt, prepared.deadline)
        self._verify_native_payload(prepared)

    def release(self, session, identifier, *, absolute_deadline=None):
        if type(identifier) is not str or len(identifier) != 64:
            raise AccessError('invalid_access_request')
        with self._lock:
            prepared = self._prepared.get(identifier)
            if prepared is None or prepared.consumed or prepared.session != session:
                raise AccessError('access_already_used')
            # Claim once before any durable write. Unknown outcomes never auto-replay.
            if prepared.native_capture is not None:
                self._prepared[identifier] = replace(prepared, consumed=True)
                if absolute_deadline is not None:
                    if type(absolute_deadline) not in (int, float) or not math.isfinite(absolute_deadline):
                        raise AccessError('invalid_access_request')
                    prepared = replace(prepared, deadline=min(prepared.deadline, absolute_deadline))
            else:
                del self._prepared[identifier]
        entry = None
        try:
            self._refresh_native_prepared(prepared)
            with self._store._transaction(**(_remaining_bounds(prepared.deadline)
                    if prepared.native_capture is not None else _BOUNDS)) as cursor:
                context, attempt = self._context(cursor, prepared.grant, prepared.execution_packet)
                if context.workspace_handle != prepared.workspace or attempt != prepared.attempt:
                    raise AccessError('access_denied')
                if prepared.native_capture is not None:
                    _remaining_bounds(prepared.deadline)
                record = prepared.envelope
                command = {'contract': 'adaptive-factory.result-admission-command/v1', 'action': 'result_admission',
                    'actor_id': prepared.grant.owner, 'idempotency_key': identifier,
                    'envelope_digest': record.record_digest, 'correlation_id': 'access:' + identifier}
                cursor.execute('SELECT factory.admit_result_v1(%s,%s,%s,%s,%s,%s,%s)',
                    (canonical_json(record.to_dict()).decode(), record.record_digest, prepared.grant.owner,
                     identifier, canonical_digest(command), canonical_json(command).decode(), 'access:' + identifier))
                if prepared.native_capture is not None:
                    _remaining_bounds(prepared.deadline)
                cursor.execute('SELECT factory.stage_access_release_v1(%s,%s,%s,%s)',
                    (record.record_digest, prepared.grant.owner, prepared.binding_wire, prepared.binding_digest))
                request = cursor.fetchone()[0].strip()
                if prepared.native_capture is not None and prepared.native_capture.retrieval_query is not None:
                    client = prepared.native_destination
                    client._revalidate_socket()
                    cursor.execute('SELECT factory.bind_access_destination_v1(%s,%s,%s,%s,%s,%s)',
                        (request, prepared.binding_digest, canonical_json({'kind': 'uds',
                            'device': client._socket_identity[0], 'inode': client._socket_identity[1]}).decode(),
                         self._payload_profile.name if self._automatic_retention else None,
                         prepared.native_capture.capture_clock[0] if self._automatic_retention else None,
                         prepared.native_capture.capture_clock[1] if self._automatic_retention else None))
                entry = self._authority._queue_cut(prepared, self._queue)
            # The context manager has verified COMMIT and released every database lock.
            if self._automatic_retention:
                # Exact DB profile/clock/retirement proof before publishing this
                # already-owned pending entry to the existing dispatcher.
                self._retention_receiver(prepared.destination).arm(self, identifier)
            self._queue._finish_commit(entry, request)
        except BaseException:
            if entry is not None:
                self._queue._abort(entry)
            raise
        return {'status': 'queued', 'operation_id': 'factory-result:' + request}

    def run_once(self):
        self._expire_retrieval()
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
                if prepared.native_capture is not None:
                    _remaining_bounds(prepared.deadline)
                if self._stop.is_set():
                    raise AccessError('access_denied')
                # Exact retained bytes/policy are checked outside SOURCE/SQL locks,
                # immediately before this fixed registered transport consumes them.
                self._verify_native_payload(prepared)
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
                self._retire_retrieval(prepared.identifier)
        if self._automatic_retention and time.monotonic() - self._retention_last_scan >= .1:
            self._retention_last_scan = time.monotonic()
            from .retrieval_retention import expire_due
            expire_due(self)
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
        if self._retrieval_enabled:
            with self._lock:
                identifiers = tuple(self._prepared)
            for identifier in identifiers:
                self._retire_retrieval(identifier)
