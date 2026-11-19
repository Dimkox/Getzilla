"""Explicit first-party one-result receiver with an irreversible local tombstone.

Trusted parent composition arms this owner from the actual checked Factory
result. No wire message can arm it, restore a retired payload, or run a model.
"""
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler
import json
import math
import os
from pathlib import Path
import re
import secrets
import socket
import socketserver
import stat
import struct
import threading
import time
import weakref

from .access_authority import AccessError, _pairs
from .access_release import AccessReleaseService, _Prepared, _remaining_bounds
from .contracts import canonical_digest, canonical_json
from .result_contracts import ResultEnvelopeV2
from .retrieval_retention import CONTRACT, FIELDS, postcondition
from .retrieval_access import PROFILE, EPHEMERAL


class _DeadlineReader:
    def __init__(self, source, peer, deadline):
        self.source, self.peer, self.deadline = source, peer, deadline

    def _next(self, count):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('receiver deadline')
        self.peer.settimeout(remaining)
        return self.source.read1(count)

    def readline(self, limit=-1):
        limit = min(65537, limit) if limit >= 0 else 65537
        output = bytearray()
        while len(output) < limit:
            block = self._next(1)
            if not block:
                break
            output.extend(block)
            if block == b'\n':
                break
        return bytes(output)

    def read(self, size=-1):
        if not 0 <= size <= 1100000:
            raise ValueError('receiver frame limit')
        output = bytearray()
        while len(output) < size:
            block = self._next(min(65536, size - len(output)))
            if not block:
                break
            output.extend(block)
        return bytes(output)

    def close(self):
        self.source.close()


class OwnedRetrievalReceiver:
    """One bounded owned derivative, not a permission service or another queue."""
    def __init__(self, path, credential, *, retention_profile=PROFILE):
        if (not isinstance(path, Path) or not path.is_absolute() or '..' in path.parts
                or type(credential) is not str or not 16 <= len(credential) <= 256
                or any(char.isspace() for char in credential) or not hasattr(socket, 'SO_PEERCRED')
                or retention_profile not in (PROFILE, EPHEMERAL)):
            raise AccessError('retirement_unavailable')
        self.path, self._credential = path, credential
        self._lock = threading.Lock()
        self._expected = self._scope = self._payload = None
        self._retired, self._accepted = False, False
        self._armed = False
        self._server = self._thread = self._identity = None
        self._retention_profile, self._epoch = retention_profile, secrets.token_hex(32)
        self._service_ref = self._reservation_scope = self._capture_due = self._capture_clock = None
        self._cleanup_pending = False

    def attach(self, service, destination):
        if type(service) is not AccessReleaseService or self._retention_profile != EPHEMERAL:
            raise AccessError('access_profile_unavailable')
        service._attach_retention_receiver(self, destination)
        self._service_ref = weakref.ref(service)

    def _reserve(self, service, context, attempt, deadline):
        if self._service_ref is None or self._service_ref() is not service:
            raise AccessError('access_profile_unavailable')
        scope = (context.task_id, context.run_id, context.owner, context.fence, context.packet_digest, attempt)
        with self._lock:
            if self._retired or self._reservation_scope not in (None, scope):
                raise AccessError('access_expired')
            if self._capture_due is None:
                wall, monotonic = time.time(), time.monotonic()
                if not math.isfinite(wall) or not 0 < deadline - monotonic <= 2:
                    raise AccessError('access_expired')
                self._reservation_scope, self._capture_due = scope, deadline
                self._capture_clock = wall, wall + (deadline - monotonic)
            if time.monotonic() >= self._capture_due:
                raise AccessError('access_expired')
            return min(deadline, self._capture_due), self._capture_clock

    def _expire(self):
        with self._lock:
            if self._capture_due is not None and not self._retired and time.monotonic() >= self._capture_due:
                self._payload, self._retired, self._cleanup_pending = None, True, True
            pending = self._cleanup_pending
        if pending:
            service = None if self._service_ref is None else self._service_ref()
            complete = service is None or service._expire_owned_memory()
            with self._lock:
                self._cleanup_pending = not complete

    @property
    def context(self):
        self._expire()
        with self._lock:
            return None if self._retired else self._payload

    @staticmethod
    def _facts(prepared):
        request = hashlib.sha256(('factory-access-release:' + prepared.envelope.record_digest
            + ':' + prepared.binding_digest).encode()).hexdigest()
        expected = {'request_digest': request, 'operation_id': 'factory-result:' + request,
            'envelope_digest': prepared.envelope.record_digest, 'retirement_request_digest': hashlib.sha256(
                ('factory-retrieval-retirement:' + prepared.envelope.record_digest).encode()).hexdigest()}
        scope = {field: getattr(prepared.envelope, field) for field in (
            'repository_id', 'task_id', 'run_id', 'fence', 'packet_digest', 'attempt_id')}
        return expected, scope

    def _pin_prepared(self, service, prepared):
        """Cleanup identity only. This does NOT arm the data handoff."""
        if (self._retention_profile != EPHEMERAL or self._service_ref is None
                or self._service_ref() is not service or type(prepared) is not _Prepared
                or prepared.native_capture.capture_clock != self._capture_clock):
            raise AccessError('access_profile_unavailable')
        expected, scope = self._facts(prepared)
        with self._lock:
            if (self._retired or time.monotonic() >= self._capture_due
                    or self._expected is not None and (self._expected != expected or self._scope != scope)):
                raise AccessError('access_expired')
            self._expected, self._scope = expected, scope

    def arm(self, service, identifier):
        if type(service) is not AccessReleaseService or not service._retrieval_enabled:
            raise AccessError('retirement_unavailable')
        if service._payload_profile.name != self._retention_profile:
            raise AccessError('retirement_unavailable')
        with service._lock:
            prepared = service._prepared.get(identifier)
        if type(prepared) is not _Prepared or prepared.native_capture is None:
            raise AccessError('retirement_unavailable')
        service._verify_native_payload(prepared)
        client = prepared.native_destination
        if (client._socket_path != self.path or client._socket_identity != self._identity
                or not hmac.compare_digest(client._token, self._credential)):
            raise AccessError('retirement_unavailable')
        # The existing durable source tombstone also fences a receiver restart.
        # Unavailable DB or a retired original can never arm a new receiver.
        with service._store._transaction(**_remaining_bounds(prepared.deadline)) as cursor:
            cursor.execute('SELECT s.payload_retired_at IS NOT NULL,o.retrieval_retention_profile,'
                'o.retrieval_capture_at,o.retrieval_retire_after,o.access_binding_digest '
                'FROM factory.result_sources_v1 s LEFT JOIN factory.next_model_request_outbox_v1 o USING(envelope_digest) '
                'WHERE s.envelope_digest=%s', (prepared.envelope.record_digest,))
            existing = cursor.fetchone()
        if existing is not None and existing[0]:
            raise AccessError('retirement_unavailable')
        if self._retention_profile == EPHEMERAL:
            if (not prepared.consumed or existing is None or existing[1] != EPHEMERAL
                    or existing[4].strip() != prepared.binding_digest
                    or prepared.native_capture.capture_clock is None
                    or any(abs(value.timestamp() - expected) > .000001
                        for value, expected in zip(existing[2:4], prepared.native_capture.capture_clock, strict=True))
                    or self._capture_clock != prepared.native_capture.capture_clock
                    or time.monotonic() >= self._capture_due):
                raise AccessError('retirement_unavailable')
        # Arm before the existing250ms committed queue window starts. These are
        # the same deterministic IDs computed by027, not an admission grant.
        expected, scope = self._facts(prepared)
        with self._lock:
            if (self._retired or self._armed or self._expected is not None
                    and (self._expected != expected or self._scope != scope)):
                raise AccessError('retirement_unavailable')
            self._expected, self._scope = expected, scope
            self._armed = True

    def _handoff(self, body, deadline):
        required = {'contract', 'operation_id', 'request_digest', 'envelope_digest',
            'repository_id', 'task_id', 'run_id', 'fence', 'packet_digest', 'attempt_id', 'result_envelope'}
        with self._lock:
            expected = self._expected
            if (expected is None or not self._armed or self._retired or type(body) is not dict or set(body) != required
                    or body['contract'] != 'adaptive-factory.native-result-handoff/v1'
                    or any(body[field] != expected[field] for field in FIELDS[:3])
                    or any(body[field] != value for field, value in self._scope.items())):
                raise AccessError('access_denied')
            record = ResultEnvelopeV2.from_dict(body['result_envelope'])
            if record.record_digest != expected['envelope_digest']:
                raise AccessError('access_denied')
            if (time.monotonic() >= deadline or self._capture_due is not None
                    and time.monotonic() >= self._capture_due):
                raise AccessError('access_expired')
            if not self._accepted:
                payload = record.sanitized_payload.encode('utf-8')
                if len(payload) > 262144 or json.loads(payload).get('contract') != self._retention_profile:
                    raise AccessError('access_denied')
                self._payload, self._accepted = payload, True
            return {'status': 'delivered', **{field: expected[field] for field in FIELDS[:3]},
                'postcondition_digest': canonical_digest({'contract': 'next-model-result-postcondition/v1',
                    **{field: expected[field] for field in FIELDS[:3]}})}

    def _retirement(self, body, deadline):
        with self._lock:
            if (self._expected is None or type(body) is not dict or set(body) != {'contract', *FIELDS}
                    or body['contract'] != CONTRACT or any(body[field] != self._expected[field] for field in FIELDS)):
                raise AccessError('access_denied')
            if time.monotonic() >= deadline:
                raise AccessError('access_expired')
            self._retired, self._payload = True, None
            return self._observation_locked()

    def _observation_locked(self):
        if self._expected is None:
            raise AccessError('access_denied')
        return {'status': 'retired' if self._retired else 'pending', **self._expected,
            'postcondition_digest': postcondition(self._expected) if self._retired else None}

    def start(self):
        if self._server is not None or os.path.lexists(self.path):
            raise AccessError('retirement_unavailable')
        for parent in (self.path.parent, *self.path.parent.parents):
            metadata = parent.lstat()
            sticky_root = metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX
            if (not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
                    or metadata.st_uid not in {0, os.geteuid()}
                    or metadata.st_mode & 0o022 and not sticky_root):
                raise AccessError('retirement_unavailable')
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                self._deadline = time.monotonic() + 2
                self.request.settimeout(2)
                super().setup()
                self.rfile = _DeadlineReader(self.rfile, self.request, self._deadline)

            def log_message(self, *args):
                pass

            def _reply(self, status, body):
                raw = canonical_json(body)
                self.close_connection = True
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _authorized(self):
                _pid, uid, _gid = struct.unpack('3i', self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                values = self.headers.get_all('Authorization', [])
                return (uid == os.geteuid() and len(values) == 1
                    and hmac.compare_digest(values[0], 'Bearer ' + owner._credential))

            def do_POST(self):
                try:
                    self.connection.settimeout(2)
                    lengths = self.headers.get_all('Content-Length', [])
                    if (not self._authorized() or self.headers.get('Transfer-Encoding') is not None
                            or len(lengths) != 1 or re.fullmatch('[0-9]{1,7}', lengths[0]) is None
                            or not 0 < int(lengths[0]) <= 1100000
                            or self.headers.get_all('Content-Type', []) != ['application/json']):
                        raise AccessError('access_denied')
                    length = int(lengths[0])
                    raw = self.rfile.read(length)
                    if len(raw) != length:
                        raise AccessError('access_denied')
                    body = json.loads(raw, object_pairs_hook=_pairs)
                    if self.path == '/v1/native-result-handoffs':
                        expected = None if owner._expected is None else owner._expected['operation_id']
                        if (self.headers.get_all('Idempotency-Key', []) != [expected]
                                or self.headers.get_all('X-Operation-ID', []) != [expected]):
                            raise AccessError('access_denied')
                        result = owner._handoff(body, self._deadline)
                    elif self.path == '/v1/native-result-retirements':
                        expected = owner._expected
                        if (expected is None or self.headers.get_all('Idempotency-Key', []) != [
                                'factory-retirement:' + expected['retirement_request_digest']]
                                or self.headers.get_all('X-Operation-ID', []) != [expected['operation_id']]):
                            raise AccessError('access_denied')
                        result = owner._retirement(body, self._deadline)
                    else:
                        raise AccessError('access_denied')
                    self._reply(200, result)
                except Exception:
                    self._reply(403, {'status': 'denied'})

            def do_GET(self):
                try:
                    self.connection.settimeout(2)
                    with owner._lock:
                        expected = owner._expected
                        if (not self._authorized() or expected is None
                                or self.path != '/v1/native-result-retirements/' + expected['retirement_request_digest']
                                or self.headers.get_all('Idempotency-Key', []) != [
                                    'factory-retirement:' + expected['retirement_request_digest']]
                                or self.headers.get_all('X-Operation-ID', []) != [expected['operation_id']]):
                            raise AccessError('access_denied')
                        result = owner._observation_locked()
                    self._reply(200, result)
                except Exception:
                    self._reply(403, {'status': 'denied'})

        class Server(socketserver.UnixStreamServer):
            def handle_error(self, *args):
                pass  # Fixed response/unknown outcome; never log source frames.
            def service_actions(self):
                owner._expire()
        self._server = Server(str(self.path), Handler)
        os.chmod(self.path, 0o600)
        info = self.path.lstat()
        self._identity = info.st_dev, info.st_ino
        self._thread = threading.Thread(target=self._server.serve_forever,
            kwargs={'poll_interval': .01}, daemon=True, name='factory-owned-retrieval-result')
        self._thread.start()

    def close(self):
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._thread.join(3)
            self._server = self._thread = None
        with self._lock:
            self._payload, self._retired = None, True
            self._cleanup_pending = self._retention_profile == EPHEMERAL
        self._expire()
        try:
            current = self.path.lstat()
            if (current.st_dev, current.st_ino) == self._identity:
                self.path.unlink()
        except FileNotFoundError:
            pass
