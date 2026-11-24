"""Optional trusted-parent access boundary; workflow metadata cannot authenticate it.

Host composition is trusted application code outside the worker write domain.
Private types prevent accidental misuse, not malicious same-process Python.
This module imports no Factory, database, credential or filesystem adapter.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import json
import math
import re
import threading
import time

_CODES = frozenset({'native_access_unavailable', 'native_access_denied', 'native_access_stale',
                    'native_access_expired', 'native_access_conflict', 'native_access_already_used',
                    'native_access_outcome_unknown', 'invalid_native_query'})
_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}')
_SHA = re.compile(r'[0-9a-f]{64}')
MAX_QUERY_BYTES = 65536
MAX_CUT_BYTES = 8 * 1048576
MAX_SOURCE_BYTES = MAX_CUT_BYTES  # One registered journal can consume the whole cut.
MAX_HANDLES = 8
REQUEST_SECONDS = 2.0


class NativeAccessError(ValueError):
    def __init__(self, code='native_access_unavailable'):
        self.code = code if type(code) is str and code in _CODES else 'native_access_unavailable'
        super().__init__(self.code)


def _require(condition, code='native_access_unavailable'):
    if not condition:
        raise NativeAccessError(code)


def _id(value):
    return type(value) is str and bool(_ID.fullmatch(value))


def _sha(value):
    return type(value) is str and bool(_SHA.fullmatch(value))


def _canonical(value):
    pending = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        _require(depth <= 32 and nodes <= 8192, 'invalid_native_query')
        if type(item) is dict:
            _require(all(type(k) is str for k in item), 'invalid_native_query')
            pending.extend((v, depth + 1) for v in item.values())
        elif type(item) is list:
            pending.extend((v, depth + 1) for v in item)
        else:
            _require(type(item) in {str, int, float, bool, type(None)}, 'invalid_native_query')
    try:
        raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    except (ValueError, TypeError, OverflowError, RecursionError, UnicodeError):
        raise NativeAccessError('invalid_native_query') from None
    _require(len(raw) <= MAX_QUERY_BYTES, 'invalid_native_query')
    return raw


@dataclass(frozen=True, init=False)
class RegisteredQuery:
    reader_id: str
    scope_ids: tuple[str, ...]
    _parameters: bytes = field(repr=False)

    def __init__(self, reader_id, scope_ids, parameters):
        _require(_id(reader_id) and type(scope_ids) is tuple and 1 <= len(scope_ids) <= 8
                 and all(_id(s) for s in scope_ids) and len(set(scope_ids)) == len(scope_ids)
                 and type(parameters) is dict, 'invalid_native_query')
        object.__setattr__(self, 'reader_id', reader_id)
        object.__setattr__(self, 'scope_ids', scope_ids)
        object.__setattr__(self, '_parameters', _canonical(parameters))

    @classmethod
    def from_dict(cls, value):
        _require(type(value) is dict and set(value) == {'reader_id', 'scope_ids', 'parameters'}
                 and type(value['scope_ids']) is list, 'invalid_native_query')
        return cls(value['reader_id'], tuple(value['scope_ids']), value['parameters'])

    @property
    def parameters(self):
        return json.loads(self._parameters)

    @property
    def identity(self):
        return self.reader_id, self.scope_ids, self._parameters


@dataclass(frozen=True)
class AuthorityStamp:
    revision: int
    permission_digest: str
    workflow_digest: str


@dataclass(frozen=True)
class SourceDependency:
    key: tuple[str, str, str, str, str]
    version: str
    content_sha256: str
    representation_sha256: str
    transform_version: str


@dataclass(frozen=True, repr=False)
class SourceDocument:
    dependency: SourceDependency
    content: bytes


@dataclass(frozen=True, repr=False)
class CapturedRead:
    documents: tuple[SourceDocument, ...]
    native_ref: object


@dataclass(frozen=True, repr=False)
class PreparedReadResponse:
    native_ref: object
    lineage: tuple[SourceDependency, ...]
    payload_sha256: str


@dataclass(frozen=True)
class ExistingOperationDisposition:
    status: str
    operation_id: str | None


class NativeAccessHost(ABC):
    """Fixed trusted composition only; never load a class/callback from request data.

    Implementations own current identity, source registration and complete lineage.
    check_current also revalidates previously used source/representation versions
    and custody; a provider permission revision alone does not validate a cached cut.
    Their final admission must participate in the actual task/source/response cut;
    a successful earlier check is not an admission permit. Every IO inherits deadline.
    """
    @abstractmethod
    def bind_native_request(self, native_request, workflow_resource, deadline): ...

    @abstractmethod
    def check_current(self, binding, deadline): ...

    @abstractmethod
    def load_authorized_cut(self, binding, query, deadline): ...

    @abstractmethod
    def prepare_owned_response(self, binding, captured, computation, response, deadline): ...

    @abstractmethod
    def admit_response(self, binding, prepared, deadline): ...

    def resume_native_request(self, native_request, checkpoint, deadline):
        raise NativeAccessError()

    def delegate_native_request(self, binding, child_launch, deadline):
        raise NativeAccessError()

    def discard_native_request(self, binding):
        """Release owned ephemeral references; never grants or recalls disclosure."""

    def attach_native_broker(self, broker):
        """Optional trusted lifecycle edge, never a request-data registration."""


class _Opaque:
    __slots__ = ()

    def __new__(cls, *args, **kwargs):
        raise TypeError('native broker reference required')

    def __repr__(self):
        return type(self).__name__ + '(opaque)'

    def __reduce_ex__(self, protocol):
        raise TypeError('native broker reference cannot be serialized')

    def __setattr__(self, name, value):
        raise AttributeError('native broker reference is immutable')


class NativeReadHandle(_Opaque):
    __slots__ = ()


class OwnedSourceCut(_Opaque):
    __slots__ = ('_documents',)

    @property
    def documents(self):
        return self._documents

    @property
    def evidence_authority(self):
        return False  # Source facts do not grant action, release or human authority.


class PreparedResponseRef(_Opaque):
    __slots__ = ()


@dataclass
class _Request:
    binding: object
    stamp: AuthorityStamp
    deadline: float
    busy: bool = False
    failed: bool = False
    query: tuple | None = None
    captured: CapturedRead | None = None
    cut: OwnedSourceCut | None = None
    preparation: tuple | None = None
    prepared: PreparedReadResponse | None = None
    response: PreparedResponseRef | None = None
    consumed: bool = False
    retiring: bool = False


class NativeAccessBroker:
    def __init__(self):
        self._host = None
        self._requests = {}
        self._lock = threading.RLock()

    @classmethod
    def _compose(cls, host):
        """Application composition, not an authentication or plugin-registration API."""
        _require(isinstance(host, NativeAccessHost))
        broker = cls()
        broker._host = host
        host.attach_native_broker(broker)
        return broker

    def _call(self, method, *args):
        if self._host is None:
            raise NativeAccessError()
        try:
            return getattr(self._host, method)(*args)
        except NativeAccessError:
            raise
        except Exception:
            raise NativeAccessError() from None

    def _stamp(self, binding, deadline):
        _require(time.monotonic() < deadline, 'native_access_expired')
        stamp = self._call('check_current', binding, deadline)
        _require(type(stamp) is AuthorityStamp and type(stamp.revision) is int and stamp.revision >= 1
                 and _sha(stamp.permission_digest) and _sha(stamp.workflow_digest))
        _require(time.monotonic() < deadline, 'native_access_expired')
        return stamp

    def _mint(self, binding, deadline):
        stamp = self._stamp(binding, deadline)
        with self._lock:
            now = time.monotonic()
            self._requests = {h: r for h, r in self._requests.items() if r.deadline > now and not r.failed}
            _require(len(self._requests) < MAX_HANDLES)
            handle = object.__new__(NativeReadHandle)
            self._requests[handle] = _Request(binding, stamp, deadline)
            return handle

    def bind_native_request(self, native_request, workflow_resource):
        deadline = time.monotonic() + REQUEST_SECONDS
        binding = self._call('bind_native_request', native_request, workflow_resource, deadline)
        _require(binding is not None)
        return self._mint(binding, deadline)

    def discard(self, handle):
        """Cancel pending owned work and drop derivatives, including expired handles.

        Bytes already returned to a recipient and an already admitted transport
        cannot be recalled. Persistent retention belongs to the native host.
        """
        with self._lock:
            _require(type(handle) is NativeReadHandle and handle in self._requests,
                     'native_access_denied')
            request = self._requests[handle]
            _require(not request.busy, 'native_access_conflict')
            del self._requests[handle]
        try:
            self._call('discard_native_request', request.binding)
        finally:
            request.captured = request.cut = request.prepared = request.binding = None
            request.query = request.preparation = request.response = None

    def _retire_dependencies(self, dependency_digests, *, cancel_all=False):
        """Fixed host lifecycle only: invalidate existing holders, not permissions."""
        _require(type(cancel_all) is bool and type(dependency_digests) is tuple
                 and (0 if cancel_all else 1) <= len(dependency_digests) <= 128
                 and all(_sha(item) for item in dependency_digests))
        bindings, idle, pending = [], [], False
        with self._lock:
            for handle, request in tuple(self._requests.items()):
                hashes = (() if request.captured is None else tuple(hashlib.sha256(_canonical(
                    [list(doc.dependency.key), doc.dependency.version, doc.dependency.content_sha256])).hexdigest()
                    for doc in request.captured.documents))
                if (not cancel_all and not set(hashes).intersection(dependency_digests)
                        and not (request.busy and not hashes)):
                    continue
                request.retiring = request.failed = request.consumed = True
                bindings.append(request.binding)
                if request.cut is not None:
                    object.__setattr__(request.cut, '_documents', ())
                request.captured = request.cut = request.prepared = None
                request.query = request.preparation = request.response = None
                if request.busy:
                    pending = True
                else:
                    del self._requests[handle]
                    idle.append(request)
        for request in idle:
            try:
                self._call('discard_native_request', request.binding)
            finally:
                request.binding = None
        return tuple(bindings), not pending

    @contextmanager
    def _operation(self, handle, absolute_deadline=None):
        with self._lock:
            _require(type(handle) is NativeReadHandle and handle in self._requests, 'native_access_denied')
            request = self._requests[handle]
            _require(not request.failed, 'native_access_stale')
            if absolute_deadline is not None:
                _require(type(absolute_deadline) in {int, float} and math.isfinite(absolute_deadline),
                         'invalid_native_query')
                request.deadline = min(request.deadline, absolute_deadline)
            if time.monotonic() >= request.deadline:
                request.failed = True
                raise NativeAccessError('native_access_expired')
            _require(not request.busy)
            request.busy = True
        try:
            stamp = self._stamp(request.binding, request.deadline)
            if stamp != request.stamp:
                request.failed = True
                raise NativeAccessError('native_access_stale')
            yield request
        except NativeAccessError as error:
            if error.code in {'native_access_stale', 'native_access_expired', 'native_access_unavailable'}:
                request.failed = True
            raise
        finally:
            with self._lock:
                request.busy = False
                retiring = request.retiring
                if retiring and self._requests.get(handle) is request:
                    del self._requests[handle]
            if retiring:
                try:
                    self._call('discard_native_request', request.binding)
                finally:
                    request.captured = request.cut = request.prepared = request.binding = None
                    request.query = request.preparation = request.response = None

    def check_current(self, handle):
        """Recheck an existing live cut; never renew its original deadline."""
        with self._operation(handle) as request:
            self._unchanged(request)

    def _unchanged(self, request):
        _require(not request.retiring, 'native_access_stale')
        stamp = self._stamp(request.binding, request.deadline)
        _require(not request.retiring and stamp == request.stamp, 'native_access_stale')

    @staticmethod
    def _documents(captured):
        _require(type(captured) is CapturedRead and captured.native_ref is not None
                 and type(captured.documents) is tuple and 1 <= len(captured.documents) <= 128)
        keys, total = set(), 0
        for document in captured.documents:
            _require(type(document) is SourceDocument and type(document.content) is bytes
                     and len(document.content) <= min(MAX_SOURCE_BYTES, MAX_CUT_BYTES - total))
            dep = document.dependency
            _require(type(dep) is SourceDependency and type(dep.key) is tuple and len(dep.key) == 5
                     and all(_id(v) for v in dep.key) and _id(dep.version) and _id(dep.transform_version)
                     and _sha(dep.content_sha256) and _sha(dep.representation_sha256)
                     and hashlib.sha256(document.content).hexdigest() == dep.representation_sha256
                     and dep.key not in keys)
            keys.add(dep.key)
            total += len(document.content)
            _require(total <= MAX_CUT_BYTES)
        return captured.documents

    def load_authorized_cut(self, handle, query, *, absolute_deadline):
        with self._operation(handle, absolute_deadline) as request:
            _require(type(query) is RegisteredQuery, 'invalid_native_query')
            if request.query is not None:
                _require(request.query == query.identity, 'native_access_conflict')
                return request.cut
            captured = self._call('load_authorized_cut', request.binding, query, request.deadline)
            documents = self._documents(captured)
            self._unchanged(request)
            cut = object.__new__(OwnedSourceCut)
            object.__setattr__(cut, '_documents', documents)
            with self._lock:
                _require(not request.retiring, 'native_access_stale')
                request.query, request.captured, request.cut = query.identity, captured, cut
            return cut

    def prepare_owned_response(self, handle, computation, cut, response, *, absolute_deadline):
        with self._operation(handle, absolute_deadline) as request:
            _require(type(cut) is OwnedSourceCut and cut is request.cut and _id(computation) and _id(response),
                     'native_access_denied')
            key = computation, response
            if request.preparation is not None:
                _require(key == request.preparation, 'native_access_conflict')
                return request.response
            prepared = self._call('prepare_owned_response', request.binding, request.captured,
                                  computation, response, request.deadline)
            _require(type(prepared) is PreparedReadResponse and prepared.native_ref is not None
                     and type(prepared.lineage) is tuple
                     and prepared.lineage == tuple(d.dependency for d in request.captured.documents)
                     and _sha(prepared.payload_sha256))
            self._unchanged(request)
            reference = object.__new__(PreparedResponseRef)
            with self._lock:
                _require(not request.retiring, 'native_access_stale')
                request.preparation, request.prepared, request.response = key, prepared, reference
            return reference

    def admit_response(self, handle, reference):
        with self._operation(handle) as request:
            _require(type(reference) is PreparedResponseRef and reference is request.response,
                     'native_access_denied')
            _require(not request.consumed, 'native_access_already_used')
            # Claim before invoking the actual task/source/response admission. No retry after ambiguity.
            request.consumed = True
            try:
                result = self._call('admit_response', request.binding, request.prepared, request.deadline)
                _require(type(result) is ExistingOperationDisposition
                         and result.status in {'queued', 'issued', 'unknown', 'denied', 'unavailable'}
                         and (result.operation_id is None or _id(result.operation_id)))
            except BaseException as error:
                if not isinstance(error, Exception):
                    raise
                raise NativeAccessError('native_access_outcome_unknown') from None
            if time.monotonic() >= request.deadline:
                return ExistingOperationDisposition('unknown', result.operation_id)
            return result

    def resume_native_request(self, native_request, checkpoint):
        deadline = time.monotonic() + REQUEST_SECONDS
        binding = self._call('resume_native_request', native_request, checkpoint, deadline)
        return self._mint(binding, deadline)

    def delegate_native_request(self, parent, child_launch):
        with self._operation(parent) as request:
            binding = self._call('delegate_native_request', request.binding, child_launch, request.deadline)
            self._unchanged(request)
            return self._mint(binding, request.deadline)
