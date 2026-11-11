"""Independent final admission over a host-owned, atomic writer boundary."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import sqlite3
import threading
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import security_bundle as bundle

if TYPE_CHECKING:
    from .github import GitHubClient
    from .public_admission import Authority, Decision, Evidence, Selector


@dataclass(frozen=True)
class SignedReview:
    payload: dict
    signature: str


@dataclass(frozen=True)
class Snapshot:
    revision: str
    selector: Selector
    base_ref: str
    is_open: bool
    reviews: tuple[SignedReview, ...]
    complete: bool
    evidence_id: str
    evidence_unique: bool
    pending_key: str | None
    merge_oid: str
    target_generation: int


@dataclass(frozen=True)
class Ticket:
    key: str
    revision: str
    selector: Selector
    evidence_id: str
    valid_from: datetime
    valid_until: datetime
    merge_oid: str
    target_generation: int


@dataclass(frozen=True)
class Receipt:
    key: str
    selector: Selector
    evidence_id: str
    merge_oid: str
    target_generation: int
    state: str = 'merged'


@dataclass(frozen=True)
class Result:
    state: str
    reason: str
    ticket: Ticket | None = None

    @property
    def key(self) -> str | None:
        return self.ticket.key if self.ticket else None


class AtomicBackend(Protocol):
    """Independent protected host, never a client selected by candidate code.

    snapshot must read a coherent, complete authority view. Its opaque revision
    must advance without ABA on every change to PR/head/base/tree, current run or
    attempt, evidence, owner decision log, producer/owner pins and exclusivity.
    If any source cannot be read completely, the host must fail closed.

    commit_once must compare that revision, exact candidate, evidence and time
    interval at the linearization point of the merge. It must exclusively own
    writes, atomically record the ticket key, and never redispatch an uncertain
    prior request. A receipt must identify the same protected target and key.
    All workers must share one durable fence. In addition the backend must
    check for ambiguous prior dispatches across *all* keys for this PR at commit.
    The trusted journal increments target_generation on a target change even
    when all SHAs eventually return to their former values. A new decision for
    an unchanged candidate advances revision alone. It qualifies one unique
    nonconflicting signed producer result for that exact target and attempt;
    duplicate contradictory evidence blocks even across fresh requests. The
    writer validates the proposed merge OID/parents/tree against the reviewed
    integration under the selected strategy. Definitive replies bind every
    ticket identity field. lookup is read-only and returns unknown while an
    operation can still take effect. A negative lookup must identify a terminal
    cancellation/no-effect for this key, including any delayed request. Absence
    of a receipt alone is always unknown.
    A regular remote merge request with a head-only guard cannot implement this.
    """
    fence: DispatchFence

    def snapshot(self, selector: Selector) -> Snapshot: ...
    def commit_once(self, ticket: Ticket) -> Receipt | str: ...
    def lookup(self, key: str) -> Receipt | str: ...


class Verifier(Protocol):
    @property
    def evidence_id(self) -> str: ...
    def __call__(self, selector: Selector, now: datetime) -> Decision: ...


def review_bytes(payload: dict) -> bytes:
    """The signed JSON encoding is sorted UTF-8, compact, and excludes NaN."""
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(',', ':'),
                      allow_nan=False).encode('utf-8')


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError('timezone-aware time required')
    return value.astimezone(timezone.utc)


def _timestamp(value: str) -> datetime:
    return _utc(datetime.fromisoformat(value))


_MAX_AGE = timedelta(hours=72)
_MAX_WINDOW = timedelta(seconds=5)
_SHA = re.compile(r'[0-9a-f]{40}')
_DIGEST = re.compile(r'[0-9a-f]{64}')


def _identity(selector: Selector) -> dict:
    names = ('repository', 'repository_id', 'pr_number', 'base_sha', 'head_sha', 'tree_sha',
             'run_id', 'run_attempt')
    data = {name: getattr(selector, name) for name in names}
    _check_identity(data)
    return data


def _check_identity(data: dict) -> None:
    if (set(data) != {'repository', 'repository_id', 'pr_number', 'base_sha', 'head_sha', 'tree_sha',
                      'run_id', 'run_attempt'}
            or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', data['repository'])
            or any(type(data[k]) is not int or data[k] <= 0
                   for k in ('repository_id', 'pr_number', 'run_id', 'run_attempt'))
            or any(not _SHA.fullmatch(data[k]) for k in ('base_sha', 'head_sha', 'tree_sha'))):
        raise ValueError('invalid selector')


def review_payload(selector: Selector, owner_id: int, sequence: int, decision: str, issued_at: datetime,
                   *, evidence_id: str, merge_oid: str, target_generation: int, expires_at: datetime | None = None) -> dict:
    """Format an unsigned human decision. Private signing keys belong outside this service."""
    issued = _utc(issued_at)
    expires = issued + _MAX_AGE if expires_at is None else _utc(expires_at)
    return {'kind': 'getzilla-owner-merge-decision-v1', 'target': _identity(selector), 'branch': 'main',
            'merge_oid': merge_oid, 'target_generation': target_generation,
            'owner_id': owner_id, 'sequence': sequence, 'decision': decision, 'evidence_id': evidence_id,
            'issued_at': issued.isoformat(), 'expires_at': expires.isoformat()}


class _OwnerDecisionBlocked(Exception):
    """Only fixed, operator-facing reasons cross the authorization boundary."""


def _ed25519(pem: bytes) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError('Ed25519 public key required')
    return key


def _owner_review(snapshot: Snapshot, now: datetime, owner_id: int, key: Ed25519PublicKey) -> tuple[str, datetime]:
    if type(owner_id) is not int or owner_id <= 0:
        raise _OwnerDecisionBlocked('owner-pin-invalid')
    if not snapshot.reviews:
        raise _OwnerDecisionBlocked('owner-decision-missing')
    target = _identity(snapshot.selector)
    # Each (repository ID, PR, owner) has one complete append-only decision stream.
    previous_time = None
    previous_generation = 0
    for sequence, item in enumerate(snapshot.reviews, 1):
        payload = item.payload
        encoded = review_bytes(payload)
        try:
            key.verify(base64.b64decode(item.signature, validate=True), encoded)
        except (InvalidSignature, TypeError, ValueError) as exc:
            raise _OwnerDecisionBlocked('owner-signature-invalid') from exc
        # Parse exactly the bytes verified, even if the transport used a mutable object.
        decision = json.loads(encoded)
        if set(decision) != {'kind', 'target', 'branch', 'owner_id', 'sequence', 'decision',
                             'evidence_id', 'issued_at', 'expires_at', 'merge_oid', 'target_generation'}:
            raise _OwnerDecisionBlocked('owner-decision-schema-invalid')
        candidate = decision['target']
        _check_identity(candidate)
        issued, expires = _timestamp(decision['issued_at']), _timestamp(decision['expires_at'])
        if (decision['kind'] != 'getzilla-owner-merge-decision-v1' or decision['branch'] != 'main'
                or type(decision['owner_id']) is not int or decision['owner_id'] != owner_id
                or type(decision['sequence']) is not int or decision['sequence'] != sequence
                or type(decision['target_generation']) is not int or decision['target_generation'] <= 0
                or decision['target_generation'] < previous_generation or not _SHA.fullmatch(decision['merge_oid'])
                or (previous_time is not None and issued < previous_time)
                or decision['decision'] not in ('approve', 'revoke') or issued > now
                or not issued <= expires <= issued + _MAX_AGE or not _DIGEST.fullmatch(decision['evidence_id'])
                or any(candidate[k] != target[k] for k in ('repository', 'repository_id', 'pr_number'))):
            raise _OwnerDecisionBlocked('owner-decision-log-invalid')
        previous_time, previous_generation = issued, decision['target_generation']
    if decision['decision'] == 'revoke':
        raise _OwnerDecisionBlocked('owner-decision-revoked')
    if (decision['evidence_id'] != snapshot.evidence_id or candidate != target
            or decision['target_generation'] != snapshot.target_generation or decision['merge_oid'] != snapshot.merge_oid):
        raise _OwnerDecisionBlocked('owner-decision-for-other-candidate')
    if expires < now:
        raise _OwnerDecisionBlocked('owner-decision-expired')
    return hashlib.sha256(encoded).hexdigest(), expires


class DispatchFence:
    """Persistent PR-wide interlock. All service workers use the same protected database."""

    def __init__(self, path: Path):
        if str(path) in (':memory:', ''):
            raise ValueError('durable host-owned fence path required')
        self.path = Path(path).resolve()
        with closing(self._connect()) as db:
            db.execute('SELECT approval_key, repo, pr, ticket, pending FROM dispatches LIMIT 0')

    @classmethod
    def create(cls, path: Path) -> DispatchFence:
        """One-time provisioning; an existing database must never be reset."""
        path = Path(path).resolve()
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        with closing(sqlite3.connect(path.as_uri() + '?mode=rw', uri=True)) as db, db:
            db.execute('BEGIN IMMEDIATE')
            db.execute("""CREATE TABLE dispatches (
                approval_key TEXT PRIMARY KEY NOT NULL,
                repo INTEGER NOT NULL, pr INTEGER NOT NULL, ticket BLOB NOT NULL,
                pending INTEGER NOT NULL CHECK(pending IN (0, 1)))""")
            db.execute('CREATE UNIQUE INDEX one_pending_pr ON dispatches(repo, pr) WHERE pending=1')
        return cls(path)

    def _connect(self):
        db = sqlite3.connect(self.path.as_uri() + '?mode=rw', uri=True, timeout=1)
        db.execute('PRAGMA synchronous=FULL')
        return db

    @staticmethod
    def _encode(t: Ticket) -> bytes:
        return review_bytes({'selector': _identity(t.selector), 'key': t.key, 'revision': t.revision,
                             'evidence_id': t.evidence_id, 'merge_oid': t.merge_oid,
                             'target_generation': t.target_generation, 'valid_from': t.valid_from.isoformat(),
                             'valid_until': t.valid_until.isoformat()})

    @staticmethod
    def _decode(blob: bytes, selector_type) -> Ticket:
        data = json.loads(blob)
        data['selector'] = selector_type(**data['selector'])
        data['valid_from'] = _timestamp(data['valid_from'])
        data['valid_until'] = _timestamp(data['valid_until'])
        return Ticket(**data)

    def claim(self, ticket: Ticket) -> Ticket | None:
        """Claim both the PR and the single-use approval before any provider call."""
        blob = self._encode(ticket)
        scope = (ticket.selector.repository_id, ticket.selector.pr_number)
        with closing(self._connect()) as db, db:
            row = db.execute('INSERT INTO dispatches VALUES (?, ?, ?, ?, 1) ON CONFLICT DO NOTHING',
                             (ticket.key, *scope, blob))
            if row.rowcount == 1:
                return None
            pending = db.execute('SELECT ticket FROM dispatches WHERE repo=? AND pr=? AND pending=1',
                                 scope).fetchone()
            if pending:
                return self._decode(pending[0], type(ticket.selector))
            raise _OwnerDecisionBlocked('owner-decision-already-used')

    def pending(self, selector: Selector) -> Ticket | None:
        """Recover the full prior ticket after a process restart without reissuing a write."""
        with closing(self._connect()) as db:
            row = db.execute('SELECT ticket FROM dispatches WHERE repo=? AND pr=? AND pending=1',
                             (selector.repository_id, selector.pr_number)).fetchone()
        return self._decode(row[0], type(selector)) if row else None

    def release(self, ticket: Ticket) -> None:
        # Preserve the approval key permanently so its old receipt cannot authorize
        # or reconcile a later dispatch under a different validation window.
        with closing(self._connect()) as db, db:
            db.execute('UPDATE dispatches SET pending=0 WHERE approval_key=? AND ticket=? AND pending=1',
                       (ticket.key, self._encode(ticket)))


class ObservationSessions:
    """Explicit resource composition, not operator/factory qualification.

    The host supplies pure client allocation and separately qualifies its actual
    exchange implementation. All sessions retain the original deadline and one
    shared raw budget. Keep this same object through UNKNOWN/recovery.
    """
    def __init__(self, original, factory, *, purpose):
        from .github import GitHubClient
        from .github_observer import BoundedGetTransport
        if (type(original) is not GitHubClient or type(original.transport) is not BoundedGetTransport
                or purpose not in {'merge', 'publisher'} or not callable(factory)):
            raise ValueError('observation allocation unavailable')
        transport = original.transport
        self.clock, self.deadline = transport.clock, transport.deadline
        self.purpose, self.limit = purpose, 2 if purpose == 'merge' else 4
        self._factory, self._left = factory, max(0, 4194304 - transport.raw_bytes)
        self._sessions, self._gets, self._publications = int(transport.calls > 0), transport.calls, 0
        self._clients = [original] if transport.calls else []
        self._evidence, self._active, self._lock = None, False, threading.RLock()
        self._nonce, self._publication, self._persist = secrets.token_hex(16), None, None

    def _snapshot(self):
        # This is a continuity comparison, never a deserialized source of authority.
        return review_bytes([self._nonce, self.deadline, self._sessions, self._gets,
                             self._publications, self._left])

    def _record(self, before):
        if self._persist is not None:
            self._persist(before, self._snapshot())

    @property
    def remaining_bytes(self):
        return self._left

    def reserve(self, maximum, *, publication=False):
        if not self._lock.acquire(blocking=False):
            raise ValueError('observation budget busy')
        try:
            before = self._snapshot()
            if self.clock() >= self.deadline or self._left <= 0:
                raise ValueError('observation budget exhausted')
            if publication:
                if self._publications >= 16:
                    raise ValueError('publication requests exhausted')
                self._publications += 1
            else:
                if self._gets >= self.limit * 14:
                    raise ValueError('observation requests exhausted')
                self._gets += 1
            amount = min(maximum, 1048576, self._left)
            if type(amount) is not int or amount <= 0:
                raise ValueError('observation reservation malformed')
            self._left -= amount
            self._record(before)
            return amount
        finally:
            self._lock.release()

    def finish(self, reserved, actual):
        with self._lock:
            before = self._snapshot()
            if type(actual) is not int or not 0 <= actual <= reserved:
                raise ValueError('observation raw bound violated')
            self._left += reserved - actual
            self._record(before)

    @contextmanager
    def session(self, evidence_id):
        from .github import GitHubClient
        from .github_observer import BoundedGetTransport, ObservationError
        if not self._lock.acquire(blocking=False):
            raise ValueError('observation session busy')
        entered = False
        try:
            if (self._active or self._sessions >= self.limit or self._left <= 0 or self.clock() >= self.deadline
                    or not _DIGEST.fullmatch(evidence_id)
                    or self._evidence is not None and self._evidence != evidence_id):
                raise ValueError('observation session unavailable')
            self._evidence, self._active, entered = evidence_id, True, True
            before = self._snapshot()
            self._sessions += 1
            self._record(before)
            if self.clock() >= self.deadline:
                raise ValueError('observation deadline exhausted during durable reservation')
            client = self._factory(self.deadline, self._left)
            if (type(client) is not GitHubClient or type(client.transport) is not BoundedGetTransport
                    or client.token_provider is not None or not isinstance(client.token, str) or not client.token
                    or client.api_url != 'https://api.github.com'
                    or any(old is client or old.transport is client.transport for old in self._clients)
                    or client.transport.calls != 0 or client.transport.raw_bytes != 0
                    or client.transport.clock is not self.clock):
                raise ValueError('fresh bounded observation client required')
            self._clients.append(client)
            transport = client.transport
            transport.deadline = min(transport.deadline, self.deadline)
            exchange = transport._exchange
            def bounded_exchange(url, headers, deadline, maximum):
                try:
                    reserved = self.reserve(maximum)
                except ValueError as exc:
                    raise ObservationError('shared-observation-budget') from exc
                status, encoded, raw_bytes = exchange(url, headers, min(deadline, self.deadline), reserved)
                try:
                    self.finish(reserved, raw_bytes)
                except ValueError as exc:
                    raise ObservationError('shared-observation-raw-bound') from exc
                return status, encoded, raw_bytes
            transport._exchange = bounded_exchange
            yield client
        finally:
            if entered:
                self._active = False
            self._lock.release()


class BoundPublicVerifier:
    """Use the existing admission evaluator with a fixed, host-owned evidence bundle."""

    def __init__(self, client: GitHubClient, authority: Authority, evidence: Evidence,
                 *, snapshot_root: Path | None = None, candidate_root: Path | None = None,
                 observations: ObservationSessions | None = None):
        from .public_admission import Evidence
        if type(evidence) is not Evidence:
            raise ValueError('canonical evidence required')
        self._client = client
        self._authority = authority
        self._root = snapshot_root
        self._candidate_root = candidate_root
        if observations is not None and type(observations) is not ObservationSessions:
            raise ValueError('explicit observation session allocation required')
        self.observations = observations
        value = bundle._bounded_value({'binding': evidence.binding, 'report': evidence.report,
                                     'integration': evidence.integration, 'descriptors': evidence.descriptors})
        parts, size = [], 0
        encoder = json.JSONEncoder(ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)
        for part in encoder.iterencode(value):
            raw = part.encode('utf-8')
            size += len(raw)
            if size > bundle.CONTROL_TOTAL:
                raise ValueError('evidence aggregate limit')
            parts.append(raw)
        self._bundle = b''.join(parts)
        self._id = hashlib.sha256(self._bundle).hexdigest()
        self._horizon = None
        self._verified = False

    @property
    def evidence_id(self) -> str:
        return self._id

    def shares_owner_key(self, owner_key: Ed25519PublicKey) -> bool:
        encoding, form = serialization.Encoding.Raw, serialization.PublicFormat.Raw
        producer_key = _ed25519(self._authority.public_key_pem)
        return producer_key.public_bytes(encoding, form) == owner_key.public_bytes(encoding, form)

    def authorizes_merge(self, merge_oid: str) -> bool:
        integration = json.loads(self._bundle)['integration']
        return isinstance(integration, dict) and integration.get('merge_sha') == merge_oid

    def matches_publisher(self, repository: str, repository_id: int, policy_digest: str) -> bool:
        return (self._authority.repository == repository and self._authority.repository_id == repository_id
                and self._authority.policy_digest == policy_digest)

    def deadline(self, now: datetime) -> datetime:
        if not self._verified or self._horizon is None or _utc(now) > self._horizon:
            raise ValueError('validated evidence lifetime unavailable')
        return self._horizon

    def __call__(self, selector: Selector, now: datetime) -> Decision:
        from .public_admission import Decision, Evidence, evaluate
        bundle = json.loads(self._bundle)
        self._verified = False
        def invoke(client):
            return evaluate(client, self._authority, selector, Evidence(**bundle),
                            now=now, snapshot_root=self._root, candidate_root=self._candidate_root)
        try:
            if self.observations is None:
                result = invoke(self._client)
            else:
                with self.observations.session(self.evidence_id) as client:
                    result = invoke(client)
        except (OSError, ValueError):
            return Decision(False, ('observation-allocation-unavailable',))
        horizon = getattr(result, 'valid_until', None)
        self._verified = False
        if result.eligible is True and result.blockers == () and type(horizon) is datetime:
            horizon = _utc(horizon)
            if horizon >= _utc(now):
                self._horizon = min(self._horizon, horizon) if self._horizon is not None else horizon
                self._verified = True
        if result.eligible is True and not self._verified:
            return Decision(False, ('validated-lifetime-unavailable',))
        return result


def execute(backend: AtomicBackend, verifier: BoundPublicVerifier, *, owner_id: int, owner_key: bytes,
            selector: Selector, clock: Callable[[], datetime], window: timedelta = _MAX_WINDOW) -> Result:
    try:
        if type(verifier) is not BoundPublicVerifier:
            return Result('blocked', 'canonical-bound-verifier-required')
        start = _utc(clock())
        if not timedelta(0) <= window <= _MAX_WINDOW:
            return Result('blocked', 'invalid-dispatch-window')
        outstanding = backend.fence.pending(selector)
        if outstanding is not None:
            return Result('unknown', 'prior-pr-dispatch-unresolved', outstanding)
        snapshot = backend.snapshot(selector)
        if snapshot.pending_key is not None:
            return Result('unknown', 'atomic-backend-pr-dispatch-unresolved')
        if (snapshot.complete is not True or snapshot.evidence_unique is not True
                or type(snapshot.target_generation) is not int or snapshot.target_generation <= 0
                or not _SHA.fullmatch(snapshot.merge_oid) or snapshot.is_open is not True or snapshot.base_ref != 'main'
                or not isinstance(snapshot.revision, str) or not snapshot.revision
                or _identity(snapshot.selector) != _identity(selector)
                or not _DIGEST.fullmatch(snapshot.evidence_id) or verifier.evidence_id != snapshot.evidence_id):
            return Result('blocked', 'current-authority-unavailable-or-stale')
        pinned_owner_key = _ed25519(owner_key)
        if isinstance(verifier, BoundPublicVerifier) and verifier.shares_owner_key(pinned_owner_key):
            return Result('blocked', 'producer-and-owner-share-key')
        if isinstance(verifier, BoundPublicVerifier) and not verifier.authorizes_merge(snapshot.merge_oid):
            return Result('blocked', 'tested-integration-missing-or-mismatched')
        if (isinstance(verifier, BoundPublicVerifier) and verifier.observations is not None
                and verifier.observations.purpose != 'merge'):
            return Result('blocked', 'merge-observation-allocation-mismatch')
        key, approval_expires = _owner_review(snapshot, start, owner_id, pinned_owner_key)
        initial = verifier(selector, start)
        if initial.eligible is not True or initial.blockers != ():
            return Result('blocked', 'independent-admission-denied')
        # A verified, frozen bundle has an absolute lifetime independent of the
        # cost of validation. Generic readers can certify only the short window.
        horizon = verifier.deadline(start)
        sampled = _utc(clock())
        horizon = min(horizon, approval_expires)
        if not start <= sampled <= horizon:
            return Result('blocked', 'evidence-expired')
        verified_until = min(horizon, sampled + window)
        final = verifier(selector, verified_until)
        if final.eligible is not True or final.blockers != ():
            return Result('blocked', 'independent-admission-denied-at-deadline')
        dispatch_start = _utc(clock())
        if verifier.evidence_id != snapshot.evidence_id or not start <= dispatch_start <= verified_until:
            return Result('blocked', 'dispatch-window-or-evidence-changed')
        deadline = min(verified_until, dispatch_start + window)
        ticket = Ticket(key, snapshot.revision, selector, snapshot.evidence_id, dispatch_start, deadline,
                        snapshot.merge_oid, snapshot.target_generation)
        dispatch = backend.commit_once
        outstanding = backend.fence.claim(ticket)
        if outstanding is not None:
            return Result('unknown', 'prior-pr-dispatch-unresolved', outstanding)
    except _OwnerDecisionBlocked as exc:
        return Result('blocked', str(exc))
    except Exception as exc:
        # Host reads, malformed evidence and clocks fail before any dispatch.
        return Result('blocked', f'precondition-failed:{type(exc).__name__}')
    try:
        outcome = dispatch(ticket)
        if _matches(outcome, ticket) and outcome.state in ('merged', 'already-merged', 'stale', 'expired', 'not-merged'):
            backend.fence.release(ticket)
            if outcome.state in ('merged', 'already-merged'):
                return Result(outcome.state, 'atomic-backend-receipt', ticket)
            return Result('blocked', f'atomic-backend-{outcome.state}', ticket)
    except Exception:
        return Result('unknown', 'receipt-unavailable', ticket)
    # A transport failure can occur after the durable write. Keep the PR-wide fence.
    return Result('unknown', 'receipt-unavailable', ticket)


def _matches(receipt: Receipt | str, ticket: Ticket) -> bool:
    return (isinstance(receipt, Receipt) and receipt.key == ticket.key
            and receipt.evidence_id == ticket.evidence_id and receipt.merge_oid == ticket.merge_oid
            and type(receipt.target_generation) is int and receipt.target_generation == ticket.target_generation
            and _identity(receipt.selector) == _identity(ticket.selector))


def reconcile(backend: AtomicBackend, ticket: Ticket) -> Result:
    """Read a durable receipt matching a prior ticket. Never resubmit a merge."""
    try:
        if isinstance(ticket, Ticket) and _DIGEST.fullmatch(ticket.key):
            receipt = backend.lookup(ticket.key)
            if _matches(receipt, ticket) and receipt.state in ('merged', 'already-merged', 'not-merged', 'stale', 'expired'):
                backend.fence.release(ticket)
                if receipt.state in ('not-merged', 'stale', 'expired'):
                    return Result('not-merged', 'backend-confirmed-no-effect', ticket)
                return Result('already-merged', 'durable-receipt', ticket)
    except Exception:
        return Result('unknown', 'receipt-unavailable', ticket)
    return Result('unknown', 'receipt-unavailable', ticket)
