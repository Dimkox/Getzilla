"""Operator-owned public check publisher. Import only from a pinned deployment.

No candidate code is imported. Callers provide a protected credential broker,
durable journal and BoundPublicVerifier. Publication is explicitly off by default.
This module grants no merge authority and does not install or configure an App.
"""
from __future__ import annotations

from contextlib import closing
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
import hashlib
import hmac
import os
from pathlib import Path
import re
import sqlite3
import threading
from typing import Callable, Protocol
from urllib.parse import quote

from .github import GitHubClient
from .github_app import GitHubAppAuth
from .models import require_digest, require_repository
from .public_admission import Selector
from .public_merge import BoundPublicVerifier, ObservationSessions
from .security_bundle import BundleError, bounded_json, canonical_json


class PublicationPort(Protocol):
    """Unqualified operator dependency, not a transport implementation or attestation.

    open must enforce deadline and raw limits before its own buffering/allocation,
    reject redirects/compression, and return a closing binary response with exact
    url/status/encoding. Callers must separately qualify its actual implementation
    and credential broker. Ordinary GitHubClient transports are never used here.
    """
    def open(self, client, method, path, body, *, deadline, maximum): ...


class _PublicationUnavailable(RuntimeError):
    pass


class _Requests:
    def __init__(self, client, port, budget):
        if type(budget) is not ObservationSessions or budget.purpose != 'publisher':
            raise ValueError('shared publication allocation required')
        self.client, self.port, self.budget = client, port, budget
        self.clock, self.deadline = budget.clock, budget.deadline
        self.calls, self.raw_bytes = 0, 0

    def _request(self, method, path, body=None):
        deadline = min(self.deadline, self.clock() + 5)
        if (self.calls >= 16 or self.clock() >= deadline or method not in {'GET', 'POST', 'PATCH'}
                or not path.startswith('/repos/') and path != '/installation/repositories?per_page=100'
                or len(path) > 2048 or body is not None and len(canonical_json(body)) > 1048576):
            raise _PublicationUnavailable('publication-request-bound')
        self.calls += 1
        maximum = min(1048576, 4194304 - self.raw_bytes)
        maximum = self.budget.reserve(maximum, publication=True)
        if maximum <= 0 or self.clock() >= deadline:
            raise _PublicationUnavailable('publication-response-bound')
        chunks, size = [], 0
        with self.port.open(self.client, method, path, body, deadline=deadline, maximum=maximum) as response:
            if (response.url != 'https://api.github.com' + path or response.encoding not in (None, 'identity')
                    or type(response.status) is not int or not 200 <= response.status < 300):
                raise _PublicationUnavailable('publication-response-scope')
            while True:
                if self.clock() > deadline:
                    raise _PublicationUnavailable('publication-request-expired')
                requested = min(65536, maximum - size + 1)
                part = response.read(requested)
                if self.clock() > deadline or type(part) is not bytes or len(part) > requested:
                    raise _PublicationUnavailable('publication-request-expired-or-shape')
                size += len(part)
                if size > maximum:
                    raise _PublicationUnavailable('publication-response-bound')
                if not part:
                    break
                chunks.append(part)
        self.raw_bytes += size
        self.budget.finish(maximum, size)
        if self.clock() > deadline:
            raise _PublicationUnavailable('publication-request-expired')
        try:
            value = bounded_json(b''.join(chunks), maximum=maximum)
        except BundleError as exc:
            raise _PublicationUnavailable('publication-response-invalid') from exc
        if self.clock() > deadline or type(value) is not dict:
            raise _PublicationUnavailable('publication-response-expired-or-shape')
        return value


@dataclass(frozen=True)
class PublisherConfig:
    repository: str
    repository_id: int
    app_id: int
    installation_id: int
    policy_digest: str

    def __post_init__(self):
        if require_repository(self.repository) != self.repository:
            raise ValueError('exact repository required')
        if require_digest(self.policy_digest, 'policy') != self.policy_digest:
            raise ValueError('exact policy required')
        if any(type(value) is not int or value <= 0
               for value in (self.repository_id, self.app_id, self.installation_id)) or self.app_id == 15368:
            raise ValueError('independent App and positive IDs required')

    @property
    def context(self) -> str:
        return 'getzilla-security/verified@' + self.policy_digest[:12]

    def token_request(self) -> dict:
        return {'repository_ids': [self.repository_id], 'permissions': {
            'checks': 'write', 'actions': 'read', 'contents': 'read', 'pull_requests': 'read'}}


@dataclass(frozen=True)
class Publication:
    state: str
    reason: str
    check_id: int | None = None


class PublicationConflict(ValueError):
    def __init__(self, key: str, check_id: int | None):
        super().__init__('contradictory-producer-evidence')
        self.key, self.check_id = key, check_id


def scoped_client_factory(config: PublisherConfig, auth: GitHubAppAuth):
    """Broker for operator-provisioned credentials; never use the broad legacy token path."""
    if (auth.app_id != config.app_id or auth.installation_id != config.installation_id
            or auth.api_url != 'https://api.github.com'):
        raise ValueError('operator App configuration mismatch')
    lock = threading.Lock()
    token, expiry = None, None

    def access_token():
        nonlocal token, expiry
        with lock:
            now = auth.now_fn()
            if token is not None and expiry is not None and expiry > now + timedelta(minutes=2):
                return token
            headers = auth._jwt_headers(now)
            status, installation = auth.transport.request('GET',
                f'https://api.github.com/app/installations/{config.installation_id}', headers, None)
            if (status != 200 or not isinstance(installation, dict)
                    or installation.get('id') != config.installation_id or installation.get('app_id') != config.app_id):
                raise ValueError('operator-installation-identity-mismatch')
            status, response = auth.transport.request('POST',
                f'https://api.github.com/app/installations/{config.installation_id}/access_tokens',
                headers, config.token_request())
            token, expiry = auth._token_from(status, response, now)
            return token

    def factory(installation_id: int, request: dict):
        if installation_id != config.installation_id or request != config.token_request():
            raise ValueError('public token scope mismatch')
        return GitHubClient(token_provider=access_token, transport=auth.transport, api_version=auth.api_version)
    return factory


def verify_webhook(raw: bytes, signature: str, secret: bytes) -> bool:
    """Authenticate raw bytes before parsing. The event is a wakeup, never authority."""
    if (not isinstance(raw, bytes) or len(raw) > 1024 * 1024 or not isinstance(secret, bytes)
            or len(secret) < 32 or not isinstance(signature, str)
            or re.fullmatch(r'sha256=[0-9a-f]{64}', signature) is None):
        return False
    expected = 'sha256=' + hmac.new(secret, raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


class PublicationJournal:
    """All publisher replicas share this host-owned database, never candidate storage."""

    def __init__(self, path: Path):
        self.path = Path(path).resolve()
        try:
            with closing(self._connect()) as db:
                db.execute('SELECT key, scope, check_id, conflicted, mutation FROM publications LIMIT 0')
                db.execute('SELECT key, snapshot FROM operations LIMIT 0')
                db.execute('SELECT id FROM deliveries LIMIT 0')
        except sqlite3.Error as exc:
            raise ValueError('publication-journal-schema-unavailable') from exc

    @classmethod
    def create(cls, path: Path):
        path = Path(path).resolve()
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        with closing(sqlite3.connect(path)) as db, db:
            db.execute('CREATE TABLE publications (key TEXT PRIMARY KEY, scope TEXT UNIQUE NOT NULL, '
                       "check_id INTEGER, conflicted INTEGER NOT NULL CHECK(conflicted IN (0,1)), "
                       "mutation TEXT NOT NULL CHECK(mutation IN ('','success','action_required')))")
            db.execute('CREATE TABLE operations (key TEXT PRIMARY KEY, snapshot BLOB NOT NULL)')
            db.execute('CREATE TABLE deliveries (id TEXT PRIMARY KEY)')
        return cls(path)

    def _connect(self):
        db = sqlite3.connect(self.path.as_uri() + '?mode=rw', uri=True, timeout=5)
        db.execute('PRAGMA synchronous=FULL')
        return db

    def accept_delivery(self, delivery_id: str) -> bool:
        # Call only after verify_webhook. Delivery headers alone are not authenticated.
        if not isinstance(delivery_id, str) or re.fullmatch(r'[A-Za-z0-9-]{1,128}', delivery_id) is None:
            raise ValueError('bounded delivery ID required')
        with closing(self._connect()) as db, db:
            return db.execute('INSERT OR IGNORE INTO deliveries VALUES (?)', (delivery_id,)).rowcount == 1

    def reserve(self, key: str, scope: str) -> bool:
        with closing(self._connect()) as db, db:
            inserted = db.execute("INSERT OR IGNORE INTO publications VALUES (?, ?, NULL, 0, '')", (key, scope)).rowcount == 1
            row = db.execute('SELECT key, check_id, conflicted FROM publications WHERE scope=?', (scope,)).fetchone()
            conflict = row[0] != key or row[2] != 0
            if conflict:
                db.execute('UPDATE publications SET conflicted=1 WHERE scope=?', (scope,))
        # Commit the latch before reporting refusal. Raising inside the transaction
        # would roll it back and allow a subsequent retry of the first bundle.
        if conflict:
            raise PublicationConflict(row[0], row[1])
        return inserted

    def _bind_allocation(self, key, allocation):
        with allocation._lock:
            identity = (self.path, key)
            if allocation._publication not in (None, identity):
                raise ValueError('publication-allocation-already-bound')
            expected = allocation._snapshot()
            if len(expected) > 512:
                raise ValueError('publication-allocation-shape')
            with closing(self._connect()) as db, db:
                db.execute('INSERT OR IGNORE INTO operations VALUES (?, ?)', (key, expected))
                row = db.execute('SELECT length(snapshot), substr(snapshot,1,513) FROM operations WHERE key=?',
                                 (key,)).fetchone()
                if row != (len(expected), expected):
                    raise ValueError('publication-allocation-continuity-unavailable')
            allocation._publication = identity
            def persist(before, after):
                with closing(self._connect()) as db, db:
                    changed = db.execute('UPDATE operations SET snapshot=? WHERE key=? AND snapshot=?',
                                         (after, key, before)).rowcount
                    if changed != 1:
                        raise ValueError('publication-allocation-continuity-unavailable')
            allocation._persist = persist

    def _pending(self, key):
        with closing(self._connect()) as db:
            row = db.execute('SELECT mutation FROM publications WHERE key=?', (key,)).fetchone()
        if row is None or row[0] not in ('', 'success', 'action_required'):
            raise ValueError('publication-mutation-state-unavailable')
        return row[0]

    def _begin(self, key, check_id, goal):
        if goal not in ('success', 'action_required'):
            raise ValueError('publication-mutation-goal')
        with closing(self._connect()) as db, db:
            if db.execute("UPDATE publications SET mutation=? WHERE key=? AND check_id=? AND mutation=''",
                          (goal, key, check_id)).rowcount != 1:
                raise _PublicationUnavailable('prior-completion-unresolved')

    def _resolve(self, key, check_id, goal):
        with closing(self._connect()) as db, db:
            db.execute("UPDATE publications SET mutation='' WHERE key=? AND check_id=? AND mutation=?",
                       (key, check_id, goal))

    def _contains(self, key: str, scope: str) -> bool:
        # Read only: unvalidated new evidence must not create a conflict latch.
        with closing(self._connect()) as db:
            return db.execute('SELECT 1 FROM publications WHERE key=? AND scope=? AND conflicted=0',
                              (key, scope)).fetchone() is not None

    def require_unconflicted(self, scope: str):
        with closing(self._connect()) as db:
            row = db.execute('SELECT key, check_id, conflicted FROM publications WHERE scope=?', (scope,)).fetchone()
        if row is None:
            raise ValueError('publication-reservation-unavailable')
        if row[2]:
            raise PublicationConflict(row[0], row[1])

    def bind(self, key: str, check_id: int):
        with closing(self._connect()) as db, db:
            changed = db.execute('UPDATE publications SET check_id=? WHERE key=? AND (check_id IS NULL OR check_id=?)',
                                 (check_id, key, check_id)).rowcount
            if changed != 1:
                raise ValueError('conflicting publication receipt')

    def check_id(self, key: str) -> int | None:
        with closing(self._connect()) as db:
            row = db.execute('SELECT check_id FROM publications WHERE key=?', (key,)).fetchone()
        return row[0] if row else None


def _check_identity(check: dict, config: PublisherConfig, selector: Selector, key: str) -> int:
    identity = check.get('id')
    if (type(identity) is not int or identity <= 0 or check.get('app', {}).get('id') != config.app_id
            or check.get('head_sha') != selector.head_sha or check.get('name') != config.context
            or check.get('external_id') != key
            or check.get('url') != f'https://api.github.com/repos/{config.repository}/check-runs/{identity}'):
        raise ValueError('check-publisher-or-candidate-identity-mismatch')
    return identity


def _recover(client: GitHubClient, config: PublisherConfig, selector: Selector, key: str) -> dict | None:
    # filter=all includes older suites. Refuse an incomplete or oversized lookup.
    matches = []
    seen = 0
    for page in range(1, 11):
        record = client._request('GET', f'/repos/{config.repository}/commits/{selector.head_sha}/check-runs'
                                 f'?check_name={quote(config.context, safe="")}&filter=all&per_page=100&page={page}')
        total, checks = record.get('total_count'), record.get('check_runs')
        if type(total) is not int or not 0 <= total <= 1000 or not isinstance(checks, list) or len(checks) > 100:
            raise ValueError('incomplete-check-reconciliation')
        seen += len(checks)
        for check in checks:
            if check.get('external_id') == key:
                _check_identity(check, config, selector, key)
                matches.append(check)
        if seen == total:
            break
        if not checks or seen > total:
            raise ValueError('incomplete-check-reconciliation')
    else:
        raise ValueError('check-reconciliation-limit')
    if len(matches) > 1:
        raise ValueError('duplicate-publication-receipts')
    return matches[0] if matches else None


def publish(config: PublisherConfig, journal: PublicationJournal, verifier: BoundPublicVerifier,
            selector: Selector, *, client_factory: Callable[[int, dict], GitHubClient],
            clock: Callable[[], datetime], enabled: bool = False,
            request_port: PublicationPort | None = None) -> Publication:
    """Publish only a currently verified head. Unknown POST outcomes never cause a second POST.

    The operator broker must enforce token_request exactly. A readback of this
    check is evidence of publication only; merge-time expiry needs a separate writer.
    """
    if enabled is not True:
        return Publication('disabled', 'publication-disabled')
    if request_port is None or not callable(getattr(request_port, 'open', None)):
        return Publication('blocked', 'bounded-publication-port-unavailable')
    try:
        if type(verifier) is not BoundPublicVerifier or not verifier.matches_publisher(
                config.repository, config.repository_id, config.policy_digest):
            return Publication('blocked', 'operator-policy-or-verifier-mismatch')
        budget = verifier.observations
        if (type(budget) is not ObservationSessions or budget.purpose != 'publisher'
                or budget.clock() >= budget.deadline or budget._sessions >= budget.limit
                or budget.remaining_bytes <= 0 or budget._publications >= 16):
            return Publication('blocked', 'publisher-observation-budget-unavailable')
        key = hashlib.sha256(canonical_json({'publisher': asdict(config), 'candidate': asdict(selector),
                                           'evidence': verifier.evidence_id})).hexdigest()
        journal._bind_allocation(key, budget)
        scope = hashlib.sha256(canonical_json({'publisher': asdict(config), 'candidate': asdict(selector)})).hexdigest()
        prior = journal._contains(key, scope)
        if not prior and verifier(selector, clock()).eligible is not True:
            return Publication('blocked', 'independent-admission-denied')
        if budget.clock() >= budget.deadline:
            return Publication('blocked', 'publisher-observation-budget-unavailable')
        client = client_factory(config.installation_id, config.token_request())
        if client.api_url != 'https://api.github.com':
            return Publication('blocked', 'publisher-provider-origin-untrusted')
        client = _Requests(client, request_port, budget)
        accessible = client._request('GET', '/installation/repositories?per_page=100')
        repositories = accessible.get('repositories')
        if (accessible.get('total_count') != 1 or not isinstance(repositories, list) or len(repositories) != 1
                or repositories[0].get('id') != config.repository_id
                or repositories[0].get('full_name') != config.repository):
            return Publication('blocked', 'publisher-token-repository-scope-mismatch')
        repo = client._request('GET', f'/repos/{config.repository}')
        if repo.get('id') != config.repository_id or repo.get('full_name') != config.repository:
            return Publication('blocked', 'publisher-repository-mismatch')
        if not prior and verifier(selector, clock()).eligible is not True:
            return Publication('blocked', 'candidate-changed-before-publication')
        first = journal.reserve(key, scope)
        check_id = journal.check_id(key)
        if check_id is not None:
            check = client._request('GET', f'/repos/{config.repository}/check-runs/{check_id}')
            _check_identity(check, config, selector, key)
        else:
            check = _recover(client, config, selector, key)
            if check is None:
                if not first:
                    return Publication('unknown', 'prior-create-unresolved')
                check = client._request('POST', f'/repos/{config.repository}/check-runs', {
                    'name': config.context, 'head_sha': selector.head_sha, 'status': 'in_progress',
                    'external_id': key, 'started_at': clock().isoformat()})
            check_id = _check_identity(check, config, selector, key)
            journal.bind(key, check_id)
        journal.require_unconflicted(scope)
        pending = journal._pending(key)
        if pending:
            if check.get('status') != 'completed' or check.get('conclusion') != pending:
                return Publication('unknown', 'prior-completion-unresolved', check_id)
            journal._resolve(key, check_id, pending)
            if pending == 'action_required':
                return Publication('blocked', 'prior-demotion-confirmed', check_id)
        if check.get('status') != 'completed' or check.get('conclusion') != 'success':
            if verifier(selector, clock()).eligible is not True:
                return Publication('blocked', 'candidate-changed-before-success', check_id)
            journal._begin(key, check_id, 'success')
            client._request('PATCH', f'/repos/{config.repository}/check-runs/{check_id}', {
                'status': 'completed', 'conclusion': 'success', 'completed_at': clock().isoformat(),
                'output': {'title': 'Independent security evidence verified',
                    'summary': f'PR {selector.pr_number}; run {selector.run_id}; attempt {selector.run_attempt}; evidence {verifier.evidence_id}'}})
        readback = client._request('GET', f'/repos/{config.repository}/check-runs/{check_id}')
        _check_identity(readback, config, selector, key)
        journal.require_unconflicted(scope)
        if readback.get('status') != 'completed' or readback.get('conclusion') != 'success':
            return Publication('unknown', 'completion-unconfirmed', check_id)
        journal._resolve(key, check_id, 'success')
        if verifier(selector, clock()).eligible is not True:
            # Bound the observed race; this cannot replace the final merge fence.
            journal._begin(key, check_id, 'action_required')
            client._request('PATCH', f'/repos/{config.repository}/check-runs/{check_id}', {
                'status': 'completed', 'conclusion': 'action_required',
                'output': {'title': 'Candidate changed', 'summary': 'A new independent decision is required.'}})
            return Publication('blocked', 'candidate-changed-after-publication', check_id)
        if journal._pending(key):
            return Publication('unknown', 'prior-completion-unresolved', check_id)
        return Publication('published', 'app-owned-check-readback', check_id)
    except PublicationConflict as conflict:
        try:
            old = (client._request('GET', f'/repos/{config.repository}/check-runs/{conflict.check_id}')
                   if conflict.check_id is not None else _recover(client, config, selector, conflict.key))
            if old is not None:
                old_id = _check_identity(old, config, selector, conflict.key)
                pending = journal._pending(conflict.key)
                if pending:
                    if old.get('status') != 'completed' or old.get('conclusion') != pending:
                        return Publication('unknown', 'prior-completion-unresolved', old_id)
                    journal._resolve(conflict.key, old_id, pending)
                if old.get('status') == 'completed' and old.get('conclusion') == 'action_required':
                    return Publication('blocked', 'producer-evidence-conflict-latched')
                journal._begin(conflict.key, old_id, 'action_required')
                client._request('PATCH', f'/repos/{config.repository}/check-runs/{old_id}', {
                    'status': 'completed', 'conclusion': 'action_required',
                    'output': {'title': 'Contradictory evidence', 'summary': 'A new protected producer run is required.'}})
            return Publication('blocked', 'producer-evidence-conflict-latched')
        except Exception:
            return Publication('unknown', 'conflict-latched-invalidation-unconfirmed')
    except (ValueError, KeyError, TypeError, AttributeError):
        return Publication('blocked', 'publisher-identity-or-input-invalid')
    except Exception:
        # A timeout can follow a committed write. Preserve journal state for lookup.
        return Publication('unknown', 'publisher-operation-unconfirmed')
