"""Opt-in protected CI bridge. Candidate JSON and provider labels grant no authority.

The hosting application supplies the producer public key, fixed policy and SDK
installation client out of band. This module never loads a signing key, token,
repository-selected plugin or authority configuration.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import math
import re
import time
from typing import Callable

from .client import EntireError
from .journal import RequestJournal

DIGEST = re.compile(r'[0-9a-f]{64}\Z')


def canonical(value: object) -> bytes:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                             allow_nan=False).encode('ascii')
    except (TypeError, ValueError, RecursionError) as error:
        raise EntireError('ci_proof', 'unsupported CI evidence') from error
    if len(encoded) > 128 * 1024:
        raise EntireError('ci_proof', 'CI evidence exceeds its bound')
    return encoded


def blocked(message: str = 'trusted source-bound CI evidence is absent or mismatched'):
    return EntireError('ci_authority', message)


@dataclass(frozen=True)
class EntireCheckAuthority:
    """Operator pins, never inferred from a check name, eval or candidate file.

    ``upstream`` is a separately qualified GitHub reader returning an exact
    {repository, branch, head} mapping. It never receives the Entire client or
    credentials. Without it mirrored merges are unsupported.
    """
    producer_id: str
    public_key: bytes
    policy_digest: str
    plan_digest: str
    required_checks: tuple[str, ...]
    upstream: Callable | None = None
    clock: Callable = time.time

    def __post_init__(self):
        if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,95}', self.producer_id)
                or not isinstance(self.public_key, bytes) or len(self.public_key) != 32
                or not DIGEST.fullmatch(self.policy_digest) or not DIGEST.fullmatch(self.plan_digest)
                or not isinstance(self.required_checks, tuple) or not 1 <= len(self.required_checks) <= 100
                or len(set(self.required_checks)) != len(self.required_checks)
                or any(not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_./-]{0,95}', name)
                       for name in self.required_checks)):
            raise blocked('invalid operator CI policy')

    def verify(self, envelope: object, target: dict, *, purpose: str = 'accepted-check') -> dict:
        if not isinstance(envelope, dict) or set(envelope) != {'payload', 'signature'}:
            raise blocked()
        if not isinstance(envelope['signature'], str) or len(envelope['signature']) != 88:
            raise blocked('CI producer signature has an unsupported shape')
        # Copy before verification: callbacks cannot mutate verified input later.
        payload = json.loads(canonical(envelope['payload']))
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.exceptions import InvalidSignature
        except ImportError as error:
            raise EntireError('unsupported', 'qualified Entire CI requires the protected cryptography profile') from error
        try:
            Ed25519PublicKey.from_public_bytes(self.public_key).verify(
                base64.b64decode(envelope['signature'], validate=True), canonical(payload))
        except (ValueError, TypeError, InvalidSignature) as error:
            raise blocked('CI producer signature does not match the operator pin') from error
        keys = {'schema_version', 'purpose', 'producer_id', 'policy_digest', 'plan_digest', 'target',
                'attempt_id', 'issued_at', 'expires_at', 'checks', 'review', 'publication'}
        if (not isinstance(payload, dict) or set(payload) != keys or type(payload['schema_version']) is not int
                or payload['schema_version'] != 1 or payload['purpose'] != purpose
                or payload['producer_id'] != self.producer_id or payload['policy_digest'] != self.policy_digest
                or payload['plan_digest'] != self.plan_digest or canonical(payload['target']) != canonical(target)
                or not isinstance(payload['attempt_id'], str)
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{7,95}', payload['attempt_id'])):
            raise blocked()
        issued, expires, now = payload['issued_at'], payload['expires_at'], self.clock()
        if (any(type(value) not in (int, float) or not math.isfinite(value) for value in (issued, expires, now))
                or not issued <= now < expires or not 0 < expires - issued <= 600):
            raise blocked('CI proof is expired or has an invalid lifetime')
        checks = payload['checks']
        if (not isinstance(checks, list) or len(checks) != len(self.required_checks)
                or any(not isinstance(item, dict) or set(item) != {'name', 'status', 'evidence_sha256'}
                       or not isinstance(item['name'], str) or item['status'] != 'passed' or not isinstance(item['evidence_sha256'], str)
                       or not DIGEST.fullmatch(item['evidence_sha256']) for item in checks)
                or sorted(item['name'] for item in checks) != sorted(self.required_checks)):
            raise blocked('the signed selected check plan is incomplete or failed')
        if canonical(payload['review']) != canonical({'head': target['head'], 'independent': True, 'status': 'passed', 'unresolved_threads': 0}):
            raise blocked('independent review or thread closure is unproved')
        if purpose == 'accepted-check':
            self.receipt(payload['publication'], payload['attempt_id'])
        elif purpose != 'verification' or payload['publication'] is not None:
            raise blocked()
        return payload

    def receipt(self, value: object, attempt: str) -> None:
        """SDK v0.3.0 UpsertResult; stale/unknown writes never create acceptance."""
        if not isinstance(value, dict) or set(value) != {'check_suite', 'results'}:
            raise blocked('publisher did not return a qualified SDK check receipt')
        suite, rows = value['check_suite'], value['results']
        if (not isinstance(suite, dict) or suite.get('key') != self.producer_id
                or suite.get('external_id') != attempt or not self._identifier(suite.get('id'))
                or not isinstance(rows, list) or len(rows) != len(self.required_checks)):
            raise blocked('publisher suite identity is unproved')
        names, ids = [], []
        for row in rows:
            run = row.get('check_run') if isinstance(row, dict) else None
            if (not isinstance(run, dict) or row.get('outcome') not in {'created', 'updated', 'unchanged'}
                    or not isinstance(run.get('key'), str) or run.get('status') != 'completed' or run.get('conclusion') != 'success'
                    or not self._identifier(run.get('id'))):
                raise blocked('check publication is stale, unknown or unsuccessful')
            names.append(run.get('key'))
            ids.append(run['id'])
        if sorted(names) != sorted(self.required_checks) or len(set(ids)) != len(ids):
            raise blocked('check publication does not cover the selected plan')

    @staticmethod
    def _identifier(value):
        return isinstance(value, str) and bool(re.fullmatch(r'[A-Za-z0-9_-]{1,128}', value))

    def upstream_head(self, repository: str, branch: str) -> str:
        if self.upstream is None:
            raise EntireError('unsupported', 'mirror merge requires a separately qualified authoritative GitHub reader')
        value = self.upstream(repository, branch)
        if (not isinstance(value, dict) or set(value) != {'repository', 'branch', 'head'}
                or value['repository'] != repository or value['branch'] != branch
                or not isinstance(value['head'], str) or not re.fullmatch(r'[0-9a-f]{40}', value['head'])):
            raise blocked('authoritative GitHub branch identity is unavailable')
        return value['head']


class EntireCheckPublisher:
    """Protected service bridge, not a CLI/user-token or candidate-side producer.

    ``upsert`` must be the operator's registered SDK v0.3.0 installation-bound
    Checks.Upsert adapter. ``sign`` is its protected producer signer. Neither
    callback is discovered/imported from repository or CLI input. A prior signed
    verification from that producer is mandatory before the SDK write.
    """
    def __init__(self, root, authority: EntireCheckAuthority, *, upsert: Callable, sign: Callable):
        self.authority, self.upsert, self.sign = authority, upsert, sign
        self.journal = RequestJournal(root)

    def publish(self, target: dict, verification: dict, request_id: str) -> dict:
        target = json.loads(canonical(target))
        payload = self.authority.verify(verification, target, purpose='verification')
        intent = {'operation': 'publish-check', 'target': target,
                  'verification_sha256': hashlib.sha256(canonical(verification)).hexdigest()}
        previous = self.journal.begin(request_id, intent)
        if previous is not None:
            self.authority.verify(previous, target)
            return previous
        try:
            # The SDK adapter receives only the exact target, selected plan,
            # producer's original timestamps and immutable attempt ID.
            receipt = self.upsert(json.loads(canonical(target)), json.loads(canonical(payload)))
            self.authority.receipt(receipt, payload['attempt_id'])
            accepted = {**payload, 'purpose': 'accepted-check', 'publication': receipt}
            result = {'payload': accepted, 'signature': base64.b64encode(self.sign(canonical(accepted))).decode('ascii')}
            self.authority.verify(result, target)
        except BaseException as error:
            self.journal.finish(request_id, intent, 'unknown', {'reason': getattr(error, 'code', 'interrupted')})
            raise
        self.journal.finish(request_id, intent, 'succeeded', result)
        return result
