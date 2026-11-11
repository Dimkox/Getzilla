"""Bounded deterministic feedback. Frozen facts are data, not authentication.

Entry points validate their own bytes. No provider/source/I/O callbacks live here.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import re

from .models import canonical_json, parse_datetime, require_digest, require_sha

BUNDLE_BYTES = 2097152
CONTROL_BYTES, CONTROL_TOTAL = 1048576, 6291456
SOURCE_BYTES = SNAPSHOT_BYTES = 33554432
MEMBER_BYTES, OUTPUT_BYTES = 16777216, 65536
AGE_SECONDS = 259200
MAX_CHECKS, MAX_SOURCES, MAX_JOBS = 64, 128, 100
_NAME = re.compile(r'[A-Za-z0-9_.:/-]{1,160}\Z')


class BundleError(ValueError):
    pass


def digest(value):
    return hashlib.sha256(canonical_json(value)).hexdigest()


def bounded_json(raw, *, maximum=CONTROL_BYTES):
    if type(raw) is not bytes or not 0 < len(raw) <= maximum:
        raise BundleError('input-size')
    try:
        text = raw.decode('utf-8', 'strict')
        depth = 0
        quoted = escaped = False
        for char in text:
            if quoted:
                if escaped:
                    escaped = False
                elif char == '\\':
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in '[{':
                depth += 1
                if depth > 24:
                    raise BundleError('input-depth')
            elif char in ']}':
                depth -= 1
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise BundleError('duplicate-key')
                result[key] = value
            return result
        def constant(_):
            raise BundleError('nonfinite-number')
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
        stack, count = [(value, 0)], 0
        while stack:
            item, level = stack.pop()
            count += 1
            if count > 32768 or level > 24:
                raise BundleError('input-complexity')
            if isinstance(item, (dict, list)):
                if len(item) > 4096:
                    raise BundleError('input-members')
                if isinstance(item, dict):
                    stack.extend((key, level + 1) for key in item)
                    stack.extend((entry, level + 1) for entry in item.values())
                else:
                    stack.extend((entry, level + 1) for entry in item)
            elif isinstance(item, str):
                if len(item) > 4096:
                    raise BundleError('input-string')
                item.encode('utf-8', 'strict')
            elif type(item) is float or type(item) is int and abs(item) > 9223372036854775807:
                raise BundleError('input-number')
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError, OverflowError) as exc:
        raise BundleError('invalid-json') from exc


def fields(value, required, optional=()):
    if type(value) is not dict or not set(required) <= set(value) <= set(required) | set(optional):
        raise BundleError('unknown-or-missing-fields')


def exact_digest(value):
    if type(value) is not str or require_digest(value, 'digest') != value:
        raise BundleError('invalid-digest')
    return value


def exact_sha(value):
    if type(value) is not str or require_sha(value, 'sha') != value:
        raise BundleError('invalid-sha')
    return value


def names(values, maximum):
    if (type(values) not in (list, tuple) or len(values) > maximum or
            any(type(item) is not str or not _NAME.fullmatch(item) for item in values) or
            len(set(values)) != len(values)):
        raise BundleError('invalid-identifiers')
    return tuple(values)


@dataclass(frozen=True)
class LocalSource:
    candidate_digest: str
    git_head: str | None = None
    git_tree: str | None = None
    mode: str = 'local'

    def as_dict(self):
        value = {'mode': self.mode, 'candidate_digest': self.candidate_digest}
        if self.git_head is not None:
            value['git'] = {'head_sha': self.git_head, 'tree_sha': self.git_tree}
        return value


@dataclass(frozen=True)
class GithubSource:
    repository: str
    repository_id: int
    pr_number: int
    target_ref: str
    base_sha: str
    head_sha: str
    tree_sha: str
    run_id: int
    run_attempt: int
    mode: str = 'github'

    def as_dict(self):
        return dict(self.__dict__)


def source_from(value):
    if type(value) is not dict:
        raise BundleError('invalid-source')
    if value.get('mode') == 'local':
        fields(value, ('mode', 'candidate_digest'), ('git',))
        exact_digest(value['candidate_digest'])
        git = value.get('git')
        if git is not None:
            fields(git, ('head_sha', 'tree_sha'))
            exact_sha(git['head_sha'])
            exact_sha(git['tree_sha'])
        return LocalSource(value['candidate_digest'], git['head_sha'] if git else None, git['tree_sha'] if git else None)
    fields(value, ('mode', 'repository', 'repository_id', 'pr_number', 'target_ref', 'base_sha', 'head_sha', 'tree_sha', 'run_id', 'run_attempt'))
    if value['mode'] != 'github' or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', value['repository']):
        raise BundleError('invalid-source')
    for key in ('repository_id', 'pr_number', 'run_id', 'run_attempt'):
        if type(value[key]) is not int or not 0 < value[key] <= 9223372036854775807:
            raise BundleError('invalid-provider-id')
    for key in ('base_sha', 'head_sha', 'tree_sha'):
        exact_sha(value[key])
    if value['target_ref'] != 'refs/heads/main':
        raise BundleError('unsupported-target')
    return GithubSource(**value)


@dataclass(frozen=True)
class BundlePolicy:
    policy_digest: str
    public_key_pem: bytes = b''
    authority_digest: str | None = None
    required_jobs: tuple = ()


@dataclass(frozen=True)
class Requirement:
    name: str
    required: bool
    source_ids: tuple
    coverage_digest: str


@dataclass(frozen=True)
class ValidationFacts:
    source_digest: str
    policy_digest: str
    report_digest: str
    inventory_digest: str
    required: tuple
    sources: tuple
    blockers: tuple
    source_validated: bool
    integration_digest: str | None = None
    integration_validated: bool = False
    content_digest: str | None = None
    snapshot_digest: str | None = None


@dataclass(frozen=True)
class ValidatedSource:
    source_id: str
    content_digest: str
    acquired_at: str
    validated: bool


@dataclass(frozen=True)
class ObservedState:
    mode: str
    source_digest: str
    validated: bool = False
    authority_digest: str | None = None
    jobs: tuple = ()
    blockers: tuple = ()


@dataclass(frozen=True)
class SecurityBundle:
    raw: bytes

    @property
    def source(self):
        return source_from(bounded_json(self.raw, maximum=BUNDLE_BYTES)['source'])

    def document(self):
        return bounded_json(self.raw, maximum=BUNDLE_BYTES)


@dataclass(frozen=True)
class BundleDecision:
    consistent: bool
    reasons: tuple
    provenance: str = 'local-feedback'
    external_eligible: bool = False


def parse_bundle(raw):
    value = bounded_json(raw, maximum=BUNDLE_BYTES)
    fields(value, ('version', 'source', 'policy_sha256', 'report', 'binding', 'integration'))
    if type(value['version']) is not int or value['version'] != 1:
        raise BundleError('unsupported-version')
    source_from(value['source'])
    exact_digest(value['policy_sha256'])
    report = value['report']
    fields(report, ('inventory_sha256', 'created_at', 'valid_until', 'checks'), ('evidence_sha256',))
    if 'evidence_sha256' in report:
        exact_digest(report['evidence_sha256'])
    exact_digest(report['inventory_sha256'])
    for key in ('created_at', 'valid_until'):
        if type(report[key]) is not str:
            raise BundleError('invalid-time')
        parse_datetime(report[key])
    if type(report['checks']) is not list or not 1 <= len(report['checks']) <= MAX_CHECKS:
        raise BundleError('invalid-checks')
    seen = []
    for check in report['checks']:
        fields(check, ('name', 'status', 'outcome', 'finding_count', 'gap_count', 'source_ids', 'coverage_sha256'))
        names([check['name']], 1)
        names(check['source_ids'], MAX_SOURCES)
        exact_digest(check['coverage_sha256'])
        if check['status'] not in ('pass', 'skip', 'fail', 'blocked') or check['outcome'] not in ('pass', 'not_applicable', 'fail', 'blocked'):
            raise BundleError('invalid-outcome')
        for key in ('finding_count', 'gap_count'):
            if type(check[key]) is not int or not 0 <= check[key] <= 32768:
                raise BundleError('invalid-findings')
        seen.append(check['name'])
    names(seen, MAX_CHECKS)
    if value['binding'] is not None:
        fields(value['binding'], ('payload', 'signature'))
        fields(value['binding']['payload'], ('version', 'kind', 'source_sha256', 'report_sha256', 'policy_sha256',
                                             'authority_sha256', 'issued_at', 'expires_at', 'integration_sha256'))
        if type(value['binding']['signature']) is not str or len(value['binding']['signature']) > 256:
            raise BundleError('invalid-signature')
    if value['integration'] is not None:
        fields(value['integration'], ('merge_sha', 'tree_sha', 'parents', 'strategy'))
        exact_sha(value['integration']['merge_sha'])
        exact_sha(value['integration']['tree_sha'])
        if value['integration']['strategy'] != 'merge' or type(value['integration']['parents']) is not list or len(value['integration']['parents']) != 2:
            raise BundleError('invalid-integration')
        for parent in value['integration']['parents']:
            exact_sha(parent)
    return SecurityBundle(canonical_json(value))


def _age(value, now):
    return 0 <= (now - parse_datetime(value)).total_seconds() <= AGE_SECONDS


def _binding(policy, source, value, now):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    binding = value['binding']
    if not binding or not policy.public_key_pem or not policy.authority_digest:
        return False
    payload = binding['payload']
    expected = {'version': 1, 'kind': 'getzilla-security-bundle-binding', 'source_sha256': digest(source.as_dict()),
                'report_sha256': digest(value['report']), 'policy_sha256': policy.policy_digest,
                'authority_sha256': policy.authority_digest, 'issued_at': payload['issued_at'],
                'expires_at': payload['expires_at'], 'integration_sha256': digest(value['integration'])}
    if payload != expected or not _age(payload['issued_at'], now):
        return False
    issued, expires = parse_datetime(payload['issued_at']), parse_datetime(payload['expires_at'])
    if not now <= expires or not 0 <= (expires - issued).total_seconds() <= AGE_SECONDS:
        return False
    try:
        key = serialization.load_pem_public_key(policy.public_key_pem)
        if not isinstance(key, Ed25519PublicKey):
            return False
        key.verify(base64.b64decode(binding['signature'], validate=True), canonical_json(payload))
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


def evaluate_bundle(policy, source, evidence, observed, facts, *, now):
    """Explicit data only. A consistent result never authorizes an external effect."""
    try:
        if (type(policy) is not BundlePolicy or type(evidence) is not SecurityBundle or
                type(observed) is not ObservedState or type(facts) is not ValidationFacts):
            return BundleDecision(False, ('invalid-input-types',))
        if type(now) is not datetime or now.tzinfo is None or now.utcoffset() is None:
            return BundleDecision(False, ('clock-unavailable',))
        parsed = parse_bundle(evidence.raw)
        value = parsed.document()
        if type(source) not in (LocalSource, GithubSource) or source != parsed.source:
            return BundleDecision(False, ('source-mismatch',))
        exact_digest(policy.policy_digest)
        if (facts.source_validated is not True or facts.blockers or facts.source_digest != digest(source.as_dict()) or
                facts.report_digest != digest(value['report']) or facts.policy_digest != policy.policy_digest or
                value['policy_sha256'] != policy.policy_digest or facts.inventory_digest != value['report']['inventory_sha256']):
            return BundleDecision(False, ('validation-or-binding-mismatch',))
        report = value['report']
        created, expires = parse_datetime(report['created_at']), parse_datetime(report['valid_until'])
        if not _age(report['created_at'], now) or not now <= expires or not 0 <= (expires - created).total_seconds() <= AGE_SECONDS:
            return BundleDecision(False, ('report-freshness',))
        if (type(facts.required) is not tuple or not 1 <= len(facts.required) <= MAX_CHECKS or
                any(type(row) is not Requirement or type(row.source_ids) is not tuple for row in facts.required) or
                type(facts.sources) is not tuple or any(type(row) is not ValidatedSource for row in facts.sources)):
            return BundleDecision(False, ('coverage-unavailable',))
        names([row.name for row in facts.required], MAX_CHECKS)
        supplied = {row['name']: row for row in report['checks']}
        if set(supplied) != {row.name for row in facts.required}:
            return BundleDecision(False, ('check-coverage',))
        names([row.source_id for row in facts.sources], MAX_SOURCES)
        for row in facts.sources:
            exact_digest(row.content_digest)
            if row.validated is not True or not _age(row.acquired_at, now):
                return BundleDecision(False, ('source-freshness-or-validation',))
        available = {row.source_id for row in facts.sources}
        for row in facts.required:
            names(row.source_ids, MAX_SOURCES)
            check = supplied[row.name]
            expected = ('pass', 'pass') if row.required is True else ('skip', 'not_applicable')
            if (type(row.required) is not bool or (check['status'], check['outcome']) != expected or
                    check['finding_count'] != 0 or check['gap_count'] != 0 or
                    set(check['source_ids']) != set(row.source_ids) or not set(row.source_ids) <= available or
                    check['coverage_sha256'] != row.coverage_digest or row.coverage_digest != facts.inventory_digest):
                return BundleDecision(False, ('check-outcome-or-coverage',))
        if observed.source_digest != facts.source_digest or observed.mode != source.mode or observed.blockers:
            return BundleDecision(False, ('observation-mismatch',))
        if value['integration'] is not None and (facts.integration_validated is not True or facts.integration_digest != digest(value['integration'])):
            return BundleDecision(False, ('integration-unverified',))
        if source.mode == 'github':
            if (observed.validated is not True or observed.authority_digest != policy.authority_digest or
                    not policy.required_jobs or set(observed.jobs) != set(policy.required_jobs) or
                    len(observed.jobs) != len(set(observed.jobs)) or value['integration'] is None or
                    value['integration']['parents'] != [source.base_sha, source.head_sha] or not _binding(policy, source, value, now)):
                return BundleDecision(False, ('provider-binding-or-integration-unverified',))
        return BundleDecision(True, ())
    except (BundleError, ValueError, TypeError, KeyError, AttributeError, OverflowError):
        return BundleDecision(False, ('invalid-input',))
