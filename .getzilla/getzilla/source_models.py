"""Zero-Git project ingestion contracts: source-baseline-v1, admission-plan-v1, adoption-receipt-v1.

Immutable records shared by inventory, admission, snapshot, shadow Git and adoption. Source
content identity (SHA-256 over admitted bytes) and Git identity (commit/tree OIDs in a declared
object format) are separate fields: no record derives one from the other, and no record carries
plaintext source contents or secret material.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Mapping

SHA256_HEX = re.compile(r'^[0-9a-f]{64}$')
GIT_OID = {'sha1': re.compile(r'^[0-9a-f]{40}$'), 'sha256': re.compile(r'^[0-9a-f]{64}$')}
OPERATION_ID = re.compile(r'^op-[0-9a-f]{32}$')

BASELINE_SCHEMA = 'source-baseline-v1'
PLAN_SCHEMA = 'admission-plan-v1'
RECEIPT_SCHEMA = 'adoption-receipt-v1'
PATH_PROFILES = frozenset({'portable-v1'})
EXECUTABLE_MODES = frozenset({'posix-mode', 'policy-manifest'})
SCAN_STATUSES = frozenset({'pass', 'fail', 'error', 'not_run'})
PLAN_STATUSES = frozenset({'PLAN_READY', 'BLOCKED_SECURITY', 'BLOCKED_UNSAFE_SOURCE',
                           'BLOCKED_UNSUPPORTED_FS', 'STALE_PLAN', 'ERROR'})
STATES = (
    'DETECTED', 'INVENTORIED', 'SECURITY_SCREENED', 'PLAN_READY', 'SNAPSHOT_VERIFIED',
    'SHADOW_MATERIALIZED', 'GIT_INITIALIZED', 'SOURCE_BASELINE_COMMITTED', 'GETZILLA_PLANNED',
    'MANAGED_LAYER_COMMITTED', 'INTEGRITY_VERIFIED', 'PUBLISHED_LOCAL',
)
TERMINAL_ERRORS = frozenset({'BLOCKED_SECURITY', 'BLOCKED_UNSAFE_SOURCE', 'BLOCKED_UNSUPPORTED_FS',
                             'STALE_PLAN', 'ERROR', 'ABORTED'})
HEALTH_STATUSES = frozenset({'not_run', 'pass', 'fail', 'unknown'})
INTEGRITY_STATUSES = frozenset({'verified', 'failed', 'not_verified'})
CONSISTENCY_MODES = frozenset({'quiesced_two_pass'})


class ContractError(ValueError):
    """A record violates its schema contract."""


def canonical_json(value: Any) -> bytes:
    """UTF-8 JSON with sorted keys and no insignificant whitespace; floats are refused."""
    def check(item: Any) -> None:
        if isinstance(item, float):
            raise ContractError('floats are not allowed in canonical records')
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ContractError('canonical record keys must be strings')
                check(child)
        elif isinstance(item, (list, tuple)):
            for child in item:
                check(child)
    check(value)
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')


def domain_digest(domain: str, value: Any) -> str:
    return hashlib.sha256(domain.encode('ascii') + b'\n' + canonical_json(value)).hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _sha256(value: Any, name: str) -> str:
    _require(isinstance(value, str) and bool(SHA256_HEX.fullmatch(value)), f'{name} must be a lowercase SHA-256 hex digest')
    return value


def _positive(value: Any, name: str) -> int:
    _require(type(value) is int and value > 0, f'{name} must be a positive integer')
    return value


@dataclass(frozen=True)
class SourceEntry:
    path: str
    executable: bool
    size: int
    sha256: str
    type: str = 'file'

    def __post_init__(self) -> None:
        _require(self.type == 'file', 'source-baseline-v1 entries are regular files')
        _require(isinstance(self.path, str) and bool(self.path), 'entry path must be a non-empty string')
        _require(type(self.executable) is bool, 'executable must be a boolean')
        _require(type(self.size) is int and self.size >= 0, 'size must be a non-negative integer')
        _sha256(self.sha256, 'entry sha256')

    def to_dict(self) -> dict[str, Any]:
        return {'path': self.path, 'type': self.type, 'executable': self.executable,
                'size': self.size, 'sha256': self.sha256}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SourceEntry:
        _require(set(data) == {'path', 'type', 'executable', 'size', 'sha256'}, 'entry fields are exact')
        return cls(path=data['path'], executable=data['executable'], size=data['size'],
                   sha256=data['sha256'], type=data['type'])


@dataclass(frozen=True)
class Finding:
    """A redacted problem: where and which rule, never the matched bytes or their hash."""
    path: str
    reason_code: str
    rule_id: str | None = None
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        record: dict[str, Any] = {'path': self.path, 'reason_code': self.reason_code}
        if self.rule_id is not None:
            record['rule_id'] = self.rule_id
        if self.line is not None:
            record['line'] = self.line
        return record


@dataclass(frozen=True)
class Exclusion:
    path: str
    reason_code: str
    policy_ref: str

    def to_dict(self) -> dict[str, Any]:
        return {'path': self.path, 'reason_code': self.reason_code, 'policy_ref': self.policy_ref}


@dataclass(frozen=True)
class FalsePositiveException:
    """Owner-approved narrow exception: one rule, one path, one exact file digest."""
    path: str
    rule_id: str
    sha256: str

    def __post_init__(self) -> None:
        _sha256(self.sha256, 'exception sha256')
        _require(bool(self.rule_id) and self.rule_id != '*', 'an exception names exactly one rule')

    def to_dict(self) -> dict[str, Any]:
        return {'path': self.path, 'rule_id': self.rule_id, 'sha256': self.sha256}


@dataclass(frozen=True)
class IngestPolicy:
    max_file_bytes: int = 16 * 1024 * 1024
    max_files: int = 100_000
    max_total_bytes: int = 2 * 1024 * 1024 * 1024
    max_depth: int = 64
    max_buffered_file_bytes: int = 16 * 1024 * 1024
    max_total_buffer_bytes: int = 64 * 1024 * 1024
    exclude: tuple[str, ...] = ()
    exceptions: tuple[FalsePositiveException, ...] = ()
    path_profile: str = 'portable-v1'
    executable_mode: str = 'posix-mode'
    executable_paths: tuple[str, ...] = ()
    allow_sensitive_example_files: bool = True

    def __post_init__(self) -> None:
        for name in ('max_file_bytes', 'max_files', 'max_total_bytes', 'max_depth',
                     'max_buffered_file_bytes', 'max_total_buffer_bytes'):
            _positive(getattr(self, name), name)
        _require(self.max_buffered_file_bytes <= self.max_total_buffer_bytes,
                 'max_buffered_file_bytes cannot exceed max_total_buffer_bytes')
        _require(self.path_profile in PATH_PROFILES, f'unsupported path profile: {self.path_profile}')
        _require(self.executable_mode in EXECUTABLE_MODES, f'unsupported executable mode: {self.executable_mode}')
        for pattern in self.exclude:
            _require(isinstance(pattern, str) and pattern not in {'', '*', '**', '**/*'},
                     'exclusions are explicit patterns, never a global ignore')

    def to_dict(self) -> dict[str, Any]:
        return {
            'max_file_bytes': self.max_file_bytes, 'max_files': self.max_files,
            'max_total_bytes': self.max_total_bytes, 'max_depth': self.max_depth,
            'max_buffered_file_bytes': self.max_buffered_file_bytes,
            'max_total_buffer_bytes': self.max_total_buffer_bytes,
            'exclude': sorted(self.exclude), 'exceptions': [item.to_dict() for item in self.exceptions],
            'path_profile': self.path_profile, 'executable_mode': self.executable_mode,
            'executable_paths': sorted(self.executable_paths),
            'allow_sensitive_example_files': self.allow_sensitive_example_files,
        }

    def digest(self) -> str:
        return domain_digest('getzilla-ingest-policy-v1', self.to_dict())

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> IngestPolicy:
        known = set(cls().to_dict())
        unknown = set(data) - known
        _require(not unknown, f'unknown policy fields: {sorted(unknown)}')
        values = dict(data)
        values['exclude'] = tuple(values.get('exclude', ()))
        values['executable_paths'] = tuple(values.get('executable_paths', ()))
        values['exceptions'] = tuple(FalsePositiveException(**item) for item in values.get('exceptions', ()))
        return cls(**values)


@dataclass(frozen=True)
class FilesystemCapabilities:
    platform: str
    nofollow_reads: bool
    link_detection: bool
    hardlink_detection: bool
    atomic_no_replace_publish: bool
    case_collisions: str = 'blocked'
    notes: tuple[str, ...] = ()

    @property
    def strict_supported(self) -> bool:
        return self.nofollow_reads and self.link_detection and self.hardlink_detection and self.atomic_no_replace_publish

    def to_dict(self) -> dict[str, Any]:
        return {'platform': self.platform, 'nofollow_reads': self.nofollow_reads,
                'link_detection': self.link_detection, 'hardlink_detection': self.hardlink_detection,
                'atomic_no_replace_publish': self.atomic_no_replace_publish,
                'case_collisions': self.case_collisions, 'strict_supported': self.strict_supported,
                'notes': list(self.notes)}


@dataclass(frozen=True)
class SourceInventory:
    entries: tuple[SourceEntry, ...]
    excluded: tuple[Exclusion, ...]
    blockers: tuple[Finding, ...]
    capabilities: FilesystemCapabilities
    empty_directories: int = 0
    observed_mutation: bool = False

    @property
    def complete(self) -> bool:
        return not self.blockers and not self.observed_mutation

    def to_dict(self) -> dict[str, Any]:
        return {'entries': [entry.to_dict() for entry in self.entries],
                'excluded': [item.to_dict() for item in self.excluded],
                'blockers': [item.to_dict() for item in self.blockers],
                'capabilities': self.capabilities.to_dict(),
                'empty_directories': self.empty_directories,
                'observed_mutation': self.observed_mutation}


@dataclass(frozen=True)
class ScanReport:
    status: str
    scanner: str
    scanner_version: str
    rules_digest: str
    files_scanned: int
    bytes_scanned: int
    findings: tuple[Finding, ...] = ()
    unsupported: tuple[Finding, ...] = ()
    errors: tuple[Finding, ...] = ()
    candidates: int = 0

    def __post_init__(self) -> None:
        _require(self.status in SCAN_STATUSES, f'unknown scan status: {self.status}')
        _sha256(self.rules_digest, 'rules_digest')
        if self.status == 'pass':
            _require(not self.findings and not self.unsupported and not self.errors,
                     'a passing scan has no findings, unsupported inputs or errors')
            _require(self.files_scanned == self.candidates, 'a passing scan covered every candidate')

    def to_dict(self) -> dict[str, Any]:
        return {'status': self.status, 'scanner': self.scanner, 'scanner_version': self.scanner_version,
                'rules_digest': self.rules_digest, 'files_scanned': self.files_scanned,
                'bytes_scanned': self.bytes_scanned, 'candidates': self.candidates,
                'findings': [item.to_dict() for item in self.findings],
                'unsupported': [item.to_dict() for item in self.unsupported],
                'errors': [item.to_dict() for item in self.errors]}


@dataclass(frozen=True)
class GitIdentity:
    object_format: str
    commit_oid: str | None = None
    tree_oid: str | None = None

    def __post_init__(self) -> None:
        _require(self.object_format in GIT_OID, f'unsupported Git object format: {self.object_format}')
        _require((self.commit_oid is None) == (self.tree_oid is None), 'commit and tree OIDs come together')
        pattern = GIT_OID[self.object_format]
        for value in (self.commit_oid, self.tree_oid):
            _require(value is None or bool(pattern.fullmatch(value)), f'OID is not a {self.object_format} object id')

    def to_dict(self) -> dict[str, Any]:
        return {'object_format': self.object_format, 'commit_oid': self.commit_oid, 'tree_oid': self.tree_oid}


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class AdmissionPlan:
    """Immutable read-only plan; `plan_id` is the digest of every other field."""
    status: str
    source_root: str
    target: str
    source_digest: str | None
    path_profile: str
    executable_mode: str
    entries: tuple[SourceEntry, ...]
    exclusions: tuple[Exclusion, ...]
    blockers: tuple[Finding, ...]
    policy: Mapping[str, Any]
    policy_digest: str
    scan: Mapping[str, Any]
    capabilities: Mapping[str, Any]
    consistency_mode: str = 'quiesced_two_pass'
    plan_id: str = field(default='')

    def body(self) -> dict[str, Any]:
        return {
            'schema_version': PLAN_SCHEMA, 'status': self.status, 'source_root': self.source_root,
            'target': self.target, 'source_digest': self.source_digest, 'path_profile': self.path_profile,
            'executable_mode': self.executable_mode,
            'entries': [entry.to_dict() for entry in self.entries],
            'exclusions': [item.to_dict() for item in self.exclusions],
            'blockers': [item.to_dict() for item in self.blockers],
            'policy': dict(self.policy), 'policy_digest': self.policy_digest, 'scan': dict(self.scan),
            'capabilities': dict(self.capabilities), 'consistency_mode': self.consistency_mode,
        }

    def compute_id(self) -> str:
        return domain_digest('getzilla-admission-plan-v1', self.body())

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), 'plan_id': self.plan_id}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AdmissionPlan:
        _require(data.get('schema_version') == PLAN_SCHEMA, 'unknown plan schema')
        plan = cls(
            status=data['status'], source_root=data['source_root'], target=data['target'],
            source_digest=data['source_digest'], path_profile=data['path_profile'],
            executable_mode=data['executable_mode'],
            entries=tuple(SourceEntry.from_dict(item) for item in data['entries']),
            exclusions=tuple(Exclusion(**item) for item in data['exclusions']),
            blockers=tuple(Finding(**item) for item in data['blockers']),
            policy=data['policy'], policy_digest=data['policy_digest'], scan=data['scan'],
            capabilities=data['capabilities'], consistency_mode=data['consistency_mode'],
            plan_id=data['plan_id'],
        )
        _require(plan.plan_id == plan.compute_id(), 'plan_id does not match the plan contents')
        return plan


def validate_source_record(record: Mapping[str, Any]) -> ValidationResult:
    """Validate a baseline, plan or adoption receipt record against its v1 contract."""
    errors: list[str] = []

    def check(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    schema = record.get('schema_version') if isinstance(record, Mapping) else None
    if schema == BASELINE_SCHEMA:
        check(record.get('path_profile') in PATH_PROFILES, 'unknown path profile')
        check(record.get('executable_mode') in EXECUTABLE_MODES, 'unknown executable mode')
        entries = record.get('entries')
        check(isinstance(entries, list), 'entries must be a list')
        for item in entries if isinstance(entries, list) else ():
            try:
                SourceEntry.from_dict(item)
            except (ContractError, TypeError, KeyError) as exc:
                errors.append(f'entry: {exc}')
        check('content' not in record, 'a baseline never carries file contents')
    elif schema == PLAN_SCHEMA:
        try:
            plan = AdmissionPlan.from_dict(record)
        except (ContractError, KeyError, TypeError) as exc:
            errors.append(f'plan: {exc}')
        else:
            check(plan.status in PLAN_STATUSES, 'unknown plan status')
            if plan.status == 'PLAN_READY':
                check(plan.scan.get('status') == 'pass', 'a ready plan needs a passing scan')
                check(not plan.blockers, 'a ready plan has no blockers')
                check(plan.source_digest is not None, 'a ready plan has a source digest')
                check(bool(plan.entries), 'a ready plan admits at least one file')
            check(plan.consistency_mode in CONSISTENCY_MODES, 'unknown consistency mode')
            limits = plan.policy
            for name in ('max_buffered_file_bytes', 'max_total_buffer_bytes'):
                check(type(limits.get(name)) is int and limits.get(name, 0) > 0, f'{name} must be positive')
    elif schema == RECEIPT_SCHEMA:
        state = record.get('state')
        check(state in STATES or state in TERMINAL_ERRORS, 'unknown adoption state')
        check(bool(OPERATION_ID.fullmatch(str(record.get('operation_id', '')))), 'operation_id is malformed')
        git = record.get('source_baseline') or {}
        committed = state in STATES and STATES.index(state) >= STATES.index('SOURCE_BASELINE_COMMITTED')
        try:
            identity = GitIdentity(**git) if git else None
        except (ContractError, TypeError) as exc:
            errors.append(f'git identity: {exc}')
            identity = None
        if committed:
            check(identity is not None and identity.commit_oid is not None, 'a committed state needs the source commit OID')
        digest = record.get('source_digest')
        check(digest is None or bool(SHA256_HEX.fullmatch(str(digest))), 'source_digest is SHA-256, not a Git OID')
        check(record.get('project_health_status', 'not_run') in HEALTH_STATUSES, 'unknown project health status')
        check(record.get('integrity_status', 'not_verified') in INTEGRITY_STATUSES, 'unknown integrity status')
        check(record.get('git_present_at_ingest') is False, 'Zero-Git receipts record git_present_at_ingest=false')
    else:
        errors.append(f'unknown schema: {schema!r}')
    return ValidationResult(not errors, tuple(errors))
