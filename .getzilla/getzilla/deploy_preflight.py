"""Bounded local deployment observations. Nothing in this module grants execution."""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from . import fsx
from ._policy_legacy import DEFAULT_SECRET_READ, _secret_path_match, consumer_secret_paths
from .component_state import BoundRoot, ComponentStateError, FileSnapshot, path_parts
from .source_admission import sensitive_class

SCHEMA_REVISION = 'getzilla-deploy-preflight-v1'
ALGORITHM_REVISION = 'getzilla-deploy-preflight-algorithm-v1'
POLICY_PATH = '.getzilla/config/project-policy.json'
MAX_INPUT_BYTES = 65536
MAX_ARTIFACTS = 128
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
TTL_SECONDS = 300
WORK_SECONDS = 10
_MAX_EPOCH = 253402300799
DIAGNOSTICS = frozenset({
    'INPUT_INVALID', 'INPUT_TOO_LARGE', 'PATH_UNSAFE', 'FILE_MISSING', 'FILE_UNSAFE',
    'FILE_CHANGED', 'HASH_MISMATCH', 'MODE_MISMATCH', 'MODE_UNSUPPORTED', 'POLICY_MISSING',
    'POLICY_INVALID', 'CONSUMER_UNREGISTERED', 'BUDGET_EXCEEDED', 'ROOT_CHANGED',
    'ALGORITHM_CHANGED', 'CLOCK_UNCERTAIN', 'OBSERVATION_EXPIRED', 'OBSERVATION_CHANGED',
    'PROVENANCE_UNVERIFIED', 'RECOVERY_UNVERIFIED', 'INTERNAL_ERROR',
})
_IDENTIFIER = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}')
_SHA256 = re.compile(r'[0-9a-f]{64}')
Revision = tuple[str, str | None, str | None, str | None]


class PreflightError(ValueError):
    """Only fixed diagnostics cross this boundary, never underlying exceptions."""

    def __init__(self, code: str) -> None:
        self.code = code if type(code) is str and code in DIAGNOSTICS else 'INTERNAL_ERROR'
        super().__init__(self.code)


@dataclass(frozen=True, repr=False)
class FileExpectation:
    path: str
    sha256: str
    mode: int
    revision: Revision | None = None


@dataclass(frozen=True, repr=False)
class DeployManifest:
    project_id: str
    operation: str
    operator: FileExpectation
    artifacts: tuple[FileExpectation, ...]
    artifact_revision: Revision
    target: tuple[str, str, str]
    credential_selector: str
    recovery: tuple[str, str, str]


def _fail(code: str = 'INPUT_INVALID') -> None:
    raise PreflightError(code) from None


def _clean_text(value: object, maximum: int) -> bool:
    return (type(value) is str and 0 < len(value) <= maximum
            and not any(ord(c) < 32 or 127 <= ord(c) <= 159 or 0xD800 <= ord(c) <= 0xDFFF for c in value))


def _object(value: object, keys: set[str]) -> dict:
    if type(value) is not dict or value.keys() != keys:
        _fail()
    return value


def _identifier(value: object) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        _fail()
    return value


def _sha256(value: object) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        _fail()
    return value


def _strict_json(raw: bytes, *, invalid: str = 'INPUT_INVALID', allow_floats: bool = False) -> object:
    if type(raw) is not bytes:
        _fail(invalid)
    if len(raw) > MAX_INPUT_BYTES:
        _fail('INPUT_TOO_LARGE')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                _fail(invalid)
            result[key] = value
        return result
    def invalid_number(_value):
        _fail(invalid)
    def finite_float(value):
        parsed = float(value)
        if not math.isfinite(parsed):
            _fail(invalid)
        return parsed
    try:
        text = raw.decode('utf-8')
        # Limit nesting before json.loads recurses, ignoring quoted/escaped braces.
        depth, quoted, escaped = 0, False, False
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
            elif char in '{[':
                depth += 1
                if depth > 8:
                    _fail(invalid)
            elif char in '}]':
                depth -= 1
        return json.loads(text, object_pairs_hook=unique, parse_float=finite_float if allow_floats else invalid_number,
                          parse_constant=invalid_number)
    except (UnicodeError, ValueError, RecursionError):
        _fail(invalid)


def _public_path(value: object) -> str:
    if not _clean_text(value, 1024):
        _fail('PATH_UNSAFE')
    try:
        parts = path_parts(value)
    except ComponentStateError:
        _fail('PATH_UNSAFE')
    if (len(parts) > 32 or any(part.casefold() == '.git' for part in parts)
            or any(char in value for char in '*?"<>|')
            or any(sensitive_class('/'.join(parts[:i]), allow_examples=False)
                   or _secret_path_match('/'.join(parts[:i]), DEFAULT_SECRET_READ)
                   for i in range(1, len(parts) + 1))):
        _fail('PATH_UNSAFE')
    return value


def _overlap(first: str, second: str) -> bool:
    a, b = _fold(first.split('/')), _fold(second.split('/'))
    return a[:len(b)] == b or b[:len(a)] == a


def _distinct(paths: tuple[str, ...]) -> None:
    for index, path in enumerate(paths):
        if any(_overlap(path, previous) for previous in paths[:index]):
            _fail('PATH_UNSAFE')


def _revision(value: object) -> Revision:
    data = _object(value, {'label', 'git'})
    label = _identifier(data['label'])
    if data['git'] is None:
        return (label, None, None, None)
    git = _object(data['git'], {'object_format', 'commit_oid', 'tree_oid'})
    fmt = git['object_format']
    if type(fmt) is not str or fmt not in {'sha1', 'sha256'}:
        _fail()
    size = 40 if fmt == 'sha1' else 64
    for key in ('commit_oid', 'tree_oid'):
        if type(git[key]) is not str or re.fullmatch('[0-9a-f]{' + str(size) + '}', git[key]) is None:
            _fail()
    return (label, fmt, git['commit_oid'], git['tree_oid'])


def _file(value: object, *, operator: bool = False) -> FileExpectation:
    keys = {'path', 'sha256', 'mode'} | ({'revision'} if operator else set())
    data = _object(value, keys)
    if type(data['mode']) is not int or not 0 <= data['mode'] <= 511:
        _fail()
    return FileExpectation(_public_path(data['path']), _sha256(data['sha256']), data['mode'],
                           _revision(data['revision']) if operator else None)


def parse_manifest(raw: bytes) -> DeployManifest:
    """Parse bounded declarations only; no filesystem, environment or policy access."""
    data = _object(_strict_json(raw), {'schema_version', 'project_id', 'operation', 'operator', 'artifacts',
                                     'artifact_revision', 'target', 'credential_selector', 'recovery'})
    if data['schema_version'] != SCHEMA_REVISION or data['operation'] != 'dev-delivery':
        _fail()
    if type(data['artifacts']) is not list or not 1 <= len(data['artifacts']) <= MAX_ARTIFACTS:
        _fail()
    operator = _file(data['operator'], operator=True)
    artifacts = tuple(_file(value) for value in data['artifacts'])
    _distinct((POLICY_PATH, operator.path, *(item.path for item in artifacts)))
    target = _object(data['target'], {'identity', 'destination_id', 'transport'})
    if type(target['transport']) is not str or target['transport'] not in {'ssh-sftp', 'local-fixture'}:
        _fail()
    recovery = _object(data['recovery'], {'protocol_id', 'version', 'descriptor_sha256'})
    if not _clean_text(data['credential_selector'], 4096):
        _fail()
    return DeployManifest(
        _identifier(data['project_id']), 'dev-delivery', operator, artifacts, _revision(data['artifact_revision']),
        (_identifier(target['identity']), _identifier(target['destination_id']), target['transport']),
        data['credential_selector'],
        (_identifier(recovery['protocol_id']), _identifier(recovery['version']), _sha256(recovery['descriptor_sha256'])),
    )


def _fold(parts) -> tuple[str, ...]:
    return tuple(unicodedata.normalize('NFC', part).casefold() for part in parts)


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=True, sort_keys=True,
                                    separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def _policy(raw: bytes) -> list[dict]:
    data = _strict_json(raw, invalid='POLICY_INVALID', allow_floats=True)
    if type(data) is not dict:
        _fail('POLICY_INVALID')
    records = data.get('secret_consumers')
    if type(records) is not list or len(records) > 64:
        _fail('POLICY_INVALID')
    for item in records:
        if (type(item) is not dict or not _clean_text(item.get('script'), 4096)
                or type(item.get('secrets')) is not list or len(item['secrets']) > 64
                or any(not _clean_text(secret, 4096) for secret in item['secrets'])):
            _fail('POLICY_INVALID')
    return records


def _lexical_parts(path: str) -> tuple[str, ...]:
    result: list[str] = []
    for part in path.split('/'):
        if part in {'', '.'}:
            continue
        if part == '..':
            if result:
                result.pop()
        else:
            result.append(part)
    return _fold(result)


def _selector_aliases(selectors: tuple[str, ...], roots: tuple[str, ...]) -> tuple[tuple[str, ...], ...]:
    """Conservative lexical exclusions only. Never resolve or inspect a selector."""
    bases = tuple(_lexical_parts(root) for root in roots)
    aliases = set()
    for selector in selectors:
        value = selector.replace('\\', '/')
        if (not _clean_text(value, 4096) or value.startswith('//')
                or any(char in value for char in ':~$%*?[]{}')):
            _fail('PATH_UNSAFE')
        candidates = (value,) if value.startswith('/') else tuple(root + '/' + value for root in roots)
        for candidate in candidates:
            parts = _lexical_parts(candidate)
            for base in bases:
                if parts[:len(base)] == base:
                    aliases.add(parts[len(base):])
    return tuple(sorted(aliases))


def _exclude_aliases(paths: tuple[str, ...], selectors: tuple[str, ...], roots: tuple[str, ...]) -> None:
    aliases = _selector_aliases(selectors, roots)
    for path in paths:
        parts = _fold(path.split('/'))
        if any(parts[:len(alias)] == alias or alias[:len(parts)] == parts for alias in aliases):
            _fail('PATH_UNSAFE')


def _script_matches(listed: str, operator: str) -> bool:
    try:
        return _public_path(listed) == operator
    except PreflightError:
        return False


@dataclass(frozen=True, repr=False)
class DeploymentObservation:
    """In-memory consistency record; not authenticated and never deserialized."""
    schema_revision: str
    algorithm_revision: str
    root_identity: tuple[int, int, int]
    manifest_path_digest: str
    inputs_digest: str
    registration: str
    issued_at: int
    expires_at: int
    digest: str


@dataclass(frozen=True, repr=False)
class PreflightReport:
    state: str
    observation_digest: str | None
    issued_at: int | None
    expires_at: int | None
    package: str
    registration: str
    recovery: str
    diagnostics: tuple[str, ...]

    @classmethod
    def blocked(cls, code: str) -> PreflightReport:
        safe = code if type(code) is str and code in DIAGNOSTICS else 'INTERNAL_ERROR'
        registration = ('missing' if safe in {'POLICY_MISSING', 'CONSUMER_UNREGISTERED'} else
                        'invalid' if safe == 'POLICY_INVALID' else 'not_evaluated')
        return cls('blocked', None, None, None, 'blocked', registration, 'not_evaluated',
                   (safe, 'PROVENANCE_UNVERIFIED', 'RECOVERY_UNVERIFIED'))

    def to_dict(self) -> dict[str, object]:
        # Callers cannot turn a constructed/tampered report into arbitrary output.
        valid = (type(self) is PreflightReport
                 and type(self.state) is str and self.state in {'ready_for_review', 'blocked'}
                 and type(self.package) is str and self.package in {'matched', 'blocked', 'not_evaluated'}
                 and type(self.registration) is str and self.registration in {'matched', 'missing', 'invalid', 'not_evaluated'}
                 and type(self.recovery) is str and self.recovery in {'declared_unverified', 'not_evaluated'}
                 and type(self.diagnostics) is tuple and len(self.diagnostics) <= 16
                 and all(type(code) is str and code in DIAGNOSTICS for code in self.diagnostics)
                 and (self.observation_digest is None or type(self.observation_digest) is str
                      and _SHA256.fullmatch(self.observation_digest) is not None)
                 and all(value is None or type(value) is int and 0 <= value <= _MAX_EPOCH
                         for value in (self.issued_at, self.expires_at)))
        if not valid:
            return PreflightReport.blocked('INTERNAL_ERROR').to_dict()
        return {'schema_version': 'getzilla-deploy-preflight-report-v1', 'state': self.state,
                'observation_digest': self.observation_digest, 'issued_at': self.issued_at, 'expires_at': self.expires_at,
                'package': self.package, 'registration': self.registration, 'provenance': 'unverified',
                'recovery': self.recovery, 'connection': 'not_attempted', 'delivery': 'not_attempted',
                'dispatch_permitted': False, 'operational_grant': False, 'diagnostics': list(self.diagnostics)}


def _clock() -> int:
    value = time.time()
    if type(value) not in (float, int) or not math.isfinite(value) or not 0 <= value <= _MAX_EPOCH - TTL_SECONDS:
        _fail('CLOCK_UNCERTAIN')
    return int(value)


def _budget(started: float) -> None:
    now = time.monotonic()
    if not math.isfinite(now) or now < started:
        _fail('CLOCK_UNCERTAIN')
    if now - started >= WORK_SECONDS:
        _fail('BUDGET_EXCEEDED')


def _root_check(bound: BoundRoot) -> None:
    try:
        bound.check()
    except (ComponentStateError, OSError):
        _fail('ROOT_CHANGED')


def _read(bound: BoundRoot, path: str, limit: int, started: float, *, policy: bool = False) -> FileSnapshot:
    _budget(started)
    _root_check(bound)
    try:
        result = bound.read(path, limit=limit)
    except ComponentStateError:
        _fail('FILE_UNSAFE')
    _budget(started)
    if result is None:
        _fail('POLICY_MISSING' if policy else 'FILE_MISSING')
    return result


def _observe(root: Path, manifest_path: str, expected_root: tuple[int, int, int] | None = None):
    _public_path(manifest_path)
    _distinct((POLICY_PATH, manifest_path))
    if fsx.WINDOWS:
        _fail('MODE_UNSUPPORTED')
    if not isinstance(root, Path):
        _fail()
    started = time.monotonic()
    if type(started) not in (float, int) or not math.isfinite(started):
        _fail('CLOCK_UNCERTAIN')
    try:
        binding = BoundRoot(root)
    except (ComponentStateError, OSError):
        _fail('ROOT_CHANGED')
    with binding as bound:
        info = fsx.fstat_dir(bound.handle)
        root_identity = (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))
        if expected_root is not None and expected_root != root_identity:
            _fail('ROOT_CHANGED')
        roots = (str(bound.path), os.path.abspath(root))
        policy = _read(bound, POLICY_PATH, MAX_INPUT_BYTES, started, policy=True)
        consumers = _policy(policy.content)
        selectors = tuple(secret for record in consumers for secret in record['secrets'])
        _exclude_aliases((manifest_path,), selectors, roots)
        source = _read(bound, manifest_path, MAX_INPUT_BYTES, started)
        manifest = parse_manifest(source.content)
        payloads = (manifest.operator, *manifest.artifacts)
        paths = (manifest_path, *(item.path for item in payloads))
        _distinct((POLICY_PATH, *paths))
        _exclude_aliases(paths, (*selectors, manifest.credential_selector), roots)
        selected = consumer_secret_paths(consumers, script_matches=lambda listed: _script_matches(listed, manifest.operator.path))
        registration = 'matched' if manifest.credential_selector in selected else 'missing'
        snapshots = [(POLICY_PATH, policy, MAX_INPUT_BYTES), (manifest_path, source, MAX_INPUT_BYTES)]
        total = 0
        for expected in payloads:
            remaining = MAX_TOTAL_BYTES - total
            if remaining <= 0:
                _fail('INPUT_TOO_LARGE')
            limit = min(MAX_FILE_BYTES, remaining)
            snapshot = _read(bound, expected.path, limit, started)
            total += len(snapshot.content)
            if snapshot.sha256 != expected.sha256:
                _fail('HASH_MISMATCH')
            if snapshot.mode != expected.mode:
                _fail('MODE_MISMATCH')
            snapshots.append((expected.path, snapshot, limit))
        # Re-read every input, not only ancestry. Stop at the first changed input;
        # a changed policy cannot permit a newly named second-pass payload.
        for path, before, limit in snapshots:
            after = _read(bound, path, limit, started, policy=path == POLICY_PATH)
            if after != before:
                _fail('FILE_CHANGED')
        _root_check(bound)
        inputs = [(path, item.sha256, item.mode, item.identity) for path, item, _ in snapshots]
        inputs_digest = _digest(['getzilla-deploy-inputs-v1', sorted(inputs)])
        _budget(started)
        return root_identity, inputs_digest, registration


def _observation_values(observation: DeploymentObservation) -> tuple:
    return (observation.schema_revision, observation.algorithm_revision, observation.root_identity,
            observation.manifest_path_digest, observation.inputs_digest, observation.registration,
            observation.issued_at, observation.expires_at)


def _checksum(values: tuple) -> str:
    return _digest(['getzilla-deploy-observation-v1', values])


def _validate_observation(observation: object) -> DeploymentObservation:
    if type(observation) is not DeploymentObservation:
        _fail()
    if (not _clean_text(observation.schema_revision, 128) or not _clean_text(observation.algorithm_revision, 128)
            or type(observation.root_identity) is not tuple or len(observation.root_identity) != 3
            or any(type(value) is not int or not 0 <= value <= 2**128 for value in observation.root_identity)
            or type(observation.registration) is not str or observation.registration not in {'matched', 'missing'}
            or any(type(value) is not int or not 0 <= value <= _MAX_EPOCH
                   for value in (observation.issued_at, observation.expires_at))
            or observation.expires_at != observation.issued_at + TTL_SECONDS):
        _fail()
    for value in (observation.manifest_path_digest, observation.inputs_digest, observation.digest):
        _sha256(value)
    if _checksum(_observation_values(observation)) != observation.digest:
        _fail('OBSERVATION_CHANGED')
    return observation


def _valid_time(observation: DeploymentObservation) -> None:
    now = _clock()
    if now < observation.issued_at:
        _fail('CLOCK_UNCERTAIN')
    if now >= observation.expires_at:
        _fail('OBSERVATION_EXPIRED')


def prepare_preflight(root: Path, manifest_path: str) -> DeploymentObservation:
    """Observe admitted public inputs twice. No secret, network or operational effects."""
    try:
        _clock()
        identity, inputs_digest, registration = _observe(root, manifest_path)
        issued = _clock()
        values = (SCHEMA_REVISION, ALGORITHM_REVISION, identity, _digest(manifest_path), inputs_digest,
                  registration, issued, issued + TTL_SECONDS)
        return DeploymentObservation(*values, _checksum(values))
    except PreflightError:
        raise
    except Exception:
        _fail('INTERNAL_ERROR')


def recheck_preflight(root: Path, observation: DeploymentObservation, manifest_path: str) -> PreflightReport:
    """Re-observe inputs; output always keeps execution, provenance and delivery unavailable."""
    try:
        observed = _validate_observation(observation)
        if observed.schema_revision != SCHEMA_REVISION or observed.algorithm_revision != ALGORITHM_REVISION:
            _fail('ALGORITHM_CHANGED')
        _valid_time(observed)
        _public_path(manifest_path)
        if _digest(manifest_path) != observed.manifest_path_digest:
            _fail('OBSERVATION_CHANGED')
        _identity, digest, registration = _observe(root, manifest_path, observed.root_identity)
        _valid_time(observed)
        if digest != observed.inputs_digest or registration != observed.registration:
            _fail('OBSERVATION_CHANGED')
        codes = ('PROVENANCE_UNVERIFIED', 'RECOVERY_UNVERIFIED')
        ready = registration == 'matched'
        return PreflightReport('ready_for_review' if ready else 'blocked', observed.digest, observed.issued_at,
                               observed.expires_at, 'matched', registration, 'declared_unverified',
                               codes if ready else ('CONSUMER_UNREGISTERED', *codes))
    except PreflightError as error:
        return PreflightReport.blocked(error.code)
    except Exception:
        return PreflightReport.blocked('INTERNAL_ERROR')
