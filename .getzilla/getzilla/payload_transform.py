"""Closed offline payload transformations; no authority or native activation.

Policy/class/lineage DTOs are factual inputs for public algorithm controls.
Constructing them does not authenticate a caller, classify a private source or
authorize release. A trusted150 host must retain exact output bytes and full
owned lineage in its registered preparation. Native inspection stays unavailable
until actual host/current-authority/transform/pre-sink composition is qualified.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import re
import time
import unicodedata

from . import _payload_engine as engine

_LABEL = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z')
_FIELD = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,63}\Z')
_SHA = re.compile(r'[0-9a-f]{64}\Z')
_LIMITS = {'max_bytes': 262144, 'max_records': 1000, 'max_depth': 32, 'max_chunks': 1000}
_REASONS = frozenset({
    'accepted', 'transformed', 'native_access_unavailable', 'transform_unavailable',
    'invalid_policy', 'purpose_mismatch', 'invalid_sources', 'unknown_class',
    'budget_exceeded', 'chunk_limit', 'invalid_chunk', 'input_too_large', 'stream_failure',
    'invalid_encoding', 'malformed_payload', 'duplicate_json_key', 'depth_limit', 'record_limit',
    'incomplete_projection', 'invalid_field', 'unclassified_personal_text',
    'invalid_text', 'text_too_large', 'secret_content', 'output_too_large',
})


class TransformError(ValueError):
    """Invalid closed configuration, with a fixed data-free code."""
    def __init__(self):
        super().__init__('invalid_policy')


class DataClass(Enum):
    PUBLIC = 'public'
    INTERNAL = 'internal'
    PERSONAL = 'personal'
    SECRET = 'secret'
    UNKNOWN = 'unknown'


class Purpose(Enum):
    NATIVE_CONTEXT = 'native_context'
    TOOL_RESPONSE = 'registered_tool_response'
    CHILD_REPORT = 'child_report'
    PROTECTED_REPORT = 'protected_report'
    PROTECTED_EXPORT = 'protected_export'


def _label(value):
    return type(value) is str and _LABEL.fullmatch(value) is not None


@dataclass(frozen=True, repr=False)
class SourceFact:
    """Offline factual carrier, never proof of source/current authority."""
    key: tuple[str, str, str, str, str]
    version: str
    content_sha256: str
    representation_sha256: str
    transform_version: str
    classification: DataClass

    def __post_init__(self):
        if (type(self.key) is not tuple or len(self.key) != 5 or not all(_label(p) for p in self.key)
                or not _label(self.version) or not _label(self.transform_version)
                or type(self.classification) is not DataClass
                or any(type(h) is not str or not _SHA.fullmatch(h)
                       for h in (self.content_sha256, self.representation_sha256))):
            raise TransformError()


@dataclass(frozen=True)
class FieldRule:
    path: tuple[str, ...]
    action: str
    value_type: str
    required: bool = True

    def __post_init__(self):
        valid = (type(self.path) is tuple and 1 <= len(self.path) <= 16
                 and all(type(p) is str and _FIELD.fullmatch(p) for p in self.path)
                 and type(self.action) is str and self.action in {'keep', 'drop', 'redact_pii'}
                 and type(self.value_type) is str
                 and self.value_type in {'text', 'integer', 'number', 'boolean', 'null'}
                 and type(self.required) is bool)
        if not valid or any(engine.sensitive_key(p) for p in self.path):
            raise TransformError()


@dataclass(frozen=True)
class TransformPolicy:
    version: str
    purpose: Purpose
    data_classes: tuple[DataClass, ...]
    content_type: str
    fields: tuple[FieldRule, ...]
    max_bytes: int = 262144
    max_records: int = 1000
    max_depth: int = 32
    max_chunks: int = 1000

    def __post_init__(self):
        valid = (_label(self.version) and type(self.purpose) is Purpose
                 and type(self.data_classes) is tuple and 1 <= len(self.data_classes) <= 3
                 and all(type(c) is DataClass and c not in {DataClass.UNKNOWN, DataClass.SECRET}
                         for c in self.data_classes)
                 and len(set(self.data_classes)) == len(self.data_classes)
                 and type(self.content_type) is str
                 and self.content_type in {'application/json', 'text/plain'}
                 and type(self.fields) is tuple and len(self.fields) <= 128
                 and all(type(f) is FieldRule for f in self.fields))
        if not valid or any(type(getattr(self, k)) is not int
                            or not 1 <= getattr(self, k) <= limit for k, limit in _LIMITS.items()):
            raise TransformError()
        if self.content_type == 'text/plain' and (self.fields or self.data_classes != (DataClass.PUBLIC,)):
            raise TransformError()
        paths = [field.path for field in self.fields]
        for index, path in enumerate(paths):
            for other in paths[index + 1:]:
                if path[:len(other)] == other or other[:len(path)] == path:
                    raise TransformError()

    @property
    def identity(self):
        """Consistency identity of public policy bytes, never an authority token."""
        value = {
            'schema_version': 1, 'version': self.version, 'purpose': self.purpose.value,
            'data_classes': [c.value for c in self.data_classes], 'content_type': self.content_type,
            'fields': [{'path': list(f.path), 'action': f.action, 'value_type': f.value_type,
                        'required': f.required} for f in self.fields],
            'limits': {**{name: getattr(self, name) for name in _LIMITS}, 'deadline_seconds': 2},
        }
        return hashlib.sha256(engine.encode_json(value, max_bytes=262144)).hexdigest()


@dataclass(frozen=True, repr=False)
class CandidateResult:
    """Internal algorithm output; a result or checksum is not a release permit."""
    state: str
    reason: str
    payload: bytes | None = None
    sources: tuple[SourceFact, ...] = ()
    policy_sha256: str | None = None

    def __post_init__(self):
        if (type(self.state) is not str or self.state not in {'candidate_complete', 'rejected', 'unavailable'}
                or type(self.reason) is not str or self.reason not in _REASONS
                or type(self.sources) is not tuple):
            raise TransformError()
        if self.state == 'candidate_complete':
            if (self.reason not in {'accepted', 'transformed'} or type(self.payload) is not bytes
                    or len(self.payload) > 262144 or not 1 <= len(self.sources) <= 128
                    or not all(type(s) is SourceFact for s in self.sources)
                    or type(self.policy_sha256) is not str or not _SHA.fullmatch(self.policy_sha256)):
                raise TransformError()
        elif (self.payload is not None or self.sources or self.policy_sha256 is not None
              or self.reason in {'accepted', 'transformed'}):
            raise TransformError()

    @property
    def payload_sha256(self):
        return hashlib.sha256(self.payload).hexdigest() if self.payload is not None else None

    def to_metadata(self):
        # No source keys, hidden membership, bytes, hashes or arbitrary detail.
        return {'state': self.state, 'reason': self.reason,
                'qualification': 'algorithm_only', 'dispatch_permitted': False}


def inspect_native(*, chunks) -> CandidateResult:
    """No qualified host/interceptor exists here. Do not even iterate input."""
    return CandidateResult('unavailable', 'native_access_unavailable')


def _sources(sources, policy):
    if type(sources) is not tuple or not 1 <= len(sources) <= 128:
        raise engine.PayloadError('invalid_sources')
    seen = set()
    for source in sources:
        if (type(source) is not SourceFact or type(source.key) is not tuple or len(source.key) != 5
                or not all(_label(p) for p in source.key)
                or not _label(source.version) or not _label(source.transform_version)
                or any(type(h) is not str or not _SHA.fullmatch(h)
                       for h in (source.content_sha256, source.representation_sha256))
                or source.key in seen):
            raise engine.PayloadError('invalid_sources')
        if (type(source.classification) is not DataClass
                or source.classification not in policy.data_classes):
            raise engine.PayloadError('unknown_class')
        seen.add(source.key)


def _text(value):
    if (unicodedata.normalize('NFC', value) != value
            or any(ord(c) < 32 and c not in {'\n', '\t'} for c in value)):
        raise engine.PayloadError('malformed_payload')
    try:
        value.encode('utf-8', 'strict')
    except UnicodeError:
        raise engine.PayloadError('malformed_payload') from None


def _texts(value):
    if isinstance(value, dict):
        for key, child in value.items():
            _text(key)
            _texts(child)
    elif isinstance(value, list):
        for child in value:
            _texts(child)
    elif isinstance(value, str):
        _text(value)


def _matches(value, kind):
    return {'text': type(value) is str, 'integer': type(value) is int,
            'number': type(value) in (int, float), 'boolean': type(value) is bool,
            'null': value is None}[kind]


def _project(value, policy, personal):
    projected = {}
    for field in policy.fields:
        if field.action == 'drop':
            continue
        item, present = value, True
        for name in field.path:
            if type(item) is not dict or name not in item:
                present = False
                break
            item = item[name]
        if not present:
            if field.required:
                raise engine.PayloadError('incomplete_projection')
            continue
        if not _matches(item, field.value_type):
            raise engine.PayloadError('invalid_field')
        if field.action == 'redact_pii':
            item = '[REDACTED]'
        elif type(item) is str:
            if personal:
                raise engine.PayloadError('unclassified_personal_text')
            item = engine.redact(item, policy.max_bytes, bound_intermediate=True)
        destination = projected
        for name in field.path[:-1]:
            destination = destination.setdefault(name, {})
        destination[field.path[-1]] = item
    return projected


def transform_candidate(*, policy, chunks, sources, purpose, absolute_deadline) -> CandidateResult:
    """Bound a public/offline candidate, without sending or granting anything.

    Production must obtain classification and complete dependencies from the
    actual trusted host. These public DTOs alone cannot supply that proof.
    """
    if type(policy) is not TransformPolicy:
        return CandidateResult('rejected', 'invalid_policy')
    if type(purpose) is not Purpose or purpose is not policy.purpose:
        return CandidateResult('rejected', 'purpose_mismatch')
    try:
        engine.check_deadline(absolute_deadline)
        absolute_deadline = min(absolute_deadline, time.monotonic() + 2.0)
        _sources(sources, policy)
        raw = engine.collect(chunks, max_bytes=policy.max_bytes, max_chunks=policy.max_chunks,
                             deadline=absolute_deadline)
        try:
            text = raw.decode('utf-8', 'strict')
        except UnicodeError:
            raise engine.PayloadError('invalid_encoding') from None
        if policy.content_type == 'application/json':
            value = engine.strict_json(text)
            if type(value) is not dict:
                raise engine.PayloadError('malformed_payload')
            engine.check_shape(value, max_depth=policy.max_depth, max_records=policy.max_records)
            _texts(value)
            engine.check_deadline(absolute_deadline)
            personal = any(s.classification is DataClass.PERSONAL for s in sources)
            output = _project(value, policy, personal)
            encoded = engine.encode_json(output, max_bytes=policy.max_bytes)
            changed = encoded != raw
        else:
            _text(text)
            cleaned = engine.redact(text, policy.max_bytes, bound_intermediate=True)
            encoded = cleaned.encode('utf-8')
            changed = cleaned != text
        result = CandidateResult('candidate_complete', 'transformed' if changed else 'accepted',
                                 encoded, sources, policy.identity)
        engine.check_deadline(absolute_deadline)
        return result
    except engine.PayloadError as exc:
        return CandidateResult('rejected', exc.code)
    except (json.JSONDecodeError, UnicodeError, ValueError, RecursionError, OverflowError):
        return CandidateResult('rejected', 'malformed_payload')
