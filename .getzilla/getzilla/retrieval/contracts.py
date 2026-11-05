"""Immutable byte/provenance inputs, not principal or permission records.

Only a qualified native adapter can authorize collecting these bytes or disclosing
these identifiers. Constructing a SourceSnapshot does not establish that authority.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import PurePosixPath
import re
from types import MappingProxyType

from .budget import RetrievalError


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def label(value):
    try:
        return isinstance(value, str) and 0 < len(value.encode()) <= 256 and all(c.isprintable() for c in value)
    except UnicodeError:
        return False


def hex_digest(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def checked_identity(value):
    if not isinstance(value, dict):
        raise RetrievalError('invalid_source_identity')
    if value.get('kind') == 'gitless':
        valid = set(value) == {'kind', 'snapshot_digest'} and hex_digest(value.get('snapshot_digest'))
    elif value.get('kind') == 'git':
        valid = (set(value) == {'kind', 'base_sha', 'head_sha', 'dirty_fingerprint'}
            and all(isinstance(value.get(k), str) and re.fullmatch('[0-9a-f]{40}|[0-9a-f]{64}', value[k])
                for k in ('base_sha', 'head_sha'))
            and (value.get('dirty_fingerprint') is None or hex_digest(value['dirty_fingerprint'])))
    else:
        valid = False
    if not valid:
        raise RetrievalError('invalid_source_identity')
    return dict(value)


@dataclass(frozen=True, order=True)
class SourceKey:
    tenant: str
    project: str
    provider: str
    site: str
    resource_id: str

    def __post_init__(self):
        if not all(label(v) for v in self.parts()):
            raise RetrievalError('invalid_source_key')

    def parts(self):
        return (self.tenant, self.project, self.provider, self.site, self.resource_id)


@dataclass(frozen=True)
class SourceDocument:
    key: SourceKey
    path: str
    version: str
    original: bytes = field(repr=False)
    representation: bytes = field(repr=False)
    transform_policy: str
    transform_revision: str
    original_sha256: str = field(init=False)
    transformed_sha256: str = field(init=False)
    _representation_identity: str = field(init=False, repr=False)

    def __post_init__(self):
        if type(self.key) is not SourceKey or not label(self.path) or not label(self.version):
            raise RetrievalError('invalid_source_document')
        path = PurePosixPath(self.path)
        if path.is_absolute() or path.as_posix() != self.path or '\\' in self.path or '..' in path.parts:
            raise RetrievalError('invalid_source_path')
        if not hex_digest(self.transform_policy) or not label(self.transform_revision):
            raise RetrievalError('invalid_transform')
        if type(self.original) is not bytes or type(self.representation) is not bytes:
            raise RetrievalError('invalid_source_bytes')
        if max(len(self.original), len(self.representation)) > 1_048_576:
            raise RetrievalError('source_file_exceeded')
        try:
            self.original.decode('utf-8')
            self.representation.decode('utf-8')
        except UnicodeError:
            raise RetrievalError('source_encoding_unavailable') from None
        # The initial profile supports line-preserving transformations only.
        # Other transforms need an independently validated range mapping.
        if len(self.original.splitlines()) != len(self.representation.splitlines()):
            raise RetrievalError('transform_mapping_unavailable')
        object.__setattr__(self, 'original_sha256', sha(self.original))
        object.__setattr__(self, 'transformed_sha256', sha(self.representation))
        object.__setattr__(self, '_representation_identity', digest([self.key.parts(), self.version,
            self.original_sha256, self.transform_policy, self.transform_revision, self.transformed_sha256]))

    @property
    def representation_identity(self):
        return self._representation_identity


@dataclass(frozen=True)
class SourceSnapshot:
    tenant: str
    project: str
    repository: str
    documents: tuple[SourceDocument, ...] = field(repr=False)
    base_sha: str | None = None
    head_sha: str | None = None

    def __post_init__(self):
        if not all(label(v) for v in (self.tenant, self.project, self.repository)) or type(self.documents) is not tuple:
            raise RetrievalError('invalid_snapshot')
        if any(type(d) is not SourceDocument for d in self.documents):
            raise RetrievalError('invalid_source_document')
        if len(self.documents) > 4000 or sum(len(d.original) for d in self.documents) > 32 * 1024 * 1024:
            raise RetrievalError('inventory_exceeded')
        seen = set()
        for doc in self.documents:
            if type(doc) is not SourceDocument:
                raise RetrievalError('invalid_source_document')
            if (doc.key.tenant, doc.key.project) != (self.tenant, self.project):
                raise RetrievalError('partition_mismatch')
            if (doc.key, doc.path) in seen:
                raise RetrievalError('duplicate_source')
            seen.add((doc.key, doc.path))
        if (self.base_sha is None) != (self.head_sha is None):
            raise RetrievalError('invalid_source_identity')
        for value in (self.base_sha, self.head_sha):
            if value is not None and (not isinstance(value, str) or not re.fullmatch('[0-9a-f]{40}|[0-9a-f]{64}', value)):
                raise RetrievalError('invalid_source_identity')

    @classmethod
    def create(cls, tenant, project, repository, documents, *, base_sha=None, head_sha=None):
        return cls(tenant, project, repository, tuple(documents), base_sha, head_sha)

    @property
    def source_digest(self):
        return digest([[d.key.parts(), d.path, d.version, d.original_sha256]
            for d in sorted(self.documents, key=lambda item: (item.key, item.path))])

    @property
    def source_identity(self):
        if self.head_sha is None:
            return {'kind': 'gitless', 'snapshot_digest': self.source_digest}
        return {'kind': 'git', 'base_sha': self.base_sha, 'head_sha': self.head_sha,
            'dirty_fingerprint': self.source_digest}


@dataclass(frozen=True)
class Chunk:
    key: SourceKey
    path: str
    version: str
    symbol: str
    start: int
    end: int
    file_sha256: str
    chunk_sha256: str
    representation_identity: str
    transformed_sha256: str
    text: str = field(repr=False)
    encoder_tokens: int | None = None
    encoder_truncated: bool | None = None

    @property
    def id(self):
        return digest([self.key.parts(), self.path, self.symbol, self.start, self.end, self.file_sha256])


@dataclass(frozen=True)
class Generation:
    repository: str
    source_snapshot: dict
    chunks: tuple[Chunk, ...]
    representation_ids: tuple[str, ...]
    overload_stubs: int
    gaps: tuple[str, ...]
    window_profile: str = 'function_no_encoder_v1'
    candidate_kind: str = 'non_overload_ast_functions'

    def __post_init__(self):
        object.__setattr__(self, 'source_snapshot', MappingProxyType(checked_identity(dict(self.source_snapshot))))
        if (type(self.chunks) is not tuple or len(self.chunks) > 8192
                or type(self.representation_ids) is not tuple or len(self.representation_ids) > 4000
                or any(not hex_digest(value) for value in self.representation_ids)):
            raise RetrievalError('invalid_generation')

    @property
    def identity(self):
        return digest({'schema': 'getzilla-retrieval-generation-v1', 'repository': self.repository,
            'source': dict(self.source_snapshot), 'representations': self.representation_ids,
            'chunks': [[c.id, c.chunk_sha256, c.transformed_sha256] for c in self.chunks],
            'window_profile': self.window_profile, 'gaps': self.gaps,
            'bm25': [1.2, .75], 'rrf': [60, 'equal_available_components']})
