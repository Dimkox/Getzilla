"""Code graph records: source-bound input, stable node/edge identities, coverage and generations.

A generation is owned by one GraphInput identity (source identity + file scope digests + config +
extractor). Exports carry paths, names, spans and digests only: never source text or literals.
Files outside the supported languages and omitted files are part of coverage, so a graph never
claims more than the scope it actually parsed.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Mapping, Sequence

from ..source_models import domain_digest

SCHEMA = 'code-index-state-v1'
EXTRACTOR = 'getzilla-python-ast-v1'
INPUT_DOMAIN = 'getzilla-code-graph-input-v1'
GENERATION_DOMAIN = 'getzilla-code-graph-generation-v1'
CONFIG_DOMAIN = 'getzilla-code-graph-config-v1'
LANGUAGES = {'.py': 'python', '.pyi': 'python', '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
             '.ts': 'typescript', '.tsx': 'typescript', '.jsx': 'javascript', '.go': 'go', '.php': 'php',
             '.rb': 'ruby', '.java': 'java', '.kt': 'kotlin', '.rs': 'rust', '.c': 'c', '.h': 'c',
             '.cc': 'cpp', '.cpp': 'cpp', '.hpp': 'cpp', '.cs': 'csharp', '.swift': 'swift', '.sh': 'shell',
             '.ps1': 'powershell', '.sql': 'sql'}
SUPPORTED = frozenset({'python'})


class GraphError(ValueError):
    def __init__(self, reason_code: str, message: str = '') -> None:
        super().__init__(message or reason_code)
        self.reason_code = reason_code


def language_of(path: str) -> str | None:
    return LANGUAGES.get(PurePosixPath(path).suffix.lower())


@dataclass(frozen=True)
class GraphConfig:
    package_roots: tuple[str, ...] = ('.',)
    namespace_packages: bool = False
    max_impact_nodes: int = 100_000
    max_file_bytes: int = 4 * 1024 * 1024
    extractor: str = EXTRACTOR

    def to_dict(self) -> dict[str, Any]:
        return {'package_roots': list(self.package_roots), 'namespace_packages': self.namespace_packages,
                'max_impact_nodes': self.max_impact_nodes, 'max_file_bytes': self.max_file_bytes,
                'extractor': self.extractor}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> 'GraphConfig':
        values = dict(data)
        if 'package_roots' in values:
            values['package_roots'] = tuple(values['package_roots'])
        return cls(**values)

    def digest(self) -> str:
        return domain_digest(CONFIG_DOMAIN, self.to_dict())


@dataclass(frozen=True)
class SourceIdentity:
    source_kind: str  # folder, local_git, remote_snapshot, zero_git_shadow
    object_format: str | None = None
    commit_oid: str | None = None
    tree_oid: str | None = None
    working_set_digest: str | None = None
    source_digest: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {'source_kind': self.source_kind, 'object_format': self.object_format, 'commit_oid': self.commit_oid,
                'tree_oid': self.tree_oid, 'working_set_digest': self.working_set_digest,
                'source_digest': self.source_digest}


@dataclass(frozen=True)
class ScopeFile:
    path: str
    sha256: str
    language: str | None

    def to_dict(self) -> dict[str, Any]:
        return {'path': self.path, 'sha256': self.sha256, 'language': self.language}


@dataclass(frozen=True)
class GraphInput:
    source: SourceIdentity
    files: tuple[ScopeFile, ...]
    omitted: tuple[tuple[str, str], ...]
    config: GraphConfig
    contents: Mapping[str, bytes] = field(default_factory=dict, repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {'schema_version': INPUT_DOMAIN, 'source': self.source.to_dict(),
                'files': [item.to_dict() for item in self.files],
                'omitted': [{'path': path, 'reason': reason} for path, reason in self.omitted],
                'config': self.config.to_dict()}

    @property
    def identity(self) -> str:
        return domain_digest(INPUT_DOMAIN, self.to_dict())

    def file(self, path: str) -> ScopeFile | None:
        return next((item for item in self.files if item.path == path), None)


def _check_path(path: str) -> str:
    pure = PurePosixPath(path)
    if not path or '\\' in path or pure.is_absolute() or '..' in pure.parts or path != pure.as_posix():
        raise GraphError('SCOPE_PATH_INVALID', f'not a normalized relative path: {path!r}')
    return path


def source_identity_from(baseline: Any) -> SourceIdentity:
    """IngestionBaseline (existing Git), a source-baseline.json mapping (Zero-Git) or a folder digest."""
    if hasattr(baseline, 'identity') and hasattr(baseline, 'source_kind'):
        identity = baseline.identity
        return SourceIdentity(baseline.source_kind, identity.object_format, identity.commit_oid, identity.tree_oid,
                              baseline.working_set_digest)
    if isinstance(baseline, Mapping) and 'source_digest' in baseline:
        git = baseline.get('git') or {}
        return SourceIdentity(baseline.get('source_kind', 'zero_git_shadow'), git.get('object_format'),
                              git.get('commit_oid'), git.get('tree_oid'), None, baseline['source_digest'])
    raise GraphError('BASELINE_UNSUPPORTED')


def make_graph_input(baseline: Any, scope: Mapping[str, bytes], config: GraphConfig, *,
                     omitted: Mapping[str, str] | None = None) -> GraphInput:
    """scope: approved file path -> bytes. Files over the size limit are omitted with a reason."""
    source = source_identity_from(baseline)
    files, contents, skipped = [], {}, dict(omitted or {})
    for path in sorted(scope):
        _check_path(path)
        data = scope[path]
        if len(data) > config.max_file_bytes:
            skipped[path] = 'FILE_OVER_GRAPH_LIMIT'
            continue
        files.append(ScopeFile(path, hashlib.sha256(data).hexdigest(), language_of(path)))
        contents[path] = data
    return GraphInput(source, tuple(files), tuple(sorted(skipped.items())), config, contents)


@dataclass(frozen=True)
class Span:
    start_line: int
    start_col: int
    end_line: int
    end_col: int

    def to_list(self) -> list[int]:
        return [self.start_line, self.start_col, self.end_line, self.end_col]


@dataclass(frozen=True)
class FileNode:
    path: str
    language: str | None
    sha256: str

    @property
    def id(self) -> str:
        return f'file:{self.path}'

    def to_dict(self) -> dict[str, Any]:
        return {'id': self.id, 'path': self.path, 'language': self.language, 'sha256': self.sha256}


@dataclass(frozen=True)
class SymbolNode:
    path: str
    qualname: str
    kind: str  # function, async_function, class
    span: Span

    @property
    def id(self) -> str:
        return f'sym:{self.path}::{self.qualname}'

    def to_dict(self) -> dict[str, Any]:
        return {'id': self.id, 'path': self.path, 'qualname': self.qualname, 'kind': self.kind,
                'span': self.span.to_list()}


@dataclass(frozen=True)
class RawImport:
    module: str | None  # None for `from . import x`
    names: tuple[tuple[str, str | None], ...]  # (name, asname); empty for `import module`
    level: int
    asname: str | None
    line: int
    is_from: bool


@dataclass(frozen=True)
class RawCall:
    scope: str  # qualname of the enclosing symbol, '' for module level
    form: str  # name, attribute, dynamic, reflection
    expression: str  # identifier chain only (never literals)
    line: int


@dataclass(frozen=True)
class ParsedFile:
    path: str
    sha256: str
    language: str
    status: str  # complete, incomplete
    reason: str | None
    symbols: tuple[SymbolNode, ...] = ()
    imports: tuple[RawImport, ...] = ()
    calls: tuple[RawCall, ...] = ()
    module_bindings: Mapping[str, tuple[str, ...]] = field(default_factory=dict)  # name -> binding kinds
    scope_locals: Mapping[str, frozenset[str]] = field(default_factory=dict)  # qualname -> local value names
    patched: tuple[tuple[str, str], ...] = ()  # (import alias, attribute) assigned in this file
    dynamic_gaps: tuple[tuple[str, int], ...] = ()  # (kind, line)


@dataclass(frozen=True)
class ImportEdge:
    source_file: str
    module: str
    target_file: str | None
    resolution: str  # internal, external, unresolved
    reason: str | None
    line: int

    @property
    def id(self) -> str:
        return f'import:{self.source_file}:{self.line}:{self.module}'

    def to_dict(self) -> dict[str, Any]:
        return {'id': self.id, 'source_file': self.source_file, 'module': self.module,
                'target_file': self.target_file, 'resolution': self.resolution, 'reason': self.reason,
                'line': self.line}


@dataclass(frozen=True)
class CallEdge:
    caller: str  # symbol id, or file id for module-level code
    expression: str
    targets: tuple[str, ...]
    resolution: str  # exact, candidate, external, unresolved
    reason: str | None
    line: int

    @property
    def id(self) -> str:
        return f'call:{self.caller}:{self.line}:{self.expression}'

    def to_dict(self) -> dict[str, Any]:
        return {'id': self.id, 'caller': self.caller, 'expression': self.expression, 'targets': list(self.targets),
                'resolution': self.resolution, 'reason': self.reason, 'line': self.line}


@dataclass(frozen=True)
class GraphCoverage:
    files_in_scope: int
    parsed_complete: int
    incomplete: tuple[tuple[str, str], ...]
    unsupported_language: tuple[tuple[str, str], ...]
    unknown_language: tuple[str, ...]
    omitted: tuple[tuple[str, str], ...]
    unresolved_imports: int
    unresolved_calls: int
    dynamic_gaps: int

    @property
    def complete(self) -> bool:
        """Every code file in scope was parsed. Non-code files (unknown_language) are listed, not analysed;
        a change to one of them is not covered by the graph and widens impact on its own."""
        return not (self.incomplete or self.unsupported_language or self.omitted)

    def to_dict(self) -> dict[str, Any]:
        return {'files_in_scope': self.files_in_scope, 'parsed_complete': self.parsed_complete,
                'incomplete': [list(item) for item in self.incomplete],
                'unsupported_language': [list(item) for item in self.unsupported_language],
                'unknown_language': list(self.unknown_language), 'omitted': [list(item) for item in self.omitted],
                'unresolved_imports': self.unresolved_imports, 'unresolved_calls': self.unresolved_calls,
                'dynamic_gaps': self.dynamic_gaps, 'complete': self.complete,
                'claim': 'python_files_only' if self.unsupported_language else 'all_code_files_in_scope'}


@dataclass(frozen=True)
class GraphGeneration:
    input_identity: str
    graph_input: Mapping[str, Any]
    files: tuple[FileNode, ...]
    symbols: tuple[SymbolNode, ...]
    imports: tuple[ImportEdge, ...]
    calls: tuple[CallEdge, ...]
    coverage: GraphCoverage
    parsed: Mapping[str, ParsedFile] = field(default_factory=dict, repr=False, compare=False)
    counters: Mapping[str, Any] = field(default_factory=dict, compare=False)

    def __post_init__(self) -> None:
        files = {node.path for node in self.files}
        symbols = {node.id for node in self.symbols}
        for node in self.symbols:
            if node.path not in files:
                raise GraphError('FOREIGN_SYMBOL', node.id)
        for edge in self.imports:
            if edge.source_file not in files or (edge.target_file is not None and edge.target_file not in files):
                raise GraphError('FOREIGN_GENERATION_EDGE', edge.id)
        file_ids = {f'file:{path}' for path in files}
        for edge in self.calls:
            if edge.caller not in symbols and edge.caller not in file_ids:
                raise GraphError('FOREIGN_GENERATION_EDGE', edge.id)
            if any(target not in symbols for target in edge.targets):
                raise GraphError('FOREIGN_GENERATION_EDGE', edge.id)

    def body(self) -> dict[str, Any]:
        return {'schema_version': SCHEMA, 'input_identity': self.input_identity, 'graph_input': dict(self.graph_input),
                'files': [node.to_dict() for node in sorted(self.files, key=lambda n: n.id)],
                'symbols': [node.to_dict() for node in sorted(self.symbols, key=lambda n: n.id)],
                'imports': [edge.to_dict() for edge in sorted(self.imports, key=lambda e: e.id)],
                'calls': [edge.to_dict() for edge in sorted(self.calls, key=lambda e: e.id)],
                'coverage': self.coverage.to_dict()}

    @property
    def generation_id(self) -> str:
        return domain_digest(GENERATION_DOMAIN, self.body())

    def export(self) -> dict[str, Any]:
        """Public index export: identities, names, spans, digests and coverage; no source text."""
        return {**self.body(), 'generation_id': self.generation_id}

    @property
    def config(self) -> GraphConfig:
        return GraphConfig.from_dict(self.graph_input['config'])


@dataclass(frozen=True)
class ImpactReport:
    previous_generation: str | None
    current_generation: str
    changed: tuple[str, ...]
    affected_files: tuple[str, ...]
    affected_symbols: tuple[str, ...]
    reasons: Mapping[str, tuple[str, ...]]
    complete: bool
    gaps: tuple[str, ...]
    fallback_scope: str  # none, configured_project
    required_checks: tuple[str, ...]
    source_identity: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {'schema_version': 'getzilla-impact-report-v1', 'previous_generation': self.previous_generation,
                'current_generation': self.current_generation, 'changed': list(self.changed),
                'affected_files': list(self.affected_files), 'affected_symbols': list(self.affected_symbols),
                'reasons': {key: list(value) for key, value in sorted(self.reasons.items())},
                'complete': self.complete, 'gaps': list(self.gaps), 'fallback_scope': self.fallback_scope,
                'required_checks': list(self.required_checks), 'source_identity': dict(self.source_identity)}

    @property
    def digest(self) -> str:
        return domain_digest('getzilla-impact-report-v1', self.to_dict())


def build_coverage(graph_input: GraphInput, parsed: Sequence[ParsedFile], unresolved_imports: int,
                   unresolved_calls: int) -> GraphCoverage:
    unsupported = tuple((item.path, item.language) for item in graph_input.files
                        if item.language is not None and item.language not in SUPPORTED)
    unknown = tuple(item.path for item in graph_input.files if item.language is None)
    incomplete = tuple((item.path, item.reason or 'INCOMPLETE') for item in parsed if item.status != 'complete')
    gaps = sum(len(item.dynamic_gaps) for item in parsed)
    return GraphCoverage(len(graph_input.files), sum(item.status == 'complete' for item in parsed), incomplete,
                         unsupported, unknown, graph_input.omitted, unresolved_imports, unresolved_calls, gaps)
