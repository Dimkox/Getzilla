"""Transactional SQLite cache of graph generations with an active-generation pointer.

A generation is written and verified inside one IMMEDIATE transaction; the pointer moves only after
the rows read back to the same generation id, and only if it still names the generation the
writer started from (so concurrent writers cannot publish a mixed or lost update). Readers see
the old or the new complete generation. A corrupt file or another schema version is moved aside
and rebuilt; correctness never depends on the cache surviving. The default path
`.getzilla/index/graph.sqlite` is local state: Zero-Git writes it into `.git/info/exclude` and the
repository ignores it, so it is never part of a source digest or a commit.
"""
from __future__ import annotations

import contextlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from .builder import build_generation
from .models import (
    CallEdge, FileNode, GraphCoverage, GraphError, GraphGeneration, GraphInput, ImportEdge, ParsedFile, RawCall,
    RawImport, Span, SymbolNode,
)

STORE_SCHEMA = 'getzilla-code-graph-store-v1'
DEFAULT_CACHE = Path('.getzilla') / 'index' / 'graph.sqlite'


def _symbol(data: dict[str, Any]) -> SymbolNode:
    return SymbolNode(data['path'], data['qualname'], data['kind'], Span(*data['span']))


def _parsed_to_dict(parsed: ParsedFile) -> dict[str, Any]:
    return {'path': parsed.path, 'sha256': parsed.sha256, 'language': parsed.language, 'status': parsed.status,
            'reason': parsed.reason, 'symbols': [symbol.to_dict() for symbol in parsed.symbols],
            'imports': [[i.module, [list(n) for n in i.names], i.level, i.asname, i.line, i.is_from] for i in parsed.imports],
            'calls': [[c.scope, c.form, c.expression, c.line] for c in parsed.calls],
            'module_bindings': {k: list(v) for k, v in parsed.module_bindings.items()},
            'scope_locals': {k: sorted(v) for k, v in parsed.scope_locals.items()},
            'patched': [list(item) for item in parsed.patched], 'dynamic_gaps': [list(g) for g in parsed.dynamic_gaps]}


def _parsed_from_dict(data: dict[str, Any]) -> ParsedFile:
    return ParsedFile(
        data['path'], data['sha256'], data['language'], data['status'], data['reason'],
        tuple(_symbol(item) for item in data['symbols']),
        tuple(RawImport(m, tuple((n, a) for n, a in names), level, asname, line, is_from)
              for m, names, level, asname, line, is_from in data['imports']),
        tuple(RawCall(*item) for item in data['calls']),
        {k: tuple(v) for k, v in data['module_bindings'].items()},
        {k: frozenset(v) for k, v in data['scope_locals'].items()},
        tuple(tuple(item) for item in data['patched']), tuple((k, line) for k, line in data['dynamic_gaps']))


def generation_from_record(body: dict[str, Any], parsed: dict[str, Any]) -> GraphGeneration:
    cov = body['coverage']
    coverage = GraphCoverage(cov['files_in_scope'], cov['parsed_complete'], tuple(tuple(i) for i in cov['incomplete']),
                             tuple(tuple(i) for i in cov['unsupported_language']), tuple(cov['unknown_language']),
                             tuple(tuple(i) for i in cov['omitted']), cov['unresolved_imports'], cov['unresolved_calls'],
                             cov['dynamic_gaps'])
    return GraphGeneration(
        body['input_identity'], body['graph_input'],
        tuple(FileNode(f['path'], f['language'], f['sha256']) for f in body['files']),
        tuple(_symbol(s) for s in body['symbols']),
        tuple(ImportEdge(e['source_file'], e['module'], e['target_file'], e['resolution'], e['reason'], e['line'])
              for e in body['imports']),
        tuple(CallEdge(e['caller'], e['expression'], tuple(e['targets']), e['resolution'], e['reason'], e['line'])
              for e in body['calls']),
        coverage, {path: _parsed_from_dict(item) for path, item in parsed.items()})


class GraphStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.rebuilt_reason: str | None = None
        self._open()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=30, isolation_level=None)
        connection.execute('PRAGMA journal_mode=WAL')
        connection.execute('PRAGMA synchronous=FULL')
        return connection

    def _open(self) -> None:
        try:
            self.db = self._connect()
            if self.db.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                raise sqlite3.DatabaseError('quick_check failed')
            tables = {row[0] for row in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if tables and 'meta' not in tables:
                raise sqlite3.DatabaseError('not a graph store')
            if 'meta' in tables:
                row = self.db.execute("SELECT value FROM meta WHERE key='schema'").fetchone()
                if row is None or row[0] != STORE_SCHEMA:
                    self._discard('SCHEMA_MISMATCH')
                    return
        except sqlite3.DatabaseError:
            self._discard('CORRUPT_CACHE')
            return
        self._create()

    def _discard(self, reason: str) -> None:
        handle = getattr(self, 'db', None)  # absent when the first connect already failed
        if handle is not None:
            with contextlib.suppress(sqlite3.Error):
                handle.close()
        aside = self.path.with_name(f'{self.path.name}.{reason.lower()}-{time.time_ns()}')
        for suffix in ('', '-wal', '-shm'):
            candidate = Path(str(self.path) + suffix)
            if candidate.exists():
                candidate.replace(Path(str(aside) + suffix))
        self.rebuilt_reason = reason
        self.db = self._connect()
        self._create()

    def _create(self) -> None:
        self.db.executescript(
            "CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS generations(id TEXT PRIMARY KEY, input_identity TEXT NOT NULL,"
            " body TEXT NOT NULL, parsed TEXT NOT NULL, complete INTEGER NOT NULL);"
            "CREATE TABLE IF NOT EXISTS active(slot INTEGER PRIMARY KEY CHECK (slot = 1), generation_id TEXT NOT NULL);")
        self.db.execute("INSERT OR IGNORE INTO meta(key, value) VALUES ('schema', ?)", (STORE_SCHEMA,))

    def close(self) -> None:
        self.db.close()

    def active_id(self) -> str | None:
        row = self.db.execute('SELECT generation_id FROM active WHERE slot = 1').fetchone()
        return None if row is None else row[0]

    def publish(self, generation: GraphGeneration, *, expected_active: str | None, _fail_before_commit: bool = False) -> str:
        generation_id = generation.generation_id
        body = json.dumps(generation.body(), sort_keys=True, separators=(',', ':'))
        parsed = json.dumps({path: _parsed_to_dict(item) for path, item in generation.parsed.items()},
                            sort_keys=True, separators=(',', ':'))
        self.db.execute('BEGIN IMMEDIATE')
        try:
            if self.active_id() != expected_active:
                raise GraphError('CONCURRENT_PUBLISH', 'the active generation changed since this build started')
            self.db.execute('INSERT OR REPLACE INTO generations(id, input_identity, body, parsed, complete) '
                            'VALUES (?, ?, ?, ?, 0)', (generation_id, generation.input_identity, body, parsed))
            stored = self.db.execute('SELECT body, parsed FROM generations WHERE id = ?', (generation_id,)).fetchone()
            if generation_from_record(json.loads(stored[0]), json.loads(stored[1])).generation_id != generation_id:
                raise GraphError('STORE_READBACK_MISMATCH')
            self.db.execute('UPDATE generations SET complete = 1 WHERE id = ?', (generation_id,))
            self.db.execute('INSERT OR REPLACE INTO active(slot, generation_id) VALUES (1, ?)', (generation_id,))
            if _fail_before_commit:
                raise RuntimeError('simulated interruption')
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK')
            raise
        return generation_id

    def read_generation(self, generation_id: str) -> GraphGeneration:
        row = self.db.execute('SELECT body, parsed, complete FROM generations WHERE id = ?', (generation_id,)).fetchone()
        if row is None or not row[2]:
            raise GraphError('GENERATION_NOT_FOUND', generation_id)
        generation = generation_from_record(json.loads(row[0]), json.loads(row[1]))
        if generation.generation_id != generation_id:
            raise GraphError('GENERATION_DIGEST_MISMATCH', generation_id)
        return generation

    def read_active(self) -> GraphGeneration | None:
        active = self.active_id()
        return None if active is None else self.read_generation(active)


def build_full_index(graph_input: GraphInput, store: GraphStore) -> GraphGeneration:
    expected = store.active_id()
    generation = build_generation(graph_input)
    store.publish(generation, expected_active=expected)
    return generation


def read_generation(store: GraphStore, generation_id: str) -> GraphGeneration:
    return store.read_generation(generation_id)
