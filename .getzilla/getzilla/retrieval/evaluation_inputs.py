"""Audit the registered public experiment's draft inputs without running a ranker.

These are consistency/provenance facts, never source permission, independent
judgments, human attestation or a Phase A/B seal. Even complete authored labels
cannot make this draft-audit boundary admit a primary experiment.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import PurePosixPath

from .budget import RetrievalError
from .contracts import digest, hex_digest, label, sha
from .lines import physical_lines

LANGUAGES = ('en', 'ru', 'mixed')
SPLITS = ('development', 'holdout')
STRATA = ('exact', 'behavior', 'boundary', 'multi', 'no_answer')


@dataclass(frozen=True)
class AuditProfile:
    function_counts: tuple[tuple[str, int], ...]
    per_stratum: int
    universe_digests: tuple[tuple[str, str], ...] = ()
    partition_digest: str | None = None
    development_en_digest: str | None = None


# Original implementation-inclusive, non-overload inventories; not qrel seals.
ISSUE_162_PROFILE = AuditProfile((('small', 55), ('large', 2194)), 4, (
    ('small', 'd64974e092c53c7276e9473c2733280298c36280386af2fbb06c5ea13fa60d79'),
    ('large', '134f207a72666e4f834c0220968d29e4640808d80f52a4d1917cdf8e7dd5c91b')),
    partition_digest='3d486f194c56e672d204a77027d05e6f67e89a4aa23417ea0443bc8d4184b424',
    development_en_digest='00f3fed2ba9843f815ed20703d51bb69358a61efc042414b159c01f5187ddee5')


@dataclass(frozen=True)
class DraftAudit:
    tasks: int
    variants: int
    holdouts: int
    functions: int
    source_files: int
    judgment_cells: int
    unjudged_cells: int

    def to_dict(self):
        return {**self.__dict__, 'status': 'draft_valid', 'primary_eligible_tasks': 0,
            'ranking_permitted': False, 'qualification': 'unsealed_metadata_only'}

    def require_rankable(self):
        raise RetrievalError('independent_seals_required')


def _shape(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise RetrievalError('invalid_input_shape')


def _version(value):
    if type(value) is not int or value != 1:
        raise RetrievalError('invalid_input_shape')


def checked_relative(value):
    """Validate a public artifact path before any optional consumer reads it."""
    if (not label(value) or '\\' in value or ':' in value
            or PurePosixPath(value).is_absolute() or '..' in PurePosixPath(value).parts
            or PurePosixPath(value).as_posix() != value or value == '.'):
        raise RetrievalError('invalid_source_path')
    return value


def _profile(profile):
    if (type(profile) is not AuditProfile or type(profile.function_counts) is not tuple
            or not 1 <= len(profile.function_counts) <= 2 or type(profile.per_stratum) is not int
            or not 1 <= profile.per_stratum <= 4):
        raise RetrievalError('invalid_audit_profile')
    try:
        counts = dict(profile.function_counts)
        pins = dict(profile.universe_digests)
    except (ValueError, TypeError):
        raise RetrievalError('invalid_audit_profile') from None
    if (len(counts) != len(profile.function_counts) or set(counts) - {'small', 'large'}
            or any(type(n) is not int or not 1 <= n <= 8192 for n in counts.values())
            or sum(counts.values()) > 8192
            or len(pins) != len(profile.universe_digests) or set(pins) - set(counts)
            or any(not hex_digest(value) for value in pins.values())
            or any(value is not None and not hex_digest(value)
                for value in (profile.partition_digest, profile.development_en_digest))):
        raise RetrievalError('invalid_audit_profile')
    return counts, pins


def source_references(document, *, profile=ISSUE_162_PROFILE):
    """Validate catalog pins before a public-artifact consumer opens source files."""
    try:
        counts, pins = _profile(profile)
        _shape(document, ('schema_version', 'authority', 'universes'))
        _version(document['schema_version'])
        if type(document['universes']) is not list or len(document['universes']) != len(counts):
            raise RetrievalError('universe_scope_mismatch')
        seen, references = set(), set()
        for universe in document['universes']:
            _shape(universe, ('corpus', 'source_commit', 'universe_digest', 'functions'))
            corpus = universe['corpus']
            if (corpus not in counts or corpus in seen or type(universe['functions']) is not list
                    or len(universe['functions']) != counts[corpus]
                    or universe['universe_digest'] != digest(universe['functions'])
                    or corpus in pins and universe['universe_digest'] != pins[corpus]):
                raise RetrievalError('universe_scope_mismatch')
            seen.add(corpus)
            for function in universe['functions']:
                if type(function) is not dict or function.get('corpus') != corpus or 'path' not in function:
                    raise RetrievalError('invalid_input_shape')
                references.add((corpus, checked_relative(function['path'])))
        if len(references) > 4000:
            raise RetrievalError('source_inventory_exceeded')
        return tuple(sorted(references))
    except RetrievalError:
        raise
    except (TypeError, ValueError, KeyError, RecursionError, OverflowError):
        raise RetrievalError('invalid_input_shape') from None


def _universes(document, source_bytes, counts, pins):
    _shape(document, ('schema_version', 'authority', 'universes'))
    _version(document['schema_version'])
    if not isinstance(document['authority'], str) or type(document['universes']) is not list:
        raise RetrievalError('invalid_input_shape')
    if type(source_bytes) is not dict or len(source_bytes) > 4000:
        raise RetrievalError('source_inventory_exceeded')
    if any(type(raw) is not bytes or len(raw) > 1048576 for raw in source_bytes.values()):
        raise RetrievalError('source_file_mismatch')
    if sum(len(raw) for raw in source_bytes.values()) > 32 * 1024 * 1024:
        raise RetrievalError('source_inventory_exceeded')
    source_bytes = dict(source_bytes)  # Bytes are immutable; capture this mapping once.
    by_corpus, used_files, seen_ids, historical_ids = {}, set(), set(), set()
    file_lines = {}
    for universe in document['universes']:
        _shape(universe, ('corpus', 'source_commit', 'universe_digest', 'functions'))
        corpus = universe['corpus']
        if corpus not in counts or corpus in by_corpus or type(universe['functions']) is not list:
            raise RetrievalError('universe_scope_mismatch')
        if len(universe['functions']) != counts[corpus]:
            raise RetrievalError('universe_scope_mismatch')
        for function in universe['functions']:
            _shape(function, ('function_id', 'corpus', 'source_commit', 'source_key', 'path', 'start',
                'end', 'symbol', 'file_sha256', 'declaration_sha256', 'historical_id'))
            identity = {k: v for k, v in function.items() if k != 'function_id'}
            if function['function_id'] != digest(identity):
                raise RetrievalError('function_identity_mismatch')
            source_key = function['source_key']
            if (function['corpus'] != corpus or function['source_commit'] != universe['source_commit']
                    or type(source_key) is not list or len(source_key) != 5
                    or any(not label(value) for value in source_key)
                    or source_key[:2] != ['public-fixture', corpus]
                    or not label(function['symbol']) or not label(function['historical_id'])
                    or not isinstance(universe['source_commit'], str)
                    or len(universe['source_commit']) not in (40, 64)
                    or any(c not in '0123456789abcdef' for c in universe['source_commit'])):
                raise RetrievalError('function_identity_mismatch')
            path = checked_relative(function['path'])
            function_id = function['function_id']
            historical = corpus, function['historical_id']
            if function_id in seen_ids or historical in historical_ids:
                raise RetrievalError('function_identity_mismatch')
            seen_ids.add(function_id)
            historical_ids.add(historical)
            key = corpus, path
            if key not in file_lines:
                raw = source_bytes.get(key)
                if raw is None:
                    raise RetrievalError('source_file_mismatch')
                file_lines[key] = sha(raw), physical_lines(raw)
            file_hash, lines = file_lines[key]
            if file_hash != function['file_sha256']:
                raise RetrievalError('source_file_mismatch')
            start, end = function['start'], function['end']
            if (type(start) is not int or type(end) is not int or not 1 <= start <= end <= len(lines)
                    or sha(b''.join(lines[start - 1:end])) != function['declaration_sha256']):
                raise RetrievalError('declaration_mismatch')
            used_files.add((corpus, path))
        if (universe['universe_digest'] != digest(universe['functions'])
                or corpus in pins and universe['universe_digest'] != pins[corpus]):
            raise RetrievalError('universe_scope_mismatch')
        by_corpus[corpus] = universe
    if set(by_corpus) != set(counts):
        raise RetrievalError('universe_scope_mismatch')
    return by_corpus, used_files


def _tasks(document, counts, per_stratum):
    _shape(document, ('schema_version', 'status', 'tasks'))
    _version(document['schema_version'])
    if type(document['tasks']) is not list or len(document['tasks']) != len(counts) * 10 * per_stratum:
        raise RetrievalError('partition_scope_mismatch')
    tasks, groups, clusters = {}, Counter(), set()
    for task in document['tasks']:
        _shape(task, ('task_id', 'cluster_id', 'corpus', 'split', 'stratum', 'partition_status',
            'novelty_independently_reviewed'))
        if (not label(task['task_id']) or not label(task['cluster_id']) or task['task_id'] in tasks
                or task['cluster_id'] in clusters or task['corpus'] not in counts
                or task['split'] not in SPLITS or task['stratum'] not in STRATA):
            raise RetrievalError('partition_scope_mismatch')
        if task['novelty_independently_reviewed'] is not False or task['partition_status'] != 'provisional':
            raise RetrievalError('unqualified_review_claim')
        tasks[task['task_id']] = task
        clusters.add(task['cluster_id'])
        groups[task['corpus'], task['split'], task['stratum']] += 1
    expected = {(c, s, k): per_stratum for c in counts for s in SPLITS for k in STRATA}
    if groups != expected:
        raise RetrievalError('partition_scope_mismatch')
    return tasks


def _queries(document, tasks):
    _shape(document, ('schema_version', 'status', 'queries'))
    _version(document['schema_version'])
    if type(document['queries']) is not list or len(document['queries']) != 3 * len(tasks):
        raise RetrievalError('query_scope_mismatch')
    groups, seen = Counter(), set()
    for query in document['queries']:
        _shape(query, ('query_id', 'task_id', 'language', 'text', 'semantic_equivalence_review'))
        if (query['task_id'] not in tasks or query['language'] not in LANGUAGES
                or not label(query['query_id']) or query['query_id'] in seen
                or type(query['text']) is not str or not query['text'].strip()
                or len(query['text'].encode('utf-8')) > 8192):
            raise RetrievalError('query_scope_mismatch')
        if query['semantic_equivalence_review'] != 'unreviewed':
            raise RetrievalError('unqualified_review_claim')
        seen.add(query['query_id'])
        groups[query['task_id'], query['language']] += 1
    if groups != {(t, language): 1 for t in tasks for language in LANGUAGES}:
        raise RetrievalError('query_scope_mismatch')


def _judgments(document, universes, tasks):
    _shape(document, ('schema_version', 'status', 'encoding', 'tables'))
    _version(document['schema_version'])
    if document['encoding'] != {'0': 'unjudged', '1': 'relevant', '2': 'nonrelevant'}:
        raise RetrievalError('invalid_judgment')
    if type(document['tables']) is not list or len(document['tables']) != len(universes):
        raise RetrievalError('judgment_scope_mismatch')
    cells, unjudged, corpora = 0, 0, set()
    for table in document['tables']:
        _shape(table, ('corpus', 'universe_digest', 'function_ids', 'rows'))
        corpus = table['corpus']
        if corpus not in universes or corpus in corpora:
            raise RetrievalError('judgment_scope_mismatch')
        corpora.add(corpus)
        universe = universes[corpus]
        expected_tasks = {t for t, row in tasks.items() if row['corpus'] == corpus}
        if (table['universe_digest'] != universe['universe_digest']
                or table['function_ids'] != [f['function_id'] for f in universe['functions']]
                or type(table['rows']) is not list or len(table['rows']) != len(expected_tasks)):
            raise RetrievalError('judgment_scope_mismatch')
        seen = set()
        for row in table['rows']:
            _shape(row, ('task_id', 'judgments', 'eligible_primary', 'independent_review'))
            if (row['task_id'] not in expected_tasks or row['task_id'] in seen
                    or type(row['judgments']) is not list or len(row['judgments']) != len(table['function_ids'])):
                raise RetrievalError('judgment_scope_mismatch')
            if row['eligible_primary'] is not False or row['independent_review'] != 'absent':
                raise RetrievalError('unqualified_review_claim')
            if any(type(value) is not int or value not in (0, 1, 2) for value in row['judgments']):
                raise RetrievalError('invalid_judgment')
            seen.add(row['task_id'])
            cells += len(row['judgments'])
            unjudged += row['judgments'].count(0)
    return cells, unjudged


def audit_draft_inputs(universes, partition, queries, qrels, source_bytes, *, profile=ISSUE_162_PROFILE):
    """Check draft source/data closure; never infer relevance, independence or access."""
    try:
        counts, pins = _profile(profile)
        by_corpus, used_files = _universes(universes, source_bytes, counts, pins)
        if profile.partition_digest is not None and digest(partition) != profile.partition_digest:
            raise RetrievalError('partition_scope_mismatch')
        tasks = _tasks(partition, counts, profile.per_stratum)
        _queries(queries, tasks)
        original_en = sorted((q['task_id'], q['text']) for q in queries['queries']
            if q['language'] == 'en' and tasks[q['task_id']]['split'] == 'development')
        if profile.development_en_digest is not None and digest(original_en) != profile.development_en_digest:
            raise RetrievalError('development_query_mismatch')
        cells, unjudged = _judgments(qrels, by_corpus, tasks)
        return DraftAudit(len(tasks), len(queries['queries']), sum(t['split'] == 'holdout' for t in tasks.values()),
            sum(counts.values()), len(used_files), cells, unjudged)
    except RetrievalError:
        raise
    except (TypeError, ValueError, RecursionError, OverflowError):
        raise RetrievalError('invalid_input_shape') from None
