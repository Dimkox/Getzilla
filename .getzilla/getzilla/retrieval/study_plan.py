"""Compiled public study order and data joins; no admission or model execution."""
from __future__ import annotations

from .budget import RetrievalError
from .contracts import sha
from .study_windows import FUNCTION_FIELDS

ARMS = ('exact_symbol', 'bm25', 'dense_minilm', 'dense_bge_m3', 'rrf_minilm', 'rrf_bge_m3')
MODELS = ('minilm', 'bge_m3')
WARM_PASSES = 10
EXPECTED_WINDOWS = {'small': 64, 'large': 3820}
EXPECTED_FUNCTIONS = {'small': 55, 'large': 2194}
STAGE_LIMITS = {'windows': 900, 'cold': 180, 'small-index': 300,
                'minilm-large-index': 900, 'bge_m3-large-index': 7200, 'total': 14400}


def query_schedule(queries):
    ids = tuple(row['query_id'] for row in queries)
    if not ids or len(ids) != len(set(ids)) or any(type(key) is not str for key in ids):
        raise RetrievalError('study_query_schedule_unavailable')
    return tuple((model, iteration, key) for model in MODELS
                 for iteration in range(WARM_PASSES) for key in ids)


def original_function_mapping(universes, original_functions):
    grouped, mapping = {}, {}
    for universe in universes['universes']:
        corpus = universe['corpus']
        for row in universe['functions']:
            key = corpus, row['historical_id']
            if key in mapping:
                raise RetrievalError('study_function_mapping_unavailable')
            mapping[key] = row['function_id']
    seen = set()
    for corpus, functions in original_functions:
        for row in functions:
            if type(row) is not dict or set(row) != FUNCTION_FIELDS or (corpus, row['id']) in seen:
                raise RetrievalError('study_function_mapping_unavailable')
            seen.add((corpus, row['id']))
            grouped.setdefault((corpus, row['path']), []).append(dict(row))
    return {key: tuple(rows) for key, rows in grouped.items()}, mapping


def map_source_documents(catalog, documents):
    expected = {}
    for corpus, path, commit, size, checksum in catalog:
        key = commit, sha((corpus + '/' + path).encode())
        if key in expected:
            raise RetrievalError('study_source_catalog_unavailable')
        expected[key] = corpus, path, size, checksum
    seen, result = set(), []
    for document in documents:
        dependency, raw = document.dependency, document.content
        key = dependency.key[-2:]
        if key not in expected or key in seen:
            raise RetrievalError('study_source_cut_mismatch')
        corpus, path, size, checksum = expected[key]
        if (type(raw) is not bytes or len(raw) != size or sha(raw) != checksum
                or dependency.version != 'sha256:' + checksum
                or dependency.content_sha256 != checksum or dependency.representation_sha256 != checksum
                or dependency.transform_version != 'exact-public-original-v1'):
            raise RetrievalError('study_source_cut_mismatch')
        seen.add(key)
        result.append((corpus, path, raw))
    return tuple(result)


def project_function_positions(window_ids, windows, historical_to_stable):
    # Preserve each unavailable original slot. Do not filter/refill a top100.
    result = []
    for key in window_ids:
        row = windows.get(key)
        original = row.get('function_id') if row is not None else None
        result.append(historical_to_stable.get(original, 'unjudged-window:' + key))
    return tuple(result)
