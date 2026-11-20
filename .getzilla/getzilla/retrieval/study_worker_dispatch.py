"""Fixed native-child data plane. Only its owned host admits these operations.

No module import loads optional packages. Inputs are fixed driver-generated
public bytes/configs; this is never a public caller text/model/command API.
"""
from __future__ import annotations

from dataclasses import asdict
import gc
import os
import stat
import time
import hashlib

from .budget import Budget, RetrievalError
from .contracts import sha
from .study_windows import windows_for_file

CONTROL = {'nonce', 'sequence', 'absolute_deadline'}
MODELS = {'minilm', 'bge_m3'}


def _fields(request, expected):
    if set(request) != CONTROL | {'op'} | set(expected):
        raise RetrievalError('study_worker_request_unavailable')


def _budget(request):
    remaining = min(2, request['absolute_deadline'] - time.monotonic())
    if remaining <= 0:
        raise RetrievalError('deadline_exceeded')
    return Budget(seconds=remaining)


def _codec_bytes(path):
    from .study_codec import CODEC_BYTES, CODEC_SHA256
    if path != '/model/codec/o200k_base.tiktoken':
        raise RetrievalError('codec_path_unavailable')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size != CODEC_BYTES or stat.S_IMODE(before.st_mode) != 0o444):
            raise RetrievalError('codec_data_unavailable')
        raw = bytearray()
        while len(raw) <= CODEC_BYTES:
            block = os.read(descriptor, min(65536, CODEC_BYTES - len(raw) + 1))
            if not block:
                break
            raw.extend(block)
        after, named = os.fstat(descriptor), os.stat(path, follow_symlinks=False)
        keys = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if (any(getattr(before, key) != getattr(after, key) or getattr(before, key) != getattr(named, key)
                for key in keys) or len(raw) != CODEC_BYTES or sha(raw) != CODEC_SHA256):
            raise RetrievalError('codec_data_unavailable')
        return bytes(raw)
    finally:
        os.close(descriptor)


def _native(state):
    import numpy as np
    import onnxruntime as ort
    import tokenizers
    import tiktoken
    from .study_codec import CodecCounter, parse_ranks
    codec = CodecCounter(tiktoken, parse_ranks(_codec_bytes('/model/codec/o200k_base.tiktoken')))
    state.update(native_ready=True, np=np, ort=ort, tokenizer_module=tokenizers, codec=codec)
    return {'numpy': np.__version__, 'onnxruntime': ort.__version__,
            'tokenizers': tokenizers.__version__, 'tiktoken': tiktoken.__version__,
            'codec_sha256': codec.identity, 'network_policy': 'none', 'network_attempts': 'unknown'}


def _tokenizer(model, state):
    if model not in MODELS:
        raise RetrievalError('study_model_unavailable')
    from .study_tokenizer import TokenizerCounter
    path = f'/model/{model}/tokenizer.json'
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o444
                or before.st_nlink != 1 or not 0 < before.st_size <= 20 * 1024**2):
            raise RetrievalError('tokenizer_file_unavailable')
        hasher, count = hashlib.sha256(), 0
        while True:
            raw = os.read(descriptor, 65536)
            if not raw:
                break
            count += len(raw)
            if count > before.st_size:
                raise RetrievalError('tokenizer_file_unavailable')
            hasher.update(raw)
        native = state['tokenizer_module'].Tokenizer.from_file(path)
        after, named = os.fstat(descriptor), os.stat(path, follow_symlinks=False)
        keys = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if (count != before.st_size or any(getattr(before, key) != getattr(after, key)
                or getattr(before, key) != getattr(named, key) for key in keys)):
            raise RetrievalError('tokenizer_file_unavailable')
    finally:
        os.close(descriptor)
    native.no_padding()
    native.no_truncation()
    empty = native.encode('', add_special_tokens=True).ids
    if type(empty) is not list or len(empty) != 2 or any(type(item) is not int for item in empty):
        raise RetrievalError('tokenizer_template_unavailable')
    counter = TokenizerCounter(native, hasher.hexdigest(), end_token_id=empty[-1])
    state.setdefault('tokenizers', {})[model] = counter
    if model == 'minilm':
        state['window_counter'] = counter
    return {'model': model, 'empty_ids': empty, 'end_token_id': empty[-1],
            'tokenizer_sha256': counter.identity, 'special_tokens_counted': True}


def _window_request(request, state):
    _fields(request, {'corpus', 'path', 'raw', 'functions'})
    if type(request['raw']) is not str or 'window_counter' not in state:
        raise RetrievalError('study_windows_unavailable')
    rows = windows_for_file(request['corpus'], request['path'], request['raw'].encode(),
        request['functions'], state['window_counter'], budget=_budget(request))
    windows = state.setdefault('windows', {}).setdefault(request['corpus'], {})
    if any(row.id in windows for row in rows):
        raise RetrievalError('study_window_repeated')
    if (sum(len(value) for value in state['windows'].values()) + len(rows) > 8192
            or sum(len(row.text.encode()) for value in state['windows'].values()
                   for row in value.values()) + sum(len(row.text.encode()) for row in rows) > 32 * 1024**2):
        raise RetrievalError('study_index_exceeded')
    windows.update((row.id, row) for row in rows)
    # Public source bytes stay inside the owned process; only provenance mapping
    # and counts return on this inspection frame, never a caller-provided path.
    records = [{key: value for key, value in asdict(row).items() if key != 'text'}
               | {'id': row.id} for row in rows]
    return {'count': len(rows), 'windows': records}


def _load_model(request, state):
    _fields(request, {'model', 'contract'})
    from .study_onnx_worker import ModelContract, _open_session
    model, value = request['model'], request['contract']
    if (model not in MODELS or type(value) is not dict or set(value) !=
            {'inputs', 'output', 'input_shape', 'output_shape', 'additional_outputs'}
            or model not in state.get('tokenizers', {})):
        raise RetrievalError('study_model_unavailable')
    contract = ModelContract(model, tuple(value['inputs']), value['output'], tuple(value['input_shape']),
        tuple(value['output_shape']), tuple((item[0], item[1], tuple(item[2]))
                                           for item in value['additional_outputs']))
    # One native model at a time. No fallback, precision change or parallel load.
    state.pop('session', None)
    gc.collect()
    started = time.monotonic()
    session = _open_session(f'/model/{model}/onnx/model.onnx', contract, state['ort'])
    state.update(session=session, contract=contract, model=model)
    return {'model': model, 'load_seconds': time.monotonic() - started,
            'providers': session.get_providers(), 'batch_size': 1, 'precision': 'float32'}


def _encode(request, state):
    from .study_onnx_worker import _encode_one
    kind = request.get('kind')
    if kind == 'window':
        _fields(request, {'kind', 'corpus', 'window_id'})
        corpus, key = request['corpus'], request['window_id']
        row = state.get('windows', {}).get(corpus, {}).get(key)
        if row is None:
            raise RetrievalError('study_window_unavailable')
        result = _encode_one(state['session'], state['contract'],
                             state['tokenizers'][state['model']], row.text, state['np'])
        vectors = state.setdefault('vectors', {}).setdefault((state['model'], corpus), {})
        if key in vectors:
            raise RetrievalError('study_encode_repeated')
        vectors[key] = result['vector']
        return {'window_id': key, 'raw_tokens': result['raw_tokens'], 'truncated': result['truncated']}
    if kind == 'query':
        _fields(request, {'kind', 'corpus', 'query_id', 'text'})
        if type(request['text']) is not str or len(request['text'].encode()) > 4096:
            raise RetrievalError('invalid_query')
        result = _encode_one(state['session'], state['contract'],
                             state['tokenizers'][state['model']], request['text'], state['np'])
        state['query'] = (request['query_id'], request['corpus'], request['text'], result['vector'])
        return {'query_id': request['query_id'], 'raw_tokens': result['raw_tokens'],
                'truncated': result['truncated']}
    raise RetrievalError('study_encode_unavailable')


def _score(request, state):
    _fields(request, {'corpus', 'query_id'})
    from .study_lexical import LexicalIndex
    from .study_vectors import rrf_ranks
    from .study_context import pack_context
    corpus = request['corpus']
    query_id, query_corpus, text, vector = state['query']
    if (request['query_id'], corpus) != (query_id, query_corpus):
        raise RetrievalError('study_query_changed')
    windows = state['windows'][corpus]
    rows = tuple(windows[key] for key in sorted(windows))
    vectors = state['vectors'][(state['model'], corpus)]
    if set(vectors) != set(windows):
        raise RetrievalError('study_index_incomplete')
    budget, np = _budget(request), state['np']
    index = state.setdefault('lexical', {}).get(corpus)
    if index is None:
        index = LexicalIndex(rows, budget=budget)
        state['lexical'][corpus] = index
    ranked = index.query(text, budget=budget)
    matrix = np.asarray([vectors[row.id] for row in rows], dtype=np.float32)
    scores = matrix @ np.asarray(vector, dtype=np.float32)
    if not np.isfinite(scores).all():
        raise RetrievalError('study_score_nonfinite')
    dense = tuple((rows[i].id, float(scores[i])) for i in sorted(range(len(rows)),
                  key=lambda i: (-float(scores[i]), rows[i].id))[:100])
    ranked['dense_' + state['model']] = dense
    ranked['rrf_' + state['model']] = rrf_ranks(tuple(tuple(key for key, _ in arm)
        for arm in (ranked['exact_symbol'], ranked['bm25'], dense)))
    packing = {}
    for arm, ranking in ranked.items():
        packing[arm] = {}
        for limit in (2048, 8192):
            packed = pack_context([key for key, _ in ranking], windows, state['codec'], limit, budget=budget)
            packing[arm][str(limit)] = {'tokens': packed.tokens, 'functions': packed.functions,
                'positions': packed.included_positions, 'context_sha256': sha(packed.text.encode())}
    budget.check()
    return {'query_id': query_id, 'model': state['model'], 'rankings': ranked, 'packing': packing}


def dispatch(request, state):
    if type(request) is not dict or type(request.get('op')) is not str:
        raise RetrievalError('study_worker_request_unavailable')
    op = request['op']
    if op == 'native-import':
        _fields(request, ())
        if state.get('native_ready'):
            raise RetrievalError('study_native_import_repeated')
        return _native(state)
    if not state.get('native_ready'):
        raise RetrievalError('study_native_unavailable')
    if op == 'load-tokenizer':
        _fields(request, {'model'})
        return _tokenizer(request['model'], state)
    if op == 'windows':
        return _window_request(request, state)
    if op == 'load-model':
        return _load_model(request, state)
    if op == 'encode' and 'session' in state:
        return _encode(request, state)
    if op == 'score' and 'query' in state:
        return _score(request, state)
    if op == 'release':
        _fields(request, ())
        return {'status': 'ready_for_host_current_release'}
    raise RetrievalError('study_worker_request_unavailable')
