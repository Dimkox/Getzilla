"""The fixed162 identifier/BM25/RRF formulas, without an embedding dependency.

Reference: research3247f7bc, engineering/benchmarks/issue162/benchmark.py.
This initial no-encoder function-window profile is distinct from its sealed
MiniLM254-token windows; it cannot replace that comparison's frozen windows.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import math
import re

from .budget import RetrievalError
from .observation import stage


def tokens(text):
    result = []
    for full in re.findall(r'[A-Za-z_][A-Za-z_0-9]*|[0-9]+', text):
        pieces = re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', full).replace('_', ' ').lower().split()
        result.append(full.lower())
        result.extend(p for p in pieces if p != full.lower())
    return result


@dataclass(frozen=True)
class RankedHit:
    chunk: object
    score: float
    rank: int


def _ranking(chunks, scores):
    return tuple(RankedHit(chunks[i], float(scores[i]), rank)
        for rank, i in enumerate(sorted((i for i, score in enumerate(scores) if score > 0),
            key=lambda i: (-scores[i], chunks[i].id))[:100], 1))


def _lexical(chunks, query, budget):
    if not isinstance(query, str):
        raise RetrievalError('invalid_query')
    if len(query.encode('utf-8')) > 4096:
        raise RetrievalError('query_bytes_exceeded')
    terms = tokens(query)
    if len(terms) > 64:
        raise RetrievalError('query_terms_exceeded')
    budget.charge('query_source_bytes', sum(len(c.text.encode()) for c in chunks))
    budget.charge('scoring_units', len(chunks) * max(1, len(terms)))
    exact = set(re.findall(r'[A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)*', query))
    exact |= {part for item in tuple(exact) for part in item.split('.')}
    symbols, counts = [], []
    for index, chunk in enumerate(chunks):
        if index % 256 == 0:
            budget.check()
        names = set(re.findall(r'[A-Za-z_][A-Za-z_0-9]*', chunk.symbol)) | {chunk.symbol}
        symbols.append(len(exact & names))
        counts.append(Counter(tokens(chunk.text)))
    lengths = [sum(row.values()) for row in counts]
    average = sum(lengths) / len(lengths) if lengths else 0
    frequencies = Counter(term for row in counts for term in row)
    scores = [0.0] * len(chunks)
    if average:
        for term in terms:
            df = frequencies[term]
            idf = math.log(1 + (len(chunks) - df + .5) / (df + .5))
            for index, row in enumerate(counts):
                if index % 256 == 0:
                    budget.check()
                tf = row.get(term, 0)
                scores[index] += idf * tf * 2.2 / (tf + 1.2 * (.25 + .75 * lengths[index] / average))
    exact_rank, bm25_rank = _ranking(chunks, symbols), _ranking(chunks, scores)
    return exact_rank, bm25_rank


def rank(chunks, query, budget):
    with stage('lexical') as measured:
        exact_rank, bm25_rank = _lexical(chunks, query, budget)
        measured.result('succeeded' if exact_rank or bm25_rank else 'empty',
                        candidate_count=len({hit.chunk.id for hit in (*exact_rank, *bm25_rank)}))
    with stage('fusion') as measured:
        fused, by_id = defaultdict(float), {c.id: c for c in chunks}
        for arm in (exact_rank, bm25_rank):
            for hit in arm:
                fused[hit.chunk.id] += 1 / (60 + hit.rank)
        rrf = tuple(RankedHit(by_id[key], fused[key], position) for position, key in enumerate(
            sorted(fused, key=lambda k: (-fused[k], k))[:100], 1))
        budget.check()
        measured.result('succeeded' if rrf else 'empty', candidate_count=len(rrf))
    return {'exact_symbol': exact_rank, 'bm25': bm25_rank, 'rrf': rrf}
