"""Fixed numerical kernels; no model imports, runtime or admission authority."""
from __future__ import annotations

import math

DIMENSIONS = {'minilm': 384, 'bge_m3': 1024}


def _vector(value, dimension):
    if (type(value) not in {tuple, list} or len(value) != dimension
            or any(type(item) not in {int, float} or not math.isfinite(item)
                   for item in value)):
        raise ValueError('invalid_study_vector')
    return tuple(float(item) for item in value)


def pool_hidden(model, hidden, mask):
    """Pool one batch's raw token states after the worker checked rank3 FP32.

Mean includes every active token, including actual special tokens. BGE takes
the first active CLS state; neither branch accepts an already pooled vector.
"""
    if (type(model) is not str or model not in DIMENSIONS
            or type(hidden) not in {tuple, list} or not 1 <= len(hidden) <= 256
            or type(mask) not in {tuple, list} or len(mask) != len(hidden)
            or any(type(item) is not int or item not in {0, 1} for item in mask)
            or not mask[0] or not sum(mask)):
        raise ValueError('invalid_hidden_states')
    dimension = DIMENSIONS[model]
    rows = tuple(_vector(row, dimension) for row in hidden)
    if model == 'minilm':
        active = sum(mask)
        pooled = tuple(math.fsum(row[column] for row, keep in zip(rows, mask) if keep)
                       / active for column in range(dimension))
    else:
        pooled = rows[0]
    norm = math.sqrt(math.fsum(item * item for item in pooled))
    if not math.isfinite(norm):
        raise ValueError('invalid_study_vector')
    divisor = max(norm, 1e-12)
    return tuple(item / divisor for item in pooled)


def dense_ranks(query, vectors):
    """Keep all signed dense scores and original-ID ties, up to original top100."""
    if (type(query) not in {tuple, list} or not 1 <= len(query) <= 1024
            or type(vectors) is not dict or len(vectors) > 8192
            or any(type(key) is not str or not key for key in vectors)):
        raise ValueError('invalid_study_index')
    query = _vector(query, len(query))
    rows = [(key, math.fsum(left * right for left, right in
                          zip(query, _vector(vector, len(query)))))
            for key, vector in vectors.items()]
    if any(not math.isfinite(score) for _, score in rows):
        raise ValueError('invalid_study_score')
    return tuple(sorted(rows, key=lambda row: (-row[1], row[0]))[:100])


def rrf_ranks(arms):
    """Exactly three equally weighted original top100 arms, fixed k60."""
    if type(arms) not in {tuple, list} or len(arms) != 3:
        raise ValueError('invalid_study_arms')
    scores = {}
    for arm in arms:
        if (type(arm) not in {tuple, list} or len(arm) > 100
                or any(type(key) is not str or not key for key in arm)
                or len(set(arm)) != len(arm)):
            raise ValueError('invalid_study_arms')
        for position, key in enumerate(arm, 1):
            scores[key] = scores.get(key, 0.0) + 1 / (60 + position)
    return tuple(sorted(scores.items(), key=lambda row: (-row[1], row[0]))[:100])
