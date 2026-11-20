"""Exact fixed-denominator summaries of retained observations, not run authority."""
from __future__ import annotations

from fractions import Fraction
import math
import json
import time

from .budget import RetrievalError
from .contracts import digest
from .study_plan import MODELS, WARM_PASSES


def _ratio(value):
    if (type(value) not in {tuple, list} or len(value) != 2
            or any(type(item) is not int for item in value)
            or not 0 <= value[0] <= value[1] or not 1 <= value[1] <= 89960):
        raise RetrievalError('study_metric_ratio_unavailable')
    return Fraction(*value)


def paired_ratios(task_ids, baseline, candidate):
    if (type(task_ids) not in {tuple, list} or len(task_ids) != 16
            or len(set(task_ids)) != 16 or any(type(key) is not str for key in task_ids)
            or type(baseline) is not dict or type(candidate) is not dict
            or any(key not in task_ids for rows in (baseline, candidate) for key in rows)):
        raise RetrievalError('study_holdout_slice_unavailable')
    missing = [key for key in task_ids if baseline.get(key) is None or candidate.get(key) is None]
    for rows in (baseline, candidate):
        for value in rows.values():
            if value is not None:
                _ratio(value)
    delta = None if missing else sum((_ratio(candidate[key]) - _ratio(baseline[key])
                                     for key in task_ids), Fraction()) / 16
    return {'status': 'INCONCLUSIVE' if missing else 'PASS' if delta >= Fraction(-1, 20) else 'FAIL',
            'denominator': 16, 'missing_tasks': missing,
            'mean_delta': None if delta is None else float(delta),
            'mean_delta_ratio': None if delta is None else [delta.numerator, delta.denominator],
            'maximum_drop_ratio': [1, 20]}


class Observations:
    def __init__(self, query_ids):
        if (type(query_ids) not in {tuple, list} or not 1 <= len(query_ids) <= 240
                or len(set(query_ids)) != len(query_ids)
                or any(type(key) is not str for key in query_ids)):
            raise RetrievalError('study_query_scope_unavailable')
        self.query_ids, self._rows = tuple(query_ids), {}

    def add(self, model, iteration, query_id, result, *, seconds, error=None,
            absolute_deadline=None, query_started=None):
        key = model, iteration, query_id
        if (model not in MODELS or type(iteration) is not int or not 0 <= iteration < WARM_PASSES
                or query_id not in self.query_ids or key in self._rows
                or type(seconds) not in {float, int} or not math.isfinite(seconds) or seconds < 0
                or result is not None and type(result) is not dict
                or error is not None and type(error) is not str):
            raise RetrievalError('study_observation_conflict')
        if absolute_deadline is not None or query_started is not None:
            if (type(absolute_deadline) is not float or type(query_started) is not float
                    or not math.isfinite(absolute_deadline) or not math.isfinite(query_started)
                    or not query_started < absolute_deadline or time.monotonic() >= absolute_deadline):
                raise RetrievalError('study_query_deadline')
        frozen = json.loads(json.dumps(result, ensure_ascii=False, allow_nan=False))
        checksum = digest({'result': frozen, 'error': error})
        if absolute_deadline is not None:
            now = time.monotonic()
            if now >= absolute_deadline:
                raise RetrievalError('study_query_deadline')
            seconds = now - query_started
        self._rows[key] = {'result': frozen, 'seconds': seconds, 'error': error, 'digest': checksum}

    def first(self, model, query_id):
        return json.loads(json.dumps(self._rows.get((model, 0, query_id)), allow_nan=False))

    def nondeterministic(self):
        changed = []
        for model in MODELS:
            for query in self.query_ids:
                values = {row['digest'] for (m, _, q), row in self._rows.items() if m == model and q == query}
                if len(values) > 1:
                    changed.append((model, query))
        return tuple(changed)

    def coverage(self):
        expected = len(MODELS) * WARM_PASSES * len(self.query_ids)
        return {'expected': expected, 'observed': len(self._rows),
                'failed': sum(row['error'] is not None for row in self._rows.values()),
                'complete': len(self._rows) == expected,
                'nondeterministic': self.nondeterministic()}

    def timings(self):
        return tuple({'model': model, 'pass': iteration, 'query_id': query,
                      'seconds': row['seconds'], 'error': row['error'], 'result_digest': row['digest']}
                     for (model, iteration, query), row in self._rows.items())
