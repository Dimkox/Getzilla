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
    differences = {key: None if baseline.get(key) is None or candidate.get(key) is None else
                   _ratio(candidate[key]) - _ratio(baseline[key]) for key in task_ids}
    return {'status': 'INCONCLUSIVE' if missing else 'PASS' if delta >= Fraction(-1, 20) else 'FAIL',
            'denominator': 16, 'missing_tasks': missing,
            'mean_delta': None if delta is None else float(delta),
            'mean_delta_ratio': None if delta is None else [delta.numerator, delta.denominator],
            'maximum_drop_ratio': [1, 20],
            'paired_task_deltas': {key: None if value is None else [value.numerator, value.denominator]
                                   for key, value in differences.items()}}


def _percentiles(values):
    """Published statistics.median and NumPy percentile default linear rule."""
    values = sorted(values)
    def linear(percent):
        position = (len(values) - 1) * percent
        lower = int(position)
        return values[lower] + (values[min(lower + 1, len(values) - 1)] - values[lower]) * (position - lower)
    return {'p50': linear(.5), 'p95': linear(.95), 'minimum': values[0], 'maximum': values[-1]}


def measurement_summary(rows):
    if type(rows) not in {list, tuple} or len(rows) > 81920:
        raise RetrievalError('study_measurements_unavailable')
    groups, peaks = {}, []
    phases = {'cold_load', 'windowing', 'index', 'window_encoding', 'query_encoding', 'query_total',
              'lexical', 'dense_score', 'rrf', 'score_and_packing'}
    from .study_plan import ARMS
    phases |= {'packing:' + arm + ':' + str(limit) for arm in ARMS for limit in (2048, 8192)}
    for row in rows:
        if (type(row) is not dict or set(row) != {'model', 'corpus', 'phase', 'wall_seconds',
                                               'cpu_seconds', 'peak_rss_bytes'}
                or row['model'] not in MODELS or row['corpus'] not in {'small', 'large', None}
                or row['phase'] not in phases
                or any(value is not None and (type(value) not in {int, float}
                    or not math.isfinite(value) or not 0 <= value <= 28800)
                       for value in (row['wall_seconds'], row['cpu_seconds']))
                or row['wall_seconds'] is None
                or row['peak_rss_bytes'] is not None and (type(row['peak_rss_bytes']) is not int
                    or not 0 < row['peak_rss_bytes'] <= 2**50)):
            raise RetrievalError('study_measurements_unavailable')
        key = row['model'], row['corpus'], row['phase']
        groups.setdefault(key, []).append(row)
        if row['peak_rss_bytes'] is not None:
            peaks.append(row['peak_rss_bytes'])
    result = []
    for (model, corpus, phase), samples in groups.items():
        cpu = [row['cpu_seconds'] for row in samples if row['cpu_seconds'] is not None]
        result.append({'model': model, 'corpus': corpus, 'phase': phase, 'samples': len(samples),
            'wall_seconds': _percentiles([row['wall_seconds'] for row in samples]),
            'cpu_seconds': _percentiles(cpu) if len(cpu) == len(samples) else None,
            'cpu_observed_samples': len(cpu)})
    return {'groups': result, 'raw_samples': rows,
        'percentile_definition': 'statistics-median; numpy-percentile-default-linear',
        'peak_native_child_rss_bytes': max(peaks) if peaks else None,
        'peak_rss_scope': 'maximum sequential native-child lifetime RUSAGE_SELF Linux RSS; excludes controller/daemon',
        'wall_scope': 'host monotonic with transport/fences; lexical/dense/rrf/packing use native child monotonic',
        'cpu_scope': 'native child process_time per operation; host/controller/daemon CPU unavailable',
        'whole_container_peak_ram_bytes': None,
        'updates': {'status': 'not_performed', 'latency': None},
        'warm_model_reload': {'status': 'not_performed', 'latency': None},
        'billed_tokens': None, 'ttft': None, 'monetary_cost': None, 'gpu': 'not_used'}


def quality_tables(dataset, metric_rows):
    """Summarize the one retained quality pass without evaluating ranks again."""
    from .study_plan import ARMS
    tasks = {row['task_id']: row for row in dataset[1]['tasks']}
    queries = dataset[2]['queries']
    if not 1 <= len(tasks) <= 80 or not 1 <= len(queries) <= 240:
        raise RetrievalError('study_quality_scope_unavailable')
    groups = {}
    for query in queries:
        task = tasks[query['task_id']]
        for arm in ARMS:
            model = 'bge_m3' if arm in {'dense_bge_m3', 'rrf_bge_m3'} else 'minilm'
            key = task['corpus'], query['language'], task['stratum'], task['split'], arm
            value = metric_rows.get((model, query['query_id']), {}).get(arm)
            groups.setdefault(key, []).append(value)
    result = []
    for (corpus, language, stratum, split, arm), values in groups.items():
        row = {'corpus': corpus, 'language': language, 'class': stratum, 'split': split,
               'arm': arm, 'expected_queries': len(values),
               'observed_queries': sum(value is not None for value in values), 'metrics': {}}
        if stratum == 'no_answer':
            row.update(status='not_applicable_no_answer', threshold='none; no post-holdout tuning')
        else:
            for name in ('recall_at_5_ratio', 'mrr_at_10_ratio',
                         'context_recall_2048_ratio', 'context_recall_8192_ratio'):
                ratios = [None if value is None else value.get(name) for value in values]
                observed = [_ratio(value) for value in ratios if value is not None]
                mean = sum(observed, Fraction()) / len(values) if len(observed) == len(values) else None
                row['metrics'][name] = {'denominator': len(values), 'observed': len(observed),
                    'mean': None if mean is None else float(mean),
                    'mean_ratio': None if mean is None else [mean.numerator, mean.denominator]}
            row['status'] = ('INCONCLUSIVE' if any(value['mean'] is None for value in row['metrics'].values())
                             else 'observed')
        result.append(row)
    coverage = {str(value): 0 for value in (0, 1, 2)}
    for table in dataset[3]['tables']:
        for row in table['rows']:
            for label in row['judgments']:
                if type(label) is not int or str(label) not in coverage:
                    raise RetrievalError('study_quality_scope_unavailable')
                coverage[str(label)] += 1
    return dict(quality_pass=0, groups=result, label_coverage=coverage,
            unknown_positions='preserved in retained per-query first-pass metrics; no refill')


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
        return seconds

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
