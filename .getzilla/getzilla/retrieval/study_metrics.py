"""Pure fixed-study summaries. Values and rows never authorize a study run.

Unknown positions retain their original rank and receive no credit. Scores with
unjudged positions are explicitly partial, not fully judged quality estimates.
"""
from __future__ import annotations

import math


def ranking_metrics(function_ids, judgments):
    if (type(function_ids) not in {list, tuple} or len(function_ids) > 100
            or any(type(item) is not str or not item for item in function_ids)
            or type(judgments) is not dict
            or any(type(key) is not str or not key or type(value) is not int
                   or value not in {0, 1, 2} for key, value in judgments.items())):
        raise ValueError('invalid_study_metrics')
    # Match the published unique-function projection, retaining its source ranks.
    # A position outside the frozen universe is not a known duplicate: keep each
    # such original slot, with no credit, rather than silently filling its place.
    projected, seen, original_positions = [], set(), []
    for position, key in enumerate(function_ids, 1):
        if key in judgments and key in seen:
            continue
        seen.add(key)
        projected.append(key)
        original_positions.append(position)
    positives = {key for key, value in judgments.items() if value == 1}
    top5 = set(projected[:5]) & positives
    top10 = projected[:10]
    unjudged = [rank for rank, key in enumerate(top10, 1)
                if judgments.get(key, 0) == 0]
    first = next((rank for rank, key in enumerate(top10, 1) if key in positives), None)
    return {'positive_functions': len(positives),
            'recall_at_5': len(top5) / len(positives) if positives else None,
            'mrr_at_10': (1 / first if first else 0.0) if positives else None,
            'recall_at_5_ratio': [len(top5), len(positives)] if positives else None,
            'mrr_at_10_ratio': ([1, first] if first else [0, 1]) if positives else None,
            'original_positions': original_positions,
            'unjudged_positions_at_10': unjudged,
            'judgment_status': 'partial' if unjudged else 'judged'}


def paired_holdout(task_ids, baseline, candidate):
    """One registered sixteen-positive-task metric slice, candidate minus baseline.

The caller supplies the original frozen task order. Missing/ineligible pairs
produce no mean and never reduce the registered denominator. This function does
not establish that these rows came from an authorized, single holdout run.
"""
    if (type(task_ids) not in {list, tuple} or len(task_ids) != 16
            or any(type(key) is not str or not key for key in task_ids)
            or len(set(task_ids)) != 16 or type(baseline) is not dict
            or type(candidate) is not dict):
        raise ValueError('invalid_holdout_slice')
    expected = set(task_ids)
    for rows in (baseline, candidate):
        if any(key not in expected or (value is not None and
               (type(value) not in {int, float} or not math.isfinite(value)
                or not 0 <= value <= 1)) for key, value in rows.items()):
            raise ValueError('invalid_holdout_metric')
    missing = [key for key in task_ids
               if baseline.get(key) is None or candidate.get(key) is None]
    delta = None if missing else math.fsum(candidate[key] - baseline[key]
                                          for key in task_ids) / 16
    return {'status': ('INCONCLUSIVE' if missing else 'PASS' if delta >= -.05 else 'FAIL'),
            'denominator': 16, 'missing_tasks': missing, 'mean_delta': delta,
            'maximum_drop': .05}
