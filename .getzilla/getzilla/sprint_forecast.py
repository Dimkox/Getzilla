"""Empirical count intervals and out-of-time scoring, never LLM probability.

Coverage is input data to this pure method, not authority. The native consumer
must establish cohort coverage before supplying any real windows.
"""
from __future__ import annotations

import math
from datetime import timedelta

from .sprint_report import TARGET, timestamp


def _counts(values):
    ordered = sorted(values)
    return dict(zip(('lower', 'median', 'upper'),
                    (ordered[math.ceil(len(ordered)*q)-1] for q in (0.1, 0.5, 0.9))))


def forecast_counts(windows, *, origin, horizon_days, remaining, cohort):
    if (type(horizon_days) is not int or not 1 <= horizon_days <= 14
            or type(remaining) is not int or not 0 <= remaining <= 4096
            or len(windows) > 4096):
        raise ValueError('invalid_forecast_input')
    cutoff = timestamp(origin)
    eligible, excluded = [], 0
    for row in windows:
        try:
            start, end = timestamp(row['start']), timestamp(row['end'])
            if (set(row) != {'start', 'end', 'count', 'coverage', 'target', 'cohort'}
                    or row['coverage'] != 'complete' or row['target'] != TARGET
                    or row['cohort'] != cohort or type(row['count']) is not int
                    or not 0 <= row['count'] <= 4096 or end > cutoff
                    or end-start != timedelta(days=horizon_days)):
                raise ValueError('incomparable_window')
            eligible.append((start, end, row['count']))
        except (KeyError, TypeError, ValueError):
            excluded += 1
    nonoverlap = []
    for item in sorted(eligible):
        if nonoverlap and item[0] < nonoverlap[-1][1]:
            excluded += 1
        else:
            nonoverlap.append(item)
    origins, hits, error = 0, 0, 0
    for index, (start, _end, actual) in enumerate(nonoverlap):
        training = [count for _begin, end, count in nonoverlap[:index] if end <= start]
        if len(training) < 8:
            continue
        prediction = _counts(training)
        origins += 1
        hits += prediction['lower'] <= actual <= prediction['upper']
        error += abs(prediction['median']-actual)
    calibration = {'origins': origins, 'interval_hits': hits,
                   'observed_coverage': hits/origins if origins else None,
                   'mean_absolute_error': error/origins if origins else None,
                   'nominal_interval': 0.8}
    available = len(nonoverlap) >= 8 and origins >= 8
    raw = _counts([count for _, _, count in nonoverlap]) if available else None
    warning = available and calibration['observed_coverage'] < 0.8
    return {'target': TARGET, 'method': 'empirical-nearest-rank-rolling-origin-v1',
            'status': 'calibration_warning' if warning else 'empirical' if available else 'insufficient_history',
            'origin': origin, 'horizon_days': horizon_days, 'eligible_windows': len(nonoverlap),
            'excluded_windows': excluded, 'calibration': calibration,
            'raw_counts': raw, 'additional_completions':
            {key: min(value, remaining) for key, value in raw.items()} if raw else None,
            'evidence_grade': 'supplied_cohort_statistics' if available else 'unavailable',
            'guaranteed': False}


def forecast_matched_origins(windows, *, origin, horizon_seconds, remaining, cohort):
    """Match the residual target and availability at every backtest origin.

    This pure method assigns no native coverage or access grade. Its caller
    must derive each complete window from admitted native roster evidence.
    """
    if (type(horizon_seconds) is not int or not 1 <= horizon_seconds <= 14*86400
            or type(remaining) is not int or not 0 <= remaining <= 64
            or cohort != 'prospective_original_roster_v1' or len(windows) > 4096):
        raise ValueError('invalid_forecast_input')
    cutoff = timestamp(origin)
    eligible, excluded = [], 0
    fields = {'start','end','count','coverage','target','cohort','remaining','available_by'}
    for row in windows:
        try:
            start, end, known = (timestamp(row[key]) for key in ('start','end','available_by'))
            if (set(row) != fields or row['coverage'] != 'complete' or row['target'] != TARGET
                    or row['cohort'] != cohort or type(row['remaining']) is not int
                    or row['remaining'] != remaining or type(row['count']) is not int
                    or not 0 <= row['count'] <= remaining or known < end or known > cutoff
                    or end-start != timedelta(seconds=horizon_seconds)):
                raise ValueError('incomparable_window')
            eligible.append((start,end,row['count'],known))
        except (KeyError,TypeError,ValueError):
            excluded += 1
    nonoverlap = []
    for row in sorted(eligible):
        if nonoverlap and row[0] < nonoverlap[-1][1]:
            excluded += 1
        else:
            nonoverlap.append(row)
    origins, hits, error = 0, 0, 0
    for index,(start,_end,actual,_known) in enumerate(nonoverlap):
        training = [count for _begin,end,count,known in nonoverlap[:index]
                    if end <= start and known <= start]
        if len(training) < 8:
            continue
        prediction = _counts(training)
        origins += 1
        hits += prediction['lower'] <= actual <= prediction['upper']
        error += abs(prediction['median']-actual)
    calibration = {'origins':origins,'interval_hits':hits,
                   'observed_coverage':hits/origins if origins else None,
                   'mean_absolute_error':error/origins if origins else None,
                   'nominal_interval':0.8}
    available = len(nonoverlap) >= 8 and origins >= 8
    raw = _counts([count for _start,_end,count,_known in nonoverlap]) if available else None
    warning = available and calibration['observed_coverage'] < 0.8
    return {'target':TARGET,'method':'matched-residual-nearest-rank-rolling-origin-v1',
            'status':'calibration_warning' if warning else 'empirical' if available else 'insufficient_history',
            'origin':origin,'horizon_seconds':horizon_seconds,'remaining':remaining,
            'eligible_windows':len(nonoverlap),'excluded_windows':excluded,'calibration':calibration,
            'raw_counts':raw,'additional_completions':raw,
            'evidence_grade':'supplied_cohort_statistics' if available else 'unavailable',
            'guaranteed':False}
