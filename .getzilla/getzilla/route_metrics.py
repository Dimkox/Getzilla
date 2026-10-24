"""Local workflow observations with explicit provenance and missing-data coverage.
Unknown costs stay unknown; failed check outcomes are not confirmed defects.
"""
from __future__ import annotations

import json
import os
import statistics
from datetime import datetime, timezone
from .metrics_journal import deduplicate, digest, load, record, source_summary, import_observations, regular  # noqa: F401
from pathlib import Path
from typing import Any, Iterable

METRICS = '.getzilla/runtime/metrics.jsonl'
COUNTERS = {'path_hints': '.getzilla/runtime/path-hints.json', 'parallel_guard': '.getzilla/runtime/parallel-guard.json'}
# Only these fields are ever written; anything else (a prompt, a path, output) is dropped.
SAFE_FIELDS = frozenset({'intent', 'risk', 'profiles', 'mode', 'status', 'blocking', 'effective_risk', 'profile',
                         'kind', 'seconds'})
MAX_TEXT = 64


def _now() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _clean(value: Any) -> Any:
    if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
        return value
    if isinstance(value, str) and len(value) <= MAX_TEXT and '/' not in value and '\\' not in value:
        return value
    return None



def record_route(root: Path, route: dict[str, Any]) -> None:
    record(root, 'route', route.get('route_id'), intent=route.get('intent'), event_id='route:' + str(route.get('route_id')), risk=route.get('risk'),
           profiles=','.join(str(item) for item in route.get('quality_profiles', [])) or None)


def profile_of(report: dict[str, Any]) -> str:
    if (report.get('light_diff') or {}).get('admitted') is True:
        return 'light'
    if report.get('profile_reason') == 'TRIVIAL_PROVEN_BY_DIFF':
        return 'trivial'
    risk = (report.get('diff_risk') or {}).get('effective_risk')
    return 'full' if risk in {'high', 'critical'} else 'standard'


def record_verify(root: Path, report: dict[str, Any]) -> None:
    checks = report.get('checks') or []
    blocking = sum(1 for check in checks if isinstance(check, dict) and check.get('status') == 'fail')
    record(root, 'verify', report.get('route_id'), event_id='verify:' + digest(report), mode=report.get('mode'), status=report.get('status'),
           blocking=blocking, effective_risk=(report.get('diff_risk') or {}).get('effective_risk'),
           profile=profile_of(report), admitted=(report.get('light_diff') or {}).get('admitted'),
           code_lines=(report.get('light_diff') or {}).get('code_lines'))


def record_receipt(root: Path, route_id: str | None, kind: str, status: str, identity: str | None = None) -> None:
    record(root, 'receipt', route_id, event_id='receipt:' + identity if identity else None, kind=kind, status=status)



def _when(item: dict[str, Any]) -> datetime:
    return datetime.strptime(item['at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)


def summarize(events: Iterable[dict[str, Any]], root: Path | None = None) -> dict[str, Any]:
    """Per route: time to the first passing verification, runs, reviews and blocking findings caught.

    `coverage` covers the journal only (unreadable or skipped lines). `route_observations` covers
    what each route did not observe (merge, cost, commits); unknown values stay None, never zero.
    """
    events = deduplicate(events, getattr(events, 'gaps', []))
    routes: dict[str, dict[str, Any]] = {}
    for item in sorted(events, key=lambda event: event['at']):
        route_id = item.get('route_id')
        if not route_id:
            continue
        route = routes.setdefault(route_id, {'route_id': route_id, 'created_at': None, 'first_green_at': None,
                                             'verify_runs': 0, 'verify_blocking': 0, 'reviews': 0, 'review_blocking': 0,
                                             'profile': 'standard', 'effective_risk': None, 'intent': None})
        if item['event'] == 'route':
            route['created_at'] = route['created_at'] or item['at']
            route['intent'] = item.get('intent')
        elif item['event'] == 'verify':
            route['verify_runs'] += 1
            route['profile'] = item.get('profile') or route['profile']
            route['effective_risk'] = item.get('effective_risk') or route['effective_risk']
            if item.get('status') == 'pass':
                route['first_green_at'] = route['first_green_at'] or item['at']
            else:
                route['verify_blocking'] += int(item.get('blocking') or 0)
        elif item['event'] == 'receipt' and item.get('kind') != 'verification':
            route['reviews'] += 1
            if item.get('status') != 'pass':
                route['review_blocking'] += 1
    for route in routes.values():
        start, done = route['created_at'], route['first_green_at']
        route['minutes_to_pass'] = (round((_when({'at': done}) - _when({'at': start})).total_seconds() / 60, 1)
                                    if start and done else None)
        route.update(source_summary(events, route['route_id'], root))
        route['failed_check_or_review_outcomes'] = route['verify_blocking'] + route['review_blocking']
    profiles: dict[str, dict[str, Any]] = {}
    for route in routes.values():
        group = profiles.setdefault(route['profile'], {'routes': 0, 'minutes': [], 'verify_runs': 0, 'reviews': 0,
                                                       'failed_check_or_review_outcomes': 0})
        group['routes'] += 1
        group['verify_runs'] += route['verify_runs']
        group['reviews'] += route['reviews']
        group['failed_check_or_review_outcomes'] += route['failed_check_or_review_outcomes']
        if route['minutes_to_pass'] is not None:
            group['minutes'].append(route['minutes_to_pass'])
    for group in profiles.values():
        minutes = group.pop('minutes')
        group['median_minutes_to_pass'] = round(statistics.median(minutes), 1) if minutes else None
        group['verify_runs_per_route'] = round(group['verify_runs'] / group['routes'], 1)
    sessions = []
    for session_id in sorted({item['session_id'] for item in events if item.get('session_id')}):
        selected = [item for item in events if item.get('session_id') == session_id]
        sessions.append({'session_id': session_id, 'route_ids': sorted({item['route_id'] for item in selected if item.get('route_id')}),
                         'observations': len(selected), 'started_at': next((item['at'] for item in selected if item['event'] == 'session_start'), None),
                         'ended_at': next((item['at'] for item in reversed(selected) if item['event'] == 'session_end'), None)})
    with_gaps = [route['route_id'] for route in routes.values() if route.get('gaps')]
    return {'routes': sorted(routes.values(), key=lambda route: route['created_at'] or ''), 'profiles': profiles, 'sessions': sessions,
            'coverage': {'complete': not events.gaps, 'gaps': events.gaps},
            'route_observations': {'complete': not with_gaps, 'routes_with_gaps': len(with_gaps), 'routes': len(routes)},
            'interpretation': 'Grant materializations are not human interventions; check outcomes are not confirmed defects.'}


def counters(root: Path) -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for name, relative in COUNTERS.items():
        try:
            with regular(root, relative) as descriptor:
                raw = os.read(descriptor, 65_537)
            if len(raw) > 65_536:
                continue
            data = json.loads(raw)
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            found[name] = data
    return found
