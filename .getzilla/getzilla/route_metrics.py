"""Per-route overhead and caught-defect counters: does the ritual pay for itself? (O01)

Every route, verification run and receipt appends one event to ``.getzilla/runtime/metrics.jsonl``.
Events carry identifiers, statuses, counts, risk and profile names only: never prompts, file
paths or command output. :func:`summarize` turns them into per-route and per-profile numbers that
``getzilla report`` prints, together with the path-hint and parallel-guard counters.
"""
from __future__ import annotations

import contextlib
import json
import statistics
from datetime import datetime, timezone
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


def record(root: Path, event: str, route_id: str | None, **fields: Any) -> None:
    """Append one event; a metrics failure never affects the work it measures."""
    item = {'at': _now(), 'event': event, 'route_id': _clean(route_id)}
    item.update({key: _clean(value) for key, value in fields.items() if key in SAFE_FIELDS})
    path = root / METRICS
    with contextlib.suppress(OSError):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('a', encoding='utf-8', newline='\n') as handle:
            handle.write(json.dumps(item, sort_keys=True) + '\n')


def record_route(root: Path, route: dict[str, Any]) -> None:
    record(root, 'route', route.get('route_id'), intent=route.get('intent'), risk=route.get('risk_level'),
           profiles=','.join(str(item) for item in route.get('quality_profiles', [])) or None)


def profile_of(report: dict[str, Any]) -> str:
    if report.get('profile_reason') == 'TRIVIAL_PROVEN_BY_DIFF':
        return 'trivial'
    risk = (report.get('diff_risk') or {}).get('effective_risk')
    return 'full' if risk in {'high', 'critical'} else 'standard'


def record_verify(root: Path, report: dict[str, Any]) -> None:
    checks = report.get('checks') or []
    blocking = sum(1 for check in checks if isinstance(check, dict) and check.get('status') == 'fail')
    record(root, 'verify', report.get('route_id'), mode=report.get('mode'), status=report.get('status'),
           blocking=blocking, effective_risk=(report.get('diff_risk') or {}).get('effective_risk'),
           profile=profile_of(report))


def record_receipt(root: Path, route_id: str | None, kind: str, status: str) -> None:
    record(root, 'receipt', route_id, kind=kind, status=status)


def load(root: Path, since: datetime | None = None) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    try:
        lines = (root / METRICS).read_text(encoding='utf-8').splitlines()
    except OSError:
        return events
    for line in lines:
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if not isinstance(item, dict) or not item.get('at'):
            continue
        if since is not None and _when(item) < since:
            continue
        events.append(item)
    return events


def _when(item: dict[str, Any]) -> datetime:
    return datetime.strptime(item['at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)


def summarize(events: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Per route: time to the first passing verification, runs, reviews and blocking findings caught."""
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
        route['caught_before_merge'] = route['verify_blocking'] + route['review_blocking']
    profiles: dict[str, dict[str, Any]] = {}
    for route in routes.values():
        group = profiles.setdefault(route['profile'], {'routes': 0, 'minutes': [], 'verify_runs': 0, 'reviews': 0,
                                                       'caught_before_merge': 0})
        group['routes'] += 1
        group['verify_runs'] += route['verify_runs']
        group['reviews'] += route['reviews']
        group['caught_before_merge'] += route['caught_before_merge']
        if route['minutes_to_pass'] is not None:
            group['minutes'].append(route['minutes_to_pass'])
    for group in profiles.values():
        minutes = group.pop('minutes')
        group['median_minutes_to_pass'] = round(statistics.median(minutes), 1) if minutes else None
        group['verify_runs_per_route'] = round(group['verify_runs'] / group['routes'], 1)
    return {'routes': sorted(routes.values(), key=lambda route: route['created_at'] or ''), 'profiles': profiles}


def counters(root: Path) -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for name, relative in COUNTERS.items():
        try:
            data = json.loads((root / relative).read_text(encoding='utf-8'))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            found[name] = data
    return found
