"""Bounded, non-authoritative source-bound observations and offline provider facts."""
from __future__ import annotations
import contextlib
import hashlib
import json
import math
import os
import re
import stat
import statistics
from pathlib import Path
from typing import Any, Iterable
from datetime import datetime, timezone
from . import fsx

MAX_BYTES, MAX_ROW, MAX_RECORDS = 8_388_608, 8192, 4096
EVENTS = frozenset({'route', 'verify', 'receipt', 'grant', 'session_start', 'session_end', 'ci', 'merge', 'cost', 'finding'})
FIELDS = frozenset({'intent', 'risk', 'profiles', 'mode', 'status', 'blocking', 'effective_risk', 'profile', 'kind', 'seconds',
    'admitted', 'code_lines', 'amount', 'currency', 'finding_id', 'confirmed', 'source', 'source_ref', 'scope'})
ENVELOPE = frozenset({'schema_version', 'event_id', 'at', 'event', 'route_id', 'session_id', 'head', 'base', 'tree'})
PATH = '.getzilla/runtime/metrics.jsonl'


class Observations(list):
    def __init__(self, values=(), *, gaps=(), available=True):
        super().__init__(values)
        self.gaps = list(gaps)
        self.available = available


def when(item):
    return datetime.strptime(item['at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, allow_nan=False).encode()).hexdigest()


def clean(value):
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float)):
        return value if math.isfinite(value) and 0 <= value <= 10**12 else None
    if isinstance(value, str) and len(value) <= 256 and not any(char in value for char in '/\\\n\r\0'):
        return value
    return None


@contextlib.contextmanager
def regular(root, relative, *, create=False):
    if not create and relative in {PATH, '.getzilla/runtime/path-hints.json', '.getzilla/runtime/parallel-guard.json'}:
        from .trace_storage import LocalRead
        with LocalRead(root) as reader:
            yield reader.open_regular(relative, MAX_BYTES)
            reader.check()
        return
    parts = relative.split('/')
    if any(part in ('', '.', '..') for part in parts):
        raise ValueError('unsafe observation path')
    handles, descriptor = [fsx.open_dir(root.resolve(strict=True))], None
    try:
        for part in parts[:-1]:
            if create:
                with contextlib.suppress(FileExistsError):
                    fsx.mkdir_at(handles[-1], part, 0o700)
            handles.append(fsx.open_dir_at(handles[-1], part))
        flags = (os.O_WRONLY | os.O_APPEND | os.O_CREAT) if create else os.O_RDONLY
        descriptor = fsx.open_at(handles[-1], parts[-1], flags | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0), 0o600)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o111 or info.st_size > MAX_BYTES:
            raise ValueError('observations require a bounded non-executable regular file')
        yield descriptor
    finally:
        if descriptor is not None:
            os.close(descriptor)
        for handle in reversed(handles):
            fsx.close_dir(handle)


def validate(item):
    if not isinstance(item, dict) or item.get('event') not in EVENTS or not isinstance(item.get('at'), str):
        raise ValueError('malformed observation')
    when(item)
    for field in ('route_id', 'session_id'):
        value = item.get(field)
        if value is not None and (not isinstance(value, str) or clean(value) != value):
            raise ValueError('invalid observation identity')
    if set(item) - ENVELOPE - FIELDS:
        raise ValueError('unknown observation field')
    if 'schema_version' in item:
        if item['schema_version'] != 2 or not ENVELOPE <= item.keys() or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,256}', item.get('event_id', '')):
            raise ValueError('malformed versioned observation')
        for field in ('head', 'base', 'tree'):
            if item[field] is not None and not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', item[field]):
                raise ValueError('source identity must be exact')
    for key in FIELDS & item.keys():
        if clean(item[key]) != item[key] or isinstance(item[key], float) and not math.isfinite(item[key]):
            raise ValueError('invalid observation value')
        value = item[key]
        if value is not None:
            if key in {'blocking', 'code_lines'} and (type(value) is not int or value < 0):
                raise ValueError('count must be a nonnegative integer')
            if key in {'amount', 'seconds'} and (type(value) not in {int, float} or value < 0):
                raise ValueError('measurement must be a nonnegative number')
            if key in {'admitted', 'confirmed'} and type(value) is not bool:
                raise ValueError('observation flag must be boolean')
            if key not in {'blocking', 'code_lines', 'amount', 'seconds', 'admitted', 'confirmed'} and not isinstance(value, str):
                raise ValueError('observation label must be text')


def record(root, event, route_id, *, event_id=None, source_identity=None, at=None, **fields):
    """Metric failure never blocks measured work; record grants only after publication."""
    try:
        if source_identity is None:
            from .state import get_active_route
            from .util import git_head, git_output
            route = get_active_route(root) or {}
            source_identity = {'session_id': clean(route.get('session_id')), 'head': git_head(root),
                               'base': route.get('base_commit'), 'tree': git_output(root, 'rev-parse', 'HEAD^{tree}')}
        item = {'schema_version': 2, 'at': at or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                'event': event, 'route_id': clean(route_id), **source_identity}
        item.update({key: clean(value) for key, value in fields.items() if key in FIELDS})
        item['event_id'] = event_id or digest(item)
        validate(item)
        raw = (json.dumps(item, sort_keys=True, allow_nan=False) + '\n').encode()
        if len(raw) > MAX_ROW:
            return False
        with regular(root, PATH, create=True) as descriptor:
            fsx.lock_file(descriptor)
            try:
                return os.fstat(descriptor).st_size + len(raw) <= MAX_BYTES and os.write(descriptor, raw) == len(raw)
            finally:
                fsx.unlock_file(descriptor)
    except (OSError, ValueError, RuntimeError, TypeError):
        return False


def deduplicate(events, gaps=()):
    seen, result, problems = {}, [], list(gaps)
    for index, item in enumerate(events):
        if index >= MAX_RECORDS:
            problems.append('record limit exceeded')
            break
        try:
            validate(item)
        except (TypeError, ValueError, KeyError):
            problems.append(f'malformed observation row {index + 1}')
            continue
        identity = item.get('event_id')
        if identity and identity in seen:
            if seen[identity] != item:
                problems.append(f'conflicting replay: {identity}')
            continue
        if identity:
            seen[identity] = item
        else:
            problems.append('legacy rows have no replay/source identity')
        result.append(item)
    return Observations(result, gaps=sorted(set(problems)))


def load(root, since=None, *, reader=None):
    try:
        if reader is None:
            from .trace_storage import LocalRead
            with LocalRead(root) as owned:
                return load(root, since, reader=owned)
        reader.check_root(root)
        raw = reader.read(PATH, MAX_BYTES)
    except (OSError, ValueError):
        return Observations(gaps=['local observations unavailable'], available=False)
    rows, gaps = [], []
    for number, row in enumerate(raw.splitlines(keepends=True)):
        if number >= MAX_RECORDS:
            gaps.append('record limit exceeded')
            break
        try:
            if len(row) > MAX_ROW or not row.endswith(b'\n'):
                raise ValueError('truncated or oversized row')
            item = json.loads(row)
            validate(item)
            if since is None or when(item) >= since:
                rows.append(item)
        except (UnicodeError, ValueError, TypeError, KeyError):
            gaps.append(f'malformed observation row {number + 1}')
    return deduplicate(rows, gaps)


def import_observations(root, relative):
    with regular(root, relative) as descriptor:
        raw = os.read(descriptor, 1_048_577)
    if len(raw) > 1_048_576:
        raise ValueError('import exceeds byte bound')
    rows = json.loads(raw)
    if not isinstance(rows, list) or len(rows) > MAX_RECORDS:
        raise ValueError('import must be a bounded observation list')
    for item in rows:
        validate(item)
        if (item.get('event') not in {'ci', 'merge', 'cost', 'finding'} or not item.get('event_id')
                or item.get('source') not in {'github', 'codex', 'bandit', 'review'} or not item.get('source_ref')
                or not item.get('head') or not item.get('base')):
            raise ValueError('offline facts need exact source, provenance and stable identity')
    count = 0
    for item in rows:
        fields = {key: value for key, value in item.items() if key in FIELDS}
        identity = {key: item[key] for key in ('session_id', 'head', 'base', 'tree')}
        count += record(root, item['event'], item['route_id'], event_id=item['event_id'], at=item['at'], source_identity=identity, **fields)
    return {'imported': count, 'requested': len(rows), 'authority': 'offline observations only'}


def inventory(root, base, head, *, reader=None):
    from .project_ingestion import _git
    if reader is None:
        from .trace_storage import LocalRead
        with LocalRead(root) as owned:
            return inventory(root, base, head, reader=owned)
    location, descriptors = reader.git_location()
    reader.check_root(root)

    def git(*args):
        reader.check()
        result = _git(location, *args, _pass_fds=descriptors)
        reader.check()
        return result

    git('merge-base', '--is-ancestor', base, head)
    commits = git('rev-list', '--max-count=4097', f'{base}..{head}').stdout.splitlines()
    if len(commits) > 4096 or any(not re.fullmatch(rb'[0-9a-f]{40}|[0-9a-f]{64}', value) for value in commits):
        raise ValueError('commit inventory incomplete')
    raw = git('diff', '--numstat', '-z', '--no-renames', '--no-textconv', '--no-ext-diff', base, head, '--').stdout
    if len(raw) > 1_048_576:
        raise ValueError('line inventory exceeds bound')
    lines = 0
    for row in raw.split(b'\0'):
        if row:
            added, removed, _path = row.split(b'\t', 2)
            if not added.isdigit() or not removed.isdigit():
                raise ValueError('binary or incomplete line inventory')
            lines += int(added) + int(removed)
    paths = git('diff', '--name-only', '-z', '--diff-filter=A', '--no-renames', base, head, '--').stdout.split(b'\0')
    introduced = sum(path.startswith((b'engineering/changes/', b'engineering/reviews/', b'.getzilla/runtime/')) for path in paths if path)
    return {'commits': len(commits), 'changed_lines': lines, 'introduced_workflow_evidence_files': introduced}


def source_summary(events, route_id, root=None, *, reader=None):
    facts = [row for row in events if row.get('route_id') == route_id and row.get('schema_version') == 2]
    verifies = [row for row in facts if row['event'] == 'verify']
    merges = [row for row in facts if row['event'] == 'merge' and row.get('head') and row.get('base')]
    source = merges[-1] if merges else next((row for row in reversed(facts) if row.get('head') and row.get('base')), None)
    result = {'grant_materializations': sum(row['event'] == 'grant' for row in facts), 'approval_count_per_commit': None,
              'fast_lane_admitted': sum(row.get('admitted') is True for row in verifies),
              'fast_lane_known': sum(type(row.get('admitted')) is bool for row in verifies),
              'fast_lane_unknown': sum(type(row.get('admitted')) is not bool for row in verifies),
              'cost_per_changed_line': None, 'observed_cost': None, 'ci_minutes': None,
              'unique_defects_before_merge': None, 'introduced_workflow_evidence_files': None, 'gaps': []}
    measured = None
    if root and source:
        try:
            measured = inventory(root, source['base'], source['head'], reader=reader)
            if measured['commits']:
                result['approval_count_per_commit'] = result['grant_materializations'] / measured['commits']
        except Exception as exc:
            result['gaps'].append(f'incomplete source inventory: {type(exc).__name__}')
    else:
        result['gaps'].append('exact commit inventory unavailable')
    if merges:
        merge = merges[-1]
        same = [row for row in facts if row.get('head') == merge['head'] and row.get('base') == merge['base']]
        costs = [row['amount'] for row in same if row['event'] == 'cost' and row.get('currency') == 'USD' and row.get('amount') is not None]
        ci = [row['seconds'] for row in same if row['event'] == 'ci' and row.get('seconds') is not None]
        result['observed_cost'] = sum(costs) if costs else None
        result['ci_minutes'] = sum(ci) / 60 if ci else None
        findings = [row for row in same if row['event'] == 'finding' and row.get('confirmed') is True
                    and row.get('finding_id') and when(row) < when(merge)]
        result['unique_defects_before_merge'] = len({row['finding_id'] for row in findings}) if findings else None
        if not findings:
            result['gaps'].append('confirmed before-merge findings not observed')
        if measured:
            result['introduced_workflow_evidence_files'] = measured['introduced_workflow_evidence_files']
            if costs and measured['changed_lines']:
                result['cost_per_changed_line'] = sum(costs) / measured['changed_lines']
    else:
        result['gaps'].append('merge not observed; session end is not merge evidence')
    if result['observed_cost'] is None:
        result['gaps'].append('cost not observed')
    return result


# Workflow observation summaries and recording share the bounded journal owner.
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


def summarize(events: Iterable[dict[str, Any]], root: Path | None = None, *, reader=None) -> dict[str, Any]:
    """Per route: time to the first passing verification, runs, reviews and blocking findings caught.

    `coverage` covers the journal only (unreadable or skipped lines). `route_observations` covers
    what each route did not observe (merge, cost, commits); unknown values stay None, never zero.
    """
    if not getattr(events, 'available', True):
        return {'routes': None, 'profiles': None, 'sessions': None, 'counters': None,
                'coverage': {'complete': False, 'gaps': ['local observations unavailable']},
                'route_observations': {'complete': False, 'routes_with_gaps': None, 'routes': None},
                'interpretation': 'Local observation counts are unknown.'}
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
        route.update(source_summary(events, route['route_id'], root, reader=reader))
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
            'coverage': {'complete': not events.gaps, 'gaps': events.gaps,
                         'source_scope': 'canonical_root_only', 'evidence_grade': 'unqualified_legacy_observations'},
            'route_observations': {'complete': not with_gaps, 'routes_with_gaps': len(with_gaps), 'routes': len(routes)},
            'interpretation': 'Grant materializations are not human interventions; check outcomes are not confirmed defects.'}


def counters(root: Path, *, reader=None) -> dict[str, dict[str, Any]]:
    if reader is None:
        from .trace_storage import LocalRead
        try:
            with LocalRead(root) as owned:
                return counters(root, reader=owned)
        except (OSError, ValueError):
            return {}
    found: dict[str, dict[str, Any]] = {}
    reader.check_root(root)
    for name, relative in COUNTERS.items():
        try:
            raw = reader.read(relative, 65_536)
            data = json.loads(raw)
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            found[name] = data
    return found
