"""Bounded, non-authoritative source-bound observations and offline provider facts."""
from __future__ import annotations
import contextlib
import hashlib
import json
import math
import os
import re
import stat
from datetime import datetime, timezone
from . import fsx

MAX_BYTES, MAX_ROW, MAX_RECORDS = 8_388_608, 8192, 4096
EVENTS = frozenset({'route', 'verify', 'receipt', 'grant', 'session_start', 'session_end', 'ci', 'merge', 'cost', 'finding'})
FIELDS = frozenset({'intent', 'risk', 'profiles', 'mode', 'status', 'blocking', 'effective_risk', 'profile', 'kind', 'seconds',
    'admitted', 'code_lines', 'amount', 'currency', 'finding_id', 'confirmed', 'source', 'source_ref', 'scope'})
ENVELOPE = frozenset({'schema_version', 'event_id', 'at', 'event', 'route_id', 'session_id', 'head', 'base', 'tree'})
PATH = '.getzilla/runtime/metrics.jsonl'


class Observations(list):
    def __init__(self, values=(), *, gaps=()):
        super().__init__(values)
        self.gaps = list(gaps)


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


def load(root, since=None):
    try:
        with regular(root, PATH) as descriptor:
            raw = os.read(descriptor, MAX_BYTES + 1)
    except FileNotFoundError:
        return Observations(gaps=['no observations'])
    except (OSError, ValueError):
        return Observations(gaps=['unsafe or oversized observation file'])
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


def inventory(root, base, head):
    from .project_ingestion import _git
    _git(root, 'merge-base', '--is-ancestor', base, head)
    commits = _git(root, 'rev-list', '--max-count=4097', f'{base}..{head}').stdout.splitlines()
    if len(commits) > 4096 or any(not re.fullmatch(rb'[0-9a-f]{40}|[0-9a-f]{64}', value) for value in commits):
        raise ValueError('commit inventory incomplete')
    raw = _git(root, 'diff', '--numstat', '-z', '--no-renames', '--no-textconv', '--no-ext-diff', base, head, '--').stdout
    if len(raw) > 1_048_576:
        raise ValueError('line inventory exceeds bound')
    lines = 0
    for row in raw.split(b'\0'):
        if row:
            added, removed, _path = row.split(b'\t', 2)
            if not added.isdigit() or not removed.isdigit():
                raise ValueError('binary or incomplete line inventory')
            lines += int(added) + int(removed)
    paths = _git(root, 'diff', '--name-only', '-z', '--diff-filter=A', '--no-renames', base, head, '--').stdout.split(b'\0')
    introduced = sum(path.startswith((b'engineering/changes/', b'engineering/reviews/', b'.getzilla/runtime/')) for path in paths if path)
    return {'commits': len(commits), 'changed_lines': lines, 'introduced_workflow_evidence_files': introduced}


def source_summary(events, route_id, root=None):
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
            measured = inventory(root, source['base'], source['head'])
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
