"""Bounded source-bound Git progress evidence."""
from __future__ import annotations

import ast
import hashlib
import json
import re
import time
from pathlib import Path, PurePosixPath

from .util import run


def _pytest_source_metadata(source: str) -> tuple[int, set[str]]:
    module = ast.parse(source)
    nodes: set[str] = set()
    for item in module.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name.startswith('test'):
            nodes.add(item.name)
        elif isinstance(item, ast.ClassDef):
            nodes.update(item.name + '::' + child.name for child in item.body
                         if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                         and child.name.startswith('test'))
    return source.count('\n') + 1, nodes


def _trusted_pytest_metadata(root: Path, output: str) -> dict[str, tuple[int, set[str]]]:
    """Bind at most 50 reported paths and test identifiers to committed source."""
    candidates = []
    for match in re.finditer(r'tests/[A-Za-z0-9_./-]+\.py', output.replace('\\', '/')):
        path = match.group(0)
        if '..' not in PurePosixPath(path).parts and path not in candidates:
            candidates.append(path)
            if len(candidates) >= 50:
                break
    if not candidates:
        return {}
    tracked = run(['git', 'ls-files', '-z', '--', *candidates], cwd=root, timeout=10)
    if tracked.returncode:
        return {}
    names = set(tracked.stdout.split('\0'))
    result: dict[str, tuple[int, set[str]]] = {}
    for path in candidates:
        if path not in names:
            continue
        size = run(['git', 'cat-file', '-s', 'HEAD:' + path], cwd=root, timeout=10)
        if size.returncode or not size.stdout.strip().isdigit() or int(size.stdout.strip()) > 1_000_000:
            continue
        source = run(['git', 'show', 'HEAD:' + path], cwd=root, timeout=10)
        if source.returncode:
            continue
        try:
            result[path] = _pytest_source_metadata(source.stdout)
        except (SyntaxError, ValueError, RecursionError):
            continue
    return result


def _trusted_progress_metadata(root: Path, paths: list[str], *, deadline: float | None = None) -> dict[str, tuple[int, set[str]]]:
    """Progress-only limits; leave terminal-output validation's contract intact."""
    if deadline is None:
        deadline = time.monotonic() + 2.0

    def bounded_git(arguments):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        result = run(['git', *arguments], cwd=root, timeout=remaining)
        if result.returncode or time.monotonic() >= deadline:
            raise TimeoutError
        return result.stdout

    result: dict[str, tuple[int, set[str]]] = {}
    try:
        head = bounded_git(['rev-parse', 'HEAD']).strip()
        if not re.fullmatch('[0-9a-f]{40,64}', head):
            return {}
        names = set(bounded_git(['ls-files', '-z', '--', *paths[:50]]).split('\0'))
        total = 0
        for path in paths[:50]:
            if path not in names:
                continue
            size = bounded_git(['cat-file', '-s', head + ':' + path]).strip()
            if not size.isdecimal() or int(size) > 1_000_000:
                continue
            total += int(size)
            if total > 8 * 1024 * 1024:
                break
            source = bounded_git(['show', head + ':' + path])
            if len(source.encode('utf-8')) > 1_000_000:
                continue
            try:
                result[path] = _pytest_source_metadata(source)
            except (SyntaxError, ValueError, RecursionError):
                continue
        if bounded_git(['rev-parse', 'HEAD']).strip() != head:
            return {}
    except (OSError, TimeoutError, UnicodeError, ValueError):
        return {}  # Deadline/currentness uncertainty cannot identify a source.
    return result


def _progress_failure_rows(progress, workers):
    raw = progress.get('failure_events')
    if (type(raw) is not dict or set(raw) != {'version', 'status', 'workers'}
            or type(raw['version']) is not int or raw['version'] != 1
            or raw['status'] not in ('not_supported', 'unavailable', 'partial', 'observed')
            or type(raw['workers']) is not list or len(raw['workers']) > 64):
        return []
    rows, seen = [], set()
    for row in raw['workers']:
        if (type(row) is not dict
                or set(row) != {'worker', 'sequence', 'overflow', 'dropped', 'partial_tail', 'events'}
                or type(row['worker']) is not int or not 0 <= row['worker'] < workers
                or type(row['sequence']) is not int or not 1 <= row['sequence'] <= 2**63 - 1
                or any(type(row[name]) is not bool for name in ('overflow', 'dropped', 'partial_tail'))
                or type(row['events']) is not list or len(row['events']) > 4
                or (row['overflow'] and len(row['events']) != 4)
                or (not row['events'] and not row['dropped'])):
            continue
        if row['worker'] in seen:
            return []
        seen.add(row['worker'])
        previous, valid = 0, True
        for event in row['events']:
            if (type(event) is not dict or set(event) != {'ordinal', 'phase', 'path', 'key'}
                    or type(event['ordinal']) is not int or not previous < event['ordinal'] <= row['sequence']
                    or event['phase'] not in ('setup', 'call', 'teardown')
                    or type(event['path']) is not str or len(event['path']) > 256
                    or not re.fullmatch(r'tests/[A-Za-z0-9_./-]+\.py', event['path'])
                    or any(part in {'', '.', '..'} for part in event['path'].split('/'))
                    or type(event['key']) is not str or not re.fullmatch('[0-9a-f]{64}', event['key'])):
                valid = False
                break
            previous = event['ordinal']
        if valid:
            rows.append(row)
    return sorted(rows, key=lambda row: row['worker'])


def _failure_progress_details(rows, identities, workers):
    output = {'version': 1, 'observation': 'FAILED_REPORTS_BEFORE_STOP', 'prefix_only': True,
              'status': 'unavailable', 'overflow': None, 'dropped': None, 'partial_tail': None,
              'render_truncated': False, 'events': []}
    if not rows:
        return output
    known = len(rows) == workers
    proven = {name: any(row[name] for row in rows) for name in ('overflow', 'dropped', 'partial_tail')}
    # Positive facts survive uncertainty; absence is not yet a negative proof.
    for name, value in proven.items():
        output[name] = True if value else None
    unknown = False
    for row in rows:
        for event in row['events']:
            identity = identities.get((event['path'], event['key']))
            unknown |= identity is None
            candidate = {'worker': row['worker'], 'ordinal': event['ordinal'],
                         'phase': event['phase'], 'identity': identity}
            proposed = {**output, 'events': output['events'] + [candidate]}
            # Reserve the longest final flag spelling without publishing a
            # provisional FALSE. Finalizing certainty must not exceed the cap.
            budgeted = {**proposed, **{name: True if value else False for name, value in proven.items()}}
            if len(json.dumps(budgeted).encode('utf-8')) > 8192:
                output['render_truncated'] = True
                break
            output['events'].append(candidate)
        if output['render_truncated']:
            break
    uncertain = not known or unknown or output['render_truncated'] or any(proven.values())
    for name, value in proven.items():
        output[name] = True if value else None if uncertain else False
    output['status'] = 'partial' if uncertain else 'observed'
    return output


def _core_progress_details(root: Path, progress: dict[str, object] | None) -> dict[str, object]:
    """Source-bound last slots and failed-report prefixes, never test totals."""
    output: dict[str, object] = {'observation': 'LAST_REPORTED_BEFORE_STOP', 'best_effort': True,
                                 'status': 'not_supported', 'selected_workers': 0,
                                 'observed_workers': 0, 'omitted_workers': 0, 'slots': [],
                                 'failure_events': _failure_progress_details([], {}, 0)}
    output['failure_events']['status'] = 'not_supported'
    if not isinstance(progress, dict):
        return output
    workers = progress.get('selected_workers')
    if type(workers) is not int or workers < 0:
        return output
    output.update(selected_workers=workers, omitted_workers=workers)
    if workers > 64 or progress.get('status') == 'not_supported':
        return output
    output['status'] = 'unavailable'
    output['failure_events']['status'] = 'unavailable'
    failures = _progress_failure_rows(progress, workers)
    raw = progress.get('slots')
    if not isinstance(raw, list) or len(raw) > 64:
        if not failures:
            return output
        raw = []
    slots, seen = [], set()
    # One shared bounded source lookup; failures precede last-reported slots.
    paths = list(dict.fromkeys(event['path'] for row in failures for event in row['events']))
    for slot in raw:
        if not isinstance(slot, dict):
            continue
        worker, state, path, key = (slot.get(name) for name in ('worker', 'state', 'path', 'key'))
        if (type(worker) is not int or not 0 <= worker < workers or worker in seen
                or not isinstance(state, str) or state not in {'active', 'idle'}):
            continue
        seen.add(worker)
        if (not isinstance(path, str) or len(path) > 256
                or not re.fullmatch(r'tests/[A-Za-z0-9_./-]+\.py', path)
                or any(part in {'', '.', '..'} for part in path.split('/'))
                or not isinstance(key, str) or not re.fullmatch('[0-9a-f]{64}', key)):
            path, key = None, None
        if path is not None and path not in paths:
            paths.append(path)
        slots.append((worker, state, path, key))
    deadline = time.monotonic() + 2.0
    trusted = _trusted_progress_metadata(root, paths, deadline=deadline) if paths else {}
    requested = {(path, key) for _, _, path, key in slots if path is not None}
    requested.update((event['path'], event['key']) for row in failures for event in row['events'])
    identities = {}
    expired = False
    for path, (_, nodes) in trusted.items():
        for node in nodes:
            if time.monotonic() >= deadline:
                expired = True
                break
            canonical = path + '::' + node
            if (len(canonical) <= 512 and re.fullmatch(
                    r'[A-Za-z_][A-Za-z0-9_]{0,127}(?:::[A-Za-z_][A-Za-z0-9_]{0,127})?', node)):
                pair = (path, hashlib.sha256(canonical.encode('utf-8')).hexdigest())
                if pair in requested:
                    identities[pair] = canonical
        if expired:
            break
    if expired:
        identities = {}
    output['failure_events'] = _failure_progress_details(failures, identities, workers)
    rendered = []
    unknown = False
    for worker, state, path, key in sorted(slots):
        identity = identities.get((path, key))
        unknown |= identity is None
        candidate = {'worker': worker, 'state': state, 'identity': identity}
        if len(json.dumps({**output, 'slots': rendered + [candidate]}).encode('utf-8')) > 16000:
            break
        rendered.append(candidate)
    output.update(status=('observed' if len(rendered) == workers and not unknown else
                           'partial' if rendered else 'unavailable'),
                  observed_workers=len(slots), omitted_workers=workers - len(rendered), slots=rendered)
    if 'phase_witness' in progress:
        from .pytest_progress import phase_witness_details
        candidate = {**output, 'phase_witness': phase_witness_details(progress['phase_witness'], workers)}
        if len(json.dumps(candidate).encode('utf-8')) <= 16000:
            output = candidate
    return output
