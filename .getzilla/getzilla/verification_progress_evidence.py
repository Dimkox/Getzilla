"""Bounded source-bound Git progress evidence."""
from __future__ import annotations

import ast
import hashlib
import json
import re
import subprocess
import time
from pathlib import Path, PurePosixPath

from .util import run, _observed_run
from .verification_failure_excerpt import valid_policy_diagnostic
from . import verification_failure_excerpt as _failure_excerpt


def _valid_failure_diagnostic(value):
    if valid_policy_diagnostic(value):
        return True
    validate = getattr(_failure_excerpt, 'valid_factory_diagnostic', None)
    return callable(validate) and validate(value) is True


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


def _trusted_progress_metadata(root: Path, paths: list[str], *, deadline: float | None = None,
                               observation: dict | None = None) -> dict[str, tuple[int, set[str]]]:
    """Progress-only limits; leave terminal-output validation's contract intact."""
    if deadline is None:
        deadline = time.monotonic() + 2.0

    observed = observation if observation is not None else {}
    observed.update(status='unavailable', reason='source-unavailable', head=None, currentness='unknown')

    def bounded_git(arguments, *, data=None, binary=False):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        options = {} if data is None else {'input': data.encode('utf-8')}
        result = _observed_run(['git', *arguments], cwd=root, timeout=remaining,
                               capture_output=True, check=False, **options)
        if result.returncode or time.monotonic() >= deadline:
            raise TimeoutError
        return result.stdout if binary else result.stdout.decode('utf-8')

    result: dict[str, tuple[int, set[str]]] = {}
    try:
        head = bounded_git(['rev-parse', 'HEAD']).strip()
        if not re.fullmatch('[0-9a-f]{40,64}', head):
            return {}
        observed['head'] = head
        names = set(bounded_git(['ls-files', '-z', '--', *paths[:50]]).split('\0'))
        selected = [path for path in paths[:50] if path in names]
        specs = ''.join(head + ':' + path + '\n' for path in selected)
        sizes = bounded_git(['cat-file', '--batch-check'], data=specs).splitlines() if selected else []
        if len(sizes) != len(selected):
            return {}
        bounded = []
        total = 0
        for path, row in zip(selected, sizes):
            fields = row.split()
            if (len(fields) != 3 or not re.fullmatch('[0-9a-f]{40,64}', fields[0])
                    or fields[1] != 'blob' or not fields[2].isdecimal()):
                continue
            size = int(fields[2])
            if size > 1_000_000:
                continue
            total += size
            if total > 8 * 1024 * 1024:
                break
            bounded.append((path, fields[0], size))
        # Query only pre-sized immutable objects; aggregate bytes never exceed
        # the existing8MiB ceiling. Five Git calls replace up to102 calls.
        specs = ''.join(blob + '\n' for _, blob, _ in bounded)
        raw = bounded_git(['cat-file', '--batch'], data=specs, binary=True) if bounded else b''
        offset = 0
        for path, blob, size in bounded:
            end = raw.find(b'\n', offset)
            if end < 0 or raw[offset:end] != f'{blob} blob {size}'.encode('ascii'):
                return {}
            offset = end + 1
            source = raw[offset:offset + size].decode('utf-8')
            offset += size
            if raw[offset:offset + 1] != b'\n':
                return {}
            offset += 1
            try:
                result[path] = _pytest_source_metadata(source)
            except (SyntaxError, ValueError, RecursionError):
                continue
        if offset != len(raw):
            return {}
        if bounded_git(['rev-parse', 'HEAD']).strip() != head:
            observed['reason'] = 'source-changed'
            return {}
        observed.update(status='observed' if len(result) == len(paths) else 'partial',
                        reason='complete' if len(result) == len(paths) else 'source-unavailable', currentness='verified')
    except (OSError, TimeoutError, subprocess.TimeoutExpired, UnicodeError, ValueError):
        observed['reason'] = 'deadline' if time.monotonic() >= deadline else 'source-unavailable'
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
            if (type(event) is not dict or set(event) not in ({'ordinal', 'phase', 'path', 'key'},
                                                {'ordinal', 'phase', 'path', 'key', 'diagnostic'},
                                                {'ordinal', 'phase', 'path', 'key', 'diagnostic_omitted'})
                    or type(event['ordinal']) is not int or not previous < event['ordinal'] <= row['sequence']
                    or event['phase'] not in ('setup', 'call', 'teardown')
                    or type(event['path']) is not str or len(event['path']) > 256
                    or not re.fullmatch(r'tests/[A-Za-z0-9_./-]+\.py', event['path'])
                    or any(part in {'', '.', '..'} for part in event['path'].split('/'))
                    or type(event['key']) is not str or not re.fullmatch('[0-9a-f]{64}', event['key'])):
                valid = False
                break
            if 'diagnostic' in event and not _valid_failure_diagnostic(event['diagnostic']):
                valid = False
                break
            if 'diagnostic_omitted' in event and event['diagnostic_omitted'] is not True:
                valid = False
                break
            previous = event['ordinal']
        if valid:
            rows.append(row)
    return sorted(rows, key=lambda row: row['worker'])


def _failure_progress_details(rows, identities, workers):
    output = {'version': 1, 'observation': 'FAILED_REPORTS_BEFORE_STOP', 'prefix_only': True,
              'status': 'unavailable', 'overflow': None, 'dropped': None, 'partial_tail': None,
              'render_truncated': False, 'omitted_events': 0, 'events': []}
    if not rows:
        return output
    diagnostic_omissions = any(event.get('diagnostic_omitted') is True
                              or 'diagnostic' in event and (event['path'], event['key']) not in identities
                              for row in rows for event in row['events'])
    if diagnostic_omissions:
        output['diagnostics_omitted'] = True
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
            if identity is None:
                candidate['source'] = {'path': event['path'], 'key': event['key']}
            if identity is not None and 'diagnostic' in event:
                candidate['diagnostic'] = dict(event['diagnostic'])
            if (event.get('diagnostic_omitted') is True
                    or identity is None and 'diagnostic' in event):
                candidate['diagnostic_omitted'] = True
            proposed = {**output, 'events': output['events'] + [candidate]}
            # Reserve the longest final flag spelling without publishing a
            # provisional FALSE. Finalizing certainty must not exceed the cap.
            budgeted = {**proposed, 'omitted_events': 256,
                        **{name: True if value else False for name, value in proven.items()}}
            if len(json.dumps(budgeted).encode('utf-8')) > 8192:
                output['render_truncated'] = True
                break
            output['events'].append(candidate)
        if output['render_truncated']:
            break
    uncertain = not known or unknown or output['render_truncated'] or any(proven.values()) or diagnostic_omissions
    for name, value in proven.items():
        output[name] = True if value else None if uncertain else False
    output['status'] = 'partial' if uncertain else 'observed'
    output['omitted_events'] = sum(len(row['events']) for row in rows) - len(output['events'])
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
    source_lookup = {'status': 'unavailable', 'reason': 'no-source', 'head': None, 'currentness': 'unknown'}
    trusted = _trusted_progress_metadata(root, paths, deadline=deadline, observation=source_lookup) if paths else {}
    output['source_lookup'] = source_lookup
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
        source_lookup.update(status='unavailable', reason='node-deadline', currentness='unknown')
    output['failure_events'] = _failure_progress_details(failures, identities, workers)
    rendered = []
    unknown = False
    for worker, state, path, key in sorted(slots):
        identity = identities.get((path, key))
        unknown |= identity is None
        candidate = {'worker': worker, 'state': state, 'identity': identity}
        if identity is None and path is not None:
            candidate['source'] = {'path': path, 'key': key}
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
