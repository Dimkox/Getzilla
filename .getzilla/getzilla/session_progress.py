"""Bounded observations of unchanged failed checks, never permission or success evidence."""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shlex
import stat
import time
from contextlib import contextmanager, suppress
from pathlib import Path

from . import fsx
from .state import get_active_route
from .util import git_head, tree_fingerprint

STATE = '.getzilla/runtime/session-progress.json'
LOCK = '.getzilla/runtime/.session-progress.guard'
MAX_BYTES, MAX_RECORDS, MAX_EVENTS, MAX_RECOVERIES = 262_144, 128, 16, 16
TTL, THRESHOLD, MAX_COUNT, LOCK_TIMEOUT = 3600, 3, 1_000_000, 1.0
REASONS = frozenset({'new-evidence', 'changed-hypothesis'})
UNAVAILABLE = 'Getzilla: progress observations unavailable; ordinary authorization still applies.'
_HEX = re.compile(r'[0-9a-f]{64}')
_FIELDS = frozenset({'scope', 'source', 'failure', 'count', 'at', 'revision', 'events', 'recoveries', 'retry'})


def _digest(domain, value):
    raw = json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(',', ':'))
    return hashlib.sha256((domain + '\0' + raw).encode()).hexdigest()


def _hex(value):
    return isinstance(value, str) and _HEX.fullmatch(value) is not None


def _clock(now):
    value = time.time() if now is None else now
    if type(value) not in (int, float) or not 0 <= value <= 10**12:
        raise ValueError('invalid-observation-time')
    return int(value)


def scope_id(root, session, agent='unknown', generation=None):
    """Only a session's matching route identifies its task; global fallbacks do not."""
    if not isinstance(session, str) or session == 'manual' or not re.fullmatch(r'[A-Za-z0-9._-]{1,128}', session):
        return None
    route = get_active_route(root) or {}
    if route.get('session_id') != session:
        return None
    task = route.get('change_id') or route.get('route_id')
    if not isinstance(task, str) or not task or len(task) > 256:
        return None
    if not isinstance(agent, str) or len(agent) > 256 or generation is not None and (not isinstance(generation, str) or len(generation) > 256):
        return None
    return _digest('scope', [str(root.resolve()), session, task, agent or 'unknown', generation])


def _eligible(command):
    if not isinstance(command, str) or not command.strip() or len(command) > 20_000 or re.search(r'[\n\r$`;&|<>]', command):
        return False
    try:
        words = shlex.split(command)
    except ValueError:
        return False
    while words and re.match(r'^[A-Za-z_][A-Za-z0-9_]*=', words[0]):
        words.pop(0)
    if not words:
        return False
    program, args = Path(words[0]).name.removesuffix('.exe'), words[1:]
    if re.fullmatch(r'python(?:\d+(?:\.\d+)?)?', program):
        if len(args) >= 2 and args[0] == '-m':
            program, args = args[1], args[2:]
        else:
            return bool(args and args[0] == 'scripts/getzilla_verify.py')
    if program in {'pytest', 'unittest', 'mypy', 'pyright', 'tsc', 'eslint', 'bandit'}:
        return True
    if program == 'ruff':
        return bool(args and args[0] == 'check')
    commands = {'npm': {'test', 'build', 'lint', 'check', 'typecheck'},
                'pnpm': {'test', 'build', 'lint', 'check', 'typecheck'},
                'yarn': {'test', 'build', 'lint', 'check', 'typecheck'},
                'cargo': {'test', 'build', 'check', 'clippy'}, 'go': {'test', 'build', 'vet'},
                'dotnet': {'test', 'build'}, 'make': {'test', 'check', 'lint', 'build'},
                'getzilla': {'verify'}}
    if program in {'npm', 'pnpm', 'yarn'} and args[:1] == ['run']:
        args = args[1:]
    return bool(args and args[0] in commands.get(program, set()))


def _key(root, scope, inputs, cwd):
    if not _hex(scope) or not isinstance(inputs, dict) or not _eligible(inputs.get('command')):
        return None
    location = str(cwd.resolve().relative_to(root.resolve()))
    meaningful = {key: value for key, value in inputs.items() if key not in {'cmd', 'yield_time_ms', 'max_output_tokens'}}
    raw = json.dumps(meaningful, sort_keys=True, ensure_ascii=True, allow_nan=False)
    if len(raw) > 32_768:
        return None
    return _digest('operation', [scope, location, raw])


def _outcome(response):
    if not isinstance(response, dict):
        return None
    codes = [response[key] for key in ('exit_code', 'exitCode', 'returncode') if key in response]
    if not codes or any(type(code) is not int or not -(2**31) <= code < 2**32 for code in codes) or len(set(codes)) != 1:
        return None
    if response.get('status') not in (None, 'completed', 'finished', 'exited', 'failed', 'success'):
        return None
    if any(response.get(key) not in (None, False) for key in ('interrupted', 'timed_out', 'running', 'isAsync')):
        return None
    if any(response.get(key) is not None for key in ('session_id', 'sessionId')):
        return None  # a yielded terminal session is not a completed check
    output = {}
    for field in ('output', 'stdout', 'stderr', 'aggregated_output'):
        value = response.get(field, '')
        if not isinstance(value, str):
            return None
        # Work and storage are bounded even when a harness delivers a large log.
        output[field] = [len(value), value[:8192], value[-8192:] if len(value) > 8192 else '']
    return codes[0], _digest('failure', [codes[0], output])


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate-observation-field')
        value[key] = item
    return value


def _validate(state):
    if not isinstance(state, dict) or set(state) != {'version', 'records'} or type(state['version']) is not int or state['version'] != 1:
        raise ValueError('invalid-observation-schema')
    records = state['records']
    if not isinstance(records, dict) or len(records) > MAX_RECORDS:
        raise ValueError('invalid-observation-bound')
    for key, row in records.items():
        if not _hex(key) or not isinstance(row, dict) or set(row) != _FIELDS:
            raise ValueError('invalid-observation-record')
        if any(not _hex(row[field]) for field in ('scope', 'failure', 'revision')) or row['source'] is not None and not _hex(row['source']):
            raise ValueError('invalid-observation-digest')
        if type(row['count']) is not int or not 0 <= row['count'] <= MAX_COUNT or type(row['at']) is not int or not 0 <= row['at'] <= 10**12 or type(row['retry']) is not bool:
            raise ValueError('invalid-observation-value')
        for field, limit in (('events', MAX_EVENTS), ('recoveries', MAX_RECOVERIES)):
            if not isinstance(row[field], list) or len(row[field]) > limit or any(not _hex(value) for value in row[field]) or len(set(row[field])) != len(row[field]):
                raise ValueError('invalid-observation-history')


def _regular(parent, name, flags, limit):
    descriptor = fsx.open_at(parent, name, flags | fsx.O_NOFOLLOW | fsx.O_NONBLOCK | fsx.O_CLOEXEC, 0o600)
    try:
        opened, named = os.fstat(descriptor), fsx.lstat_at(parent, name)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened.st_mode & 0o111
                or opened.st_size > limit or fsx.is_link(named)
                or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)):
            raise ValueError('unsafe-observation-file')
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


@contextmanager
def _store(root, *, write=False):
    """Stable lock inode; pinned no-follow directories; bounded atomic state publication."""
    handles, lock, locked, temporary = [fsx.open_dir(root.resolve(strict=True))], None, False, None
    try:
        for name in ('.getzilla', 'runtime'):
            with suppress(FileExistsError):
                fsx.mkdir_at(handles[-1], name, 0o700)
            handles.append(fsx.open_dir_at(handles[-1], name))
        directory = handles[-1]
        lock = _regular(directory, Path(LOCK).name, os.O_RDWR | os.O_CREAT, 1)
        deadline = time.monotonic() + LOCK_TIMEOUT
        while not locked:
            try:
                fsx.lock_file(lock, blocking=False)
                locked = True
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError('observation-lock-unavailable') from None
                time.sleep(0.01)
        try:
            descriptor = _regular(directory, Path(STATE).name, os.O_RDONLY, MAX_BYTES)
        except FileNotFoundError:
            state = {'version': 1, 'records': {}}
        else:
            try:
                raw = os.read(descriptor, MAX_BYTES + 1)
                if len(raw) > MAX_BYTES:
                    raise ValueError('observation-byte-bound')
                state = json.loads(raw, object_pairs_hook=_pairs)
            finally:
                os.close(descriptor)
        _validate(state)
        before = json.dumps(state, sort_keys=True)
        yield state
        if not write or json.dumps(state, sort_keys=True) == before:
            return
        _validate(state)
        raw = (json.dumps(state, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
        if len(raw) > MAX_BYTES:
            raise ValueError('observation-byte-bound')
        for index, name in enumerate(('.getzilla', 'runtime')):
            named, opened = fsx.lstat_at(handles[index], name), fsx.fstat_dir(handles[index + 1])
            if fsx.is_link(named) or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino):
                raise ValueError('observation-directory-changed')
        temporary = '.session-progress-' + secrets.token_hex(12) + '.tmp'
        descriptor = _regular(directory, temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        fsx.replace_at(directory, temporary, directory, Path(STATE).name)
        temporary = None
    finally:
        if temporary is not None:
            with suppress(OSError):
                fsx.unlink_at(handles[-1], temporary)
        if lock is not None:
            try:
                if locked:
                    fsx.unlock_file(lock)
            finally:
                os.close(lock)
        for handle in reversed(handles):
            fsx.close_dir(handle)


def _expired(row, now):
    # Concurrent observations can acquire the lock out of timestamp order. A
    # small backward clock movement is not evidence of expiry or of progress.
    return abs(now - row['at']) > TTL


def _revision(row, now):
    row.update(at=now, revision=secrets.token_hex(32))


def observe(root, scope, inputs, cwd, response, source, *, event_id=None, now=None):
    key, outcome = _key(root, scope, inputs, cwd), _outcome(response)
    if key is None or outcome is None:
        return ''
    if source is not None and not _hex(source):
        raise ValueError('invalid-source-digest')
    now, (code, failure) = _clock(now), outcome
    event = _digest('event', event_id) if isinstance(event_id, str) and 0 < len(event_id) <= 256 else None
    with _store(root, write=True) as state:
        rows = state['records']
        for old in [identity for identity, row in rows.items() if _expired(row, now)]:
            del rows[old]
        previous = rows.get(key)
        if previous and event and event in previous['events']:
            return ''
        if not previous and len(rows) >= MAX_RECORDS:
            harmless = [(row['at'], identity) for identity, row in rows.items() if row['count'] < THRESHOLD]
            if not harmless:
                return 'Getzilla: progress observation capacity reached; this result was not recorded.'
            del rows[min(harmless)[1]]
        same = previous is not None and (previous['source'], previous['failure']) == (source, failure)
        row = {'scope': scope, 'source': source, 'failure': failure,
               'count': min(MAX_COUNT, previous['count'] + 1) if code and same else int(code != 0),
               'events': list(previous['events']) if previous else [],
               'recoveries': list(previous['recoveries']) if same else [], 'retry': False}
        if event:
            row['events'] = [*row['events'], event][-MAX_EVENTS:]
        _revision(row, now)
        rows[key] = row
        if row['count'] >= THRESHOLD:
            return (f'Getzilla: {row["count"]} identical completed check failures without observed source progress. '
                    'Inspect the cause before retrying; use `getzilla agent progress-inspect --session-id <current-session>`. '
                    + ('The next unchanged retry is stopped.' if source else 'Source identity is unavailable; warning only.'))
    return ''


def refusal(root, scope, inputs, cwd, *, source=None, now=None):
    key = _key(root, scope, inputs, cwd)
    if key is None:
        return None
    now = _clock(now)
    with _store(root, write=True) as state:
        row = state['records'].get(key)
        if not row or row['count'] < THRESHOLD or row['source'] is None or _expired(row, now):
            return None
        # No tree scan on ordinary commands or before the threshold.
        if source is None:
            source = tree_fingerprint(root) if git_head(root) else None
        if source is None or source != row['source']:
            return None
        if row['retry']:
            row['retry'] = False
            _revision(row, now)
            return None
        return ('Getzilla: unchanged retry stopped after repeated identical completed failures. '
                f'Loop ID: {key}. '
                'Read the failure and test a new hypothesis, change the relevant source, or inspect with '
                '`getzilla agent progress-inspect --session-id <current-session>` and use '
                '`getzilla agent progress-recover` with that loop ID, revision and new evidence for one retry. '
                'Ordinary authorization still applies.')


def inspect(root, scope, *, now=None):
    now, loops = _clock(now), []
    if not _hex(scope):
        return {'status': 'scope-unavailable', 'loops': [], 'control': 'local-observation-only'}
    with _store(root) as state:
        for key, row in state['records'].items():
            if row['scope'] != scope:
                continue
            status = ('expired' if _expired(row, now) else 'retry-available' if row['retry'] else
                      'blocked' if row['count'] >= THRESHOLD and row['source'] else
                      'warning' if row['count'] >= THRESHOLD else 'observing')
            loops.append({'loop_id': key, 'revision': row['revision'], 'count': row['count'],
                          'status': status, 'last_observed_at': row['at']})
    return {'status': 'available', 'loops': loops, 'control': 'local-observation-only', 'retention_seconds': TTL}


def recover(root, scope, loop_id, revision, reason, evidence, *, now=None):
    if not all(_hex(value) for value in (scope, loop_id, revision)) or reason not in REASONS:
        raise ValueError('invalid-recovery-target')
    if not isinstance(evidence, str) or not evidence.strip() or len(evidence) > 4096:
        raise ValueError('new-diagnosis-required')
    now, diagnosis = _clock(now), _digest('diagnosis', evidence.strip())
    with _store(root, write=True) as state:
        row = state['records'].get(loop_id)
        if (not row or row['scope'] != scope or row['revision'] != revision or _expired(row, now)
                or row['count'] < THRESHOLD or row['retry'] or diagnosis in row['recoveries']
                or len(row['recoveries']) >= MAX_RECOVERIES):
            raise ValueError('stale-or-reused-recovery')
        row['recoveries'].append(diagnosis)
        row['retry'] = True
        _revision(row, now)
        return {'loop_id': loop_id, 'revision': row['revision'], 'retry_available': True,
                'control': 'local-observation-only', 'success_asserted': False}
