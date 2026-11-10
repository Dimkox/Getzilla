"""Bounded, private observation history. Missing events never establish success."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
import hashlib
import functools
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import unittest
import uuid

from . import fsx

EVENT_BYTES = 2048
SEGMENT_BYTES = 128 * 1024
SEGMENTS = 4
ACTORS = 65
RUN_BYTES = 33 * 1024 * 1024
RUNS = 4
_CURRENT = ContextVar('verification_journal', default=None)
_ID = re.compile(r'(?:[a-z][a-z0-9-]{0,63}|tool:[a-z][a-z0-9_-]{0,63})\Z')
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')
_RUN = re.compile(r'[0-9a-f]{32}\Z')
_SESSION = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z')
_ACTOR = re.compile(r'controller|worker-(?:[0-9]|[1-5][0-9]|6[0-3])\Z')
_STAGES = {'action', 'command', 'check', 'collection', 'setup', 'call', 'teardown', 'test', 'run', 'cleanup'}
_STATES = {'start', 'end', 'pass', 'fail', 'skip', 'error', 'cancelled', 'timeout', 'unknown', 'expected-failure', 'unexpected-success'}
_ERRORS = {'AssertionError', 'OSError', 'ValueError', 'TypeError', 'RuntimeError', 'ImportError',
           'ModuleNotFoundError', 'TimeoutError', 'KeyboardInterrupt', 'SystemExit'}


def _json(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('ascii')


def _regular(info):
    return (stat.S_ISREG(info.st_mode) and not fsx.is_link(info) and info.st_nlink == 1
            and (os.name == 'nt' or info.st_uid == os.getuid() and not info.st_mode & 0o077))


def _directory(path):
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or fsx.is_link(info)
            or os.name != 'nt' and (info.st_uid != os.getuid() or info.st_mode & 0o077)):
        raise OSError('journal-directory-unavailable')
    handle = fsx.open_dir(path)
    after = fsx.fstat_dir(handle)
    if (after.st_dev, after.st_ino) != (info.st_dev, info.st_ino):
        fsx.close_dir(handle)
        raise OSError('journal-directory-changed')
    return handle


def _read(handle, name, limit):
    before = fsx.lstat_at(handle, name)
    if not _regular(before) or before.st_size > limit:
        raise OSError('journal-file-unavailable')
    fd = fsx.open_at(handle, name, os.O_RDONLY | fsx.O_NOFOLLOW | fsx.O_NONBLOCK)
    try:
        raw = b''
        while len(raw) <= limit:
            block = os.read(fd, min(65536, limit + 1 - len(raw)))
            if not block:
                break
            raw += block
        after, named = os.fstat(fd), fsx.lstat_at(handle, name)
        def key(s):
            return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if not _regular(after) or key(before) != key(after) or key(after) != key(named) or len(raw) != after.st_size:
            raise OSError('journal-file-changed')
        return raw
    finally:
        os.close(fd)


def _publish(handle, name, value, limit):
    raw = _json(value) + b'\n'
    if len(raw) > limit:
        raise ValueError('journal-metadata-limit')
    try:
        prior = fsx.lstat_at(handle, name)
        if not _regular(prior):
            raise OSError('journal-metadata-replaced')
    except FileNotFoundError:
        prior = None
    temporary = name + '.tmp'
    fd = fsx.open_at(handle, temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | fsx.O_NOFOLLOW, 0o600)
    try:
        if os.write(fd, raw) != len(raw):
            raise OSError('journal-short-write')
    finally:
        os.close(fd)
    if prior is not None:
        named = fsx.lstat_at(handle, name)
        if (named.st_dev, named.st_ino) != (prior.st_dev, prior.st_ino):
            raise OSError('journal-metadata-replaced')
    fsx.replace_at(handle, temporary, handle, name)


def test_identity(nodeid):
    """Strip all parameter text before hashing or validating identity."""
    if type(nodeid) is not str:
        return None
    value = nodeid.partition('[')[0].replace('\\', '/')
    parts = value.split('::')
    if (len(value) > 512 or not 1 <= len(parts) <= 3 or len(parts[0]) > 256
            or not re.fullmatch(r'tests/[A-Za-z0-9_./-]+\.py', parts[0])
            or any(p in {'', '.', '..'} for p in parts[0].split('/'))
            or any(not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', p) for p in parts[1:])):
        return None
    return {'path': parts[0], 'key': hashlib.sha256(value.encode('ascii')).hexdigest()}


def skip_classification(reason):
    # Classify a closed subset; never publish the arbitrary reason itself.
    if type(reason) is not str:
        return 'redacted-unknown'
    patterns = {'dependency': r'(?:requires|missing|no) (?:pytest|xdist|coverage|PostgreSQL|psycopg|node|npm|git)(?: dependency)?',
                'platform': r'(?:Windows|POSIX|Linux|macOS) only',
                'opt-in': r'(?:optional|opt-in) (?:integration|network|database) test'}
    return next((kind for kind, pattern in patterns.items() if re.fullmatch(pattern, reason)), 'redacted-unknown')


def failure(exc, root=None):
    """No exception text, source lines, locals or absolute paths."""
    kind = type(exc).__name__
    result = {'error_class': kind if kind in _ERRORS else 'other'}
    frames = []
    trace = exc.__traceback__
    while trace is not None:
        if root is not None:
            try:
                relative = Path(trace.tb_frame.f_code.co_filename).relative_to(root).as_posix()
                if (len(relative) <= 256 and re.fullmatch(r'(?:tests|scripts|\.getzilla/getzilla)/[A-Za-z0-9_./-]+\.py', relative)
                        and all(p not in {'', '.', '..'} for p in relative.split('/'))
                        and 1 <= trace.tb_lineno <= 1000000):
                    frames.append({'path': relative, 'line': trace.tb_lineno})
            except ValueError:
                pass
        trace = trace.tb_next
    if frames:
        result['frames'] = frames[-4:]
    return result


class Writer:
    def __init__(self, path, run_id, actor, nonce):
        if not _RUN.fullmatch(run_id) or not _ACTOR.fullmatch(actor) or not _RUN.fullmatch(nonce):
            raise ValueError('journal-identity')
        self.handle = _directory(path)
        self.source_root = path.parents[3]
        self.actor, self.run_id, self.nonce = actor, run_id, nonce
        self.fd = self.lock = None
        self.disabled = False
        self.started = time.monotonic_ns()
        self.sequence = self.rotated = self.dropped = 0
        self.attempt = 1
        self.generation = self.size = 0
        self.identity = None
        self.active = {}
        try:
            header = json.loads(_read(self.handle, 'index.json', 16384))
            if header['run_id'] != run_id or header['nonce'] != nonce or header['status'] != 'active':
                raise ValueError('journal-run-binding')
            self.lock = fsx.open_at(self.handle, actor + '.lock', os.O_RDWR | os.O_CREAT | fsx.O_NOFOLLOW, 0o600)
            if not _regular(os.fstat(self.lock)):
                raise OSError('journal-lock-unavailable')
            fsx.lock_file(self.lock, blocking=False)
            try:
                prior = json.loads(_read(self.handle, actor + '.json', 2048))
                if (prior['run_id'] != run_id or prior['nonce'] != nonce or prior['actor'] != actor
                        or prior['status'] != 'closed' or prior.get('open_spans', 0)):
                    raise ValueError('journal-stream-not-closed')
                self.sequence, self.generation, self.rotated = prior['sequence'], prior['generation'] + 1, prior['rotated']
                self.attempt = prior['attempt'] + 1
            except FileNotFoundError:
                pass
            self._open_segment()
            self.health('active')
        except BaseException:
            self.close()
            raise

    def _open_segment(self):
        name = f'{self.actor}-{self.generation % SEGMENTS}.jsonl'
        try:
            old = _read(self.handle, name, SEGMENT_BYTES)
            self.rotated += len(old.splitlines())
            fsx.unlink_at(self.handle, name)
        except FileNotFoundError:
            pass
        self.fd = fsx.open_at(self.handle, name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | fsx.O_NOFOLLOW, 0o600)
        info = os.fstat(self.fd)
        if not _regular(info):
            raise OSError('journal-stream-unavailable')
        self.identity, self.name, self.size = (info.st_dev, info.st_ino), name, 0

    def health(self, status):
        _publish(self.handle, self.actor + '.json', {'version': 1, 'run_id': self.run_id, 'nonce': self.nonce,
            'actor': self.actor, 'sequence': self.sequence, 'generation': self.generation, 'rotated': self.rotated,
            'attempt': self.attempt,
            'dropped': self.dropped, 'open_spans': sum(map(len, self.active.values())),
            'status': status, 'segment': self.name}, 2048)

    def emit(self, stage, state, *, step=None, nodeid=None, outcome=None, code=None, error=None, skip=None, location=None, process=None):
        if self.disabled:
            return False
        try:
            if stage not in _STAGES or state not in _STATES or step is not None and not _ID.fullmatch(step):
                raise ValueError('journal-event-schema')
            row = {'version': 1, 'run_id': self.run_id, 'actor': self.actor, 'sequence': self.sequence + 1,
                   'actor_attempt': self.attempt,
                   'stage': stage, 'state': state, 'pid': os.getpid(), 'elapsed_ns': time.monotonic_ns() - self.started,
                   'utc': datetime.now(timezone.utc).isoformat(timespec='milliseconds')}
            if not 0 <= row['elapsed_ns'] <= 2**63 - 1 or row['sequence'] > 2**63 - 1:
                raise ValueError('journal-clock-or-sequence')
            if step is not None:
                row['step'] = step
            if process is not None:
                if type(process) is not int or not 1 <= process <= 2**31 - 1:
                    raise ValueError('journal-process')
                row['process'] = process
            if nodeid is not None:
                identity = test_identity(nodeid)
                if identity is None:
                    row['identity_status'] = 'unavailable'
                    self.dropped += 1
                else:
                    row.update(identity)
            identity = (stage, step, row.get('key'))
            if state == 'start':
                if sum(map(len, self.active.values())) >= 256:
                    raise ValueError('journal-open-span-limit')
                self.active.setdefault(identity, []).append(self.sequence + 1)
                row['invocation'] = self.sequence + 1
            elif state == 'end':
                if self.active.get(identity):
                    row['invocation'] = self.active[identity].pop()
                else:
                    row['unmatched_end'] = True
            if outcome is not None:
                if outcome not in _STATES:
                    raise ValueError('journal-outcome')
                row['outcome'] = outcome
            if code is not None:
                if type(code) is not int or not -255 <= code <= 65535:
                    raise ValueError('journal-exit')
                row['exit'] = code
            if error is not None:
                if not isinstance(error, BaseException):
                    raise ValueError('journal-error')
                row.update(failure(error, self.source_root))
            if skip is not None:
                if skip not in {'dependency', 'platform', 'opt-in', 'redacted-unknown'}:
                    raise ValueError('journal-skip-class')
                row['skip_class'] = skip
                row['location_status'] = 'reported' if location is not None else 'unavailable'
            if location is not None:
                path, line = location
                if (type(path) is not str or not re.fullmatch(r'(?:tests|scripts|\.getzilla/getzilla)/[A-Za-z0-9_./-]+\.py', path)
                        or any(p in {'', '.', '..'} for p in path.split('/'))
                        or type(line) is not int or not 1 <= line <= 1000000):
                    raise ValueError('journal-location')
                row['location'] = {'path': path, 'line': line}
            raw = _json(row) + b'\n'
            if len(raw) > EVENT_BYTES:
                raise ValueError('journal-event-limit')
            if self.size + len(raw) > SEGMENT_BYTES:
                os.close(self.fd)
                self.fd = None
                self.generation += 1
                self._open_segment()
            held, named = os.fstat(self.fd), fsx.lstat_at(self.handle, self.name)
            if (not _regular(held) or not _regular(named) or (held.st_dev, held.st_ino) != self.identity
                    or (named.st_dev, named.st_ino) != self.identity or held.st_size != self.size):
                raise OSError('journal-stream-replaced')
            if os.write(self.fd, raw) != len(raw):
                raise OSError('journal-short-write')
            self.size += len(raw)
            self.sequence += 1
            self.health('active')
            return True
        except (OSError, ValueError, TypeError):
            self.disabled = True
            self.dropped += 1
            try:
                self.health('unavailable')
            except (OSError, ValueError):
                pass
            print('getzilla journal: unavailable; history may be incomplete', file=sys.stderr, flush=True)
            return False

    def close(self):
        if self.fd is not None:
            try:
                self.health('unavailable' if self.disabled else 'closed')
            except (OSError, ValueError):
                self.disabled = True
            os.close(self.fd)
            self.fd = None
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None
        if self.handle is not None:
            fsx.close_dir(self.handle)
            self.handle = None


class Run:
    def __init__(self, root, source, entrypoint):
        self.root, self.writer = root, None
        self.run_id, self.nonce = uuid.uuid4().hex, uuid.uuid4().hex
        self.status, self.path = 'unavailable', None
        self.source = source if type(source) is str and _DIGEST.fullmatch(source) else None
        self.session_id = None
        self.entrypoint = entrypoint
        try:
            if not _ID.fullmatch(entrypoint):
                raise ValueError('journal-entrypoint')
            anchor = root / '.getzilla' / 'runtime'
            for parent in (root / '.getzilla', anchor):
                parent.mkdir(mode=0o700, exist_ok=True)
                info = parent.lstat()
                if fsx.is_link(info) or not stat.S_ISDIR(info.st_mode):
                    raise OSError('journal-anchor')
            history = anchor / 'verification-history'
            history.mkdir(mode=0o700, exist_ok=True)
            handle = _directory(history)
            lock = None
            try:
                lock = fsx.open_at(handle, 'registry.lock', os.O_RDWR | os.O_CREAT | fsx.O_NOFOLLOW, 0o600)
                if not _regular(os.fstat(lock)):
                    raise OSError('journal-registry-lock')
                fsx.lock_file(lock, blocking=False)
                try:
                    registry = json.loads(_read(handle, 'registry.json', 16384))
                except FileNotFoundError:
                    registry = {'version': 1, 'runs': []}
                if set(registry) != {'version', 'runs'} or registry['version'] != 1 or len(registry['runs']) > RUNS:
                    raise ValueError('journal-registry')
                admitted = {r['run_id'] for r in registry['runs'] if _RUN.fullmatch(r['run_id'])}
                if set(os.listdir(history)) - admitted - {'registry.json', 'registry.lock'}:
                    raise ValueError('journal-unknown-storage')
                # Never evict active or unknown runs. Exact terminal owned runs alone qualify.
                if len(registry['runs']) >= RUNS:
                    candidate = next((r for r in registry['runs'] if r.get('status') == 'closed'), None)
                    if candidate is None:
                        raise OSError('journal-retention-unavailable')
                    _remove_run(history, candidate)
                    registry['runs'].remove(candidate)
                path = history / self.run_id
                path.mkdir(mode=0o700)
                self.path = path
                run_handle = _directory(path)
                try:
                    _publish(run_handle, 'index.json', {'version': 1, 'run_id': self.run_id, 'nonce': self.nonce,
                        'source': self.source, 'source_status': 'reported-integrity-only' if self.source else 'unavailable',
                        'session_id': None, 'session_status': 'unavailable',
                        'entrypoint': entrypoint, 'status': 'active', 'expected': []}, 16384)
                finally:
                    fsx.close_dir(run_handle)
                registry['runs'].append({'run_id': self.run_id, 'nonce': self.nonce, 'status': 'active'})
                _publish(handle, 'registry.json', registry, 16384)
            finally:
                if lock is not None:
                    os.close(lock)
                fsx.close_dir(handle)
            self.writer = Writer(path, self.run_id, 'controller', self.nonce)
            self.status = 'active'
            print('getzilla journal: ' + self.relative_index, file=sys.stderr, flush=True)
        except (OSError, ValueError, KeyError, TypeError):
            print('getzilla journal: unavailable; no complete history claim', file=sys.stderr, flush=True)

    @property
    def relative_index(self):
        return '.getzilla/runtime/verification-history/' + self.run_id + '/index.json'

    def child_environment(self, environment, actor=0):
        values = dict(environment if environment is not None else os.environ)
        for name in ('GETZILLA_JOURNAL_DIR', 'GETZILLA_JOURNAL_RUN', 'GETZILLA_JOURNAL_NONCE', 'GETZILLA_JOURNAL_ACTOR'):
            values.pop(name, None)
        if self.writer is not None and self.path is not None and type(actor) is int and 0 <= actor < 64:
            self.expect_workers(actor + 1)
            values.update(GETZILLA_JOURNAL_DIR=str(self.path), GETZILLA_JOURNAL_RUN=self.run_id,
                          GETZILLA_JOURNAL_NONCE=self.nonce, GETZILLA_JOURNAL_ACTOR=str(actor))
        return values

    def expect_workers(self, workers):
        if self.path is None or type(workers) is not int or not 1 <= workers <= 64:
            return
        handle = _directory(self.path)
        try:
            value = json.loads(_read(handle, 'index.json', 16384))
            value['expected'] = sorted(set(value['expected']) | {'worker-' + str(i) for i in range(workers)})
            _publish(handle, 'index.json', value, 16384)
        except (OSError, ValueError, KeyError):
            self.status = 'unavailable'
        finally:
            fsx.close_dir(handle)

    def summary(self):
        return {'version': 1, 'run_id': self.run_id, 'index': self.relative_index if self.path else None,
                'status': 'unavailable' if self.writer is None or self.writer.disabled else self.status,
                'source_status': 'reported-integrity-only' if self.source is not None else 'unavailable',
                'session_status': 'canonical-route-observation' if self.session_id is not None else 'unavailable',
                'completeness': 'unknown-until-terminal-and-all-actors-validated'}

    def bind_source(self, digest, session_id=None):
        if self.path is None or type(digest) is not str or not _DIGEST.fullmatch(digest):
            return
        handle = _directory(self.path)
        try:
            value = json.loads(_read(handle, 'index.json', 16384))
            value['source'] = digest
            value['source_status'] = 'reported-integrity-only'
            value['session_id'] = session_id if type(session_id) is str and _SESSION.fullmatch(session_id) else None
            value['session_status'] = 'canonical-route-observation' if value['session_id'] is not None else 'unavailable'
            _publish(handle, 'index.json', value, 16384)
            self.source = digest
            self.session_id = value['session_id']
        except (OSError, ValueError):
            self.status = 'unavailable'
        finally:
            fsx.close_dir(handle)

    def close(self):
        if self.writer is None:
            return
        self.writer.close()
        self.status = 'closed' if not self.writer.disabled and self.status == 'active' else 'unavailable'
        handle = _directory(self.path)
        try:
            value = json.loads(_read(handle, 'index.json', 16384))
            expected = value['expected']
            for actor in ['controller', *('worker-' + str(i) for i in range(64))]:
                try:
                    health = json.loads(_read(handle, actor + '.json', 2048))
                    if (health.get('status') != 'closed' or health.get('open_spans', 0)
                            or health.get('run_id') != self.run_id or health.get('nonce') != self.nonce):
                        self.status = 'incomplete' if self.status == 'closed' else self.status
                except FileNotFoundError:
                    if actor in expected:
                        self.status = 'incomplete' if self.status == 'closed' else self.status
                    continue
            value['status'] = self.status
            _publish(handle, 'index.json', value, 16384)
        except (OSError, ValueError):
            self.status = 'unavailable'
        finally:
            fsx.close_dir(handle)
        handle = _directory(self.path.parent)
        lock = None
        try:
            lock = fsx.open_at(handle, 'registry.lock', os.O_RDWR | fsx.O_NOFOLLOW)
            fsx.lock_file(lock, blocking=False)
            value = json.loads(_read(handle, 'registry.json', 16384))
            for row in value['runs']:
                if row['run_id'] == self.run_id and row['nonce'] == self.nonce:
                    row['status'] = self.status
                    value['runs'].remove(row)
                    value['runs'].append(row)
                    break
            _publish(handle, 'registry.json', value, 16384)
        except (OSError, ValueError, KeyError):
            self.status = 'unavailable'
        finally:
            if lock is not None:
                os.close(lock)
            fsx.close_dir(handle)


def _remove_run(history, record):
    if (set(record) != {'run_id', 'nonce', 'status'} or record['status'] != 'closed'
            or not _RUN.fullmatch(record['run_id']) or not _RUN.fullmatch(record['nonce'])):
        raise ValueError('journal-retention-record')
    path = history / record['run_id']
    handle = _directory(path)
    locks = []
    try:
        index = json.loads(_read(handle, 'index.json', 16384))
        if index['run_id'] != record['run_id'] or index['nonce'] != record['nonce'] or index['status'] != 'closed':
            raise ValueError('journal-retention-identity')
        names = os.listdir(path)
        if len(names) > ACTORS * 7 + 1:
            raise ValueError('journal-retention-count')
        for name in names:
            if name != 'index.json' and not re.fullmatch(r'(?:controller|worker-(?:[0-9]|[1-5][0-9]|6[0-3]))(?:\.lock|\.json|-[0-3]\.jsonl)', name):
                raise ValueError('journal-retention-shape')
            _read(handle, name, SEGMENT_BYTES)
            if name.endswith('.lock'):
                descriptor = fsx.open_at(handle, name, os.O_RDWR | fsx.O_NOFOLLOW)
                locks.append(descriptor)
                fsx.lock_file(descriptor, blocking=False)
            elif name.endswith('.json') and name != 'index.json':
                health = json.loads(_read(handle, name, 2048))
                if (health['run_id'] != record['run_id'] or health['nonce'] != record['nonce']
                        or health['status'] != 'closed' or health.get('open_spans', 0)):
                    raise ValueError('journal-retention-active-stream')
        for name in names:
            fsx.unlink_at(handle, name)
    finally:
        for descriptor in locks:
            os.close(descriptor)
        fsx.close_dir(handle)
    path.rmdir()


def child_writer(environment=None, ordinal=None):
    values = environment if environment is not None else os.environ
    try:
        ordinal = str(ordinal) if ordinal is not None else values['GETZILLA_JOURNAL_ACTOR']
        if not re.fullmatch(r'[0-9]{1,2}', ordinal) or int(ordinal) >= 64:
            raise ValueError('journal-worker')
        return Writer(Path(values['GETZILLA_JOURNAL_DIR']), values['GETZILLA_JOURNAL_RUN'],
                      'worker-' + str(int(ordinal)), values['GETZILLA_JOURNAL_NONCE'])
    except (OSError, ValueError, KeyError, TypeError):
        if values.get('GETZILLA_JOURNAL_DIR'):
            print('getzilla journal: worker history unavailable', file=sys.stderr, flush=True)
        return None


@contextmanager
def activate(run):
    token = _CURRENT.set(run)
    try:
        yield run
    finally:
        _CURRENT.reset(token)


def current():
    return _CURRENT.get()


@contextmanager
def session(root, entrypoint, report=None):
    existing = current()
    if existing is not None:
        yield existing
        return
    run = Run(root, None, entrypoint)
    with activate(run):
        try:
            if run.writer:
                run.writer.emit('run', 'start', step=entrypoint)
            yield run
        finally:
            if run.writer:
                run.writer.emit('run', 'end', step=entrypoint)
            try:
                run.close()
            except (OSError, ValueError, KeyError):
                run.status = 'unavailable'
            if report is not None:
                report['diagnostics'] = run.summary()
            if run.status != 'closed':
                print('getzilla journal: ' + run.status + '; retained history is incomplete', file=sys.stderr, flush=True)


def entrypoint(name):
    def decorate(function):
        @functools.wraps(function)
        def wrapped(root, *args, **kwargs):
            with session(root, name) as run:
                result = function(root, *args, **kwargs)
            try:
                result.diagnostics = run.summary()
            except (AttributeError, TypeError):
                pass
            return result
        return wrapped
    return decorate


def observed(name, stage='check'):
    def decorate(function):
        @functools.wraps(function)
        def wrapped(*args, **kwargs):
            with span(name, stage=stage) as details:
                result = function(*args, **kwargs)
                if details is not None:
                    outcome = getattr(result, 'status', None)
                    code = getattr(result, 'returncode', None)
                    if code is not None:
                        outcome = 'pass' if code == 0 else 'timeout' if code == 124 else 'fail'
                    if outcome in _STATES:
                        details.update(outcome=outcome, code=code)
                return result
        return wrapped
    return decorate


@contextmanager
def span(step, *, stage='check'):
    run = current()
    writer = run.writer if run else None
    if writer:
        writer.emit(stage, 'start', step=step)
    try:
        details = {}
        yield details
    except BaseException as exc:
        if writer:
            writer.emit(stage, 'end', step=step, outcome='error', error=exc)
        raise
    else:
        if writer:
            writer.emit(stage, 'end', step=step, **details)


def case_identity(test):
    module = type(test).__module__
    if not module.startswith('tests.'):
        module = 'tests.' + module
    return module.replace('.', '/') + '.py::' + type(test).__name__ + '::' + str(getattr(test, '_testMethodName', 'unknown'))


def case_location(test):
    method = getattr(test, getattr(test, '_testMethodName', ''), None)
    code = getattr(method, '__code__', None)
    if code is not None:
        return (case_identity(test).split('::')[0], code.co_firstlineno)
    return None


def unittest_runner(writer):
    """Use the standard runner once; observe its actual call boundaries only."""
    class Result(unittest.TextTestResult):
        def startTest(self, test):
            super().startTest(test)
            node = case_identity(test)
            writer.emit('test', 'start', nodeid=node)
            originals = {}
            for name, stage in (('_callSetUp', 'setup'), ('_callTestMethod', 'call'), ('_callTearDown', 'teardown')):
                original = getattr(test, name)
                originals[name] = (name in test.__dict__, test.__dict__.get(name))
                def observed(*args, _original=original, _stage=stage, **kwargs):
                    writer.emit(_stage, 'start', nodeid=node)
                    try:
                        value = _original(*args, **kwargs)
                    except BaseException as exc:
                        writer.emit(_stage, 'end', nodeid=node, outcome='skip' if isinstance(exc, unittest.SkipTest) else 'error',
                                    error=exc, skip=skip_classification(str(exc)) if isinstance(exc, unittest.SkipTest) else None)
                        raise
                    writer.emit(_stage, 'end', nodeid=node, outcome='pass')
                    return value
                setattr(test, name, observed)
            self._journal_originals = (test, originals)

        def stopTest(self, test):
            prior = getattr(self, '_journal_originals', None)
            if prior is not None and prior[0] is test:
                for name, (had, value) in prior[1].items():
                    if had:
                        setattr(test, name, value)
                    else:
                        test.__dict__.pop(name, None)
            super().stopTest(test)

        def addSuccess(self, test):
            writer.emit('test', 'end', nodeid=case_identity(test), outcome='pass')
            super().addSuccess(test)

        def addFailure(self, test, err):
            writer.emit('test', 'end', nodeid=case_identity(test), outcome='fail', error=err[1])
            super().addFailure(test, err)

        def addError(self, test, err):
            writer.emit('test', 'end', nodeid=case_identity(test), outcome='error', error=err[1])
            super().addError(test, err)

        def addSkip(self, test, reason):
            writer.emit('test', 'end', nodeid=case_identity(test), outcome='skip', skip=skip_classification(reason), location=case_location(test))
            super().addSkip(test, reason)

        def addExpectedFailure(self, test, err):
            writer.emit('test', 'end', nodeid=case_identity(test), outcome='expected-failure', error=err[1])
            super().addExpectedFailure(test, err)

        def addUnexpectedSuccess(self, test):
            writer.emit('test', 'end', nodeid=case_identity(test), outcome='unexpected-success')
            super().addUnexpectedSuccess(test)

        def addSubTest(self, test, subtest, err):
            writer.emit('call', 'unknown', nodeid=case_identity(test), outcome='pass' if err is None else 'fail',
                        error=None if err is None else err[1])
            super().addSubTest(test, subtest, err)

    class Runner(unittest.TextTestRunner):
        resultclass = Result

        def run(self, test):
            writer.emit('collection', 'end')
            return super().run(test)
    return Runner


def _validated_events(raw, run_id, actor):
    allowed = {'version', 'run_id', 'actor', 'actor_attempt', 'sequence', 'stage', 'state', 'pid', 'elapsed_ns', 'utc',
               'step', 'path', 'key', 'invocation', 'unmatched_end', 'outcome', 'exit', 'error_class',
               'frames', 'skip_class', 'location_status', 'location', 'process', 'identity_status'}
    def closed(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('journal-duplicate-key')
            result[key] = value
        return result
    result = []
    for line in raw.splitlines():
        if len(line) > EVENT_BYTES:
            raise ValueError('journal-record-bound')
        row = json.loads(line, object_pairs_hook=closed)
        if (type(row) is not dict or set(row) - allowed or row.get('version') != 1
                or row.get('run_id') != run_id or row.get('actor') != actor
                or row.get('stage') not in _STAGES or row.get('state') not in _STATES
                or any(type(row.get(key)) is not int or not 0 <= row[key] <= 2**63 - 1
                       for key in ('actor_attempt', 'sequence', 'pid', 'elapsed_ns'))
                or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}\+00:00', str(row.get('utc', '')))):
            raise ValueError('journal-record-schema')
        if 'step' in row and (type(row['step']) is not str or not _ID.fullmatch(row['step'])):
            raise ValueError('journal-record-step')
        if 'path' in row and test_identity(row['path']) is None:
            raise ValueError('journal-record-path')
        if 'key' in row and (type(row['key']) is not str or not _DIGEST.fullmatch(row['key'])):
            raise ValueError('journal-record-key')
        if 'outcome' in row and row['outcome'] not in _STATES:
            raise ValueError('journal-record-outcome')
        if 'error_class' in row and row['error_class'] not in _ERRORS | {'other'}:
            raise ValueError('journal-record-error')
        if 'skip_class' in row and row['skip_class'] not in {'dependency', 'platform', 'opt-in', 'redacted-unknown'}:
            raise ValueError('journal-record-skip')
        if 'location_status' in row and row['location_status'] not in {'reported', 'unavailable'}:
            raise ValueError('journal-record-location')
        if 'identity_status' in row and row['identity_status'] != 'unavailable':
            raise ValueError('journal-record-identity')
        if 'unmatched_end' in row and row['unmatched_end'] is not True:
            raise ValueError('journal-record-unmatched')
        for key in ('process', 'exit', 'invocation'):
            if key in row and (type(row[key]) is not int or not -255 <= row[key] <= 2**63 - 1):
                raise ValueError('journal-record-number')
        locations = row.get('frames', []) + ([row['location']] if 'location' in row else [])
        if len(locations) > 5:
            raise ValueError('journal-record-frames')
        for location in locations:
            if (type(location) is not dict or set(location) != {'path', 'line'}
                    or type(location['path']) is not str or len(location['path']) > 256
                    or not re.fullmatch(r'(?:tests|scripts|\.getzilla/getzilla)/[A-Za-z0-9_./-]+\.py', location['path'])
                    or any(p in {'', '.', '..'} for p in location['path'].split('/'))
                    or type(location['line']) is not int or not 1 <= location['line'] <= 1000000):
                raise ValueError('journal-record-frame')
        result.append(_json(row) + b'\n')
    return b''.join(result)


def export_entries(root):
    """A safe bounded subset; never a complete-history or authorization claim."""
    entries, summary = [], {'version': 1, 'status': 'unavailable', 'subset': True}
    history = root / '.getzilla/runtime/verification-history'
    try:
        handle = _directory(history)
        try:
            registry = json.loads(_read(handle, 'registry.json', 16384))
        finally:
            fsx.close_dir(handle)
        row = registry['runs'][-1]
        if not _RUN.fullmatch(row['run_id']) or not _RUN.fullmatch(row['nonce']):
            raise ValueError('journal-export-identity')
        handle = _directory(history / row['run_id'])
        try:
            index = json.loads(_read(handle, 'index.json', 16384))
            if (index['run_id'] != row['run_id'] or index['nonce'] != row['nonce']
                    or index['status'] not in {'active', 'closed', 'incomplete', 'unavailable'}):
                raise ValueError('journal-export-identity')
            summary.update(run_id=row['run_id'], status=index['status'], actors=[])
            for actor in ['controller', *('worker-' + str(i) for i in range(64))]:
                try:
                    health = json.loads(_read(handle, actor + '.json', 2048))
                    if (set(health) != {'version', 'run_id', 'nonce', 'actor', 'attempt', 'sequence', 'generation', 'rotated', 'dropped', 'open_spans', 'status', 'segment'}
                            or health['run_id'] != row['run_id'] or health['nonce'] != row['nonce'] or health['actor'] != actor
                            or health['status'] not in {'active', 'closed', 'unavailable'}
                            or any(type(health[k]) is not int or not 0 <= health[k] <= 2**63 - 1
                                   for k in ('attempt', 'sequence', 'generation', 'rotated', 'dropped', 'open_spans'))
                            or health['segment'] != f'{actor}-{health["generation"] % SEGMENTS}.jsonl'):
                        raise ValueError('journal-export-actor')
                    raw = _read(handle, f'{actor}-{health["generation"] % SEGMENTS}.jsonl', SEGMENT_BYTES)
                    tail = raw[-65536:]
                    if len(raw) > len(tail):
                        tail = tail.partition(b'\n')[2]
                    complete = tail.rpartition(b'\n')[0] + b'\n' if b'\n' in tail else b''
                    entries.append(('journal/' + actor + '.jsonl', _validated_events(complete, row['run_id'], actor)))
                    summary['actors'].append(health)
                except FileNotFoundError:
                    continue
        finally:
            fsx.close_dir(handle)
        summary['status'] = 'bounded-subset'
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        summary['status'] = 'unavailable'
    entries.insert(0, ('journal/index.json', _json(summary) + b'\n'))
    return entries
