"""Bounded, private observation history. Missing events never establish success."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from dataclasses import dataclass, replace
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
from types import FunctionType, MethodType
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
_peer = sys.modules.get('getzilla.verification_journal')
if __package__ == 'getzilla':
    _run = os.environ.get('GETZILLA_JOURNAL_RUN', '')
    _peer = sys.modules.get('_getzilla_observer_' + _run + '.verification_journal') if _RUN.fullmatch(_run) else None
_SINK = getattr(_peer, '_SINK', None)
if (not isinstance(_SINK, ContextVar) or (getattr(_peer, '__file__', None),
        getattr(getattr(_peer, '__spec__', None), 'origin', None),
        getattr(__spec__, 'origin', None)) != (__file__,) * 3):
    _SINK = ContextVar('verification_action_sink', default=None)
_SESSION = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z')
_ACTOR = re.compile(r'controller|worker-(?:[0-9]|[1-5][0-9]|6[0-3])\Z')
_STAGES = {'action', 'command', 'check', 'collection', 'setup', 'call', 'teardown', 'test', 'run', 'cleanup'}
_STATES = {'start', 'end', 'pass', 'fail', 'skip', 'error', 'cancelled', 'timeout', 'unknown', 'expected-failure', 'unexpected-success'}
_ERRORS = {'AssertionError', 'OSError', 'ValueError', 'TypeError', 'RuntimeError', 'ImportError',
           'ModuleNotFoundError', 'TimeoutError', 'KeyboardInterrupt', 'SystemExit'}
_OWNERSHIP_CASE = 'tests/test_python_test_runner.py::PythonTestRunnerTests::test_term_resistant_grandchild_is_killed_on_every_stop_path'
_OWNERSHIP_FORMS = ('exit', 'flood', 'timeout', 'controller')
_OWNERSHIP_FIELDS = {
    'form': set(_OWNERSHIP_FORMS),
    'phase': {'entered', 'execute', 'ready', 'term', 'grace', 'kill', 'reap', 'result',
              'controller-stop', 'controller-reaped', 'descendant-check', 'finished'},
    'status': {'active', 'returned', 'failed', 'cancelled', 'unknown'},
    'cleanup': {'none-reported', 'recorded', 'unavailable'},
    'descendant': {'absent', 'zombie', 'nonzombie', 'unavailable'},
}
_FAILURE_PHASES = {'setup', 'call', 'teardown', 'unknown'}
_FAILURE_OPS = {'action', 'command', 'check', 'cleanup', 'owned-command'}
_OMISSIONS = ('ownership_omitted', 'failure_omitted', 'action_omitted')


@dataclass(frozen=True)
class StopMetadata:
    version: int = 1
    decision: str = 'unavailable'
    result_policy: str = 'unavailable'
    cancel: str = 'unavailable'
    late_output: str = 'unavailable'
    scope: str = 'unavailable'


if ((getattr(_peer, '__file__', None), getattr(getattr(_peer, '__spec__', None), 'origin', None),
        getattr(__spec__, 'origin', None)) == (__file__,) * 3
        and isinstance(getattr(_peer, 'StopMetadata', None), type)):
    StopMetadata = _peer.StopMetadata


_STOP_FIELDS = {
    'decision': {'unavailable', 'child_exit', 'child_signal', 'deadline', 'output_limit', 'owned_cancel',
                 'primary_exception', 'spawn_error'},
    'result_policy': {'unavailable', 'child_status', 'limit_124', 'cancel_preserve_child', 'cancel_128_signal',
                      'fallback_1', 'spawn_127', 'aggregate', 'collection_refusal', 'coverage_refusal'},
    'cancel': {'unavailable', 'none', 'sigint', 'sigterm'},
    'late_output': {'unavailable', 'not_exceeded', 'exceeded'},
    'scope': {'process', 'parallel_batch', 'selected_shard', 'coverage_combine', 'unavailable'},
}


def _validate_stop(value):
    if (type(value) is not dict or set(value) != {'version', *_STOP_FIELDS}
            or type(value['version']) is not int or value['version'] != 1
            or any(type(value[k]) is not str or value[k] not in choices for k, choices in _STOP_FIELDS.items())
            or len(_json(value)) > 256):
        raise ValueError('stop-metadata-shape')
    return dict(value)


def stop_details(value):
    try:
        metadata = getattr(value, 'stop_metadata', None)
        if metadata is None:
            metadata = getattr(value, '_getzilla_stop_metadata', None)
        if type(metadata) is not StopMetadata:
            return vars(StopMetadata()).copy()
        return _validate_stop(vars(metadata))
    except BaseException:
        return vars(StopMetadata()).copy()


def updated_stop(value, **changes):
    return replace(StopMetadata(**stop_details(value)), **changes)


def retain_stop(value, metadata):
    try:
        value._getzilla_stop_metadata = metadata
    except BaseException:
        return None


def child_stop(code, *, scope='process'):
    decision = ('child_signal' if code < 0 and os.name != 'nt' else 'child_exit') if type(code) is int else 'unavailable'
    return StopMetadata(decision=decision, result_policy='child_status' if code is not None else 'fallback_1',
                        cancel='none', scope=scope)


def cancelled_stop(value, number):
    metadata = updated_stop(value, cancel={2: 'sigint', 15: 'sigterm'}.get(number, 'unavailable'))
    return replace(metadata, decision='owned_cancel') if metadata.decision == 'unavailable' else metadata


_CORE_STOP = ContextVar('core_stop_origin', default=None)


@contextmanager
def core_stop_scope():
    try:
        run = current()
        writer = run.writer if run else None
    except BaseException:
        writer = None
    token = _CORE_STOP.set(writer)
    try:
        yield
    except BaseException as exc:
        record_core_stop(exc)
        raise
    finally:
        _CORE_STOP.reset(token)


def record_core_stop(value):
    try:
        writer = _CORE_STOP.get()
        if writer is not None:
            _observe(writer, 'record_core_stop', value)
    except BaseException:
        return None


def _health_stop(health):
    if 'core_stop' not in health:
        return None
    value = health['core_stop']
    if (health.get('actor') != 'controller' or type(value) is not dict
            or set(value) != {'attempt', 'repeated', 'overflow', 'metadata'}
            or type(value['attempt']) is not int or not 1 <= value['attempt'] <= 2**63 - 1
            or any(type(value[k]) is not bool for k in ('repeated', 'overflow')) or len(_json(value)) > 320):
        raise ValueError('core-stop-shape')
    return {**value, 'metadata': _validate_stop(value['metadata'])}


def _exception_kind(error):
    kind = type(error).__name__
    return 'unavailable' if error is None else kind if kind in _ERRORS else 'other'


def _test_key(node):
    return (test_identity(node) or {}).get('key')


def _validate_first_failure(value):
    fields = {'version', 'attempt', 'node_key', 'phase', 'exception_kind', 'repeated', 'overflow', 'action_status', 'action'}
    if (type(value) is not dict or set(value) != fields or type(value['version']) is not int or value['version'] != 1
            or type(value['attempt']) is not int or not 1 <= value['attempt'] <= 2**63 - 1
            or value['node_key'] is not None and (type(value['node_key']) is not str or not _DIGEST.fullmatch(value['node_key']))
            or any(type(value[key]) is not bool for key in ('repeated', 'overflow'))
            or any(type(value[k]) is not str or value[k] not in choices for k, choices in (
                ('phase', _FAILURE_PHASES), ('exception_kind', _ERRORS | {'other', 'unavailable'}),
                ('action_status', {'correlated', 'unavailable', 'omitted'})))):
        raise ValueError('failure-capsule-shape')
    action = value['action']
    if action is not None and (type(action) is not dict or set(action) != {'op', 'sequence'}
            or type(action['op']) is not str or action['op'] not in _FAILURE_OPS
            or type(action['sequence']) is not int or not 1 <= action['sequence'] <= 2**63 - 1):
        raise ValueError('failure-action-shape')
    if (action is not None) != (value['action_status'] == 'correlated') or len(_json(value)) > 384:
        raise ValueError('failure-capsule-bound')
    return _decode(_json(value))


def _retained_health(health):
    flags = health.get('observation_omissions', dict.fromkeys(_OMISSIONS, False))
    if (type(flags) is not dict or set(flags) not in (set(_OMISSIONS), {*_OMISSIONS, 'stop_omitted'})
            or any(type(v) is not bool for v in flags.values())):
        raise ValueError('observation-omissions')
    _health_stop(health)
    return (_validate_ownership_snapshot(health['ownership']) if 'ownership' in health else None,
            _validate_first_failure(health['first_failure']) if 'first_failure' in health else None, flags)


def _collect_retained(health, owners, failures, omissions, stops):
    owner, failure, flags = _retained_health(health)
    for item, target in ((owner, owners), (failure, failures)):
        if item is not None:
            target.append(item)
    for flag in flags:
        omissions[flag] = omissions.get(flag, False) or flags[flag]
    stop = _health_stop(health)
    if stop is not None:
        stops.append(stop)


def _fit_observations(value, limit, *, public=False):
    value = deepcopy(value)
    flags = value['observation_omissions']
    def over():
        return len(_json(value)) + (0 if public else 1) > limit
    if over() and 'core_stop' in value:
        value.pop('core_stop')
        if public:
            value['core_stop'] = {'status': 'unavailable'}
        flags['stop_omitted'] = True
    failure = value.get('first_failure')
    rows = failure['capsules'] if public else [failure] if failure else []
    if over():
        for row in rows:
            if row['action'] is not None:
                row.update(action=None, action_status='omitted')
                flags['action_omitted'] = True
    if over() and 'ownership' in value:
        value.pop('ownership')
        if public:
            value['ownership'] = {'status': 'unavailable'}
        flags['ownership_omitted'] = True
    while over() and rows:
        rows.pop()
        flags['failure_omitted'] = True
        if public:
            failure.update(overflow=True, status='reported' if rows else 'unavailable')
        else:
            value.pop('first_failure', None)
    return value


def _observation_projection(owners, failures, complete, flags, stops=()):
    rows = failures[:2] if complete else []
    value = {'ownership': _ownership_projection(owners, complete),
             'first_failure': {'status': 'reported' if rows else 'unavailable', 'ambiguous': len(failures) > 1,
                               'overflow': len(failures) > 2, 'capsules': rows},
             'observation_omissions': dict(flags, failure_omitted=flags['failure_omitted'] or len(failures) > 2)}
    value['core_stop'] = ({'status': 'reported', 'snapshot': stops[0]} if complete and len(stops) == 1 else
                          {'status': 'ambiguous' if len(stops) > 1 else 'unavailable'})
    return _fit_observations(value, 1536, public=True)


def _observe(writer, method, *args):
    try:
        getattr(writer, method)(*args)
    except Exception:
        return None


def _validate_ownership_snapshot(value):
    if (type(value) is not dict or set(value) != {'version', 'case', 'attempt', 'repeated', 'overflow', 'forms'}
            or type(value['version']) is not int or value['version'] != 1
            or type(value['case']) is not str or value['case'] != 'term-resistant-grandchild' or type(value['attempt']) is not int
            or not 1 <= value['attempt'] <= 2**63 - 1
            or any(type(value[key]) is not bool for key in ('repeated', 'overflow'))
            or type(value['forms']) is not list or not 1 <= len(value['forms']) <= 4):
        raise ValueError('ownership-snapshot-shape')
    prior = -1
    for row in value['forms']:
        if (type(row) is not dict or set(row) != set(_OWNERSHIP_FIELDS)
                or any(type(row[key]) is not str or row[key] not in allowed
                       for key, allowed in _OWNERSHIP_FIELDS.items())):
            raise ValueError('ownership-row-shape')
        position = _OWNERSHIP_FORMS.index(row['form'])
        if position <= prior:
            raise ValueError('ownership-form-order')
        prior = position
    raw = _json(value)
    if len(raw) > 1024:
        raise ValueError('ownership-snapshot-limit')
    return _decode(raw)


def _ownership_projection(values, complete=True):
    if not complete or not values:
        return {'status': 'unavailable'}
    if len(values) != 1:
        return {'status': 'ambiguous'}
    return {'status': 'reported', 'snapshot': _validate_ownership_snapshot(values[0])}


@contextmanager
def ownership_case(form):
    writer, node = action_sink()
    if writer is None or node != _OWNERSHIP_CASE:
        yield
        return
    previous = getattr(writer, '_ownership_form', None)
    try:
        writer._ownership_form = None
        if type(form) is str and form in _OWNERSHIP_FORMS:
            snapshot = getattr(writer, '_ownership', None)
            if snapshot and any(row['form'] == form for row in snapshot['forms']):
                snapshot['repeated'] = True
                writer._ownership_blocked = True
            writer._ownership_form = form
            ownership_mark('entered')
    except Exception:
        try:
            yield
        finally:
            writer._ownership_form = previous
        return
    try:
        yield
    except BaseException as exc:
        ownership_mark(None, status='cancelled' if isinstance(exc, (KeyboardInterrupt, SystemExit))
                       or type(exc).__name__ == 'RunCancelled' else 'failed')
        raise
    else:
        ownership_mark('finished', status='returned')
    finally:
        writer._ownership_form = previous


def ownership_mark(phase, *, status='active', cleanup='unavailable', descendant='unavailable'):
    writer, node = action_sink()
    if writer is not None and node == _OWNERSHIP_CASE and getattr(writer, '_ownership_form', None) is not None:
        try:
            writer.record_ownership(phase, status=status, cleanup=cleanup, descendant=descendant)
        except Exception:
            return None


def _json(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('ascii')


def _decode(raw, **options):
    try:
        return json.loads(raw, **options)
    except RecursionError:
        raise ValueError('journal-json-depth') from None


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
    def __init__(self, path, run_id, actor, nonce, *, require_expected=False):
        if not _RUN.fullmatch(run_id) or not _ACTOR.fullmatch(actor) or not _RUN.fullmatch(nonce):
            raise ValueError('journal-identity')
        self.handle = _directory(path)
        self.source_root = path.parents[3]
        self.actor, self.run_id, self.nonce = actor, run_id, nonce
        self.fd = self.lock = None
        self.disabled = False
        self.sequence = self.rotated = self.dropped = 0
        self.attempt = 1
        self.generation = self.size = 0
        self.identity = None
        self.active = {}
        self._ownership = self._ownership_form = None
        self._ownership_blocked = False
        self._ownership_counts = {}
        self._first_failure = self._pending = self._action = None
        self._core_stop = None
        self._test_phase = (None, 'unknown')
        self._omissions = dict.fromkeys(_OMISSIONS, False)
        try:
            header = _decode(_read(self.handle, 'index.json', 16384))
            if header['run_id'] != run_id or header['nonce'] != nonce or header['status'] != 'active':
                raise ValueError('journal-run-binding')
            if require_expected and (type(header.get('expected')) is not list or actor not in header['expected']):
                raise ValueError('journal-undeclared-actor')
            self.lock = fsx.open_at(self.handle, actor + '.lock', os.O_RDWR | os.O_CREAT | fsx.O_NOFOLLOW, 0o600)
            if not _regular(os.fstat(self.lock)):
                raise OSError('journal-lock-unavailable')
            fsx.lock_file(self.lock, blocking=False)
            try:
                prior = _decode(_read(self.handle, actor + '.json', 2048))
                if (prior['run_id'] != run_id or prior['nonce'] != nonce or prior['actor'] != actor
                        or prior['status'] != 'closed' or prior.get('open_spans', 0)):
                    raise ValueError('journal-stream-not-closed')
                self.sequence, self.generation, self.rotated = prior['sequence'], prior['generation'] + 1, prior['rotated']
                self.attempt = prior['attempt'] + 1
                self._ownership, self._first_failure, self._omissions = _retained_health(prior)
                self._core_stop = _health_stop(prior)
                self._ownership_blocked = self._ownership is not None
            except FileNotFoundError:
                pass
            self.started = time.monotonic_ns()
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
        value = {'version': 1, 'run_id': self.run_id, 'nonce': self.nonce,
            'actor': self.actor, 'sequence': self.sequence, 'generation': self.generation, 'rotated': self.rotated,
            'attempt': self.attempt,
            'dropped': self.dropped, 'open_spans': sum(map(len, self.active.values())),
            'status': status, 'segment': self.name}
        value['observation_omissions'] = dict(self._omissions)
        if self._core_stop is not None:
            value['core_stop'] = _health_stop({'actor': self.actor, 'core_stop': self._core_stop})
        for key, item, validate, flag in (('ownership', self._ownership, _validate_ownership_snapshot, 'ownership_omitted'),
                ('first_failure', self._first_failure, _validate_first_failure, 'failure_omitted')):
            if item is None:
                continue
            try:
                value[key] = validate(item)
            except ValueError:
                value['observation_omissions'][flag] = True
        _publish(self.handle, self.actor + '.json', _fit_observations(value, 2048), 2048)

    def record_core_stop(self, result):
        metadata = stop_details(result)
        if self.actor != 'controller' or metadata['decision'] == 'unavailable':
            return
        if metadata['decision'] == 'child_exit' and getattr(result, 'returncode', None) == 0:
            return
        if self._core_stop is None:
            self._core_stop = _health_stop({'actor': self.actor, 'core_stop': {
                'attempt': self.attempt, 'repeated': False, 'overflow': False, 'metadata': metadata}})
        else:
            self._core_stop.update(repeated=True, overflow=True)
        self.health('unavailable' if self.disabled else 'active')

    def begin_test_phase(self, nodeid, phase):
        self._test_phase = (_test_key(nodeid), phase)
        self._pending = self._action = None

    def note_exception(self, nodeid, phase, error):
        self._pending = (_test_key(nodeid), phase, _exception_kind(error))

    def record_test_failure(self, nodeid, phase=None, kind=None):
        key = _test_key(nodeid)
        pending = self._pending if key is not None and self._pending and self._pending[0] == key else None
        phase = phase if phase is not None else pending[1] if pending else 'unknown'
        kind = kind if kind is not None else pending[2] if pending and pending[1] == phase else 'unavailable'
        if self._first_failure is None:
            action = self._action[1] if self._action and self._action[0] == (key, phase) else None
            value = {'version': 1, 'attempt': self.attempt, 'node_key': key, 'phase': phase, 'exception_kind': kind,
                     'repeated': False, 'overflow': False, 'action_status': 'correlated' if action else 'unavailable', 'action': action}
            self._first_failure = _validate_first_failure(value)
        else:
            self._first_failure['repeated'] |= key is not None and key == self._first_failure['node_key']
            self._first_failure['overflow'] = True
        self._pending = None
        self.health('unavailable' if self.disabled else 'active')

    def record_ownership(self, phase, *, status, cleanup, descendant):
        form = self._ownership_form
        if form not in _OWNERSHIP_FORMS:
            return
        fields = {'phase': phase, 'status': status, 'cleanup': cleanup, 'descendant': descendant}
        if any((type(value) is not str or value not in _OWNERSHIP_FIELDS[key])
               and not (key == 'phase' and value is None) for key, value in fields.items()):
            return
        if self._ownership is None:
            self._ownership = {'version': 1, 'case': 'term-resistant-grandchild', 'attempt': self.attempt,
                               'repeated': False, 'overflow': False, 'forms': []}
        if self._ownership_blocked:
            self._ownership['repeated'] = True
            self.health('active')
            return
        rows = self._ownership['forms']
        row = next((row for row in rows if row['form'] == form), None)
        if row is None:
            row = {'form': form, 'phase': 'entered', 'status': 'active',
                   'cleanup': 'unavailable', 'descendant': 'unavailable'}
            rows.append(row)
            rows.sort(key=lambda item: _OWNERSHIP_FORMS.index(item['form']))
        count = self._ownership_counts.get(form, 0)
        overflow = count >= 24
        if overflow:
            self._ownership['overflow'] = True
        else:
            self._ownership_counts[form] = count + 1
        if row['status'] not in {'failed', 'cancelled'}:
            if not overflow or status in {'failed', 'cancelled'}:
                row.update(phase=phase or row['phase'], status=status)
                for key in ('cleanup', 'descendant'):
                    if fields[key] != 'unavailable':
                        row[key] = fields[key]
            elif status == 'returned':
                row['status'] = 'unknown'
        self.health('active')
        if not overflow:
            self.emit('action', 'unknown', step='own-' + form + '-' + row['phase'], nodeid=_OWNERSHIP_CASE)

    def emit(self, stage, state, *, step=None, nodeid=None, outcome=None, code=None, error=None, skip=None, location=None, process=None, stop=None):
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
            if stop is not None:
                row['stop'] = _validate_stop(stop)
                if len(_json(row)) + 1 > EVENT_BYTES:
                    row.pop('stop')
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
            if (stage in {'action', 'command', 'check', 'cleanup'} and row.get('outcome', state) in {'fail', 'error', 'timeout', 'cancelled'}
                    and self._test_phase[0] is not None and row.get('key') == self._test_phase[0]
                    and action_sink()[0] is self and _test_key(action_sink()[1]) == row.get('key')):
                self._action = (self._test_phase, {'op': 'owned-command' if step == 'owned-command' else stage, 'sequence': self.sequence})
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
        self._ownership = []
        self._stops = []
        self._ownership_complete = False
        self._failures = []
        self._omissions = dict.fromkeys(_OMISSIONS, False)
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
                registry, _ = self._registry(handle, create=True)
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

    @contextmanager
    def _metadata(self, path):
        handle = None
        try:
            try:
                handle = _directory(path)
            except (OSError, ValueError):
                self.status = 'unavailable'
            yield handle
        except (OSError, ValueError, KeyError):
            self.status = 'unavailable'
        finally:
            try:
                fsx.close_dir(handle)
            except OSError:
                self.status = 'unavailable'

    def _index(self, handle):
        value = _decode(_read(handle, 'index.json', 16384))
        fields = {'version', 'run_id', 'nonce', 'source', 'source_status', 'session_id',
                  'session_status', 'entrypoint', 'status', 'expected'}
        if (type(value) is not dict or set(value) != fields or type(value['version']) is not int
                or value['version'] != 1 or value['run_id'] != self.run_id or value['nonce'] != self.nonce
                or value['status'] != 'active' or value['entrypoint'] != self.entrypoint
                or value['source'] != self.source or value['session_id'] != self.session_id
                or value['source_status'] != ('reported-integrity-only' if self.source else 'unavailable')
                or value['session_status'] != ('canonical-route-observation' if self.session_id else 'unavailable')):
            raise ValueError('journal-index-binding')
        expected = value['expected']
        if (type(expected) is not list or len(expected) > 64
                or any(type(actor) is not str or not _ACTOR.fullmatch(actor) or actor == 'controller'
                       for actor in expected) or len(set(expected)) != len(expected)):
            raise ValueError('journal-index-expected')
        return value

    def _registry(self, handle, create=False):
        try:
            value = _decode(_read(handle, 'registry.json', 16384))
        except FileNotFoundError:
            if not create:
                raise
            value = {'version': 1, 'runs': []}
        if (type(value) is not dict or set(value) != {'version', 'runs'}
                or type(value['version']) is not int or value['version'] != 1
                or type(value['runs']) is not list or len(value['runs']) > RUNS):
            raise ValueError('journal-registry')
        seen, own = set(), None
        for row in value['runs']:
            if (type(row) is not dict or set(row) != {'run_id', 'nonce', 'status'}
                    or any(type(row[key]) is not str or not _RUN.fullmatch(row[key]) for key in ('run_id', 'nonce'))
                    or type(row['status']) is not str or row['status'] not in {'active', 'closed', 'incomplete', 'unavailable'}
                    or row['run_id'] in seen):
                raise ValueError('journal-registry-row')
            seen.add(row['run_id'])
            if row['run_id'] == self.run_id:
                if row['nonce'] != self.nonce or row['status'] != 'active':
                    raise ValueError('journal-registry-binding')
                own = row
        if own is None and not create:
            raise ValueError('journal-registry-missing')
        return value, own

    def expect_workers(self, workers):
        if self.path is None or type(workers) is not int or not 1 <= workers <= 64:
            return
        with self._metadata(self.path) as handle:
            if handle is None:
                return
            value = self._index(handle)
            value['expected'] = sorted(set(value['expected']) | {'worker-' + str(i) for i in range(workers)})
            _publish(handle, 'index.json', value, 16384)

    def summary(self):
        return {'version': 1, 'run_id': self.run_id, 'index': self.relative_index if self.path else None,
                'status': 'unavailable' if self.writer is None or self.writer.disabled else self.status,
                'source_status': 'reported-integrity-only' if self.source is not None else 'unavailable',
                'session_status': 'canonical-route-observation' if self.session_id is not None else 'unavailable',
                **_observation_projection(self._ownership, self._failures, self._ownership_complete, self._omissions, self._stops),
                'completeness': 'unknown-until-terminal-and-all-actors-validated'}

    def bind_source(self, digest, session_id=None):
        if self.path is None or type(digest) is not str or not _DIGEST.fullmatch(digest):
            return
        with self._metadata(self.path) as handle:
            if handle is None:
                return
            value = self._index(handle)
            value['source'] = digest
            value['source_status'] = 'reported-integrity-only'
            value['session_id'] = session_id if type(session_id) is str and _SESSION.fullmatch(session_id) else None
            value['session_status'] = 'canonical-route-observation' if value['session_id'] is not None else 'unavailable'
            _publish(handle, 'index.json', value, 16384)
            self.source = digest
            self.session_id = value['session_id']

    def close(self):
        if self.writer is None:
            return
        try:
            self.writer.close()
        except OSError:
            self.status = 'unavailable'
        terminal = 'closed' if not self.writer.disabled and self.status == 'active' else 'unavailable'
        self.status = 'unavailable'
        with self._metadata(self.path) as handle:
            if handle is None:
                return
            value = self._index(handle)
            expected = value['expected']
            for actor in ['controller', *('worker-' + str(i) for i in range(64))]:
                try:
                    health = _decode(_read(handle, actor + '.json', 2048))
                    if (type(health) is not dict or health.get('run_id') != self.run_id
                            or health.get('nonce') != self.nonce or health.get('actor') != actor
                            or type(health.get('open_spans')) is not int or health['open_spans'] < 0
                            or type(health.get('status')) is not str
                            or health['status'] not in {'active', 'closed', 'unavailable'}):
                        raise ValueError('journal-health-binding')
                    if health['status'] != 'closed' or health['open_spans']:
                        terminal = 'incomplete' if terminal == 'closed' else terminal
                    _collect_retained(health, self._ownership, self._failures, self._omissions, self._stops)
                except FileNotFoundError:
                    if actor == 'controller' or actor in expected:
                        terminal = 'incomplete' if terminal == 'closed' else terminal
                    continue
            self._ownership_complete = True
            with self._metadata(self.path.parent) as registry_handle:
                if registry_handle is None:
                    return
                lock = None
                try:
                    lock = fsx.open_at(registry_handle, 'registry.lock', os.O_RDWR | fsx.O_NOFOLLOW)
                    if not _regular(os.fstat(lock)):
                        raise OSError('journal-registry-lock')
                    fsx.lock_file(lock, blocking=False)
                    registry, row = self._registry(registry_handle)
                    row['status'] = terminal
                    registry['runs'].remove(row)
                    registry['runs'].append(row)
                    _publish(registry_handle, 'registry.json', registry, 16384)
                    value['status'] = terminal
                    _publish(handle, 'index.json', value, 16384)
                    self.status = terminal
                finally:
                    if lock is not None:
                        try:
                            os.close(lock)
                        except OSError:
                            self.status = 'unavailable'


def _remove_run(history, record):
    if (set(record) != {'run_id', 'nonce', 'status'} or record['status'] != 'closed'
            or not _RUN.fullmatch(record['run_id']) or not _RUN.fullmatch(record['nonce'])):
        raise ValueError('journal-retention-record')
    path = history / record['run_id']
    handle = _directory(path)
    locks = []
    try:
        index = _decode(_read(handle, 'index.json', 16384))
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
                health = _decode(_read(handle, name, 2048))
                if (health['run_id'] != record['run_id'] or health['nonce'] != record['nonce']
                        or health['status'] != 'closed' or health.get('open_spans', 0)):
                    raise ValueError('journal-retention-active-stream')
                _retained_health(health)
        for name in names:
            fsx.unlink_at(handle, name)
    finally:
        for descriptor in locks:
            os.close(descriptor)
        fsx.close_dir(handle)
    path.rmdir()


def child_writer(environment=None, ordinal=None, worker_count=None):
    values = environment if environment is not None else os.environ
    try:
        ordinal = str(ordinal) if ordinal is not None else values['GETZILLA_JOURNAL_ACTOR']
        if not re.fullmatch(r'(?:[0-9]|[1-5][0-9]|6[0-3])', ordinal):
            raise ValueError('journal-worker')
        path, run_id, nonce = Path(values['GETZILLA_JOURNAL_DIR']), values['GETZILLA_JOURNAL_RUN'], values['GETZILLA_JOURNAL_NONCE']
        if not path.is_absolute() or not _RUN.fullmatch(run_id) or not _RUN.fullmatch(nonce):
            raise ValueError('journal-context')
        actor = 'worker-' + ordinal
        handle = _directory(path)
        try:
            header = _decode(_read(handle, 'index.json', 16384))
            expected = header.get('expected')
            if (header['run_id'] != run_id or header['nonce'] != nonce or header['status'] != 'active'
                    or type(expected) is not list or len(expected) > 64
                    or any(not isinstance(item, str) or not _ACTOR.fullmatch(item) or item == 'controller' for item in expected)
                    or len(set(expected)) != len(expected) or actor not in expected):
                raise ValueError('journal-child-binding')
            if worker_count is not None and (type(worker_count) is not int or not 1 <= worker_count <= 64
                    or int(ordinal) >= worker_count
                    or not {'worker-' + str(i) for i in range(worker_count)}.issubset(expected)):
                raise ValueError('journal-child-count')
        finally:
            fsx.close_dir(handle)
        return Writer(path, run_id, actor, nonce, require_expected=True)
    except (OSError, ValueError, KeyError, TypeError):
        if values.get('GETZILLA_JOURNAL_DIR'):
            print('getzilla journal: worker history unavailable', file=sys.stderr, flush=True)
        return None


@contextmanager
def activate(run):
    token = _CURRENT.set(run)
    sink = _SINK.set((getattr(run, 'writer', None), None))
    try:
        yield run
    finally:
        _SINK.reset(sink)
        _CURRENT.reset(token)


def current():
    return _CURRENT.get()


@contextmanager
def bind_sink(writer, nodeid):
    node = nodeid.partition('[')[0].replace('\\', '/') if test_identity(nodeid) else ''
    token = _SINK.set((writer, node))
    try:
        yield
    finally:
        _SINK.reset(token)


def action_sink():
    return _SINK.get() or (None, None)


def _emit(writer, *args, **fields):
    try:
        writer.emit(*args, **fields)
    except (OSError, ValueError, TypeError):
        return None


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
                    details['stop'] = stop_details(result)
                    outcome = getattr(result, 'status', None)
                    code = getattr(result, 'returncode', None)
                    if code is not None:
                        outcome = 'pass' if code == 0 else 'fail'
                    if outcome in _STATES:
                        details.update(outcome=outcome, code=code)
                return result
        return wrapped
    return decorate


@contextmanager
def span(step, *, stage='check'):
    writer, node = action_sink()
    if writer:
        _emit(writer, stage, 'start', step=step, nodeid=node)
    try:
        details = {}
        yield details
    except BaseException as exc:
        if writer:
            _emit(writer, stage, 'end', step=step, nodeid=node, outcome='skip' if isinstance(exc, unittest.SkipTest) else 'error', error=exc,
                  skip=skip_classification(str(exc)) if isinstance(exc, unittest.SkipTest) else None, stop=stop_details(exc))
        raise
    else:
        if writer:
            _emit(writer, stage, 'end', step=step, nodeid=node, **details)


def case_identity(test):
    module = type(test).__module__
    if not module.startswith('tests.'):
        module = 'tests.' + module
    return module.replace('.', '/') + '.py::' + type(test).__name__ + '::' + str(getattr(test, '_testMethodName', 'unknown'))


def case_location(test, root=None):
    try:
        method = getattr(test, getattr(test, '_testMethodName', ''), None)
        if isinstance(method, MethodType):
            method = method.__func__
        seen = set()
        for _ in range(8):
            if not isinstance(method, FunctionType) or id(method) in seen:
                return None
            seen.add(id(method))
            wrapped = method.__dict__.get('__wrapped__')
            if wrapped is None:
                break
            method = wrapped
        else:
            return None
        code = method.__code__
        if root is not None:
            path = Path(code.co_filename).relative_to(root).as_posix()
            if test_identity(path) is not None and test_identity(path)['path'] == path and 1 <= code.co_firstlineno <= 1000000:
                return (path, code.co_firstlineno)
    except Exception:
        return None  # Unsupported metadata cannot change the original skip outcome.
    return None


def unittest_runner(writer):
    """Use the standard runner once; observe its actual call boundaries only."""
    class Result(unittest.TextTestResult):
        def startTest(self, test):
            super().startTest(test)
            node = case_identity(test)
            _observe(writer, 'begin_test_phase', node, 'unknown')
            writer.emit('test', 'start', nodeid=node)
            originals = {}
            for name, stage in (('_callSetUp', 'setup'), ('_callTestMethod', 'call'), ('_callTearDown', 'teardown')):
                original = getattr(test, name)
                originals[name] = (name in test.__dict__, test.__dict__.get(name))
                def observed(*args, _original=original, _stage=stage, **kwargs):
                    _observe(writer, 'begin_test_phase', node, _stage)
                    try:
                        with bind_sink(writer, node), span(None, stage=_stage) as detail:
                            detail['outcome'] = 'pass'
                            return _original(*args, **kwargs)
                    except BaseException as error:
                        _observe(writer, 'note_exception', node, _stage, error)
                        raise
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
            _observe(self, '_retain', test, err)

        def addError(self, test, err):
            writer.emit('test', 'end', nodeid=case_identity(test), outcome='error', error=err[1])
            super().addError(test, err)
            _observe(self, '_retain', test, err)

        def _retain(self, test, err=None, phase=None):
            started = getattr(self, '_journal_originals', (None,))[0] is test
            node = case_identity(test) if started else None
            _observe(writer, 'record_test_failure', node, phase if started else 'unknown', _exception_kind(err[1] if err else None))

        def addSkip(self, test, reason):
            writer.emit('test', 'end', nodeid=case_identity(test), outcome='skip', skip=skip_classification(reason), location=case_location(test, writer.source_root))
            super().addSkip(test, reason)

        def addExpectedFailure(self, test, err):
            writer.emit('test', 'end', nodeid=case_identity(test), outcome='expected-failure', error=err[1])
            super().addExpectedFailure(test, err)

        def addUnexpectedSuccess(self, test):
            writer.emit('test', 'end', nodeid=case_identity(test), outcome='unexpected-success')
            super().addUnexpectedSuccess(test)
            if self.unexpectedSuccesses and self.unexpectedSuccesses[-1] is test:
                _observe(self, '_retain', test, None, 'call')

        def addSubTest(self, test, subtest, err):
            writer.emit('call', 'unknown', nodeid=case_identity(test), outcome='pass' if err is None else 'fail',
                        error=None if err is None else err[1])
            super().addSubTest(test, subtest, err)
            if err is not None:
                _observe(self, '_retain', test, err, 'call')

    class Runner(unittest.TextTestRunner):
        resultclass = Result

        def run(self, test):
            writer.emit('collection', 'end')
            return super().run(test)
    return Runner


def _validated_events(raw, run_id, actor):
    allowed = {'version', 'run_id', 'actor', 'actor_attempt', 'sequence', 'stage', 'state', 'pid', 'elapsed_ns', 'utc',
               'step', 'path', 'key', 'invocation', 'unmatched_end', 'outcome', 'exit', 'error_class',
               'frames', 'skip_class', 'location_status', 'location', 'process', 'identity_status', 'stop'}
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
        row = _decode(line, object_pairs_hook=closed)
        if (type(row) is not dict or set(row) - allowed or row.get('version') != 1
                or row.get('run_id') != run_id or row.get('actor') != actor
                or row.get('stage') not in _STAGES or row.get('state') not in _STATES
                or any(type(row.get(key)) is not int or not 0 <= row[key] <= 2**63 - 1
                       for key in ('actor_attempt', 'sequence', 'pid', 'elapsed_ns'))
                or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}\+00:00', str(row.get('utc', '')))):
            raise ValueError('journal-record-schema')
        if 'step' in row and (type(row['step']) is not str or not _ID.fullmatch(row['step'])):
            raise ValueError('journal-record-step')
        if 'stop' in row:
            _validate_stop(row['stop'])
        if 'path' in row:
            canonical = test_identity(row['path'])
            if canonical is None or canonical['path'] != row['path']:
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


def export_entries(root, *, binding=None):
    """A safe bounded subset; never a complete-history or authorization claim."""
    entries, summary = [], {'version': 1, 'status': 'unavailable', 'run_status': 'unavailable',
                           'export_status': 'unavailable', 'association': 'unbound', 'subset': True}
    ownership, ownership_complete = [], False
    failures, omissions = [], dict.fromkeys(_OMISSIONS, False)
    stops = []
    history = root / '.getzilla/runtime/verification-history'
    try:
        handle = _directory(history)
        try:
            registry = _decode(_read(handle, 'registry.json', 16384))
        finally:
            fsx.close_dir(handle)
        row = registry['runs'][-1]
        if not _RUN.fullmatch(row['run_id']) or not _RUN.fullmatch(row['nonce']):
            raise ValueError('journal-export-identity')
        handle = _directory(history / row['run_id'])
        try:
            index = _decode(_read(handle, 'index.json', 16384))
            if (index['run_id'] != row['run_id'] or index['nonce'] != row['nonce']
                    or index['status'] not in {'active', 'closed', 'incomplete', 'unavailable'}
                    or index['status'] != row.get('status')):
                raise ValueError('journal-export-identity')
            source, session = index.get('source'), index.get('session_id')
            if (source is not None and (type(source) is not str or not _DIGEST.fullmatch(source))
                    or session is not None and (type(session) is not str or not _SESSION.fullmatch(session))
                    or index.get('source_status') != ('reported-integrity-only' if source is not None else 'unavailable')
                    or index.get('session_status') != ('canonical-route-observation' if session is not None else 'unavailable')):
                raise ValueError('journal-export-provenance')
            expected = index.get('expected')
            if (type(expected) is not list or len(expected) > 64 or any(type(actor) is not str or actor == 'controller'
                    or not _ACTOR.fullmatch(actor) for actor in expected) or len(set(expected)) != len(expected)):
                raise ValueError('journal-export-expected')
            summary.update(run_id=row['run_id'], status=index['status'], run_status=index['status'], actors=[],
                source=source, source_status=index['source_status'], session_id=session, session_status=index['session_status'],
                expected=expected, missing=list(expected))
            if binding is not None:
                if (type(binding) is not dict or set(binding) != {'run_id', 'source', 'session_id'}
                        or binding['run_id'] != row['run_id'] or binding['source'] != source
                        or binding['session_id'] != session or source is None):
                    summary['association'] = 'unmatched'
                    raise ValueError('journal-export-unmatched')
                summary['association'] = 'source-run-matched'
            for actor in ['controller', *('worker-' + str(i) for i in range(64))]:
                try:
                    health = _decode(_read(handle, actor + '.json', 2048))
                    if (set(health) - {'ownership', 'first_failure', 'observation_omissions', 'core_stop'} != {'version', 'run_id', 'nonce', 'actor', 'attempt', 'sequence', 'generation', 'rotated', 'dropped', 'open_spans', 'status', 'segment'}
                            or health['run_id'] != row['run_id'] or health['nonce'] != row['nonce'] or health['actor'] != actor
                            or health['status'] not in {'active', 'closed', 'unavailable'}
                            or any(type(health[k]) is not int or not 0 <= health[k] <= 2**63 - 1
                                   for k in ('attempt', 'sequence', 'generation', 'rotated', 'dropped', 'open_spans'))
                            or health['segment'] != f'{actor}-{health["generation"] % SEGMENTS}.jsonl'):
                        raise ValueError('journal-export-actor')
                    _collect_retained(health, ownership, failures, omissions, stops)
                    raw = _read(handle, f'{actor}-{health["generation"] % SEGMENTS}.jsonl', SEGMENT_BYTES)
                    tail = raw[-65536:]
                    if len(raw) > len(tail):
                        tail = tail.partition(b'\n')[2]
                    complete = tail.rpartition(b'\n')[0] + b'\n' if b'\n' in tail else b''
                    entries.append(('journal/' + actor + '.jsonl', _validated_events(complete, row['run_id'], actor)))
                    summary['actors'].append({key: value for key, value in health.items() if key not in {'first_failure', 'observation_omissions', 'core_stop'}})
                    if actor in summary['missing']:
                        summary['missing'].remove(actor)
                except FileNotFoundError:
                    continue
            ownership_complete = True
        finally:
            fsx.close_dir(handle)
        if summary['status'] == 'closed' and (summary['missing'] or any(
                actor['status'] != 'closed' or actor['open_spans'] for actor in summary['actors'])):
            summary['status'] = summary['run_status'] = 'incomplete'
        summary['export_status'] = 'bounded-subset'
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        summary['export_status'] = 'unavailable'
    summary.update(_observation_projection(ownership, failures, ownership_complete, omissions, stops))
    entries.insert(0, ('journal/index.json', _json(summary) + b'\n'))
    return entries
