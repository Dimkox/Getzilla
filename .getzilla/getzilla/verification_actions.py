"""Shared in-process action and stop observations, independent of history storage.

Observer aliases share only source-matched sink/type identities. Each import
keeps its own current-run context, as the original journal implementation did.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, replace
import functools
import hashlib
import json
import os
import re
import sys
import unittest

OUTPUT_LIMIT = 2 * 1024 * 1024

_CURRENT = ContextVar('verification_journal', default=None)
_RUN = re.compile(r'[0-9a-f]{32}\Z')
_peer = sys.modules.get('getzilla.verification_actions')
if __package__ == 'getzilla':
    _run = os.environ.get('GETZILLA_JOURNAL_RUN', '')
    _peer = sys.modules.get('_getzilla_observer_' + _run + '.verification_actions') if _RUN.fullmatch(_run) else None
_SINK = getattr(_peer, '_SINK', None)
if (not isinstance(_SINK, ContextVar) or (getattr(_peer, '__file__', None),
        getattr(getattr(_peer, '__spec__', None), 'origin', None),
        getattr(__spec__, 'origin', None)) != (__file__,) * 3):
    _SINK = ContextVar('verification_action_sink', default=None)


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


_STATES = {'start', 'end', 'pass', 'fail', 'skip', 'error', 'cancelled', 'timeout', 'unknown', 'expected-failure', 'unexpected-success'}

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

_STOP_FIELDS = {
    'decision': {'unavailable', 'child_exit', 'child_signal', 'deadline', 'output_limit', 'owned_cancel',
                 'primary_exception', 'spawn_error'},
    'result_policy': {'unavailable', 'child_status', 'limit_124', 'cancel_preserve_child', 'cancel_128_signal',
                      'fallback_1', 'spawn_127', 'aggregate', 'collection_refusal', 'coverage_refusal'},
    'cancel': {'unavailable', 'none', 'sigint', 'sigterm'},
    'late_output': {'unavailable', 'not_exceeded', 'exceeded'},
    'scope': {'process', 'parallel_batch', 'selected_shard', 'coverage_combine', 'unavailable'},
}


def _json(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('ascii')


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


def _observe(writer, method, *args):
    try:
        getattr(writer, method)(*args)
    except Exception:
        return None


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
def span(step, *, stage='check', location=None):
    writer, node = action_sink()
    if writer:
        _emit(writer, stage, 'start', step=step, nodeid=node, location=location)
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
