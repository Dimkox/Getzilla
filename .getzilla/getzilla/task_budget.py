"""Limited managed-command budgets in the canonical task route, never authority.

Opaque child tokens, money and CPU remain unknown. Other native/model clients
are not intercepted. Unknown effects require reconciliation, never blind retry.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import time
from pathlib import Path

from . import state
from .continuity import has_task_context

DIMENSIONS = ('tokens', 'cpu_ms', 'cost_micros', 'elapsed_ms')
MAX_OPERATIONS = 256
_ID = re.compile(r'[A-Za-z0-9_-]{1,64}\Z')
_HEX = re.compile(r'[a-f0-9]{64}\Z')


def _integer(value):
    return type(value) is int and 0 <= value <= 10**15


def _usage(value):
    if (not isinstance(value, dict) or set(value) != set(DIMENSIONS)
            or any(v is not None and not _integer(v) for v in value.values())):
        raise ValueError('invalid-budget-usage')
    return copy.deepcopy(value)


def _limits(value):
    if not isinstance(value, dict) or set(value) != {*DIMENSIONS, 'calls', 'failures', 'repeat_failures', 'deadline_epoch'}:
        raise ValueError('invalid-budget-limits')
    _usage({key: value[key] for key in DIMENSIONS})
    if (any(not _integer(value[key]) or value[key] < 1 for key in ('calls', 'failures', 'repeat_failures', 'deadline_epoch'))
            or value['calls'] > MAX_OPERATIONS or value['deadline_epoch'] > 253402300799
            or value['elapsed_ms'] is None or value['elapsed_ms'] == 0):
        raise ValueError('invalid-budget-limits')
    return copy.deepcopy(value)


def _clock(now=None):
    value = time.time() if now is None else now
    if type(value) not in (int, float) or not 0 <= value <= 253402300799:
        raise ValueError('invalid-budget-clock')
    return int(value)


def _owned(root, epoch=None, revision=None, task_id=None):
    route = state.require_route_owner(root)
    if not has_task_context(route) or route.get('status') in {'completed', 'cancelled', 'released', 'archived'}:
        raise ValueError('inactive-budget-authority')
    if (epoch is not None and (type(epoch) is not int or epoch != route['authority_epoch'] or task_id != route['logical_task_id'])
            or revision is not None and (type(revision) is not int or revision != route['state_revision'])):
        raise ValueError('stale-budget-authority')
    return route


def _read(route):
    value = copy.deepcopy(route.get('task_budget'))
    if value is None:
        raise ValueError('budget-not-configured')
    if (not isinstance(value, dict) or set(value) != {'version', 'task_id', 'limits', 'operations', 'last_epoch', 'stopped'}
            or type(value['version']) is not int or value['version'] != 1
            or value['task_id'] != route['logical_task_id'] or not _integer(value['last_epoch'])
            or type(value['stopped']) is not bool or not isinstance(value['operations'], dict)
            or len(value['operations']) > MAX_OPERATIONS):
        raise ValueError('invalid-budget-state')
    _limits(value['limits'])
    for identity, row in value['operations'].items():
        if (not isinstance(identity, str) or not _ID.fullmatch(identity) or not isinstance(row, dict)
                or set(row) != {'key', 'reserved', 'actual', 'state', 'outcome', 'failure', 'owner_epoch'}
                or not isinstance(row['key'], str) or not _HEX.fullmatch(row['key'])
                or row['state'] not in {'reserved', 'running', 'settled'}
                or row['outcome'] not in {None, 'succeeded', 'failed'} or not _integer(row['owner_epoch'])
                or row['failure'] is not None and (not isinstance(row['failure'], str) or not _HEX.fullmatch(row['failure']))
                or (row['state'] == 'settled') != (row['outcome'] is not None)
                or (row['outcome'] == 'failed') != (row['failure'] is not None)
                or row['state'] != 'settled' and row['actual'] is not None):
            raise ValueError('invalid-budget-operation')
        _usage(row['reserved'])
        if row['actual'] is not None:
            _usage(row['actual'])
    return value


def _save(root, route, budget):
    return state.update_route(root, expected_route=route, task_budget=budget)


@state.serialized_task
def initialize(root: Path, limits: dict, epoch: int, revision: int, *, task_id: str):
    route = _owned(root, epoch, revision, task_id)
    limits = _limits(limits)
    if 'task_budget' in route:
        if _read(route)['limits'] != limits:
            raise ValueError('budget-reset-or-increase-forbidden')
        return inspect(root)
    budget = {'version': 1, 'task_id': route['logical_task_id'], 'limits': limits,
              'operations': {}, 'last_epoch': 0, 'stopped': False}
    _save(root, route, budget)
    return inspect(root)


def _charged(row, dimension):
    actual = None if row['actual'] is None else row['actual'][dimension]
    return actual if actual is not None else row['reserved'][dimension]


def _total(budget, dimension):
    values = [_charged(row, dimension) for row in budget['operations'].values()]
    return None if any(value is None for value in values) else sum(values)


@state.serialized_task
def inspect(root: Path):
    route = _owned(root)
    budget = _read(route)
    rows = budget['operations'].values()
    return {'version': 1, 'coverage': 'limited-managed-command', 'task_id': budget['task_id'],
            'limits': budget['limits'], 'calls': len(budget['operations']),
            'failures': sum(row['outcome'] == 'failed' for row in rows),
            'unresolved': sum(row['state'] != 'settled' for row in rows),
            'charged': {dimension: _total(budget, dimension) for dimension in DIMENSIONS},
            'observed': {dimension: (None if any(row['actual'] is None or row['actual'][dimension] is None for row in rows)
                                    else sum(row['actual'][dimension] for row in rows)) for dimension in DIMENSIONS},
            'stopped': budget['stopped'], 'escalation': 'needs-review' if budget['stopped'] or any(row['state'] != 'settled' for row in rows) else None,
            'accepted_pr_cost': None, 'accepted_pr_count': None}


@state.serialized_task
def reserve(root: Path, operation_id: str, key: str, usage: dict, epoch: int, revision: int, *, task_id: str, now=None):
    route = _owned(root, epoch, revision, task_id)
    budget, usage, now = _read(route), _usage(usage), _clock(now)
    if not isinstance(operation_id, str) or not _ID.fullmatch(operation_id) or not isinstance(key, str) or not _HEX.fullmatch(key):
        raise ValueError('invalid-budget-operation')
    existing = budget['operations'].get(operation_id)
    if existing is not None:
        if existing['key'] != key or existing['reserved'] != usage:
            raise ValueError('budget-idempotency-conflict')
        return copy.deepcopy(existing)
    limits = budget['limits']
    if budget['stopped']:
        raise ValueError('budget-hard-stop')
    if now < budget['last_epoch'] or now >= limits['deadline_epoch']:
        raise ValueError('budget-clock-or-deadline')
    if any(row['state'] != 'settled' for row in budget['operations'].values()):
        raise ValueError('budget-unresolved-outcome')
    if len(budget['operations']) >= limits['calls']:
        raise ValueError('budget-calls-exhausted')
    failures = [row for row in budget['operations'].values() if row['outcome'] == 'failed']
    if len(failures) >= limits['failures'] or sum(row['key'] == key for row in failures) >= limits['repeat_failures']:
        raise ValueError('budget-failure-loop-stop')
    for dimension in DIMENSIONS:
        cap = limits[dimension]
        if cap is not None:
            total = _total(budget, dimension)
            if usage[dimension] is None or total is None:
                raise ValueError('unknown-reservation')
            if total + usage[dimension] > cap:
                raise ValueError('budget-dimension-exhausted')
    row = {'key': key, 'reserved': usage, 'actual': None, 'state': 'reserved', 'outcome': None,
           'failure': None, 'owner_epoch': epoch}
    budget['operations'][operation_id] = row
    budget['last_epoch'] = now
    _save(root, route, budget)
    return copy.deepcopy(row)


@state.serialized_task
def claim(root: Path, operation_id: str, epoch: int, revision: int, *, task_id: str, now=None):
    route = _owned(root, epoch, revision, task_id)
    budget, now = _read(route), _clock(now)
    row = budget['operations'].get(operation_id)
    if row is None or row['state'] != 'reserved' or row['owner_epoch'] != epoch:
        raise ValueError('budget-effect-already-claimed-or-stale')
    if budget['stopped'] or now < budget['last_epoch'] or now >= budget['limits']['deadline_epoch']:
        raise ValueError('budget-clock-or-deadline')
    row['state'] = 'running'
    budget['last_epoch'] = now
    _save(root, route, budget)
    return copy.deepcopy(row)


@state.serialized_task
def reconcile(root: Path, operation_id: str, outcome: str, actual: dict, epoch: int, revision: int, *, task_id: str, failure=None):
    """Trusted adapter observation only. No CLI accepts caller-authored outcomes."""
    route = _owned(root, epoch, revision, task_id)
    budget, actual = _read(route), _usage(actual)
    if outcome not in {'succeeded', 'failed'} or (outcome == 'failed') != (failure is not None):
        raise ValueError('invalid-budget-outcome')
    if failure is not None and (not isinstance(failure, str) or not _HEX.fullmatch(failure)):
        raise ValueError('invalid-budget-failure')
    row = budget['operations'].get(operation_id)
    if row is None or row['state'] == 'reserved':
        raise ValueError('budget-effect-not-claimed')
    if row['state'] == 'settled':
        if (row['outcome'], row['actual'], row['failure']) != (outcome, actual, failure):
            raise ValueError('budget-reconciliation-conflict')
        return inspect(root)
    row.update(state='settled', outcome=outcome, actual=actual, failure=failure)
    for dimension in DIMENSIONS:
        measured, reserved = actual[dimension], row['reserved'][dimension]
        if measured is not None and reserved is not None and measured > reserved:
            budget['stopped'] = True
        total, cap = _total(budget, dimension), budget['limits'][dimension]
        if cap is not None and (total is None or total > cap):
            budget['stopped'] = True
    _save(root, route, budget)
    return inspect(root)


def _same_authority(root, original):
    """Read the original canonical record, never another session's projection."""
    try:
        current = state.canonical_route(root, original['route_id'])
        return (all(current[key] == original[key] for key in
                    ('route_id', 'logical_task_id', 'session_id', 'authority_epoch', 'workspace'))
                and current.get('status') not in {'cancelled', 'completed', 'released', 'archived'}
                and not _read(current)['stopped'])
    except (OSError, ValueError, KeyError, TypeError):
        return False


def execute_local(root: Path, operation_id: str, argv: list[str], *, timeout: float):
    """Policy-checked POSIX process group with a short claim/spawn fence.

    Release the task lock while running. Poll the original authority and stop on
    withdrawal. WNOWAIT pins the child PID until group termination completes.
    A crash or stale owner retains unknown spend; no manual-proof CLI exists.
    Process management is not a sandbox or a universal native/model interceptor.
    """
    import math
    import os
    import shlex
    import signal
    import subprocess

    from .parallel import policy_refusal

    if (os.name != 'posix' or not all(hasattr(os, name) for name in ('waitid', 'WNOWAIT', 'P_PID'))
            or not hasattr(os, 'killpg')):
        raise ValueError('unsupported-budget-process-control')
    if (not isinstance(argv, list) or not 1 <= len(argv) <= 128
            or any(not isinstance(arg, str) or not arg or '\0' in arg for arg in argv)
            or sum(len(arg.encode('utf-8')) for arg in argv) > 32768
            or type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 60):
        raise ValueError('invalid-budget-command')
    proc, withdrawn, timed_out = None, False, False
    with state.task_transition(root):
        route = _owned(root)
        budget = _read(route)
        command = shlex.join(argv)
        if policy_refusal(root, command, cwd=root):
            raise ValueError('budget-command-policy-refused')
        key = hashlib.sha256(json.dumps(argv, ensure_ascii=True, separators=(',', ':')).encode()).hexdigest()
        usage = {'tokens': None, 'cpu_ms': None, 'cost_micros': None, 'elapsed_ms': math.ceil(timeout * 1000)}
        prior = budget['operations'].get(operation_id)
        reserve(root, operation_id, key, usage, route['authority_epoch'], route['state_revision'], task_id=route['logical_task_id'])
        if prior is not None and prior['state'] == 'settled':
            return {'outcome': prior['outcome'], 'replayed': True, 'coverage': 'limited-managed-command'}
        route = _owned(root)
        claim(root, operation_id, route['authority_epoch'], route['state_revision'], task_id=route['logical_task_id'])
        remaining = budget['limits']['deadline_epoch'] - time.time()
        if remaining <= 0:
            raise ValueError('budget-clock-or-deadline')
        duration = min(timeout, remaining)
        started = time.monotonic()
        # The owner/epoch cannot change between durable claim and spawn.
        proc = subprocess.Popen(argv, cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, start_new_session=True)  # nosec B603 - policy-checked argv, no shell
    try:
        while True:
            if not _same_authority(root, route):
                withdrawn = True
                break
            observed = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if observed is not None:
                break
            if time.monotonic() - started >= duration:
                timed_out = True
                break
            time.sleep(min(0.01, duration))
    finally:
        # Child PID is still owned (unreaped); never signal a reused PID.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
    elapsed = math.ceil((time.monotonic() - started) * 1000)
    with state.task_transition(root):
        if withdrawn or not _same_authority(root, route):
            return {'outcome': 'unknown', 'replayed': False, 'coverage': 'limited-managed-command',
                    'stopped_for': 'authority-withdrawn', 'escalation': 'needs-review'}
        outcome = 'failed' if timed_out or proc.returncode else 'succeeded'
        failure = hashlib.sha256(('timeout' if timed_out else 'exit:' + str(proc.returncode)).encode()).hexdigest() if outcome == 'failed' else None
        current = _owned(root)
        reconcile(root, operation_id, outcome, {**usage, 'elapsed_ms': elapsed},
                  current['authority_epoch'], current['state_revision'], task_id=current['logical_task_id'], failure=failure)
    return {'outcome': outcome, 'replayed': False, 'coverage': 'limited-managed-command'}
