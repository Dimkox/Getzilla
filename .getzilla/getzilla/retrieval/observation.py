"""Fixed native read observations; never an access or execution capability.

The actual native-local host owns capture and publication. Pure algorithms can
mark their actual stages while that capture is active, but cannot enroll a task,
select a route, authorize a read, or send observations anywhere.
"""
from __future__ import annotations

import contextvars
import copy
import os
import secrets
import threading
import time
from contextlib import contextmanager
from concurrent.futures import CancelledError
from asyncio import CancelledError as AsyncCancelledError
from datetime import datetime, timezone

from ..metrics_journal import digest
from ..trace_contracts import STAGES, validate_v3

_ACTIVE = contextvars.ContextVar('native_retrieval_observation', default=None)
_ISSUER = object()
MAX_SPANS = 20
PUBLICATION_SECONDS = 1.0


def _utc_now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _outcome(error):
    if isinstance(error, (CancelledError, AsyncCancelledError, KeyboardInterrupt)):
        return 'cancelled'
    from .budget import RetrievalError
    from ..native_access import NativeAccessError
    if (isinstance(error, TimeoutError)
            or isinstance(error, RetrievalError) and error.args == ('deadline_exceeded',)
            or isinstance(error, NativeAccessError) and error.code == 'native_access_expired'):
        return 'timeout'
    return 'failed'


class _Capture:
    def __init__(self, issuer, route, anchor, binding, profile, policy_digest):
        if issuer is not _ISSUER:
            raise ValueError('native_observation_required')
        from ..sprint_lifecycle import _scope
        self.route = copy.deepcopy(route)
        self.anchor = anchor
        self.profile, self.policy_digest = profile, policy_digest
        self.owner = os.getpid(), threading.get_ident()
        self.attempt = 'read_' + secrets.token_hex(16)
        self.operation_id = 'retrieval_' + digest({'task': route['logical_task_id'],
            'route': route['route_id'], 'attempt': self.attempt})[:40]
        self.common = {'schema_version': 3, 'producer_version': 1,
            'route_id': route['route_id'], 'logical_task_id': route['logical_task_id'],
            'session_id': route['session_id'], 'authority_epoch': route['authority_epoch'],
            'state_revision': route['state_revision'], 'context_revision': route['context']['revision'],
            'scope_digest': _scope(binding, route), 'spec_digest': binding['spec_digest'],
            'evidence_digest': None, **anchor.git_source(), 'base': route['base_commit'],
            **anchor.binding}
        self.rows, self.metadata, self.spans, self.dropped = [], {}, 0, 0
        self.started_ns = time.monotonic_ns()
        self.active = True
        self.valid = True
        self._row('operation', 'operation_started', outcome=None, elapsed_ns=None)
        self._row('policy', 'policy_observed', decision='allow', policy_digest=policy_digest,
                  reason_code='policy_allowed', read_profile=profile)

    def _owned(self):
        return self.active and self.owner == (os.getpid(), threading.get_ident())

    def _row(self, event, kind, **fields):
        at = _utc_now()
        row = {**self.common, 'at': at, 'captured_at': at, 'event': event, 'kind': kind,
               'operation_id': self.operation_id, **fields}
        if event in {'operation', 'span'}:
            row['attempt_id'] = self.attempt
        row['event_id'] = digest(row)
        validate_v3(row)
        self.rows.append(row)

    def metadata_from(self, source, generation, config):
        if self._owned():
            self.metadata = {'source_revision': digest(source), 'index_revision': digest(generation),
                             'config_digest': digest(config)}

    def finish(self, outcome):
        if self._owned():
            self._row('operation', 'operation_finished', outcome=outcome,
                      elapsed_ns=max(0, time.monotonic_ns() - self.started_ns))
            self.active = False


class _Span:
    def __init__(self):
        self.outcome = 'succeeded'
        self.fields = {}

    def result(self, outcome='succeeded', *, candidate_count=None, context_bytes=None):
        if outcome not in {'succeeded', 'empty', 'cache_hit', 'cache_miss'}:
            raise ValueError('invalid_native_stage_outcome')
        for value in (candidate_count, context_bytes):
            if value is not None and (type(value) is not int or not 0 <= value <= 10**18):
                raise ValueError('invalid_native_stage_measurement')
        self.outcome = outcome
        self.fields = {'candidate_count': candidate_count, 'context_bytes': context_bytes}


@contextmanager
def stage(name):
    """Memory-only actual algorithm stage; inactive paths perform no I/O."""
    captured = _ACTIVE.get()
    span = _Span()
    if type(captured) is not _Capture or not captured._owned():
        yield span
        return
    if name not in STAGES or captured.spans >= MAX_SPANS:
        # A missing span stays a coverage gap, never a fabricated success.
        captured.dropped = min(10**18, captured.dropped + 2)
        yield span
        return
    captured.spans += 1
    identity = 'stage_' + str(captured.spans)
    fields = {'span_id': identity, 'parent_span_id': None, 'stage': name,
              'timing_source': 'monotonic', **captured.metadata}
    try:
        captured._row('span', 'stage_started', **fields, outcome=None, elapsed_ns=None)
    except Exception:
        captured.valid = False
        yield span
        return
    started = time.monotonic_ns()
    try:
        yield span
    except BaseException as error:
        span.outcome = _outcome(error)
        raise
    finally:
        if captured._owned():
            try:
                captured._row('span', 'stage_finished', **fields, **span.fields,
                    outcome=span.outcome, elapsed_ns=max(0, time.monotonic_ns() - started))
            except Exception:
                captured.valid = False


def capture(root, route, anchor, profile):
    """Only the fixed native host calls this after its actual owner admission."""
    if 'observation_publication' not in route:
        return None
    try:
        from .. import state
        from ..continuity import context_binding
        from .policy_inputs import current_policy_digest
        state.require_route_owner(root, route, anchor=anchor)
        return _Capture(_ISSUER, route, anchor, context_binding(root, route, anchor=anchor),
                        profile, current_policy_digest(anchor, profile))
    except Exception as error:
        if _outcome(error) == 'cancelled':
            raise
        return None


@contextmanager
def observing(captured):
    token = _ACTIVE.set(captured)
    try:
        yield
    finally:
        _ACTIVE.reset(token)


def publish(root, captured, host):
    """Best-effort original-scope CAS, then existing delivery after control ends."""
    if (type(captured) is not _Capture or captured.active or not captured.valid
            or captured.anchor is not host.anchor):
        return False
    try:
        from .. import state
        from ..sprint_lifecycle import MAX_PENDING, deliver
        from ..util import now_utc
        from .budget import Budget
        # Native read authority, held source identity and the original route are
        # checked before publication. An active-route change cannot retag rows.
        anchor = captured.anchor
        budget = Budget(seconds=PUBLICATION_SECONDS)
        deadline = budget.deadline
        with state.task_transition(root, anchor=anchor, timeout=0.05):
            current = state.require_route_owner(root, captured.route, anchor=anchor)
            host.observation_current(budget)
            from .policy_inputs import current_policy_digest
            if (captured.profile != host.sink
                    or current_policy_digest(anchor, captured.profile) != captured.policy_digest
                    or host.reader is not None and host.reader.policy_digest != captured.policy_digest):
                return False
            if current != captured.route or anchor.git_source() != {
                    key: captured.common[key] for key in ('head', 'tree')}:
                return False
            publication = copy.deepcopy(current['observation_publication'])
            publication['dropped'] += captured.dropped
            present = {row['event_id']: row for row in publication['events']}
            for row in captured.rows:
                validate_v3(row)
                if row['event_id'] in present:
                    if present[row['event_id']] != row:
                        return False
                elif len(publication['events']) < MAX_PENDING:
                    publication['events'].append(copy.deepcopy(row))
                else:
                    publication['dropped'] += 1
            changed = copy.deepcopy(current)
            changed['observation_publication'] = publication
            changed['state_revision'] += 1
            changed['updated_at'] = now_utc()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            state._commit_route(root, changed, expected=current, observation_only=True,
                                anchor=anchor, lock_timeout=min(0.05, remaining))
        if not deliver(root, captured.route['route_id'], anchor=anchor):
            return False
        final = state.canonical_route(root, captured.route['route_id'], anchor=anchor)['observation_publication']
        return all(final['delivery'].get(row['event_id'], {}).get('row_digest') == digest(row)
                   for row in captured.rows)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError):
        return False
