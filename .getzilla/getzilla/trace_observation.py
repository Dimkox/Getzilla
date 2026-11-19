"""Actual managed-operation observations; no command, payload or authority API."""
from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timezone

from . import state
from .metrics_journal import digest
from .observation_privacy import local_identity
from .trace_contracts import validate_v3
from .util import now_utc


@dataclass(frozen=True)
class NativeClaim:
    row: dict
    key: str  # Existing budget key, memory only. Never included in a trace row.


def _utc_now():
    return datetime.fromisoformat(now_utc()).astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def capture_claim(root, route, operation_id, key, *, anchor=None):
    """Called by actual153 claim before its canonical CAS, inside its fence."""
    if 'observation_publication' not in route:
        return None
    if anchor is None:
        raise ValueError('native_claim_anchor_required')
    from .continuity import context_binding
    from .sprint_lifecycle import _scope
    state.require_route_owner(root, route, anchor=anchor)
    operation = route['task_budget']['operations'][operation_id]
    if operation['state'] != 'reserved' or operation['key'] != key or operation['owner_epoch'] != route['authority_epoch']:
        raise ValueError('native_claim_mismatch')
    binding = context_binding(root, route, anchor=anchor)
    at = _utc_now()
    row = {'schema_version': 3, 'event': 'operation', 'kind': 'budget_claimed',
           'at': at, 'captured_at': at, 'producer_version': 1,
           'route_id': route['route_id'], 'logical_task_id': route['logical_task_id'],
           'session_id': route['session_id'], 'authority_epoch': route['authority_epoch'],
           'state_revision': route['state_revision']+1, 'context_revision': route['context']['revision'],
           'scope_digest': _scope(binding, route), 'spec_digest': binding['spec_digest'],
           'evidence_digest': None, **anchor.git_source(), 'base': route.get('base_commit'),
           'operation_id': operation_id, 'attempt_id': None, 'outcome': None, 'elapsed_ns': None,
           **local_identity(root, anchor=anchor)}
    row['event_id'] = digest(row)
    validate_v3(row)
    return NativeClaim(row, key)


def claimed_row(route, previous, captured):
    """Validate the real reserved→running cut; JSON cannot supply this object."""
    if type(captured) is not NativeClaim:
        raise ValueError('native_claim_mismatch')
    row = captured.row
    validate_v3(row)
    before = previous['task_budget']['operations'][row['operation_id']]
    after = route['task_budget']['operations'][row['operation_id']]
    if (row['route_id'] != route['route_id'] or row['logical_task_id'] != route['logical_task_id']
            or row['session_id'] != route['session_id'] or row['authority_epoch'] != route['authority_epoch']
            or row['state_revision'] != route['state_revision']
            or row['context_revision'] != route['context']['revision']
            or before['state'] != 'reserved' or after['state'] != 'running'
            or before['key'] != captured.key or after['key'] != captured.key
            or after['owner_epoch'] != route['authority_epoch']):
        raise ValueError('native_claim_mismatch')
    return copy.deepcopy(row)


def committed_claim(root, route_id, operation_id, key, *, anchor=None):
    """Read original A inside the claim/spawn fence, never an ambient pointer."""
    try:
        if anchor is None:
            return None
        route = state.canonical_route(root, route_id, anchor=anchor)
        state.require_route_owner(root, route, anchor=anchor)
        operation = route['task_budget']['operations'][operation_id]
        binding = local_identity(root, anchor=anchor)
        for row in reversed(route['observation_publication']['events']):
            if row['kind'] == 'budget_claimed' and row.get('operation_id') == operation_id:
                validate_v3(row)
                if (operation['key'] == key and operation['state'] == 'running'
                        and row['authority_epoch'] == route['authority_epoch'] == operation['owner_epoch']
                        and row['route_id'] == route['route_id'] and row['logical_task_id'] == route['logical_task_id']
                        and row['session_id'] == route['session_id']
                        and row['context_revision'] == route['context']['revision']
                        and all(row[name] == value for name, value in binding.items())):
                    return NativeClaim(copy.deepcopy(row), key)
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return None


def capture_phase(captured, kind, *, outcome=None, elapsed_ns=None):
    """Pure bounded memory capture at actual Popen/reap; no I/O in child control."""
    if type(captured) is not NativeClaim or kind not in {'operation_started', 'operation_finished'}:
        return None
    row = copy.deepcopy(captured.row)
    row.update(kind=kind, outcome=outcome, elapsed_ns=elapsed_ns, at=_utc_now())
    row['captured_at'] = row['at']
    if row['captured_at'] < captured.row['captured_at']:
        return None
    row['event_id'] = digest({'claim': captured.row['event_id'], 'kind': kind})
    try:
        validate_v3(row)
    except ValueError:
        return None
    return row


def _elapsed_observation(claim, key, finished):
    """Only the validated native reap path publishes this projection.

    Elapsed is the actual managed child's monotonic observation. No tariff,
    CPU/GPU/energy, attempt identity or acceptance is inferred from it.
    """
    if type(finished.get('elapsed_ns')) is not int or finished['elapsed_ns'] < 0:
        return None
    from .trace_contracts import native_context, validate_v4
    context = native_context(claim)
    producer = digest({'context': context, 'claim_key': key,
                       'claim_event': claim['event_id']})
    def unknown(unit):
        return {'value': None, 'unit': unit, 'unknown_reason': 'not_observed'}
    payload = {'candidate_kind': 'local_usage', 'source_fact_digest': finished['event_id'],
        'source_proof_ref': finished['event_id'], 'service_period': None,
        'operation': {'claim_event_digest': claim['event_id'],
            'operation_id': claim['operation_id'], 'attempt_id': claim['attempt_id'],
            'producer_binding_digest': producer, 'physical_operation_digest': claim['event_id']},
        'measurement_method': 'native_direct_child',
        'elapsed': {'value': finished['elapsed_ns'], 'unit': 'elapsed_ns', 'unknown_reason': None},
        'cpu': unknown('cpu_ns'), 'gpu': unknown('gpu_ns'), 'energy': unknown('microjoule'),
        'peak_rss': unknown('byte')}
    row = {'schema_version': 4, 'event': 'observation', 'kind': 'economics_observation',
        'at': finished['at'], 'captured_at': finished['captured_at'], 'producer_version': 1,
        'repository_digest': finished['repository_digest'], 'workspace_digest': finished['workspace_digest'],
        'observer': {'profile': 'core_native', 'operation_id': claim['operation_id'],
                     'context': context}, 'payload': payload}
    row['event_id'] = digest({'definition': 'native-child-elapsed-v1', 'claim': claim['event_id'],
                              'finished': finished['event_id']})
    validate_v4(row)
    return row


def publish_observations(root, captured, rows, *, anchor=None):
    """After owned child reap, persist only under still-valid explicit A scope."""
    if type(captured) is not NativeClaim:
        return False
    if anchor is None:
        from .trace_storage import native_root
        try:
            with native_root(root) as native:
                return publish_observations(root, captured, rows, anchor=native)
        except (OSError, ValueError):
            return False
    try:
        with state.task_transition(root, anchor=anchor):
            route = state.canonical_route(root, captured.row['route_id'], anchor=anchor)
            state.require_route_owner(root, route, anchor=anchor)
            operation = route['task_budget']['operations'][captured.row['operation_id']]
            if (route['logical_task_id'] != captured.row['logical_task_id']
                    or route['authority_epoch'] != captured.row['authority_epoch']
                    or route['session_id'] != captured.row['session_id']
                    or operation['key'] != captured.key or operation['owner_epoch'] != captured.row['authority_epoch']
                    or operation['state'] not in {'running', 'settled'}
                    or any(captured.row[key] != value for key, value in local_identity(root, anchor=anchor).items())):
                return False
            publication = copy.deepcopy(route['observation_publication'])
            present = {row['event_id']: row for row in publication['events']}
            from .sprint_lifecycle import MAX_PENDING
            selected = [row for row in rows if row is not None]
            starts = [row for row in selected if row.get('kind') == 'operation_started']
            finishes = [row for row in selected if row.get('kind') == 'operation_finished']
            if starts and finishes and finishes[0]['captured_at'] < starts[0]['captured_at']:
                return False
            for row in selected:
                validate_v3(row)
                expected = {**captured.row, 'kind': row['kind'], 'at': row['at'], 'captured_at': row['captured_at'],
                            'outcome': row['outcome'], 'elapsed_ns': row['elapsed_ns'], 'event_id': row['event_id']}
                if (row != expected or row['kind'] not in {'operation_started', 'operation_finished'}
                        or row['event_id'] != digest({'claim': captured.row['event_id'], 'kind': row['kind']})):
                    return False
                if row['event_id'] in present:
                    if present[row['event_id']] != row:
                        return False
                    continue
                if len(publication['events']) >= MAX_PENDING:
                    publication['dropped'] += 1
                    continue
                publication['events'].append(copy.deepcopy(row))
            economic = _elapsed_observation(captured.row, captured.key, finishes[0]) if len(starts) == len(finishes) == 1 and len(selected) == len(rows) == 2 else None
            if economic is not None:
                selected.append(economic)
                if economic['event_id'] in present:
                    if present[economic['event_id']] != economic:
                        return False
                elif len(publication['events']) < MAX_PENDING:
                    publication['events'].append(economic)
                else:
                    publication['dropped'] += 1
            changed = copy.deepcopy(route)
            changed['observation_publication'] = publication
            changed['state_revision'] += 1
            changed['updated_at'] = now_utc()
            state._commit_route(root, changed, expected=route, observation_only=True, anchor=anchor)
        # The entire task/control/settlement scope has ended before journal I/O.
        from .sprint_lifecycle import deliver
        if not deliver(root, route['route_id'], anchor=anchor):
            return False
        final = state.canonical_route(root, route['route_id'], anchor=anchor)['observation_publication']
        return len(rows) == 2 and len(selected) == 2 + int(economic is not None) and bool(starts and finishes) and all(final['delivery'].get(row['event_id'], {}).get('row_digest') == digest(row)
                                      for row in selected)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError):
        return False
