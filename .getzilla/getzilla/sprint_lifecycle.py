"""Owner-bound native sprint metadata and immutable best-effort observations.

Pending bytes live in the existing canonical route. This is not a second task
ledger or an acceptance API. Separate file publication is always censored.
"""
from __future__ import annotations

import copy
import json
import os
from datetime import datetime, timedelta, timezone

from . import fsx, state
from .metrics_journal import MAX_BYTES, MAX_RECORDS, digest
from .observation_privacy import initialize_private, local_identity, owned_journal
from .trace_contracts import utc, validate_v3
from .util import git_head, git_output, now_utc

MAX_PENDING = 64


def append_native(root, observation):
    """Append only a closed, actually project-bound row; never consult active B."""
    try:
        validate_v3(observation)
        payload = (json.dumps(observation, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode()
        with owned_journal(root, writable=True) as (descriptor, _, binding):
            if any(observation[key] != value for key, value in binding.items()):
                return False
            fsx.lock_file(descriptor)
            try:
                raw = os.read(descriptor, MAX_BYTES+1)
                lines = raw.splitlines(keepends=True)
                if len(raw)+len(payload) > MAX_BYTES or len(lines) >= MAX_RECORDS:
                    return False
                for line in lines:
                    if not line.endswith(b'\n'):
                        return False
                    row = json.loads(line)
                    if row.get('event_id') == observation['event_id']:
                        if row != observation:
                            return False
                        os.fsync(descriptor)
                        return True
                written = os.write(descriptor, payload) == len(payload)
                if written:
                    os.fsync(descriptor)
                return written
            finally:
                fsx.unlock_file(descriptor)
    except (OSError, ValueError, TypeError, KeyError):
        return False


def _scope(binding, route):
    return digest({'logical_task_id': route['logical_task_id'],
                   'context_revision': route['context']['revision'],
                   'spec_digest': binding['spec_digest'],
                   'requirements_digest': binding['requirements_digest']})


def prepare_transition(root, route, previous):
    """Called under the existing native owner/CAS cut before canonical publish."""
    if previous is None or 'sprint' not in route:
        return route
    from .continuity import context_binding, assert_finishable
    state.require_route_owner(root, previous)
    binding = context_binding(root, previous)
    scope = _scope(binding, route)
    kinds = []
    if 'sprint' not in previous:
        kinds.append('selected')
    if previous['context']['revision'] != route['context']['revision']:
        kinds.append('scope_changed')
    if previous.get('status') != route.get('status') and route.get('status') in {'completed', 'cancelled'}:
        assert_finishable(root, previous, cancel=route['status'] == 'cancelled')
        kinds.append('task_completed' if route['status'] == 'completed' else 'task_cancelled')
    publication = copy.deepcopy(previous.get('observation_publication',
                            {'version': 1, 'coverage': 'censored', 'events': [], 'delivery': {}, 'dropped': 0}))
    if (set(publication) != {'version', 'coverage', 'events', 'delivery', 'dropped'}
            or publication['version'] != 1 or not isinstance(publication['events'], list)
            or len(publication['events']) > MAX_PENDING):
        raise ValueError('invalid_native_publication')
    for existing in publication['events']:
        validate_v3(existing)
    native = local_identity(root)
    if not kinds:
        return route
    at = datetime.fromisoformat(route.get('updated_at') or now_utc()).astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    evidence = None
    if 'task_completed' in kinds:
        from .receipts import get_receipt
        receipts = {kind: get_receipt(root, previous['route_id'], kind)
                    for kind in previous.get('required_evidence', [])}
        evidence = digest({'context': binding, 'receipts': receipts})
    for kind in kinds:
        if len(publication['events']) >= MAX_PENDING:
            publication['dropped'] += 1
            continue
        event = {'schema_version': 3, 'event': 'task', 'kind': kind,
                 'at': at, 'captured_at': at, 'producer_version': 1,
                 'route_id': route['route_id'], 'logical_task_id': route['logical_task_id'],
                 'session_id': route['session_id'], 'authority_epoch': route['authority_epoch'],
                 'state_revision': route['state_revision'], 'context_revision': route['context']['revision'],
                 'scope_digest': scope, 'spec_digest': binding['spec_digest'],
                 'evidence_digest': evidence if kind == 'task_completed' else None,
                 'head': git_head(root), 'tree': git_output(root, 'rev-parse', 'HEAD^{tree}'),
                 'base': route.get('base_commit'), **native}
        if kind == 'selected':
            event['window_start'] = route['sprint']['window_start']
        event['event_id'] = digest(event)
        validate_v3(event)
        publication['events'].append(event)
        if kind == 'selected':
            route['sprint']['selected_scope_digest'] = scope
    route['observation_publication'] = publication
    return route


@state.serialized_task
def ack_delivery(root, expected, identities):
    """Native CAS proves availability BY an upper bound, not first visibility."""
    state.require_route_owner(root, expected)
    publication = copy.deepcopy(expected['observation_publication'])
    rows = {row['event_id']: row for row in publication['events']}
    until = datetime.fromisoformat(now_utc()).astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    previous_times = [proof['delivered_by'] for proof in publication['delivery'].values()]
    for identity in identities:
        if identity not in rows or until < rows[identity]['captured_at'] or any(until < at for at in previous_times):
            return False
        if not append_native(root, rows[identity]):
            return False
        publication['delivery'].setdefault(identity, {'row_digest': digest(rows[identity]), 'delivered_by': until})
    if len(publication['delivery']) == len(rows) and not publication['dropped']:
        publication['coverage'] = 'delivered'
    changed = copy.deepcopy(expected)
    changed['observation_publication'] = publication
    changed['state_revision'] += 1
    changed['updated_at'] = until
    state._commit_route(root, changed, expected=expected)
    return True


@state.serialized_task
def deliver(root, route_id):
    """Reconcile observations only, from original canonical bytes, never work."""
    route = state.canonical_route(root, route_id)
    state.require_route_owner(root, route)
    publication = route.get('observation_publication')
    if not publication:
        return False
    pending = [row for row in publication['events'] if row['event_id'] not in publication['delivery']]
    if not pending:
        return True
    try:
        succeeded = [row['event_id'] for row in pending if append_native(root, row)]
        if succeeded and not ack_delivery(root, route, succeeded):
            return False
        return len(succeeded) == len(pending)
    except (OSError, ValueError, TypeError, KeyError):
        return False


@state.serialized_task
def select_sprint(root, start, *, expected_epoch, expected_revision):
    route = state.require_route_owner(root)
    if (type(expected_epoch) is not int or type(expected_revision) is not int
            or route['authority_epoch'] != expected_epoch):
        raise ValueError('stale_sprint_selection')
    begin = utc(start)
    if route.get('status') in {'completed', 'cancelled', 'archived', 'released'}:
        raise ValueError('terminal_sprint_selection')
    existing = route.get('sprint')
    if existing:
        if (existing.get('window_start') == start
                and existing.get('request_revision') == expected_revision):
            deliver(root, route['route_id'])
            return route
        raise ValueError('sprint_reselection_requires_rescope')
    if route['state_revision'] != expected_revision:
        raise ValueError('stale_sprint_selection')
    initialize_private(root)
    changed = copy.deepcopy(route)
    changed['sprint'] = {'version': 1, 'window_start': start,
                         'window_end': (begin+timedelta(days=14)).strftime('%Y-%m-%dT%H:%M:%SZ'),
                         'selected_at': now_utc(), 'request_revision': expected_revision}
    changed['state_revision'] += 1
    changed['updated_at'] = changed['sprint']['selected_at']
    state._commit_route(root, changed, expected=route)
    return state.canonical_route(root, route['route_id'])
