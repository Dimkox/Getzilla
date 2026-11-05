"""Owner-bound native sprint metadata and immutable best-effort observations.

Pending bytes live in the existing canonical route. This is not a second task
ledger or an acceptance API. Separate file publication is always censored.
"""
from __future__ import annotations

import copy
import json
import os
import time
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone

from . import fsx, state
from .metrics_journal import MAX_BYTES, MAX_RECORDS, MAX_ROW, digest, validate
from .observation_privacy import initialize_private, local_identity, owned_journal, initial_owner
from .trace_contracts import utc, validate_v3, validate_delivery, delivery_utc
from .util import now_utc

MAX_PENDING = 64
DELIVERY_SECONDS = 0.05
_DELIVERY_ISSUER = object()


def _native_clock():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


class _Delivery:
    def __init__(self, issuer, anchor, rows):
        if issuer is not _DELIVERY_ISSUER:
            raise ValueError('native_delivery_required')
        self.anchor = anchor
        self.digests = {row['event_id']: digest(row) for row in rows}
        self.after_fsync = _native_clock()


def append_batch(root, observations, *, anchor, deadline):
    """One nonblocking admission/scan/fsync outside every command control lock."""
    try:
        if state._TRANSITIONS.get() or len(observations) > MAX_PENDING:
            return None
        expected = {}
        for row in observations:
            validate(row)
            from .trace_contracts import native_context
            if native_context(row) is None:
                return None
            if any(row[key] != value for key, value in anchor.binding.items()):
                return None
            previous = expected.setdefault(row['event_id'], row)
            if previous != row:
                return None
        if time.monotonic() > deadline:
            return None
        with owned_journal(root, writable=True, anchor=anchor) as (descriptor, parent, _):
            fsx.lock_file(descriptor, exclusive=True, blocking=False)
            try:
                raw = os.read(descriptor, MAX_BYTES+1)
                anchor.charge(size=len(raw))
                lines = raw.splitlines(keepends=True)
                if len(raw) > MAX_BYTES or len(lines) > MAX_RECORDS:
                    return None
                seen = {}
                from .spec import _pairs_object, _reject_constant
                for line in lines:
                    if time.monotonic() > deadline or len(line) > MAX_ROW or not line.endswith(b'\n'):
                        return None
                    row = json.loads(line, object_pairs_hook=_pairs_object, parse_constant=_reject_constant)
                    identity = row.get('event_id')
                    if identity is not None:
                        previous = seen.setdefault(identity, row)
                        if previous != row:
                            return None
                additions = []
                for identity, row in expected.items():
                    if identity in seen:
                        if seen[identity] != row:
                            return None
                    else:
                        additions.append((json.dumps(row, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode())
                payload = b''.join(additions)
                if (len(raw)+len(payload) > MAX_BYTES or len(lines)+len(additions) > MAX_RECORDS
                        or time.monotonic() > deadline):
                    return None
                anchor.check_parent(parent)
                offset = 0
                while offset < len(payload):
                    anchor.charge()
                    written = os.write(descriptor, payload[offset:])
                    if not written:
                        return None
                    offset += written
                os.fsync(descriptor)
                fsx.fsync_dir(parent)
                return _Delivery(_DELIVERY_ISSUER, anchor, observations)
            finally:
                fsx.unlock_file(descriptor)
    except (OSError, ValueError, TypeError, KeyError):
        return None


def _scope(binding, route):
    return digest({'logical_task_id': route['logical_task_id'],
                   'context_revision': route['context']['revision'],
                   'spec_digest': binding['spec_digest'],
                   'requirements_digest': binding['requirements_digest']})


def prepare_transition(root, route, previous, *, native_claim=None, anchor=None):
    """Called under the existing native owner/CAS cut before canonical publish."""
    if previous is None or not ('sprint' in route or 'observation_publication' in route):
        return route
    kinds = []
    if 'sprint' in route and 'sprint' not in previous:
        kinds.append('selected')
    if previous['context']['revision'] != route['context']['revision']:
        kinds.append('scope_changed')
    if previous.get('status') != route.get('status') and route.get('status') in {'completed', 'cancelled'}:
        # The original guard still reaches unanchored receipt/worker/source
        # readers. Its factual transition cannot qualify this forecast target.
        # Do not manufacture a native completion witness from a path bracket.
        raise ValueError('native_completion_guard_unqualified')
    if not kinds and native_claim is None:
        return route
    if anchor is None:
        raise ValueError('native_capture_anchor_required')
    from .continuity import context_binding
    state.require_route_owner(root, previous, anchor=anchor)
    binding = context_binding(root, previous, anchor=anchor)
    scope = _scope(binding, route)
    publication = copy.deepcopy(previous.get('observation_publication', route.get('observation_publication',
                            {'version': 1, 'coverage': 'censored', 'events': [], 'delivery': {}, 'dropped': 0})))
    if (set(publication) - {'version', 'coverage', 'events', 'delivery', 'dropped', 'enrolled_at', 'enrollment_revision'}
            or publication['version'] != 1 or not isinstance(publication['events'], list)
            or len(publication['events']) > MAX_PENDING):
        raise ValueError('invalid_native_publication')
    for existing in publication['events']:
        validate_v3(existing)
    native = local_identity(root, anchor=anchor)
    at = datetime.fromisoformat(route.get('updated_at') or now_utc()).astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    publication.setdefault('enrolled_at', at)
    publication.setdefault('enrollment_revision', previous['state_revision'])
    if native_claim is not None:
        from .trace_observation import claimed_row
        claim = claimed_row(route, previous, native_claim)
        if claim['scope_digest'] != scope or any(claim[key] != value for key, value in native.items()):
            raise ValueError('native_claim_mismatch')
        if len(publication['events']) < MAX_PENDING:
            publication['events'].append(claim)
        else:
            publication['dropped'] += 1
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
                 'evidence_digest': None,
                 **anchor.git_source(),
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


def enroll_trace(root, *, expected_epoch, expected_revision):
    """Explicit local metadata purpose; this cannot authorize a product effect."""
    from .trace_storage import native_root
    with native_root(root) as anchor:
        route = initial_owner(root, anchor)
        if (type(expected_epoch) is not int or type(expected_revision) is not int
                or route['authority_epoch'] != expected_epoch
                or route.get('status') in {'completed', 'cancelled', 'archived', 'released'}):
            raise ValueError('stale_trace_enrollment')
        existing = route.get('observation_publication')
        if existing and expected_revision in {route['state_revision'], existing.get('enrollment_revision')}:
            return route
        if existing or route['state_revision'] != expected_revision:
            raise ValueError('stale_trace_enrollment')
        initialize_private(root, anchor=anchor, selected_package=True)
        with state.task_transition(root, anchor=anchor):
            if state.require_route_owner(root, anchor=anchor) != route:
                raise ValueError('stale_trace_enrollment')
            changed = copy.deepcopy(route)
            changed['observation_publication'] = {'version': 1, 'coverage': 'enrolled', 'events': [],
                'delivery': {}, 'dropped': 0, 'enrolled_at': now_utc(), 'enrollment_revision': expected_revision}
            changed['state_revision'] += 1
            changed['updated_at'] = now_utc()
            return state._commit_route(root, changed, expected=route, anchor=anchor)


def ack_delivery(root, expected, delivered, *, anchor=None, deadline=None):
    """Native CAS proves availability BY an upper bound, not first visibility."""
    if type(delivered) is not _Delivery or anchor is not delivered.anchor or deadline is None:
        return False
    remaining = deadline-time.monotonic()
    if remaining < 0:
        return False
    with state.task_transition(root, anchor=anchor, timeout=remaining):
        state.require_route_owner(root, expected, anchor=anchor)
        if state.canonical_route(root, expected['route_id'], anchor=anchor) != expected:
            return False
        publication = copy.deepcopy(expected['observation_publication'])
        rows = {row['event_id']: row for row in publication['events']}
        until = _native_clock()
        previous_times = []
        for identity, proof in publication['delivery'].items():
            try:
                validate_delivery(proof, rows[identity])
                previous_times.append(delivery_utc(proof['delivered_by']))
            except (ValueError, KeyError):
                pass  # Old/invalid proofs may gain a fresh current-owner cut only after real fsync.
        if delivery_utc(until) < delivery_utc(delivered.after_fsync):
            return False
        for identity, row_digest in delivered.digests.items():
            if (identity not in rows or row_digest != digest(rows[identity])
                    or delivery_utc(until) < utc(rows[identity]['captured_at'])
                    or any(delivery_utc(until) < at for at in previous_times)):
                return False
            try:
                validate_delivery(publication['delivery'].get(identity), rows[identity])
            except ValueError:
                publication['delivery'][identity] = {'proof_version': 2, 'clock_domain': 'native_local_utc',
                    'row_digest': row_digest, 'delivered_by': until}
        if len(publication['delivery']) == len(rows) and not publication['dropped']:
            publication['coverage'] = 'delivered'
        if publication == expected['observation_publication']:
            return True
        changed = copy.deepcopy(expected)
        changed['observation_publication'] = publication
        changed['state_revision'] += 1
        changed['updated_at'] = until
        remaining = deadline-time.monotonic()
        if remaining < 0:
            return False
        state._commit_route(root, changed, expected=expected, observation_only=True,
                            anchor=anchor, lock_timeout=remaining)
        return True


def deliver(root, route_id, *, anchor=None):
    """Reconcile observations only, from original canonical bytes, never work."""
    if state._TRANSITIONS.get():
        return False
    from .trace_storage import native_root
    deadline = time.monotonic()+DELIVERY_SECONDS
    try:
        with ExitStack() as resources:
            if anchor is None:
                anchor = resources.enter_context(native_root(root))
            route = state.canonical_route(root, route_id, anchor=anchor)
            state.require_route_owner(root, route, anchor=anchor)
            publication = route.get('observation_publication')
            if not publication:
                return False
            delivered = append_batch(root, publication['events'], anchor=anchor, deadline=deadline)
            return bool(delivered and ack_delivery(root, route, delivered, anchor=anchor, deadline=deadline))
    except (OSError, ValueError, TypeError, KeyError, RuntimeError):
        return False


def flush_after_scope(root, route_id):
    """Explicit CLI owner, after all work/guards: no ambient route or replay.

    A successful original action stays successful when observation storage is
    unavailable. Return the actually reread canonical revision, never a claim
    that the action's earlier revision is still current after an ACK.
    """
    from .trace_storage import native_root
    from concurrent.futures import CancelledError
    try:
        with native_root(root) as anchor:
            deliver(root, route_id, anchor=anchor)
            return state.canonical_route(root, route_id, anchor=anchor)
    except CancelledError:
        raise
    except Exception:
        return None


def select_sprint(root, start, *, expected_epoch, expected_revision):
    from .trace_storage import native_root
    with native_root(root) as anchor:
        route = initial_owner(root, anchor)
        if (type(expected_epoch) is not int or type(expected_revision) is not int
                or route['authority_epoch'] != expected_epoch):
            raise ValueError('stale_sprint_selection')
        begin = utc(start)
        if route.get('status') in {'completed', 'cancelled', 'archived', 'released'}:
            raise ValueError('terminal_sprint_selection')
        existing = route.get('sprint')
        if existing:
            if (existing.get('window_start') == start and existing.get('request_revision') == expected_revision):
                return route
            raise ValueError('sprint_reselection_requires_rescope')
        if route['state_revision'] != expected_revision:
            raise ValueError('stale_sprint_selection')
        initialize_private(root, anchor=anchor, selected_package=True)
        with state.task_transition(root, anchor=anchor):
            if state.require_route_owner(root, anchor=anchor) != route:
                raise ValueError('stale_sprint_selection')
            changed = copy.deepcopy(route)
            changed['sprint'] = {'version': 1, 'window_start': start,
                               'window_end': (begin+timedelta(days=14)).strftime('%Y-%m-%dT%H:%M:%SZ'),
                               'selected_at': now_utc(), 'request_revision': expected_revision}
            changed['state_revision'] += 1
            changed['updated_at'] = changed['sprint']['selected_at']
            return state._commit_route(root, changed, expected=route, anchor=anchor)
