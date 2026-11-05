"""OS-owner local observation boundary; this is not an enterprise principal ACL."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime, timezone
from dataclasses import dataclass
from contextlib import contextmanager, ExitStack

from .metrics_journal import MAX_BYTES, MAX_RECORDS, MAX_ROW, EVENTS, digest


@dataclass(frozen=True)
class _ReadToken:
    uid: int
    binding: tuple
    fingerprint: tuple


class _LocalRead(dict):
    """Native ephemeral read cut; the token is not a serialized payload field."""

    def __init__(self, value, token):
        super().__init__(value)
        self._token = token


def _fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _directory(parent, name, uid, *, private=False):
    descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                         dir_fd=parent)
    info = os.fstat(descriptor)
    mode = stat.S_IMODE(info.st_mode)
    trusted = info.st_uid == uid and not mode & 0o022
    if not trusted or private and (info.st_uid != uid or mode != 0o700):
        os.close(descriptor)
        raise ValueError('private_observation_directory_required')
    return descriptor


@contextmanager
def owned_journal(root, *, private=True, writable=False, anchor=None):
    """Yield an actually owned no-follow descriptor, never a payload principal."""
    if (os.name != 'posix' or not hasattr(os, 'getuid')
            or os.getuid() != os.geteuid()):
        raise ValueError('local_owner_unavailable')
    from .trace_storage import native_root, _NativeRoot
    with ExitStack() as stack:
        if anchor is None:
            anchor = stack.enter_context(native_root(root))
        if type(anchor) is not _NativeRoot or anchor.workspace != os.path.abspath(root):
            raise ValueError('native_trace_root_required')
        anchor.check()
        if writable and not private:
            raise ValueError('private_write_required')
        descriptor, parent = stack.enter_context(anchor.file('.getzilla/runtime/metrics.jsonl',
                                               private=private, writable=writable, limit=MAX_BYTES))
        yield descriptor, parent, anchor.binding


def initial_owner(root, anchor):
    """Explicit initialization only: bounded native binding before private modes.

    This admits no trace read/export and never normalizes permissions itself.
    """
    from . import state
    from .continuity import has_task_context, validate_route
    from .spec import _pairs_object, _reject_constant
    session = state.current_session()
    if not isinstance(session, str) or not state._SESSION_ID.fullmatch(session):
        raise ValueError('native_initialization_owner_required')
    pointer = json.loads(anchor.read(f'.getzilla/runtime/sessions/{session}.json', 4096, private=False),
                         object_pairs_hook=_pairs_object, parse_constant=_reject_constant)
    if (type(pointer) is not dict or set(pointer) != {'route_id', 'session_id', 'logical_task_id', 'authority_epoch'}
            or pointer['session_id'] != session or not isinstance(pointer['route_id'], str)
            or not re.fullmatch(r'[0-9a-f]{12}', pointer['route_id'])):
        raise ValueError('native_initialization_binding_required')
    route = json.loads(anchor.read(f".getzilla/runtime/routes/{pointer['route_id']}.json", private=False),
                       object_pairs_hook=_pairs_object, parse_constant=_reject_constant)
    validate_route(root, route, anchor=anchor)
    if (not has_task_context(route) or any(pointer[key] != route.get(key) for key in pointer)
            or route.get('session_id') != session):
        raise ValueError('native_initialization_binding_required')
    return route


def initialize_private(root, *, anchor=None, selected_package=False):
    """Explicit owner-only at-rest setup; v2 data remains unqualified forever."""
    from .trace_storage import native_root
    with ExitStack() as stack:
        if anchor is None:
            anchor = stack.enter_context(native_root(root))
        original = initial_owner(root, anchor) if selected_package else None
        with owned_journal(root, private=False, anchor=anchor) as (descriptor, parent, _):
            if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o600:
                raise ValueError('legacy_file_initialization_refused')
            os.fchmod(parent, 0o700)
        if selected_package:
            from . import state
            from .continuity import has_task_context
            from .workflow_storage import valid_package_path, RUNTIME_CHANGES
            with state.task_transition(root, anchor=anchor):
                route = state.require_route_owner(root, anchor=anchor)
                if route != original:
                    raise ValueError('native_initialization_context_changed')
                active = state.get_active_change(root, anchor=anchor)
                if not has_task_context(route):
                    raise ValueError('native_package_initialization_required')
                if active is None and route.get('change_id') is None:
                    return
                if (not isinstance(active, dict) or set(active) != {'change_id', 'path'}
                        or active['change_id'] != route.get('change_id')
                        or not valid_package_path(active['path'], active['change_id'])
                        or active['path'] != RUNTIME_CHANGES + '/' + active['change_id']):
                    raise ValueError('selected_runtime_package_required')
                # Pre-admit all three original native metadata files before
                # changing any package mode. No recursive or caller-path chmod.
                with ExitStack() as metadata:
                    package, _ = metadata.enter_context(anchor.parent(active['path'] + '/.private-init', private=False))
                    files = [metadata.enter_context(anchor.file(active['path'] + '/' + name, private=False, writable=True))[0]
                             for name in ('state.json', 'change-spec.yaml', 'requirements.md')]
                    if (state.require_route_owner(root, anchor=anchor) != route
                            or state.get_active_change(root, anchor=anchor) != active):
                        raise ValueError('selected_package_changed')
                    anchor.check_parent(package)
                    os.fchmod(package, 0o700)
                    for descriptor in files:
                        os.fchmod(descriptor, 0o600)


def local_identity(root, *, anchor=None):
    """Canonical-root-only native descriptor binding, not a supplied project ID."""
    with owned_journal(root, anchor=anchor) as (_, _, binding):
        return binding


def _delivery_proofs(root, rows, *, anchor):
    """Read bounded native canonical acknowledgements, never an imported label."""
    from .trace_contracts import utc, validate_delivery, delivery_utc
    native = [row for row in rows if row.get('schema_version') == 3]
    proofs, gaps = {}, set()
    grouped = {}
    for row in native:
        grouped.setdefault(row['route_id'], []).append(row)
    with owned_journal(root, anchor=anchor) as (_, parent, binding):
        try:
            directory = _directory(parent, 'routes', os.getuid(), private=True)
            directory_identity = os.fstat(directory).st_dev, os.fstat(directory).st_ino
        except FileNotFoundError:
            return {}, ['native_delivery_proof_missing'] if grouped else []
        try:
            names = []
            with os.scandir(directory) as inventory:
                for index, entry in enumerate(inventory):
                    if index >= 4096:
                        gaps.add('native_inventory_limit'); break
                    if re.fullmatch(r'[0-9a-f]{12}\.json', entry.name):
                        names.append(entry.name[:-5])
                    else:
                        gaps.add('native_inventory_unqualified')
            for route_id in names:
                grouped.setdefault(route_id, [])
            consumed = 0
            for route_id, selected in grouped.items():
                anchor.charge()
                descriptor = None
                try:
                    descriptor = os.open(route_id+'.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                    info = os.fstat(descriptor)
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 1_048_576):
                        raise ValueError('canonical_record_unavailable')
                    consumed += info.st_size
                    anchor.charge(size=info.st_size)
                    if consumed > MAX_BYTES:
                        gaps.add('native_inventory_limit'); break
                    raw = os.read(descriptor, 1_048_577)
                    after = os.fstat(descriptor)
                    named = os.stat(route_id+'.json', dir_fd=directory, follow_symlinks=False)
                    if (_fingerprint(info) != _fingerprint(after)
                            or (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino)
                            or len(raw) != info.st_size):
                        raise ValueError('canonical_record_changed')
                    route = json.loads(raw)
                    if (route.get('route_id') != route_id or route.get('workspace') != str(root.absolute())
                            or selected and route.get('logical_task_id') != selected[0]['logical_task_id']):
                        raise ValueError('canonical_binding_mismatch')
                    if 'observation_publication' not in route:
                        continue
                    publication = route['observation_publication']
                    if (not isinstance(publication['events'], list) or len(publication['events']) > 64
                            or not isinstance(publication['delivery'], dict) or len(publication['delivery']) > 64):
                        raise ValueError('native_retention_gap')
                    if publication.get('dropped') or route.get('observation_capture_failed'):
                        gaps.add('native_capture_gap')
                    frozen = {row['event_id']: row for row in publication['events']}
                    present = {row['event_id'] for row in selected}
                    if frozen.keys() - present:
                        gaps.add('native_journal_gap')
                    for row in selected:
                        proof = publication['delivery'].get(row['event_id'])
                        validate_delivery(proof, row)
                        if (frozen.get(row['event_id']) != row
                                or route['authority_epoch'] < row['authority_epoch']
                                or route['state_revision'] < row['state_revision']
                                or route['context']['revision'] < row['context_revision']
                                or delivery_utc(proof['delivered_by']) > datetime.now(timezone.utc)):
                            gaps.add('native_delivery_proof_missing'); continue
                        proofs[row['event_id']] = dict(proof)
                except (OSError, ValueError, TypeError, KeyError, RecursionError):
                    gaps.add('native_delivery_proof_missing')
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
        finally:
            if directory is not None:
                try:
                    named = os.stat('routes', dir_fd=parent, follow_symlinks=False)
                    if (not stat.S_ISDIR(named.st_mode) or named.st_uid != os.getuid()
                            or stat.S_IMODE(named.st_mode) != 0o700
                            or (named.st_dev, named.st_ino) != directory_identity):
                        raise ValueError('native_inventory_changed')
                finally:
                    os.close(directory)
    return proofs, sorted(gaps)


def load_local(root):
    """Private rows or safe legacy aggregates; unknown ownership discloses none."""
    from .trace_storage import native_root
    try:
        with native_root(root) as anchor:
            return _load_local(root, anchor)
    except (OSError, ValueError):
        return {'access': 'metadata_only', 'events': [], 'input_digest': None,
                'scope': 'canonical_root_only', 'gaps': ['private_local_storage_unqualified']}


def _load_local(root, anchor):
    denied = {'access': 'metadata_only', 'events': [], 'input_digest': None,
              'scope': 'canonical_root_only', 'gaps': ['private_local_storage_unqualified']}
    private = True
    try:
        with owned_journal(root, anchor=anchor) as (descriptor, _, binding):
            raw = os.read(descriptor, MAX_BYTES + 1)
            anchor.charge(size=len(raw))
            token = _ReadToken(os.getuid(), tuple(sorted(binding.items())), _fingerprint(os.fstat(descriptor)))
    except (OSError, ValueError):
        private = False
        try:
            with owned_journal(root, private=False, anchor=anchor) as (descriptor, _, binding):
                raw = os.read(descriptor, MAX_BYTES + 1)
                anchor.charge(size=len(raw))
                token = _ReadToken(os.getuid(), tuple(sorted(binding.items())), _fingerprint(os.fstat(descriptor)))
        except (OSError, ValueError):
            return denied
    try:
        if len(raw) > MAX_BYTES:
            return denied
        rows, row_ids, gaps, seen, disputed = [], [], [], {}, set()
        for index, line in enumerate(raw.splitlines(keepends=True)):
            if index >= MAX_RECORDS:
                gaps.append('record_limit'); break
            try:
                if len(line) > MAX_ROW or not line.endswith(b'\n'):
                    raise ValueError('row_bound')
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise ValueError('invalid_row')
                identity = row.get('event_id')
                if isinstance(identity, str):
                    if identity in seen:
                        if seen[identity] != row:
                            gaps.append('conflicting_replay')
                            disputed.add(identity)
                        continue
                    seen[identity] = row
                if row.get('schema_version') == 3:
                    if not private:
                        gaps.append('restricted_rows_unavailable'); continue
                    from .trace_contracts import validate_v3
                    validate_v3(row)
                    if any(row[name] != expected for name, expected in binding.items()):
                        gaps.append('project_binding_mismatch'); continue
                    rows.append(row)
                    row_ids.append(identity)
                elif row.get('event') in EVENTS:
                    # Never return legacy IDs, labels, paths, payload or source claims.
                    rows.append({key: row[key] for key in ('at', 'event') if key in row})
                    row_ids.append(identity if isinstance(identity, str) else None)
            except (ValueError, UnicodeError, TypeError, RecursionError):
                gaps.append('malformed_row')
        if not private:
            gaps.append('private_local_storage_unqualified')
        rows = [row for identity, row in zip(row_ids, rows) if identity not in disputed]
        proofs = {}
        if private:
            proofs, proof_gaps = _delivery_proofs(root, rows, anchor=anchor)
            gaps += proof_gaps
        return _LocalRead({'access': 'local_owner' if private else 'metadata_only', 'events': rows,
                'input_digest': hashlib.sha256(raw).hexdigest(),
                'scope': 'canonical_root_only', 'delivery_proofs': proofs, 'gaps': sorted(set(gaps))}, token)
    except (OSError, ValueError, ImportError):
        return denied


def revalidate_local(root, captured):
    """Check actual current access and source cut again immediately before output."""
    if type(captured) is not _LocalRead or type(captured._token) is not _ReadToken:
        return False
    fresh = load_local(root)
    return (type(fresh) is _LocalRead and fresh._token == captured._token
            and fresh['access'] == captured['access']
            and fresh['input_digest'] == captured['input_digest']
            and fresh['events'] == captured['events']
            and fresh['delivery_proofs'] == captured['delivery_proofs'])
