"""OS-owner local observation boundary; this is not an enterprise principal ACL."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime, timezone
from contextlib import contextmanager

from .metrics_journal import MAX_BYTES, MAX_RECORDS, MAX_ROW, EVENTS, digest


def _directory(parent, name, uid, *, private=False):
    descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                         dir_fd=parent)
    info = os.fstat(descriptor)
    mode = stat.S_IMODE(info.st_mode)
    trusted = info.st_uid in {0, uid} and (not mode & 0o022 or
                                          info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX))
    if not trusted or private and (info.st_uid != uid or mode != 0o700):
        os.close(descriptor)
        raise ValueError('private_observation_directory_required')
    return descriptor


@contextmanager
def owned_journal(root, *, private=True, writable=False):
    """Yield an actually owned no-follow descriptor, never a payload principal."""
    if os.name != 'posix' or not hasattr(os, 'getuid'):
        raise ValueError('local_owner_unavailable')
    handles = []
    descriptor = None
    try:
        uid = os.getuid()
        absolute = root.absolute()
        handles.append(os.open('/', os.O_RDONLY | os.O_DIRECTORY))
        for part in absolute.parts[1:]:
            handles.append(_directory(handles[-1], part, uid))
        if os.fstat(handles[-1]).st_uid != uid:
            raise ValueError('local_owner_unavailable')
        root_info = os.fstat(handles[-1])
        native_identity = f'{root_info.st_dev}:{root_info.st_ino}'.encode()
        binding = {name: hashlib.sha256(name.encode()+b':'+native_identity).hexdigest()
                   for name in ('repository_digest', 'workspace_digest')}
        handles.append(_directory(handles[-1], '.getzilla', uid))
        handles.append(_directory(handles[-1], 'runtime', uid, private=private))
        if os.fstat(handles[-1]).st_uid != uid:
            raise ValueError('local_owner_unavailable')
        if writable and not private:
            raise ValueError('private_write_required')
        flags = os.O_RDWR | os.O_APPEND if writable else os.O_RDONLY
        descriptor = os.open('metrics.jsonl', flags | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=handles[-1])
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1
                or info.st_mode & 0o111 or info.st_size > MAX_BYTES
                or private and stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError('private_observation_file_required')
        yield descriptor, handles[-1], binding
    finally:
        if descriptor is not None:
            os.close(descriptor)
        for handle in reversed(handles):
            os.close(handle)


def initialize_private(root):
    """Explicit owner-only at-rest setup; v2 data remains unqualified forever."""
    with owned_journal(root, private=False) as (descriptor, parent, _):
        if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o600:
            raise ValueError('legacy_file_initialization_refused')
        os.fchmod(parent, 0o700)


def local_identity(root):
    """Canonical-root-only native descriptor binding, not a supplied project ID."""
    with owned_journal(root) as (_, _, binding):
        return binding


def _delivery_proofs(root, rows):
    """Read bounded native canonical acknowledgements, never an imported label."""
    from .trace_contracts import utc
    native = [row for row in rows if row.get('schema_version') == 3]
    proofs, gaps = {}, set()
    grouped = {}
    for row in native:
        grouped.setdefault(row['route_id'], []).append(row)
    with owned_journal(root) as (_, parent, binding):
        try:
            directory = _directory(parent, 'routes', os.getuid())
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
                descriptor = None
                try:
                    descriptor = os.open(route_id+'.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                    info = os.fstat(descriptor)
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 1_048_576):
                        raise ValueError('canonical_record_unavailable')
                    consumed += info.st_size
                    if consumed > MAX_BYTES:
                        gaps.add('native_inventory_limit'); break
                    route = json.loads(os.read(descriptor, 1_048_577))
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
                        if (frozen.get(row['event_id']) != row or not isinstance(proof, dict)
                                or set(proof) != {'row_digest', 'delivered_by'}
                                or proof['row_digest'] != digest(row)
                                or route['authority_epoch'] < row['authority_epoch']
                                or route['state_revision'] < row['state_revision']
                                or route['context']['revision'] < row['context_revision']
                                or utc(proof['delivered_by']) < utc(row['captured_at'])
                                or utc(proof['delivered_by']) > datetime.now(timezone.utc)):
                            gaps.add('native_delivery_proof_missing'); continue
                        proofs[row['event_id']] = dict(proof)
                except (OSError, ValueError, TypeError, KeyError, RecursionError):
                    gaps.add('native_delivery_proof_missing')
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
        finally:
            if directory is not None:
                os.close(directory)
    return proofs, sorted(gaps)


def load_local(root):
    """Private rows or safe legacy aggregates; unknown ownership discloses none."""
    denied = {'access': 'metadata_only', 'events': [], 'input_digest': None,
              'scope': 'canonical_root_only', 'gaps': ['private_local_storage_unqualified']}
    private = True
    try:
        with owned_journal(root) as (descriptor, _, binding):
            raw = os.read(descriptor, MAX_BYTES + 1)
    except (OSError, ValueError):
        private = False
        try:
            with owned_journal(root, private=False) as (descriptor, _, binding):
                raw = os.read(descriptor, MAX_BYTES + 1)
        except (OSError, ValueError):
            return denied
    try:
        if len(raw) > MAX_BYTES:
            return denied
        rows, gaps, seen = [], [], {}
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
                elif row.get('event') in EVENTS:
                    # Never return legacy IDs, labels, paths, payload or source claims.
                    rows.append({key: row[key] for key in ('at', 'event') if key in row})
            except (ValueError, UnicodeError, TypeError, RecursionError):
                gaps.append('malformed_row')
        if not private:
            gaps.append('private_local_storage_unqualified')
        proofs = {}
        if private:
            proofs, proof_gaps = _delivery_proofs(root, rows)
            gaps += proof_gaps
        return {'access': 'local_owner' if private else 'metadata_only', 'events': rows,
                'input_digest': hashlib.sha256(raw).hexdigest(),
                'scope': 'canonical_root_only', 'delivery_proofs': proofs, 'gaps': sorted(set(gaps))}
    except (OSError, ValueError, ImportError):
        return denied
