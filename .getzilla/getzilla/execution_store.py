"""Bounded local attempt ledger; it grants no execution or external-write authority."""
from __future__ import annotations

import copy
from datetime import datetime
import json
from pathlib import Path
import re
from typing import Any, Callable

from . import fsx, state
from .package_status import InspectionError, read_package_file
from .spec import SpecError, _bounded_walk, _pairs_object, _reject_constant, validate_schema
from .execution_output import normalize_output

REGISTRY_PATH = '.getzilla/runtime/executions/registry.json'
MAX_REGISTRY_BYTES = 4 * 1024 * 1024
MAX_RECORDS = 256
TERMINAL = frozenset({'succeeded', 'failed', 'cancelled', 'timed_out', 'orphaned'})
STATUSES = (*sorted(TERMINAL), 'running', 'cancel_requested')
IMMUTABLE = ('schema_version', 'execution_id', 'execution_generation', 'owner', 'input', 'source',
             'deadline', 'backend', 'operation_id', 'mcp_request_id', 'remote_task_id')


class RegistryError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _object(properties):
    return {'type': 'object', 'required': list(properties), 'additionalProperties': False, 'properties': properties}


def _string(maximum=128, *, nullable=False, pattern=None):
    result = {'type': ['string', 'null'] if nullable else 'string', 'minLength': 1, 'maxLength': maximum}
    if pattern:
        result['pattern'] = pattern
    return result


_DIGEST = _string(64, pattern=r'^[0-9a-f]{64}$')
_ID = _string(128, pattern=r'^[A-Za-z0-9:._-]+$')
_OPTIONAL_ID = {**_ID, 'type': ['string', 'null']}
_TIME = _string(64)
_OWNER = _object({
    'workspace': _string(4096), 'project': _DIGEST, 'session_id': _ID, 'route_id': _ID,
    'logical_task_id': _ID, 'change_id': _OPTIONAL_ID, 'authority_epoch': {'type': 'integer', 'minimum': 0},
    'principal_kind': {'enum': ['session', 'agent']}, 'principal_id': _ID,
    'agent_id': _OPTIONAL_ID, 'agent_generation': _OPTIONAL_ID, 'run_id': _OPTIONAL_ID,
})
_SOURCE = _object({
    'git_head': _string(64, nullable=True, pattern=r'^(?:[0-9a-f]{40}|[0-9a-f]{64})$'),
    'fingerprint': _DIGEST, 'inventory_digest': _DIGEST, 'dirty': {'type': 'boolean'},
    'tree_fingerprint': {**_DIGEST, 'type': ['string', 'null']},
    'context_digest': {**_DIGEST, 'type': ['string', 'null']},
    'evidence_links': {'type': 'array', 'maxItems': 16, 'items': _string(256)},
})
_CANCEL = _object({'request_id': _string(32, pattern=r'^[0-9a-f]{32}$'), 'token_digest': _DIGEST,
                    'state': {'enum': ['reserved', 'consumed', 'accepted', 'rejected', 'unknown']},
                    'requested_at': _TIME, 'deadline_at': _TIME})
RECORD_SCHEMA = _object({
    'schema_version': {'type': 'integer', 'const': 1}, 'execution_id': _string(32, pattern=r'^[0-9a-f]{32}$'),
    'revision': {'type': 'integer', 'minimum': 1}, 'execution_generation': _string(32, pattern=r'^[0-9a-f]{32}$'),
    'owner': _OWNER, 'input': _object({'intent_digest': _DIGEST, 'request_digest': _DIGEST,
                                     'display': _object({'label': _string(80, pattern=r'^[A-Za-z0-9 ._-]+$')})}),
    'source': _SOURCE,
    'deadline': _object({'submitted_at': _TIME, 'hard_deadline_at': _TIME,
                          'duration_seconds': {'type': 'integer', 'minimum': 1, 'maximum': 86400}}),
    'backend': _object({'kind': _ID, 'token_digest': _DIGEST, 'claim': {'const': 'committed'},
                         'external_mutations': {'type': 'boolean', 'const': False}}),
    'operation_id': _OPTIONAL_ID, 'mcp_request_id': _OPTIONAL_ID, 'remote_task_id': _OPTIONAL_ID,
    'execution_status': {'enum': list(STATUSES)},
    'cleanup_status': {'enum': ['not_required', 'pending', 'confirmed', 'failed', 'unconfirmed']},
    'operation_outcome': {'enum': ['confirmed_applied', 'confirmed_not_applied', 'unknown', 'not_applicable']},
    'terminal_reason': _string(80, nullable=True, pattern=r'^[A-Za-z0-9._-]+$'),
    'source_final': {**_SOURCE, 'type': ['object', 'null']}, 'source_changed': {'type': 'boolean'},
    'output': {'type': ['object', 'null'], 'maxProperties': 32},
    'retention_until': {**_TIME, 'type': ['string', 'null']}, 'expired': {'type': 'boolean'},
    'event_receipts': {'type': 'object', 'maxProperties': 64},
    'dispatch_claim': {'enum': ['pending', 'consumed']},
    'cancel_claim': {**_CANCEL, 'type': ['object', 'null']},
})
REGISTRY_SCHEMA = _object({'schema_version': {'type': 'integer', 'const': 1},
                           'revision': {'type': 'integer', 'minimum': 0},
                           'records': {'type': 'object', 'maxProperties': MAX_RECORDS},
                           'intents': {'type': 'object', 'maxProperties': MAX_RECORDS}})


def empty_registry() -> dict:
    return {'schema_version': 1, 'revision': 0, 'records': {}, 'intents': {}}


def _timestamp(value):
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError('timezone required')
    return parsed


def _validate(value: Any) -> None:
    try:
        if not isinstance(value, dict) or len(value.get('records', {})) > MAX_RECORDS:
            raise RegistryError('registry_full')
        validate_schema(value, REGISTRY_SCHEMA)
        expected = {}
        for key, record in value['records'].items():
            safe = {**record, 'output': normalize_output(record.get('output'))}
            _bounded_walk(safe)
            validate_schema(safe, RECORD_SCHEMA)
            if key != record['execution_id'] or type(record['revision']) is not int:
                raise ValueError('record identity')
            intent = record['input']['intent_digest']
            if intent in expected:
                raise ValueError('duplicate intent')
            expected[intent] = key
            start = _timestamp(record['deadline']['submitted_at'])
            end = _timestamp(record['deadline']['hard_deadline_at'])
            if (end - start).total_seconds() != record['deadline']['duration_seconds']:
                raise ValueError('inconsistent deadline')
            if record['retention_until'] is not None:
                _timestamp(record['retention_until'])
            if record['cancel_claim'] is not None:
                claim = record['cancel_claim']
                if (_timestamp(claim['deadline_at']) - _timestamp(claim['requested_at'])).total_seconds() != 30:
                    raise ValueError('invalid cancellation admission deadline')
            if record['expired'] and record['execution_status'] not in TERMINAL:
                raise ValueError('nonterminal tombstone')
            for event, digest in record['event_receipts'].items():
                if not re.fullmatch(r'[A-Za-z0-9._:-]{1,128}', event) or not re.fullmatch(r'[0-9a-f]{64}', digest):
                    raise ValueError('invalid event receipt')
        if expected != value['intents'] or type(value['revision']) is not int:
            raise ValueError('index mismatch')
    except RegistryError:
        raise
    except (SpecError, ValueError, TypeError, KeyError, OverflowError, RecursionError) as error:
        raise RegistryError('registry_unavailable') from error


def _prepare(root: Path) -> None:
    """Pin each ancestor and flush newly created directory entries before admission."""
    handles = [fsx.open_dir(root)]
    try:
        for part in ('.getzilla', 'runtime', 'executions'):
            try:
                fsx.mkdir_at(handles[-1], part, 0o700)
            except FileExistsError:
                pass
            child = fsx.open_dir_at(handles[-1], part)
            handles.append(child)
            # Flush existing entries too: an earlier interrupted initialization is not proof.
            fsx.fsync_dir(child)
            fsx.fsync_dir(handles[-2])
    finally:
        for handle in reversed(handles):
            fsx.close_dir(handle)


def load_registry(root: Path) -> dict:
    """Read-only; missing state never creates a runtime, lock, or record."""
    try:
        raw = read_package_file(root, REGISTRY_PATH, limit=MAX_REGISTRY_BYTES, single_link=True)
        # The stable reader brackets inode identity. A multiply linked ledger is not authority.
        if (root / REGISTRY_PATH).lstat().st_nlink != 1:
            raise RegistryError('registry_unavailable')
        value = json.loads(raw, object_pairs_hook=_pairs_object, parse_constant=_reject_constant)
        _validate(value)
        return value
    except InspectionError as error:
        raise RegistryError('registry_not_found' if error.code == 'file_missing' else 'registry_unavailable') from error
    except (OSError, ValueError, UnicodeError, RecursionError) as error:
        if isinstance(error, RegistryError):
            raise
        raise RegistryError('registry_unavailable') from error


def _namespace(root):
    handles = [fsx.open_dir(root)]
    identities = []
    try:
        for part in ('.getzilla', 'runtime', 'executions'):
            handle = fsx.open_dir_at(handles[-1], part)
            handles.append(handle)
            info = fsx.fstat_dir(handle)
            identities.append((info.st_dev, info.st_ino))
        # Interrupted writes remain protected. Refuse saturation rather than deleting unknown state.
        with fsx.scandir(handles[-1]) as listing:
            count = 0
            for entry in listing:
                if entry.name == 'registry.json':
                    continue
                if not re.fullmatch(r'\.task-[0-9a-f]{32}\.tmp', entry.name):
                    raise RegistryError('registry_unavailable')
                count += 1
                if count > 16:
                    raise RegistryError('registry_full')
        return identities
    finally:
        for handle in reversed(handles):
            fsx.close_dir(handle)


def _publish(root, previous, value):
    value = copy.deepcopy(value)
    for record in value['records'].values():
        if record['output'] is not None:
            record['output'] = normalize_output(record['output'])
    _validate(value)
    if previous:
        if not previous['records'].keys() <= value['records'].keys():
            raise RegistryError('registry_conflict')
        for key, before in previous['records'].items():
            after = value['records'][key]
            if any(before[field] != after[field] for field in IMMUTABLE):
                raise RegistryError('registry_conflict')
            if after != before and after['revision'] != before['revision'] + 1:
                raise RegistryError('registry_conflict')
            if before['dispatch_claim'] == 'consumed' and after['dispatch_claim'] != 'consumed':
                raise RegistryError('registry_conflict')
            old_cancel, new_cancel = before['cancel_claim'], after['cancel_claim']
            if old_cancel is not None:
                transitions = {'reserved': {'reserved', 'consumed', 'rejected', 'unknown'},
                               'consumed': {'consumed', 'accepted', 'rejected', 'unknown'},
                               'accepted': {'accepted'}, 'rejected': {'rejected'}, 'unknown': {'unknown'}}
                if (new_cancel is None or any(old_cancel[k] != new_cancel[k] for k in old_cancel if k != 'state')
                        or new_cancel['state'] not in transitions[old_cancel['state']]):
                    raise RegistryError('registry_conflict')
            if before['execution_status'] in TERMINAL and after != before:
                allowed = {'revision', 'expired', 'output'}
                normalized = after['output'] == normalize_output(before['output'])
                if ((not after['expired'] and not normalized) or before['expired'] and not after['expired']
                        or any(before[k] != after[k] for k in before if k not in allowed)):
                    raise RegistryError('registry_conflict')
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
    if len(raw) > MAX_REGISTRY_BYTES:
        raise RegistryError('registry_full')
    try:
        namespace = _namespace(root)
        state.durable_bytes(root, root / REGISTRY_PATH, raw)
        if _namespace(root) != namespace or load_registry(root) != value:
            raise RegistryError('registry_persistence_unknown')
    except (OSError, ValueError) as error:
        if isinstance(error, RegistryError):
            raise
        raise RegistryError('registry_persistence_unknown') from error
    return copy.deepcopy(value)


def commit_registry(root: Path, expected_revision: int | None, value: dict) -> dict:
    """CAS one whole envelope; a failed publication never acknowledges intent durability."""
    if expected_revision is not None and (type(expected_revision) is not int or expected_revision < 0):
        raise RegistryError('registry_conflict')
    _validate(value)
    try:
        _prepare(root)
        with state.runtime_lock(root, 'executions'):
            try:
                before = load_registry(root)
            except RegistryError as error:
                if error.code != 'registry_not_found':
                    raise
                before = None
            if (before is None) != (expected_revision is None) or (before and before['revision'] != expected_revision):
                raise RegistryError('registry_conflict')
            candidate = copy.deepcopy(value)
            candidate['revision'] = (before['revision'] if before else 0) + 1
            return _publish(root, before, candidate)
    except (OSError, TimeoutError) as error:
        raise RegistryError('registry_persistence_unknown') from error


def mutate_registry(root: Path, transform: Callable[[dict], Any], *, create=False, timeout=5.0):
    """Transform under the one registry lock; callbacks and wait sleeps belong outside."""
    try:
        _prepare(root)
        with state.runtime_lock(root, 'executions', timeout=timeout):
            try:
                before = load_registry(root)
            except RegistryError as error:
                if not create or error.code != 'registry_not_found':
                    raise
                before = empty_registry()
            candidate = copy.deepcopy(before)
            result = transform(candidate)
            if candidate != before:
                candidate['revision'] = before['revision'] + 1
                candidate = _publish(root, before, candidate)
            return copy.deepcopy(candidate), result
    except (OSError, TimeoutError) as error:
        raise RegistryError('registry_persistence_unknown') from error
