"""Closed v3 observation syntax. Validation grants no execution or access authority."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

MAX_RECORDS, MAX_ROW, MAX_NUMBER = 4096, 8192, 10**18
STAGES = frozenset({'lexical', 'structural', 'semantic', 'fusion', 'rerank',
    'access_check', 'context_assembly', 'cache_lookup', 'inference', 'calculation'})
OUTCOMES = frozenset({'succeeded', 'empty', 'cache_hit', 'cache_miss', 'failed',
    'timeout', 'cancelled', 'not_run', 'unsupported', 'unknown'})
COMMON = frozenset({'schema_version', 'event_id', 'at', 'captured_at', 'event', 'kind',
    'logical_task_id', 'route_id', 'session_id', 'authority_epoch', 'state_revision',
    'context_revision', 'repository_digest', 'workspace_digest', 'scope_digest',
    'spec_digest', 'evidence_digest', 'head', 'tree', 'base', 'producer_version'})
KINDS = {
    'task': frozenset({'selected', 'task_started', 'task_completed', 'task_cancelled',
        'scope_changed', 'removed', 'blocker_changed'}),
    'operation': frozenset({'budget_claimed', 'operation_started', 'operation_finished'}),
    'span': frozenset({'stage_started', 'stage_finished'}),
    'policy': frozenset({'policy_observed'}),
    'evidence': frozenset({'evidence_linked'}),
}
STAGE_OPTIONAL = frozenset({'source_revision', 'index_revision', 'config_digest',
    'provider_digest', 'model_digest', 'candidate_count', 'context_bytes',
    'usage_input_tokens', 'usage_output_tokens', 'ttft_ns', 'timing_source'})
EXTRA = {
    'operation': frozenset({'operation_id', 'outcome', 'elapsed_ns', 'attempt_id'}),
    'span': frozenset({'operation_id', 'span_id', 'parent_span_id', 'attempt_id',
        'stage', 'outcome', 'elapsed_ns'}),
    'policy': frozenset({'operation_id', 'decision', 'policy_digest', 'reason_code'}),
    'evidence': frozenset({'operation_id', 'evidence_kind', 'reference_digest'}),
}
_HEX = re.compile(r'[0-9a-f]{64}\Z')
_ID = re.compile(r'[A-Za-z0-9_-]{1,64}\Z')
_UTC = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z')
_DELIVERY_UTC = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z')


def utc(value):
    """Parse the protocol's exact UTC seconds format, with fixed diagnostics."""
    if not isinstance(value, str) or not _UTC.fullmatch(value):
        raise ValueError('invalid_timestamp')
    try:
        return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError:
        raise ValueError('invalid_timestamp') from None


def delivery_utc(value):
    """Strict local native proof precision; event timestamps remain seconds."""
    if not isinstance(value, str) or not _DELIVERY_UTC.fullmatch(value):
        raise ValueError('invalid_delivery_timestamp')
    try:
        return datetime.strptime(value, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=timezone.utc)
    except ValueError:
        raise ValueError('invalid_delivery_timestamp') from None


def validate_delivery(proof, row):
    """Syntax/byte binding only. The caller must prove native storage/owner cut."""
    from .metrics_journal import digest
    try:
        if (type(proof) is not dict or set(proof) != {'proof_version', 'clock_domain', 'row_digest', 'delivered_by'}
                or type(proof['proof_version']) is not int or proof['proof_version'] != 2
                or proof['clock_domain'] != 'native_local_utc' or proof['row_digest'] != digest(row)
                or delivery_utc(proof['delivered_by']) < utc(row['captured_at'])):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        raise ValueError('invalid_delivery_proof') from None


def native_id(value):
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _hex(value):
    return isinstance(value, str) and _HEX.fullmatch(value) is not None


def _number(value):
    return type(value) is int and 0 <= value <= MAX_NUMBER


def _validate(row):
    if type(row) is not dict or not COMMON <= row.keys():
        raise ValueError
    if type(row['schema_version']) is not int or row['schema_version'] != 3:
        raise ValueError
    if type(row['producer_version']) is not int or row['producer_version'] != 1:
        raise ValueError
    event, kind = row['event'], row['kind']
    if not isinstance(event, str) or event not in KINDS or not isinstance(kind, str) or kind not in KINDS[event]:
        raise ValueError
    required = EXTRA.get(event, frozenset())
    if event == 'task' and kind == 'selected':
        required = frozenset({'window_start'})
    allowed = COMMON | required | (STAGE_OPTIONAL if event == 'span' else frozenset())
    # Check the closed keys before serializing or evaluating caller payload values.
    if not required <= row.keys() or row.keys() - allowed:
        raise ValueError
    if utc(row['captured_at']) < utc(row['at']):
        raise ValueError
    if not _hex(row['event_id']):
        raise ValueError
    for name, pattern in (
            ('logical_task_id', r'task:[0-9a-f]{32}'), ('route_id', r'[0-9a-f]{12}'),
            ('session_id', r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')):
        if not isinstance(row[name], str) or not re.fullmatch(pattern, row[name]):
            raise ValueError
    for name in ('authority_epoch', 'state_revision', 'context_revision'):
        if not _number(row[name]):
            raise ValueError
    for name in ('repository_digest', 'workspace_digest', 'scope_digest'):
        if not _hex(row[name]):
            raise ValueError
    for name in ('spec_digest', 'evidence_digest'):
        if row[name] is not None and not _hex(row[name]):
            raise ValueError
    for name in ('head', 'tree', 'base'):
        if not isinstance(row[name], str) or not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', row[name]):
            raise ValueError
    if 'window_start' in row:
        utc(row['window_start'])
    if 'operation_id' in row and not native_id(row['operation_id']):
        raise ValueError
    if event in {'operation', 'span'}:
        if row['attempt_id'] is not None and not native_id(row['attempt_id']):
            raise ValueError
        if row['elapsed_ns'] is not None and not _number(row['elapsed_ns']):
            raise ValueError
        if kind.endswith('_started') or kind == 'budget_claimed':
            if row['outcome'] is not None or row['elapsed_ns'] is not None:
                raise ValueError
        elif not isinstance(row['outcome'], str) or row['outcome'] not in OUTCOMES:
            raise ValueError
    if event == 'span':
        if (not native_id(row['span_id']) or not isinstance(row['stage'], str)
                or row['stage'] not in STAGES or row['parent_span_id'] == row['span_id']):
            raise ValueError
        if row['parent_span_id'] is not None and not native_id(row['parent_span_id']):
            raise ValueError
        for name in STAGE_OPTIONAL & row.keys():
            value = row[name]
            if value is None:
                continue
            if name in {'source_revision', 'index_revision', 'config_digest', 'provider_digest', 'model_digest'}:
                valid = _hex(value)
            elif name == 'timing_source':
                valid = isinstance(value, str) and value in {'monotonic', 'provider_reported', 'unavailable'}
            else:
                valid = _number(value)
            if not valid:
                raise ValueError
    if event == 'policy':
        if (row['decision'] not in ('allow', 'deny', 'unknown') or not _hex(row['policy_digest'])
                or row['reason_code'] not in ('policy_allowed', 'policy_denied', 'policy_unavailable')):
            raise ValueError
    if event == 'evidence':
        if (row['evidence_kind'] not in ('approval', 'commit', 'test', 'ci', 'receipt', 'model', 'source', 'calculation')
                or not _hex(row['reference_digest'])):
            raise ValueError
    if len(json.dumps(row, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()) > MAX_ROW:
        raise ValueError


def validate_v3(row) -> None:
    """Reject unknown/malformed data without echoing any caller value."""
    try:
        _validate(row)
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise ValueError('invalid_observation') from None
