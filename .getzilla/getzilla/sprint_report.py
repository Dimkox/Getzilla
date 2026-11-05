"""Deterministic, non-authoritative sprint projection with censored coverage."""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from .trace_contracts import validate_v3, validate_delivery, delivery_utc

TARGET = 'qualified_original_scope_task_completion_count_v1'


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError('utc_timestamp_required')
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise ValueError('utc_timestamp_required') from exc
    if result.tzinfo is None or result.utcoffset() != timedelta(0):
        raise ValueError('utc_timestamp_required')
    return result.astimezone(timezone.utc)


def summarize_sprint(events, *, start, as_of, source_manifest=None):
    begin, cutoff = timestamp(start), timestamp(as_of)
    if cutoff < begin:
        raise ValueError('cutoff_before_start')
    end = begin + timedelta(days=14)
    cutoff = min(cutoff, end)
    material = list(events)
    if len(material) > 4096:
        raise ValueError('observation_limit')
    gaps = {'selection_inventory_unqualified', 'native_coverage_unproved'}
    manifest = source_manifest or {'scope': 'canonical_root_only', 'gaps': []}
    gaps.update(manifest.get('gaps', []))
    seen, accepted, disputed = {}, [], set()
    legacy = 0
    legacy_kinds = Counter()
    for row in material:
        try:
            at = timestamp(row['at'])
            if not begin <= at < cutoff:
                continue
            if row.get('schema_version') != 3:
                legacy += 1
                legacy_kinds[row.get('event', 'unknown')] += 1
                continue
            validate_v3(row)
            if 'delivery_proofs' in manifest:
                proof = manifest['delivery_proofs'].get(row['event_id'])
                try:
                    validate_delivery(proof, row)
                except ValueError:
                    gaps.add('native_delivery_proof_missing')
                    continue
                if delivery_utc(proof['delivered_by']) > cutoff:
                    gaps.add('native_delivery_proof_missing')
                    continue
            observed = timestamp(row['captured_at'])
            if observed >= cutoff:
                gaps.add('late_observations')
                continue
            identity = row['event_id']
            if identity in seen:
                if seen[identity] != row:
                    gaps.add('conflicting_replay')
                    disputed.add(row.get('logical_task_id'))
                    disputed.add(seen[identity].get('logical_task_id'))
                continue
            seen[identity] = row
            accepted.append(row)
        except (KeyError, ValueError, TypeError):
            gaps.add('malformed_observation')
    tasks = {}
    for row in sorted(accepted, key=lambda item: (item['at'], item.get('state_revision', 0), item['event_id'])):
        task_id = row.get('logical_task_id')
        if row.get('event') != 'task' or task_id in disputed:
            continue
        kind = row.get('kind')
        if kind == 'selected' and row.get('window_start') == start:
            tasks.setdefault(task_id, {'logical_task_id': task_id, 'selected_scope': row['scope_digest'],
                                      'state': 'selected', 'qualified_completed': False,
                                      'at_risk': [], 'elapsed_seconds': None, 'cost': None,
                                      'acceptance_evidence': None, 'selected_at': row['at']})
        task = tasks.get(task_id)
        if task is None:
            continue
        if row.get('scope_digest') != task['selected_scope']:
            task['at_risk'] = ['scope_changed']
        if kind == 'removed':
            task['state'] = 'removed'
        elif kind == 'task_cancelled':
            task['state'] = 'cancelled'
        elif kind == 'task_started':
            task['state'] = 'started'
        elif kind == 'task_completed' and row.get('evidence_digest'):
            task['state'] = 'qualified_local'
            task['qualified_completed'] = row['scope_digest'] == task['selected_scope']
            task['acceptance_evidence'] = row['evidence_digest']
            task['elapsed_seconds'] = int((timestamp(row['at'])-timestamp(task['selected_at'])).total_seconds())
    ordered = [tasks[key] for key in sorted(tasks)]
    restricted_unavailable = manifest.get('access') == 'metadata_only' or bool(gaps & {
        'native_delivery_proof_missing', 'native_journal_gap', 'native_capture_gap',
        'conflicting_replay',
        'native_inventory_limit', 'native_inventory_unqualified'})
    legacy_unavailable = manifest.get('input_digest', 'available') is None
    encoded = json.dumps(material, sort_keys=True, allow_nan=False, separators=(',', ':')).encode()
    return {'schema_version': 1, 'algorithm': 'sprint-count-v1', 'start': start,
            'end_exclusive': end.strftime('%Y-%m-%dT%H:%M:%SZ'), 'as_of': cutoff.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'source_scope': 'canonical_root_only', 'input_digest': hashlib.sha256(encoded).hexdigest(),
            'legacy_observations': None if legacy_unavailable else legacy,
            'legacy_event_counts': None if legacy_unavailable else dict(sorted(legacy_kinds.items())),
            'evidence_grade': 'partial_local_observations',
            'counts': {'selected': None, 'started': None, 'qualified_completed': None, 'accepted_merged': None,
                       'observed_selected': None if restricted_unavailable else len(ordered),
                       'observed_removed': None if restricted_unavailable else sum(task['state'] == 'removed' for task in ordered),
                       'observed_qualified_completed': None if restricted_unavailable else sum(task['qualified_completed'] for task in ordered)},
            'tasks': ordered, 'human_interventions': None, 'human_minutes': None, 'cost': None,
            'coverage': {'complete': False, 'gaps': sorted(gaps)},
            'forecast': {'target': TARGET, 'status': 'insufficient_history', 'eligible_windows': 0,
                         'calibration_origins': 0, 'additional_completions': None,
                         'evidence_grade': 'unavailable', 'reason': 'native_covered_cohorts_unavailable'}}
