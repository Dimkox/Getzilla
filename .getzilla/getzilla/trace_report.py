"""Pure, non-authoritative projection of already access-scoped observations.

Callers must enforce current project/principal and field-purpose permissions before
loading data and again before disclosure. This reducer grants no such permission.
No filesystem, provider, receipt activation, or network access occurs here.
"""
from __future__ import annotations

import hashlib
import json

from .trace_contracts import MAX_RECORDS, STAGES, STAGE_OPTIONAL, native_id, utc, validate_v3

_BINDING = ('logical_task_id', 'route_id', 'session_id', 'authority_epoch', 'context_revision',
    'repository_digest', 'workspace_digest', 'scope_digest', 'spec_digest', 'head', 'tree', 'base')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _binding(row):
    return {name: row[name] for name in _BINDING}


def reconstruct(events, operation_id, cutoff) -> dict:
    """Reconstruct as-known observations, never full trace or acceptance authority.

Event time and native capture time must be strictly before cutoff. The caller
must additionally check native delivery upper-bound proofs before disclosure. Input
must already be a bounded access-scoped iterable. Version 2/legacy rows contribute
only an aggregate unqualified count, never identities or a reconstructed edge.
"""
    if not native_id(operation_id):
        raise ValueError('invalid_operation_id')
    try:
        until = utc(cutoff)
    except ValueError:
        raise ValueError('invalid_cutoff') from None
    gaps, legacy, eligible = set(), 0, []
    for index, row in enumerate(events):
        if index >= MAX_RECORDS:
            gaps.add('record_limit')
            break
        if isinstance(row, dict) and row.get('schema_version') in (None, 2):
            try:
                if utc(row.get('at')) < until:
                    legacy += 1
            except ValueError:
                gaps.add('invalid_observation')
            continue
        try:
            validate_v3(row)
        except ValueError:
            gaps.add('invalid_observation')
            continue
        if utc(row['at']) >= until or utc(row['captured_at']) >= until:
            continue
        # Check replay identity before selecting an operation: a conflicting
        # replay cannot evade detection by changing its operation_id.
        eligible.append(dict(row))
    indexed, conflicts = {}, set()
    for row in eligible:
        key = row['event_id']
        if key in indexed and indexed[key] != row:
            conflicts.add(key)
            if row.get('operation_id') == operation_id or indexed[key].get('operation_id') == operation_id:
                gaps.add('conflicting_replay')
        indexed[key] = row
    rows = sorted((r for key, r in indexed.items() if key not in conflicts and r.get('operation_id') == operation_id),
        key=lambda r: (r['at'], r['state_revision'], r['event_id']))
    starts = [r for r in rows if r['event'] == 'operation' and r['kind'] == 'operation_started']
    claims = [r for r in rows if r['event'] == 'operation' and r['kind'] == 'budget_claimed']
    anchor = starts[0] if starts else None
    bound = _binding(anchor) if anchor else None
    if not anchor:
        gaps.add('operation_start_missing')
    if len(starts) > 1:
        gaps.add('multiple_operation_starts')
    accepted = []
    for row in rows:
        if anchor and _binding(row) != bound:
            gaps.add('binding_mismatch')
            continue
        if anchor and (row['state_revision'] < anchor['state_revision'] or row['at'] < anchor['at']):
            gaps.add('stale_revision')
            continue
        accepted.append(row)
    ends = [r for r in accepted if r['event'] == 'operation' and r['kind'] == 'operation_finished']
    if not ends:
        gaps.add('operation_finish_missing')
    if len(ends) > 1:
        gaps.add('multiple_operation_finishes')
    terminal = ends[0] if anchor and len(starts) == 1 and len(ends) == 1 else None
    grouped = {}
    for row in accepted:
        if row['event'] == 'span':
            grouped.setdefault((row['attempt_id'], row['span_id']), []).append(row)
    if len(grouped) > 128:
        gaps.add('span_limit')
    attempts = {r['attempt_id'] for r in accepted if r.get('attempt_id') is not None}
    if len(attempts) > 16:
        gaps.add('attempt_limit')
    spans = []
    for key in sorted(grouped, key=lambda pair: (pair[0] or '', pair[1]))[:128]:
        group = grouped[key]
        first = next((r for r in group if r['kind'] == 'stage_started'), None)
        last = next((r for r in group if r['kind'] == 'stage_finished'), None)
        if not first:
            gaps.add('span_start_missing')
        if not last:
            gaps.add('span_finish_missing')
        if len({r['stage'] for r in group}) != 1 or len({r['parent_span_id'] for r in group}) != 1:
            gaps.add('span_identity_conflict')
            last = None
        if sum(r['kind'] == 'stage_started' for r in group) > 1 or sum(r['kind'] == 'stage_finished' for r in group) > 1:
            gaps.add('span_phase_conflict')
            last = None
        if first and last and (last['at'] < first['at'] or last['state_revision'] < first['state_revision']):
            gaps.add('span_order_conflict')
            last = None
        source = first or group[0]
        spans.append({'span_id': key[1], 'attempt_id': key[0], 'parent_span_id': source['parent_span_id'],
            'stage': source['stage'], 'outcome': last['outcome'] if first and last else 'unknown',
            'elapsed_ns': last['elapsed_ns'] if first and last else None,
            **{name: last.get(name) if first and last else None for name in sorted(STAGE_OPTIONAL)}})
    by_id = {(span['attempt_id'], span['span_id']): span for span in spans}
    for span in spans:
        visited, current = set(), span
        while current['parent_span_id'] is not None:
            identity = (current['attempt_id'], current['span_id'])
            if identity in visited or len(visited) >= 8:
                gaps.add('span_parent_cycle_or_depth')
                break
            visited.add(identity)
            current = by_id.get((current['attempt_id'], current['parent_span_id']))
            if current is None:
                gaps.add('span_parent_missing')
                break
    # No producer watermark is part of this pure contract. Parsing cannot prove
    # that a stage/action was never omitted; retain the explicit completeness gap.
    gaps.add('producer_coverage_unqualified')
    if legacy:
        gaps.add('legacy_unqualified')
    if not anchor:
        # An orphan span cannot establish which task/source owned the operation.
        # Keep the structural gaps but disclose no reconstructed span edges.
        spans = []
    stage_status = {}
    for name in sorted(STAGES):
        observed = [span['outcome'] for span in spans if span['stage'] == name]
        stage_status[name] = observed[0] if len(set(observed)) == 1 else ('partial' if observed else 'unsupported')
    evidence = [{'kind': r['evidence_kind'], 'reference_digest': r['reference_digest'],
        'qualification': 'observed_unverified'} for r in accepted if r['event'] == 'evidence' and anchor]
    policies = [{'decision': r['decision'], 'policy_digest': r['policy_digest'],
        'reason_code': r['reason_code']} for r in accepted if r['event'] == 'policy' and anchor]
    result = {'authority': 'observations_only', 'operation_id': operation_id, 'cutoff': cutoff,
        'claim_observed': len(claims) == 1, 'claim_binding': _binding(claims[0]) if len(claims) == 1 else None,
        'execution_state_revision': anchor['state_revision'] if anchor else None,
        'terminal_workspace_state': None,
        'binding': bound, 'observations': len(rows), 'legacy_observations': legacy,
        'outcome': terminal['outcome'] if terminal else 'unknown',
        'elapsed_ns': terminal['elapsed_ns'] if terminal else None,
        'spans': spans, 'stages': stage_status, 'evidence': evidence, 'policies': policies,
        'resource_usage': None, 'export_delivery': None,
        'coverage': {'complete': False, 'status': 'partial', 'gaps': sorted(gaps)}}
    result['input_digest'] = hashlib.sha256(_canonical({'events': rows, 'legacy_count': legacy}).encode()).hexdigest()
    return result
