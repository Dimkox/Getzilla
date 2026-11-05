"""Local workflow observations with explicit provenance and missing-data coverage.
Unknown costs stay unknown; failed check outcomes are not confirmed defects.
"""
from __future__ import annotations

import json
import copy
import os
import re
import statistics
from dataclasses import dataclass
from datetime import datetime, timezone
from .metrics_journal import deduplicate, digest, load, record, source_summary, import_observations, regular  # noqa: F401
from pathlib import Path
from typing import Any, Iterable

METRICS = '.getzilla/runtime/metrics.jsonl'
COUNTERS = {'path_hints': '.getzilla/runtime/path-hints.json', 'parallel_guard': '.getzilla/runtime/parallel-guard.json'}
# Only these fields are ever written; anything else (a prompt, a path, output) is dropped.
SAFE_FIELDS = frozenset({'intent', 'risk', 'profiles', 'mode', 'status', 'blocking', 'effective_risk', 'profile',
                         'kind', 'seconds'})
MAX_TEXT = 64


def _now() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _clean(value: Any) -> Any:
    if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
        return value
    if isinstance(value, str) and len(value) <= MAX_TEXT and '/' not in value and '\\' not in value:
        return value
    return None



def record_route(root: Path, route: dict[str, Any]) -> None:
    record(root, 'route', route.get('route_id'), intent=route.get('intent'), event_id='route:' + str(route.get('route_id')), risk=route.get('risk'),
           profiles=','.join(str(item) for item in route.get('quality_profiles', [])) or None)


def profile_of(report: dict[str, Any]) -> str:
    if (report.get('light_diff') or {}).get('admitted') is True:
        return 'light'
    if report.get('profile_reason') == 'TRIVIAL_PROVEN_BY_DIFF':
        return 'trivial'
    risk = (report.get('diff_risk') or {}).get('effective_risk')
    return 'full' if risk in {'high', 'critical'} else 'standard'


def record_verify(root: Path, report: dict[str, Any]) -> None:
    checks = report.get('checks') or []
    blocking = sum(1 for check in checks if isinstance(check, dict) and check.get('status') == 'fail')
    record(root, 'verify', report.get('route_id'), event_id='verify:' + digest(report), mode=report.get('mode'), status=report.get('status'),
           blocking=blocking, effective_risk=(report.get('diff_risk') or {}).get('effective_risk'),
           profile=profile_of(report), admitted=(report.get('light_diff') or {}).get('admitted'),
           code_lines=(report.get('light_diff') or {}).get('code_lines'))


def record_receipt(root: Path, route_id: str | None, kind: str, status: str, identity: str | None = None) -> None:
    record(root, 'receipt', route_id, event_id='receipt:' + identity if identity else None, kind=kind, status=status)



def _when(item: dict[str, Any]) -> datetime:
    return datetime.strptime(item['at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)


def summarize(events: Iterable[dict[str, Any]], root: Path | None = None) -> dict[str, Any]:
    """Per route: time to the first passing verification, runs, reviews and blocking findings caught.

    `coverage` covers the journal only (unreadable or skipped lines). `route_observations` covers
    what each route did not observe (merge, cost, commits); unknown values stay None, never zero.
    """
    events = deduplicate(events, getattr(events, 'gaps', []))
    routes: dict[str, dict[str, Any]] = {}
    for item in sorted(events, key=lambda event: event['at']):
        route_id = item.get('route_id')
        if not route_id:
            continue
        route = routes.setdefault(route_id, {'route_id': route_id, 'created_at': None, 'first_green_at': None,
                                             'verify_runs': 0, 'verify_blocking': 0, 'reviews': 0, 'review_blocking': 0,
                                             'profile': 'standard', 'effective_risk': None, 'intent': None})
        if item['event'] == 'route':
            route['created_at'] = route['created_at'] or item['at']
            route['intent'] = item.get('intent')
        elif item['event'] == 'verify':
            route['verify_runs'] += 1
            route['profile'] = item.get('profile') or route['profile']
            route['effective_risk'] = item.get('effective_risk') or route['effective_risk']
            if item.get('status') == 'pass':
                route['first_green_at'] = route['first_green_at'] or item['at']
            else:
                route['verify_blocking'] += int(item.get('blocking') or 0)
        elif item['event'] == 'receipt' and item.get('kind') != 'verification':
            route['reviews'] += 1
            if item.get('status') != 'pass':
                route['review_blocking'] += 1
    for route in routes.values():
        start, done = route['created_at'], route['first_green_at']
        route['minutes_to_pass'] = (round((_when({'at': done}) - _when({'at': start})).total_seconds() / 60, 1)
                                    if start and done else None)
        route.update(source_summary(events, route['route_id'], root))
        route['failed_check_or_review_outcomes'] = route['verify_blocking'] + route['review_blocking']
    profiles: dict[str, dict[str, Any]] = {}
    for route in routes.values():
        group = profiles.setdefault(route['profile'], {'routes': 0, 'minutes': [], 'verify_runs': 0, 'reviews': 0,
                                                       'failed_check_or_review_outcomes': 0})
        group['routes'] += 1
        group['verify_runs'] += route['verify_runs']
        group['reviews'] += route['reviews']
        group['failed_check_or_review_outcomes'] += route['failed_check_or_review_outcomes']
        if route['minutes_to_pass'] is not None:
            group['minutes'].append(route['minutes_to_pass'])
    for group in profiles.values():
        minutes = group.pop('minutes')
        group['median_minutes_to_pass'] = round(statistics.median(minutes), 1) if minutes else None
        group['verify_runs_per_route'] = round(group['verify_runs'] / group['routes'], 1)
    sessions = []
    for session_id in sorted({item['session_id'] for item in events if item.get('session_id')}):
        selected = [item for item in events if item.get('session_id') == session_id]
        sessions.append({'session_id': session_id, 'route_ids': sorted({item['route_id'] for item in selected if item.get('route_id')}),
                         'observations': len(selected), 'started_at': next((item['at'] for item in selected if item['event'] == 'session_start'), None),
                         'ended_at': next((item['at'] for item in reversed(selected) if item['event'] == 'session_end'), None)})
    with_gaps = [route['route_id'] for route in routes.values() if route.get('gaps')]
    return {'routes': sorted(routes.values(), key=lambda route: route['created_at'] or ''), 'profiles': profiles, 'sessions': sessions,
            'coverage': {'complete': not events.gaps, 'gaps': events.gaps},
            'route_observations': {'complete': not with_gaps, 'routes_with_gaps': len(with_gaps), 'routes': len(routes)},
            'interpretation': 'Grant materializations are not human interventions; check outcomes are not confirmed defects.'}


def counters(root: Path) -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for name, relative in COUNTERS.items():
        try:
            with regular(root, relative) as descriptor:
                raw = os.read(descriptor, 65_537)
            if len(raw) > 65_536:
                continue
            data = json.loads(raw)
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            found[name] = data
    return found


# Economic payloads are a closed v4 family. They are facts, never source/access
# qualification. The journal owner supplies the independently admitted envelope.
ECONOMICS_DEFINITION = 'task-economics-v1'
ECONOMICS_MAX_BYTES = 8192
ECONOMICS_MAX_INTEGER = 10**18
ECONOMICS_CURRENCIES = frozenset({'USD', 'EUR', 'GBP', 'JPY', 'CAD', 'AUD', 'CHF', 'CNY'})
ECONOMICS_UNKNOWN = frozenset({'not_observed', 'unsupported', 'not_applicable', 'redacted', 'ambiguous',
    'conflicted', 'source_unqualified', 'tariff_missing', 'currency_missing', 'capture_gap', 'history_gap'})
_USAGE_FIELDS = 'source_fact_digest source_proof_ref operation service_period '
_STATE_FIELDS = 'task effective_at decision_id source_proof_ref supersedes '
_ECONOMIC_FIELDS = {
    'model_usage': _USAGE_FIELDS + 'provider_id model_id provider_account_digest observation_origin cache_policy '
        'input_semantics output_semantics input_total uncached_input cache_write cache_read output reasoning_output',
    'local_usage': _USAGE_FIELDS + 'measurement_method elapsed cpu gpu energy peak_rss',
    'ci_usage': _USAGE_FIELDS + 'job_digest job_attempt head runner_kind runner_time',
    'human_usage': _USAGE_FIELDS + 'activity actor_scope_digest basis human_time',
    'charge': _USAGE_FIELDS + 'provider_account_digest external_line_digest direction adjusts_charge_event amount',
    'tariff': 'provider_id model_id category unit cache_policy_digest currency decimal_scale rate_numerator '
        'rate_denominator validity source_digest source_published_at source_proof_ref',
    'fx': 'from_currency to_currency numerator denominator validity source_digest source_published_at source_proof_ref',
    'allocation': 'operation shares supersedes method source_proof_ref',
    'workflow_end': _STATE_FIELDS + 'result',
    'completion': _STATE_FIELDS + 'result original_scope_digest criteria_digest evidence_digest',
    'merge': _STATE_FIELDS + 'repository_digest pr_number source_head merge_commit',
    'task_disposition': _STATE_FIELDS + 'decision criteria_digest evidence_digest evidence_version',
    'attempt_relation': 'task from_attempt to_attempt relation source_proof_ref',
    'review_for_push': 'task push_event_digest push_head round_index review_event_digest source_proof_ref',
    'task_pr_link': 'task repository_digest pr_number mapping_evidence_digest validity supersedes source_proof_ref',
    'cache_pair': 'normal_operations long_operations workload_source_digest model_revision_digest '
        'quality_criteria_digest normal_config_digest long_config_digest basis source_proof_ref',
    'human_decision': 'task decision_id activity decision source_proof_ref related_request_digest',
}
_ECONOMIC_FIELDS = {kind: frozenset(fields.split()) | {'candidate_kind'}
                    for kind, fields in _ECONOMIC_FIELDS.items()}
_ECONOMIC_DIGESTS = frozenset(('source_fact_digest source_proof_ref provider_account_digest job_digest '
    'actor_scope_digest external_line_digest cache_policy_digest source_digest decision_id original_scope_digest '
    'criteria_digest evidence_digest repository_digest push_event_digest review_event_digest mapping_evidence_digest '
    'workload_source_digest model_revision_digest quality_criteria_digest normal_config_digest '
    'long_config_digest related_request_digest supersedes adjusts_charge_event').split())
_NULL_DIGESTS = frozenset({'provider_account_digest', 'cache_policy_digest', 'related_request_digest',
                         'supersedes', 'adjusts_charge_event', 'evidence_digest'})
_ECONOMIC_TIME = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{6})?Z')
_ECONOMIC_ID = re.compile(r'[A-Za-z0-9_.:-]{1,64}')
_TARIFF_UNITS = {'uncached_input': 'token', 'cache_write': 'token', 'cache_read': 'token', 'output': 'token',
    'reasoning_output': 'token', 'ci_runner': 'runner_ns', 'cpu': 'cpu_ns', 'gpu': 'gpu_ns',
    'energy': 'microjoule', 'human_review': 'human_ns', 'human_approval': 'human_ns', 'human_unblocking': 'human_ns'}


class EconomicsError(ValueError):
    """Fixed local classification; rejected data is never echoed."""


def _economic_require(condition):
    if not condition:
        raise EconomicsError('invalid_economics_payload')


def _economic_object(value, fields):
    _economic_require(type(value) is dict and set(value) == set(fields))


def _economic_int(value, minimum=0, maximum=ECONOMICS_MAX_INTEGER):
    _economic_require(type(value) is int and minimum <= value <= maximum)


def _economic_digest(value, *, optional=False):
    _economic_require(optional and value is None or type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value))


def _economic_id(value, *, optional=False):
    _economic_require(optional and value is None or type(value) is str and _ECONOMIC_ID.fullmatch(value))


def _economic_utc(value):
    _economic_require(type(value) is str and _ECONOMIC_TIME.fullmatch(value))
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def _economic_range(value):
    _economic_object(value, ('start', 'end_exclusive'))
    _economic_require(_economic_utc(value['start']) < _economic_utc(value['end_exclusive']))


def _economic_task(value):
    _economic_object(value, ('domain', 'project_digest', 'task_id'))
    _economic_digest(value['project_digest'])
    pattern = {'core_native': r'task:[0-9a-f]{32}',
               'factory': r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'}.get(value['domain'])
    _economic_require(pattern is not None and type(value['task_id']) is str
                      and re.fullmatch(pattern, value['task_id']))


def _economic_operation(value):
    _economic_object(value, ('claim_event_digest', 'operation_id', 'attempt_id', 'producer_binding_digest',
                             'physical_operation_digest'))
    for field in ('claim_event_digest', 'producer_binding_digest', 'physical_operation_digest'):
        _economic_digest(value[field])
    _economic_id(value['operation_id'])
    _economic_id(value['attempt_id'], optional=True)


def _economic_quantity(value, unit):
    _economic_object(value, ('value', 'unit', 'unknown_reason'))
    _economic_require(value['unit'] == unit)
    if value['value'] is None:
        _economic_require(value['unknown_reason'] in ECONOMICS_UNKNOWN)
    else:
        _economic_int(value['value'])
        _economic_require(value['unknown_reason'] is None)


def _economic_money(value):
    _economic_object(value, ('value', 'currency', 'decimal_scale', 'unknown_reason'))
    _economic_int(value['decimal_scale'], maximum=9)
    _economic_require(value['currency'] is None or value['currency'] in ECONOMICS_CURRENCIES)
    if value['currency'] is None:
        _economic_require(value['value'] is None and value['unknown_reason'] == 'currency_missing')
    elif value['value'] is None:
        _economic_require(value['unknown_reason'] in ECONOMICS_UNKNOWN)
    else:
        _economic_int(value['value'])
        _economic_require(value['unknown_reason'] is None)


def _economic_builtin(value, depth=0, nodes=None):
    """Bound the transport tree and reject subclasses before calling any methods."""
    nodes = [0] if nodes is None else nodes
    nodes[0] += 1
    _economic_require(depth <= 10 and nodes[0] <= 4096)
    if type(value) is dict:
        for key, item in value.items():
            _economic_require(type(key) is str)
            _economic_builtin(key, depth + 1, nodes)
            _economic_builtin(item, depth + 1, nodes)
    elif type(value) is list:
        for item in value:
            _economic_builtin(item, depth + 1, nodes)
    elif type(value) is str:
        _economic_require(len(value.encode('utf-8', errors='strict')) <= 8192)
    else:
        _economic_require(value is None or type(value) in (bool, int))


def _economic_model(value):
    _economic_require(value['observation_origin'] in ('local_measurement', 'provider_export'))
    _economic_require(value['input_semantics'] in ('exclusive_buckets', 'total_includes_read',
                                                   'total_includes_read_and_write', 'unknown'))
    _economic_require(value['output_semantics'] in ('includes_reasoning', 'excludes_reasoning', 'unknown'))
    for field in ('input_total', 'uncached_input', 'cache_write', 'cache_read', 'output', 'reasoning_output'):
        _economic_quantity(value[field], 'token')
    policy = value['cache_policy']
    _economic_object(policy, ('mode', 'policy_digest', 'ttl_seconds', 'cache_instance_digest'))
    _economic_require(policy['mode'] in ('none', 'normal', 'long', 'unknown'))
    for field in ('policy_digest', 'cache_instance_digest'):
        _economic_digest(policy[field], optional=True)
    if policy['ttl_seconds'] is not None:
        _economic_int(policy['ttl_seconds'])
    if policy['mode'] in ('normal', 'long'):
        _economic_require(policy['policy_digest'] is not None and policy['ttl_seconds'] is not None)
    if policy['mode'] == 'none':
        _economic_require(all(value[key]['value'] in (0, None) for key in ('cache_write', 'cache_read')))
    total, uncached, write, read = (value[key]['value'] for key in
                                  ('input_total', 'uncached_input', 'cache_write', 'cache_read'))
    buckets = (uncached, read) if value['input_semantics'] == 'total_includes_read' else (uncached, write, read)
    if value['input_semantics'] != 'unknown' and total is not None and all(item is not None for item in buckets):
        _economic_require(total == sum(buckets))
    output, reasoning = value['output']['value'], value['reasoning_output']['value']
    if value['output_semantics'] == 'includes_reasoning' and output is not None and reasoning is not None:
        _economic_require(reasoning <= output)


def _economic_payload(value):
    kind = value.get('candidate_kind')
    _economic_require(type(kind) is str and kind in _ECONOMIC_FIELDS)
    _economic_object(value, _ECONOMIC_FIELDS[kind])
    for key in _ECONOMIC_DIGESTS & value.keys():
        _economic_digest(value[key], optional=key in _NULL_DIGESTS)
    for key in ('provider_id', 'model_id'):
        if key in value:
            _economic_id(value[key], optional=True)
    if 'task' in value:
        _economic_task(value['task'])
    if 'operation' in value:
        if value['operation'] is not None:
            _economic_operation(value['operation'])
        else:
            _economic_require(kind in ('model_usage', 'local_usage', 'ci_usage', 'human_usage', 'charge'))
    for key in ('service_period', 'validity'):
        if key in value and value[key] is not None:
            _economic_range(value[key])
    if 'validity' in value:
        _economic_require(value['validity'] is not None)
    for key in ('effective_at', 'source_published_at'):
        if key in value:
            _economic_utc(value[key])
    if 'decision_id' in value and 'supersedes' in value:
        _economic_require(value['decision_id'] != value['supersedes'])
    for key in ('head', 'source_head', 'merge_commit', 'push_head'):
        if key in value:
            _economic_require(type(value[key]) is str and re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', value[key]))
    if 'pr_number' in value:
        _economic_int(value['pr_number'], minimum=1)
    if kind == 'model_usage':
        _economic_model(value)
    elif kind == 'local_usage':
        _economic_require(value['measurement_method'] in ('native_direct_child', 'native_process_group',
            'native_backend_operation', 'native_energy_counter', 'unavailable'))
        for key, unit in (('elapsed', 'elapsed_ns'), ('cpu', 'cpu_ns'), ('gpu', 'gpu_ns'),
                          ('energy', 'microjoule'), ('peak_rss', 'byte')):
            _economic_quantity(value[key], unit)
    elif kind == 'ci_usage':
        _economic_int(value['job_attempt'])
        _economic_require(value['runner_kind'] in ('managed', 'self_hosted', 'unknown'))
        _economic_quantity(value['runner_time'], 'runner_ns')
    elif kind == 'human_usage':
        _economic_require(value['activity'] in ('review', 'approval', 'unblocking'))
        _economic_require(value['basis'] in ('measured', 'explicit_attestation'))
        _economic_quantity(value['human_time'], 'human_ns')
    elif kind == 'charge':
        _economic_digest(value['provider_account_digest'])
        _economic_require(value['direction'] in ('debit', 'credit'))
        _economic_require((value['direction'] == 'credit') == (value['adjusts_charge_event'] is not None))
        _economic_money(value['amount'])
    elif kind == 'tariff':
        _economic_require(value['category'] in _TARIFF_UNITS and value['unit'] == _TARIFF_UNITS[value['category']])
        _economic_require(value['currency'] in ECONOMICS_CURRENCIES)
        _economic_int(value['decimal_scale'], maximum=9)
        _economic_int(value['rate_numerator'])
        _economic_int(value['rate_denominator'], minimum=1)
    elif kind == 'fx':
        _economic_require(value['from_currency'] in ECONOMICS_CURRENCIES
                          and value['to_currency'] in ECONOMICS_CURRENCIES
                          and value['from_currency'] != value['to_currency'])
        _economic_int(value['numerator'], minimum=1)
        _economic_int(value['denominator'], minimum=1)
    elif kind == 'allocation':
        _economic_require(value['method'] in ('native_measured', 'explicit_attestation'))
        _economic_require(type(value['shares']) is list and 1 <= len(value['shares']) <= 16)
        tasks = []
        for share in value['shares']:
            _economic_object(share, ('task', 'weight_ppm'))
            _economic_task(share['task'])
            _economic_int(share['weight_ppm'], maximum=1_000_000)
            tasks.append(json.dumps(share['task'], sort_keys=True))
        _economic_require(len(tasks) == len(set(tasks)) and sum(s['weight_ppm'] for s in value['shares']) <= 1_000_000)
    elif kind == 'workflow_end':
        _economic_require(value['result'] in ('succeeded', 'failed', 'cancelled', 'unknown'))
    elif kind == 'completion':
        _economic_require(value['result'] in ('completed', 'not_completed', 'unknown'))
        _economic_require(value['result'] != 'completed' or value['evidence_digest'] is not None)
    elif kind == 'task_disposition':
        _economic_digest(value['evidence_digest'])
        _economic_id(value['evidence_version'])
        _economic_require(value['decision'] in ('accepted', 'rejected', 'abandoned', 'revoked', 'reopened', 'unknown'))
    elif kind == 'attempt_relation':
        _economic_id(value['from_attempt'])
        _economic_id(value['to_attempt'])
        _economic_require(value['relation'] in ('retry', 'repair') and value['from_attempt'] != value['to_attempt'])
    elif kind == 'review_for_push':
        _economic_int(value['round_index'], minimum=1, maximum=4096)
    elif kind == 'cache_pair':
        identities = []
        for field in ('normal_operations', 'long_operations'):
            _economic_require(type(value[field]) is list and 1 <= len(value[field]) <= 16)
            for operation in value[field]:
                _economic_operation(operation)
                identities.append(operation['physical_operation_digest'])
        _economic_require(len(identities) == len(set(identities)))
        _economic_require(value['basis'] in ('actual_pair', 'explicit_scenario')
                          and value['normal_config_digest'] != value['long_config_digest'])
    elif kind == 'human_decision':
        _economic_require(value['activity'] in ('review', 'approval', 'unblocking')
                          and value['decision'] in ('approved', 'rejected', 'acknowledged', 'unknown'))


def validate_economics_payload(value):
    """Return an owned closed payload; this does not admit an observation or grant access."""
    try:
        _economic_builtin(value)
        _economic_require(type(value) is dict)
        _economic_require(len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode('utf-8')) <= ECONOMICS_MAX_BYTES)
        _economic_payload(value)
        return copy.deepcopy(value)
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise EconomicsError('invalid_economics_payload') from None


def decode_economics_payload(raw):
    """Strict duplicate-key/nonfinite/UTF8 decode; no filesystem, network or journal write."""
    from .spec import _parse_canonical_json

    try:
        _economic_require(type(raw) is bytes and len(raw) <= ECONOMICS_MAX_BYTES)
        return validate_economics_payload(_parse_canonical_json(raw, Path('economic-payload')))
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise EconomicsError('invalid_economics_payload') from None


_QUERY_FIELDS = frozenset(('scope_ids as_of cohort accounting_interval views group_by money_bases '
                           'fx_refs cache_pair_refs snapshot_ref').split())
_QUERY_ENUMS = {
    'views': ({'task_lifetime', 'period_spend', 'cache_comparison', 'friction138'}, 1, 4),
    'group_by': ({'task', 'provider', 'model', 'cache_mode', 'runner_kind', 'disposition'}, 0, 2),
    'money_bases': ({'confirmed_billed', 'tariff_estimate'}, 1, 2),
}


def _economic_json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(',', ':'))


def _economic_normal_time(value):
    return _economic_utc(value).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def _normalize_report_query(value):
    _economic_builtin(value)
    _economic_object(value, _QUERY_FIELDS)
    _economic_require(len(_economic_json(value).encode('utf-8')) <= 65536)
    value = copy.deepcopy(value)
    _economic_require(type(value['scope_ids']) is list and 1 <= len(value['scope_ids']) <= 8)
    for scope in value['scope_ids']:
        _economic_id(scope)
    _economic_require(len(set(value['scope_ids'])) == len(value['scope_ids']))
    value['scope_ids'].sort()
    value['as_of'] = _economic_normal_time(value['as_of'])
    _economic_range(value['accounting_interval'])
    for key in ('start', 'end_exclusive'):
        value['accounting_interval'][key] = _economic_normal_time(value['accounting_interval'][key])
    for field, (allowed, minimum, maximum) in _QUERY_ENUMS.items():
        items = value[field]
        _economic_require(type(items) is list and minimum <= len(items) <= maximum)
        _economic_require(all(type(item) is str and item in allowed for item in items))
        _economic_require(len(items) == len(set(items)))
        if field != 'group_by':
            items.sort()
    for field in ('fx_refs', 'cache_pair_refs'):
        items = value[field]
        _economic_require(type(items) is list and len(items) <= 16)
        for item in items:
            _economic_digest(item)
        _economic_require(len(items) == len(set(items)))
        items.sort()
    _economic_digest(value['snapshot_ref'], optional=True)
    cohort = value['cohort']
    _economic_require(type(cohort) is dict and type(cohort.get('kind')) is str)
    if cohort['kind'] == 'task_ids':
        _economic_object(cohort, ('kind', 'tasks'))
        _economic_require(type(cohort['tasks']) is list and 1 <= len(cohort['tasks']) <= 256)
        for task in cohort['tasks']:
            _economic_task(task)
        identities = [_economic_json(task) for task in cohort['tasks']]
        _economic_require(len(identities) == len(set(identities)))
        cohort['tasks'].sort(key=_economic_json)
    elif cohort['kind'] == 'selection_window':
        _economic_object(cohort, ('kind', 'selection_interval'))
        _economic_range(cohort['selection_interval'])
        for key in ('start', 'end_exclusive'):
            cohort['selection_interval'][key] = _economic_normal_time(cohort['selection_interval'][key])
    elif cohort['kind'] == 'verified_pr_ids':
        _economic_object(cohort, ('kind', 'repository_digest', 'pr_numbers'))
        _economic_digest(cohort['repository_digest'])
        items = cohort['pr_numbers']
        _economic_require(type(items) is list and 1 <= len(items) <= 256)
        for number in items:
            _economic_int(number, minimum=1)
        _economic_require(len(items) == len(set(items)))
        items.sort()
    else:
        _economic_require(False)
    return value


@dataclass(frozen=True)
class ReportQuery:
    """Immutable pure request; construction confers no source or destination rights."""
    canonical: str

    def __post_init__(self):
        from .spec import _parse_canonical_json

        try:
            _economic_require(type(self.canonical) is str and len(self.canonical.encode('utf-8')) <= 65536)
            value = _parse_canonical_json(self.canonical.encode('utf-8'), Path('report-query'))
            object.__setattr__(self, 'canonical', _economic_json(_normalize_report_query(value)))
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
            raise EconomicsError('invalid_report_query') from None

    def as_dict(self):
        return json.loads(self.canonical)


def parse_report_query(value):
    try:
        if type(value) is ReportQuery:
            return value
        return ReportQuery(_economic_json(_normalize_report_query(value)))
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise EconomicsError('invalid_report_query') from None


def decode_report_query(raw):
    from .spec import _parse_canonical_json

    try:
        _economic_require(type(raw) is bytes and len(raw) <= 65536)
        return parse_report_query(_parse_canonical_json(raw, Path('report-query')))
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise EconomicsError('invalid_report_query') from None


@dataclass(frozen=True)
class ReportResult:
    """Immutable canonical result; a calculation is never a release capability."""
    canonical: str

    def __post_init__(self):
        from .spec import _parse_canonical_json

        try:
            _economic_require(type(self.canonical) is str and len(self.canonical.encode('utf-8')) <= 1_048_576)
            value = _parse_canonical_json(self.canonical.encode('utf-8'), Path('report-result'))
            _economic_object(value, ('definition_version', 'status', 'reason'))
            _economic_require(value['definition_version'] == ECONOMICS_DEFINITION
                              and value['status'] in ('unavailable', 'invalid_request')
                              and value['reason'] in ('protected_read_unavailable', 'invalid_report_query',
                                  'input_unavailable', 'input_limit', 'snapshot_unavailable'))
            object.__setattr__(self, 'canonical', _economic_json(value))
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
            raise EconomicsError('invalid_report_result') from None

    def as_dict(self):
        return json.loads(self.canonical)


def _unavailable_economics(reason='protected_read_unavailable', status='unavailable'):
    return ReportResult(_economic_json({'definition_version': ECONOMICS_DEFINITION, 'status': status, 'reason': reason}))


def read_report(request, *, handle=None):
    """Protected read has no qualified150151 adapter yet; never open sources here.

    A UID, role, private-FD token or public pure DTO cannot bootstrap that adapter.
    Sequential integration must bind actual current authorization/sanitizer/release.
    """
    try:
        parse_report_query(request)
    except EconomicsError:
        return _unavailable_economics('invalid_report_query', 'invalid_request')
    return _unavailable_economics()


def render_report_json(result):
    if type(result) is not ReportResult:
        raise EconomicsError('invalid_report_result')
    return result.canonical + '\n'


def render_report_text(result):
    if type(result) is not ReportResult:
        raise EconomicsError('invalid_report_result')
    value = result.as_dict()
    return 'Economics unavailable: ' + value['reason'] + '\n'
