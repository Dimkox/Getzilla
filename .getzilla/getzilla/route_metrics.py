"""Local workflow observations with explicit provenance and missing-data coverage.
Unknown costs stay unknown; failed check outcomes are not confirmed defects.
"""
from __future__ import annotations

import json
import copy
import os
import re
import statistics
import time
from dataclasses import dataclass
from fractions import Fraction
from datetime import datetime, timezone
from .metrics_journal import deduplicate, digest, load, record, source_summary, import_observations, regular  # noqa: F401
from pathlib import Path
from typing import Any, Iterable, TypedDict

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
ECONOMICS_MAX_WALL_SECONDS = 2.0
ECONOMICS_MAX_CPU_SECONDS = 2.0
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
    if value['input_semantics'] != 'unknown' and total is not None:
        _economic_require(sum(item for item in buckets if item is not None) <= total)
        if all(item is not None for item in buckets):
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
            if value.get('status') in ('ok', 'partial'):
                _validate_computed_economics(value)
            else:
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
    if value['status'] in ('unavailable', 'invalid_request'):
        return 'Economics unavailable: ' + value['reason'] + '\n'
    lines = ['Economics calculation: ' + value['status'], 'Snapshot: ' + value['snapshot_ref']]
    ratios = value['ratios']
    if ratios is not None:
        accepted = ratios['accepted_tasks']
        lines.append('accepted_tasks=' + ('unknown' if accepted is None else str(accepted)))
    def amount_line(name, amount):
        number = amount['value']
        display = 'unknown' if number is None else str(_economic_fraction(number))
        currency = amount['currency'] or 'currency_unknown'
        line = f"{name} {amount['basis']}: {display} {currency}"
        if number is None and amount['known_subtotal'] is not None:
            line += f" (known subtotal {_economic_fraction(amount['known_subtotal'])})"
        return line
    for view, amounts in value['totals'].items():
        for amount in amounts:
            lines.append(amount_line(view, amount))
    if ratios is not None:
        for name in ('accepted_task_mean', 'cohort_spend_per_accepted', 'rejected_abandoned_share', 'unsuccessful_attempt_share'):
            for amount in ratios[name]:
                denominator = amount['denominator']
                if type(denominator) is dict:
                    denominator = str(_economic_fraction(denominator))
                lines.append(amount_line(name, amount) + f"; {amount['denominator_definition']}={denominator if denominator is not None else 'unknown'}")
    lines.append('Conflicting observations: ' + str(value['reconciliation']['conflict_count']))
    for amount in value['reconciliation']['unallocated']:
        lines.append(amount_line('Unallocated', amount))
    if value['friction138'] is not None:
        friction = value['friction138']
        minutes = friction['human_minutes']
        lines.append('Human minutes: ' + ('unknown' if minutes is None else str(_economic_fraction(minutes))))
        decisions = friction['human_decision_count']
        lines.append('Human decisions: ' + ('unknown' if decisions is None else str(decisions)))
    for converted in value['fx_totals']:
        for amount in converted['amounts']:
            lines.append(amount_line(f"FX {converted['view']} {converted['from_currency']}->{converted['to_currency']}", amount))
    for pair in value['cache_comparison']:
        lines.append(f"Cache pair {pair['pair_ref']} {pair['basis'] or 'unknown'}: {pair['status']}")
        for side in ('normal', 'long', 'savings'):
            for amount in pair[side]:
                lines.append(amount_line('Cache ' + side, amount))
    for group in value['groups']:
        for amount in group['amounts']:
            lines.append(amount_line('Group ' + group['view'] + ' ' + _economic_json(group['dimensions']), amount))
    _economic_require(len(('\n'.join(lines) + '\n').encode('utf-8')) <= 1_048_576)
    return '\n'.join(lines) + '\n'


class EconomicsInput(TypedDict):
    """An ephemeral arithmetic input, NOT an access/source capability or wire event.

    A genuine host must derive this cut from admitted source/coverage. These
    public Python values cannot bootstrap read_report, import or publication.
    Observer identity stays separate from original effect/subject bindings.
    """
    observations: list[dict]
    bindings: list[dict]
    selections: list[dict]
    census: list[dict] | None
    gaps: list[str]
    source_cut_digest: str


_ECONOMIC_ENVELOPE = frozenset(('schema_version event event_id kind at captured_at producer_version '
                              'repository_digest workspace_digest observer payload').split())
_OBSERVER_CONTEXT = frozenset(('route_id logical_task_id session_id authority_epoch state_revision '
    'context_revision scope_digest spec_digest evidence_digest head tree base').split())
_OPERATION_FIELDS = frozenset(('claim_event_digest operation_id attempt_id producer_binding_digest '
                               'physical_operation_digest').split())
_BINDING_FIELDS = _OPERATION_FIELDS | {'task', 'head', 'outcome'}
_USAGE_KINDS = frozenset({'model_usage', 'local_usage', 'ci_usage', 'human_usage'})


def _task_key(task):
    return _economic_json(task)


def _observer_shape(observer):
    _economic_require(type(observer) is dict)
    if observer.get('profile') == 'core_native':
        _economic_object(observer, ('profile', 'operation_id', 'context'))
        _economic_id(observer['operation_id'])
        context = observer['context']
        _economic_object(context, _OBSERVER_CONTEXT)
        for key, pattern in (('route_id', r'[0-9a-f]{12}'), ('logical_task_id', r'task:[0-9a-f]{32}'),
                ('session_id', r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')):
            _economic_require(type(context[key]) is str and re.fullmatch(pattern, context[key]))
        for key in ('authority_epoch', 'state_revision', 'context_revision'):
            _economic_int(context[key])
        for key in ('scope_digest', 'spec_digest', 'evidence_digest'):
            _economic_digest(context[key], optional=key != 'scope_digest')
        for key in ('head', 'tree', 'base'):
            _economic_require(type(context[key]) is str and re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', context[key]))
    else:
        _economic_object(observer, ('profile', 'operation_digest', 'binding_digest', 'scope_digest'))
        _economic_require(observer['profile'] == 'registered_host')
        for key in ('operation_digest', 'binding_digest', 'scope_digest'):
            _economic_digest(observer[key])
    # This checks the frozen observer syntax only. It supplies NO host admission.


def _economic_budget(started):
    wall, cpu = time.monotonic() - started[0], time.process_time() - started[1]
    if not 0 <= wall <= ECONOMICS_MAX_WALL_SECONDS or not 0 <= cpu <= ECONOMICS_MAX_CPU_SECONDS:
        raise EconomicsError('input_limit')


def _snapshot_economics_input(value, started=None):
    _economic_object(value, ('observations', 'bindings', 'selections', 'census', 'gaps', 'source_cut_digest'))
    _economic_digest(value['source_cut_digest'])
    _economic_require(type(value['gaps']) is list and len(value['gaps']) <= 16)
    _economic_require(all(type(gap) is str and gap in ECONOMICS_UNKNOWN for gap in value['gaps']))
    for key, limit in (('observations', 4096), ('bindings', 4096), ('selections', 256)):
        _economic_require(type(value[key]) is list and len(value[key]) <= limit)
    facts, size = [], 0
    for item in value['observations']:
        if started is not None:
            _economic_budget(started)
        _economic_builtin(item)
        _economic_object(item, ('row', 'delivery'))
        item = copy.deepcopy(item)
        row, proof = item['row'], item['delivery']
        _economic_object(row, _ECONOMIC_ENVELOPE)
        _economic_require(type(row['schema_version']) is int and row['schema_version'] == 4
                          and type(row['producer_version']) is int and row['producer_version'] == 1
                          and row['event'] == 'observation' and row['kind'] == 'economics_observation')
        for field in ('event_id', 'repository_digest', 'workspace_digest'):
            _economic_digest(row[field])
        for field in ('at', 'captured_at'):
            _economic_require(type(row[field]) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', row[field]))
            _economic_utc(row[field])
        _economic_require(_economic_utc(row['at']) <= _economic_utc(row['captured_at']))
        _observer_shape(row['observer'])
        row['payload'] = validate_economics_payload(row['payload'])
        raw_size = len(_economic_json(row).encode('utf-8'))
        _economic_require(raw_size <= 8192)
        size += raw_size
        _economic_require(size <= 8_388_608)
        _economic_object(proof, ('proof_version', 'clock_domain', 'row_digest', 'delivered_by'))
        _economic_require(type(proof['proof_version']) is int and proof['proof_version'] == 2
                          and proof['clock_domain'] == 'native_local_utc' and proof['row_digest'] == digest(row))
        _economic_require(type(proof['delivered_by']) is str and re.fullmatch(
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z', proof['delivered_by']))
        _economic_require(_economic_utc(proof['delivered_by']) >= _economic_utc(row['captured_at']))
        facts.append(item)
    bindings = []
    for item in value['bindings']:
        _economic_builtin(item)
        _economic_object(item, _BINDING_FIELDS)
        _economic_operation({key: item[key] for key in _OPERATION_FIELDS})
        _economic_task(item['task'])
        _economic_require(item['outcome'] in ('succeeded', 'failed', 'cancelled', 'unknown'))
        _economic_require(item['head'] is None or type(item['head']) is str
                          and re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', item['head']))
        bindings.append(copy.deepcopy(item))
    selections = []
    for item in value['selections']:
        _economic_builtin(item)
        _economic_object(item, ('task', 'selected_at', 'selection_event_digest'))
        _economic_task(item['task'])
        _economic_utc(item['selected_at'])
        _economic_digest(item['selection_event_digest'])
        selections.append(copy.deepcopy(item))
    census = value['census']
    if census is not None:
        _economic_require(type(census) is list and len(census) <= 256)
        for task in census:
            _economic_builtin(task)
            _economic_task(task)
        _economic_require(len({_task_key(task) for task in census}) == len(census))
        census = copy.deepcopy(census)
    return {'observations': facts, 'bindings': bindings, 'selections': selections, 'census': census,
            'gaps': sorted(set(value['gaps'])), 'source_cut_digest': value['source_cut_digest']}


def _known_economics(cut, query):
    cutoff = _economic_utc(query['as_of'])
    by_identity = {}
    for fact in cut['observations']:
        row, proof = fact['row'], fact['delivery']
        if (_economic_utc(row['at']) < cutoff and _economic_utc(row['captured_at']) < cutoff
                and _economic_utc(proof['delivered_by']) <= cutoff):
            key = (row['event_id'], proof['row_digest'])
            _economic_require(key not in by_identity or by_identity[key]['delivery'] == proof)
            by_identity.setdefault(key, fact)
    return sorted(by_identity.values(), key=lambda fact: (fact['row']['event_id'], fact['delivery']['row_digest']))


def _semantic_economics(payload):
    return {key: value for key, value in payload.items()
            if key not in ('source_fact_digest', 'source_proof_ref', 'observation_origin')}


def _reconcile_economics(facts, bindings):
    groups, conflict_ids = {}, set()
    for fact in facts:
        row, payload = fact['row'], fact['row']['payload']
        groups.setdefault(('event', row['event_id']), []).append(fact)
        kind = payload['candidate_kind']
        if 'source_fact_digest' in payload:
            groups.setdefault(('source', kind, payload['source_fact_digest']), []).append(fact)
        if kind == 'charge':
            groups.setdefault(('bill', payload['provider_account_digest'], payload['external_line_digest']), []).append(fact)
        elif kind in _USAGE_KINDS and payload['operation'] is not None:
            groups.setdefault(('usage', kind, payload['operation']['physical_operation_digest']), []).append(fact)
        elif 'decision_id' in payload:
            groups.setdefault(('decision', kind, payload['decision_id']), []).append(fact)
    for key, group in groups.items():
        versions = {fact['delivery']['row_digest'] if key[0] == 'event'
                    else _economic_json(_semantic_economics(fact['row']['payload'])) for fact in group}
        if len(versions) > 1:
            conflict_ids.update(fact['row']['event_id'] for fact in group)
    by_operation, by_claim = {}, {}
    bad_operations = set()
    for item in bindings:
        identity = item['physical_operation_digest']
        if identity in by_operation and by_operation[identity] != item:
            bad_operations.add(identity)
        by_operation[identity] = item
        by_claim.setdefault(item['claim_event_digest'], []).append(item)
    for group in by_claim.values():
        owners = {(_task_key(item['task']), item['producer_binding_digest']) for item in group}
        # An actual Core native reserved→running claim permits one managed
        # Popen. Many observations may describe that same effect, not invent
        # another. Factory groupings are not coerced to this native rule.
        native_effects = {item['physical_operation_digest'] for item in group if item['task']['domain'] == 'core_native'}
        if len(owners) != 1 or len(native_effects) > 1:
            bad_operations.update(item['physical_operation_digest'] for item in group)
    for fact in facts:
        operation = fact['row']['payload'].get('operation')
        if operation is not None:
            bound = by_operation.get(operation['physical_operation_digest'])
            if bound is not None and any(bound[key] != operation[key] for key in _OPERATION_FIELDS):
                bad_operations.add(operation['physical_operation_digest'])
    for fact in facts:
        operation = fact['row']['payload'].get('operation')
        if operation and operation['physical_operation_digest'] in bad_operations:
            conflict_ids.add(fact['row']['event_id'])
    # An unresolved credit cannot silently reduce another account/currency/operation.
    charges = {fact['row']['event_id']: fact for fact in facts
               if fact['row']['payload']['candidate_kind'] == 'charge'}
    for fact in charges.values():
        payload = fact['row']['payload']
        if payload['direction'] == 'credit':
            parent = charges.get(payload['adjusts_charge_event'])
            if parent is None or parent['row']['payload']['direction'] != 'debit':
                conflict_ids.add(fact['row']['event_id'])
            elif (parent['row']['payload']['provider_account_digest'] != payload['provider_account_digest']
                  or parent['row']['payload']['amount']['currency'] != payload['amount']['currency']
                  or parent['row']['payload']['operation'] != payload['operation']):
                conflict_ids.update((fact['row']['event_id'], parent['row']['event_id']))
    kept, merged = {}, 0
    for fact in facts:
        row, payload = fact['row'], fact['row']['payload']
        if row['event_id'] in conflict_ids:
            continue
        kind = payload['candidate_kind']
        operation = payload.get('operation')
        if kind == 'charge':
            key = ('bill', payload['provider_account_digest'], payload['external_line_digest'])
        elif kind in _USAGE_KINDS and operation is not None:
            key = ('usage', kind, operation['physical_operation_digest'])
        else:
            key = ('event', row['event_id'])
        if key in kept:
            kept[key]['refs'].add(row['event_id'])
            kept[key]['refs'].add(payload['source_proof_ref'])
            merged += 1
        else:
            kept[key] = {'fact': fact, 'refs': {row['event_id'], payload['source_proof_ref']}}
    return list(kept.values()), by_operation, sorted(conflict_ids), bad_operations, merged


def _economic_lineage(items, *, decision=False):
    """Exactly one complete acyclic supersession chain; timestamps cannot repair it."""
    if not items:
        return None, None
    by_id = {}
    for item in items:
        row, payload = item['fact']['row'], item['fact']['row']['payload']
        identity = payload['decision_id'] if decision else row['event_id']
        if identity in by_id:
            return None, 'conflicted'
        by_id[identity] = item
    parents = {identity: item['fact']['row']['payload']['supersedes'] for identity, item in by_id.items()}
    if any(parent is not None and parent not in by_id for parent in parents.values()):
        return None, 'history_gap'
    if sum(parent is None for parent in parents.values()) != 1:
        return None, 'ambiguous'
    children = {}
    for child, parent in parents.items():
        if parent is not None:
            if parent in children:
                return None, 'ambiguous'
            children[parent] = child
            if _economic_utc(by_id[parent]['fact']['row']['at']) > _economic_utc(by_id[child]['fact']['row']['at']):
                return None, 'conflicted'
    root = next(identity for identity, parent in parents.items() if parent is None)
    visited = set()
    while root not in visited:
        visited.add(root)
        if root not in children:
            return (by_id[root], None) if len(visited) == len(by_id) else (None, 'ambiguous')
        root = children[root]
    return None, 'ambiguous'


def _economic_states(items, task, cutoff):
    result = {'workflow_end': None, 'completion': None, 'merged': None, 'disposition': None}
    gaps = set()
    for kind, field in (('workflow_end', 'workflow_end'), ('completion', 'completion'),
                        ('merge', 'merged'), ('task_disposition', 'disposition')):
        selected = [item for item in items if item['fact']['row']['payload']['candidate_kind'] == kind
                    and item['fact']['row']['payload']['task'] == task
                    and _economic_utc(item['fact']['row']['payload']['effective_at']) <= cutoff]
        latest, gap = _economic_lineage(selected, decision=True)
        if gap:
            gaps.add(gap)
        if latest:
            payload = latest['fact']['row']['payload']
            result[field] = True if kind == 'merge' else payload['decision'] if kind == 'task_disposition' else payload['result']
    return result, gaps


def _selected_economic_tasks(cut, query, items):
    cohort = query['cohort']
    if cohort['kind'] == 'task_ids':
        return cohort['tasks'], []
    if cohort['kind'] == 'selection_window':
        interval = cohort['selection_interval']
        selected = {_task_key(item['task']): item['task'] for item in cut['selections']
            if _economic_utc(interval['start']) <= _economic_utc(item['selected_at']) < _economic_utc(interval['end_exclusive'])
            and _economic_utc(item['selected_at']) < _economic_utc(query['as_of'])}
        return [selected[key] for key in sorted(selected)], [] if cut['census'] is not None else ['history_gap']
    groups = {}
    for item in items:
        payload = item['fact']['row']['payload']
        if (payload['candidate_kind'] == 'task_pr_link' and payload['repository_digest'] == cohort['repository_digest']
                and payload['pr_number'] in cohort['pr_numbers']):
            groups.setdefault(payload['pr_number'], []).append(item)
    tasks, gaps = {}, []
    for number in cohort['pr_numbers']:
        latest, gap = _economic_lineage(groups.get(number, []))
        if gap or latest is None:
            gaps.append(gap or 'not_observed')
            continue
        payload = latest['fact']['row']['payload']
        interval = payload['validity']
        if not _economic_utc(interval['start']) <= _economic_utc(query['as_of']) < _economic_utc(interval['end_exclusive']):
            gaps.append('not_observed')
        else:
            tasks[_task_key(payload['task'])] = payload['task']
    return [tasks[key] for key in sorted(tasks)], gaps


def _economic_rational(value):
    return {'numerator': str(value.numerator), 'denominator': str(value.denominator)}


def _economic_fraction(value):
    _economic_object(value, ('numerator', 'denominator'))
    _economic_require(type(value['numerator']) is str and re.fullmatch(r'-?\d{1,100}', value['numerator'])
                      and type(value['denominator']) is str and re.fullmatch(r'[1-9]\d{0,99}', value['denominator']))
    return Fraction(int(value['numerator']), int(value['denominator']))


def _economic_period(period, interval):
    if period is None:
        return None
    start, end = _economic_utc(period['start']), _economic_utc(period['end_exclusive'])
    left, right = _economic_utc(interval['start']), _economic_utc(interval['end_exclusive'])
    if end <= left or start >= right:
        return False
    return True if left <= start and end <= right else None


def _economic_rate(items, payload, category):
    period = payload.get('service_period')
    if period is None:
        return None, [], 'not_observed'
    start, end = _economic_utc(period['start']), _economic_utc(period['end_exclusive'])
    matches, overlapping = [], []
    for item in items:
        rate = item['fact']['row']['payload']
        if (rate['candidate_kind'] != 'tariff' or rate['category'] != category
                or rate['provider_id'] != payload.get('provider_id') or rate['model_id'] != payload.get('model_id')):
            continue
        if (rate['cache_policy_digest'] is not None
                and rate['cache_policy_digest'] != (payload.get('cache_policy') or {}).get('policy_digest')):
            continue
        left, right = _economic_utc(rate['validity']['start']), _economic_utc(rate['validity']['end_exclusive'])
        if (_economic_utc(rate['source_published_at']) <= _economic_utc(item['fact']['row']['captured_at'])
                and left < end and start < right):
            overlapping.append(item)
            if left <= start and end <= right:
                matches.append(item)
    signatures = {(item['fact']['row']['payload']['currency'], item['fact']['row']['payload']['decimal_scale'],
                   item['fact']['row']['payload']['rate_numerator'], item['fact']['row']['payload']['rate_denominator'])
                  for item in overlapping}
    refs = sorted({ref for item in overlapping for ref in item['refs']})
    # Partial/split coverage is present pricing, not permission to ignore this
    # category. Unsegmented usage needs one full-period rate and no conflicting
    # overlapping quote; do not infer allocation between dated rate segments.
    if not matches or len(signatures) != 1:
        return None, refs, 'ambiguous' if overlapping else 'tariff_missing'
    rate = matches[0]['fact']['row']['payload']
    return rate, refs, None


def _economic_prices(item, items):
    payload = item['fact']['row']['payload']
    kind = payload['candidate_kind']
    quantities = []
    if kind == 'model_usage':
        for category in ('uncached_input', 'cache_write', 'cache_read'):
            value = payload[category]['value']
            reason = payload[category]['unknown_reason']
            if payload['input_semantics'] == 'unknown':
                value, reason = None, 'ambiguous'
            elif category == 'uncached_input' and value is None:
                fields = ['input_total', 'cache_read']
                if payload['input_semantics'] != 'total_includes_read':
                    fields.append('cache_write')
                if all(payload[field]['value'] is not None for field in fields):
                    value = payload[fields[0]]['value'] - sum(payload[field]['value'] for field in fields[1:])
                    if value < 0:
                        value, reason = None, 'ambiguous'
                    else:
                        reason = None
            quantities.append((category, value, reason))
        output, reasoning = payload['output']['value'], payload['reasoning_output']['value']
        reasoning_rate, _, reasoning_missing = _economic_rate(items, payload, 'reasoning_output')
        if payload['output_semantics'] == 'unknown':
            quantities.extend((('output', None, 'ambiguous'), ('reasoning_output', None, 'ambiguous')))
        elif (payload['output_semantics'] == 'includes_reasoning' and reasoning_rate is None
              and reasoning_missing == 'tariff_missing'):
            # A single output rate prices the inclusive total once. Reasoning is
            # still reported as usage, but never added to that total again.
            quantities.append(('output', output, payload['output']['unknown_reason']))
        else:
            if payload['output_semantics'] == 'includes_reasoning':
                output = output - reasoning if output is not None and reasoning is not None else None
            quantities.extend((('output', output, None if output is not None else 'not_observed'),
                               ('reasoning_output', reasoning, payload['reasoning_output']['unknown_reason'])))
    elif kind == 'ci_usage':
        quantities.append(('ci_runner', payload['runner_time']['value'], payload['runner_time']['unknown_reason']))
    elif kind == 'local_usage':
        quantities.extend((key, payload[key]['value'], payload[key]['unknown_reason']) for key in ('cpu', 'gpu', 'energy'))
    elif kind == 'human_usage':
        quantities.append(('human_' + payload['activity'], payload['human_time']['value'], payload['human_time']['unknown_reason']))
    result = []
    for category, quantity, reason in quantities:
        if quantity is None and reason == 'not_applicable':
            continue
        rate, rate_refs, missing = _economic_rate(items, payload, category)
        refs = set(item['refs']) | set(rate_refs)
        amount = None
        if quantity is not None and rate is not None:
            amount = Fraction(quantity * rate['rate_numerator'], rate['rate_denominator'] * 10**rate['decimal_scale'])
        result.append({'basis': 'tariff_estimate', 'currency': rate['currency'] if rate else None,
                       'amount': amount, 'reasons': {reason or missing or 'not_observed'} if amount is None else set(),
                       'refs': refs, 'operation': payload['operation'], 'period': payload['service_period'],
                       'payload': payload, 'category': category})
    return result


def _economic_contributions(items, started=None):
    result = []
    for item in items:
        if started is not None:
            _economic_budget(started)
        payload = item['fact']['row']['payload']
        if payload['candidate_kind'] == 'charge':
            money = payload['amount']
            amount = None if money['value'] is None else Fraction(money['value'], 10**money['decimal_scale'])
            if amount is not None and payload['direction'] == 'credit':
                amount = -amount
            result.append({'basis': 'confirmed_billed', 'currency': money['currency'], 'amount': amount,
                           'reasons': {money['unknown_reason']} if amount is None else set(),
                           'refs': set(item['refs']), 'operation': payload['operation'], 'period': payload['service_period'],
                           'payload': payload, 'category': 'charge'})
        elif payload['candidate_kind'] in _USAGE_KINDS:
            result.extend(_economic_prices(item, items))
    return result


def _economic_allocations(items, bindings):
    groups = {}
    for item in items:
        payload = item['fact']['row']['payload']
        if payload['candidate_kind'] == 'allocation':
            groups.setdefault(payload['operation']['physical_operation_digest'], []).append(item)
    allocations, gaps = {}, set()
    for operation, group in groups.items():
        latest, gap = _economic_lineage(group)
        if gap:
            gaps.add(gap)
            allocations[operation] = None
        elif latest:
            payload = latest['fact']['row']['payload']
            bound = bindings.get(operation)
            if bound is None or any(bound[key] != payload['operation'][key] for key in _OPERATION_FIELDS):
                gaps.add('source_unqualified')
                allocations[operation] = None
            else:
                allocations[operation] = [(_task_key(share['task']), Fraction(share['weight_ppm'], 1_000_000))
                                           for share in payload['shares']]
    return allocations, gaps


def _economic_shares(operation, bindings, allocations):
    if operation is None:
        return [], 'ambiguous'
    identity = operation['physical_operation_digest']
    bound = bindings.get(identity)
    if bound is None:
        return [], 'source_unqualified'
    if any(bound[key] != operation[key] for key in _OPERATION_FIELDS):
        return [], 'conflicted'
    if identity in allocations:
        return (allocations[identity], None) if allocations[identity] is not None else ([], 'ambiguous')
    return [(_task_key(bound['task']), Fraction(1))], None


def _economic_money_rows(contributions, *, bases, gaps=(), currencies=None, divisor=1, basis_gaps=None):
    grouped = {}
    seen = set(currencies or ())
    basis_missing = {basis: set(gaps) | set((basis_gaps or {}).get(basis, ())) for basis in bases}
    for item, weight, extra in contributions:
        if item['basis'] not in bases or weight == 0:
            continue
        key = (item['basis'], item['currency'])
        seen.add(key)
        group = grouped.setdefault(key, {'sum': Fraction(0), 'reasons': set(), 'refs': set()})
        group['refs'].update(item['refs'])
        group['reasons'].update(item['reasons'])
        group['reasons'].update(extra)
        if item['amount'] is not None:
            group['sum'] += item['amount'] * weight
        if item['currency'] is None or item['amount'] is None:
            basis_missing[item['basis']].update(item['reasons'] or {'currency_missing'})
    for basis in bases:
        if not any(key[0] == basis for key in seen):
            seen.add((basis, None))
            basis_missing[basis].add('not_observed')
    rows = []
    for basis, currency in sorted(seen, key=lambda key: (key[0], key[1] or '')):
        if basis not in bases:
            continue
        group = grouped.get((basis, currency), {'sum': Fraction(0), 'reasons': set(), 'refs': set()})
        reasons = group['reasons'] | basis_missing[basis]
        if currency is None:
            reasons.add('currency_missing')
        if divisor is None:
            reasons.add('unknown_denominator')
        elif divisor == 0:
            reasons.add('zero_denominator')
        subtotal = group['sum'] / divisor if divisor not in (None, 0) else group['sum']
        rows.append({'basis': basis, 'currency': currency, 'value': None if reasons else _economic_rational(subtotal),
                     'known_subtotal': _economic_rational(subtotal), 'unknown_reasons': sorted(reasons),
                     'source_refs': sorted(group['refs'])})
    return rows


def _economic_usage(items, task_key, bindings, allocations, gaps):
    grouped = {}
    for item in items:
        payload = item['fact']['row']['payload']
        kind = payload['candidate_kind']
        if kind not in _USAGE_KINDS:
            continue
        shares, gap = _economic_shares(payload['operation'], bindings, allocations)
        weight = sum((share for identity, share in shares if identity == task_key), Fraction(0))
        if weight == 0:
            continue
        if kind == 'model_usage':
            quantities = [(key, payload[key]) for key in ('input_total', 'uncached_input', 'cache_write', 'cache_read',
                                                          'output', 'reasoning_output')]
        elif kind == 'local_usage':
            quantities = [(key, payload[key]) for key in ('elapsed', 'cpu', 'gpu', 'energy', 'peak_rss')]
        elif kind == 'ci_usage':
            quantities = [('ci_runner', payload['runner_time'])]
        else:
            quantities = [('human_' + payload['activity'], payload['human_time'])]
        for category, quantity in quantities:
            key = (category, quantity['unit'])
            group = grouped.setdefault(key, {'sum': Fraction(0), 'reasons': set(gaps), 'refs': set()})
            group['refs'].update(item['refs'])
            if gap:
                group['reasons'].add(gap)
            if quantity['value'] is None:
                group['reasons'].add(quantity['unknown_reason'])
            else:
                group['sum'] += quantity['value'] * weight
    rows = []
    for (category, unit), group in sorted(grouped.items()):
        exact = _economic_rational(group['sum'])
        # Integral counts keep their natural JSON representation; attribution
        # shares retain an exact rational rather than premature rounding.
        value = group['sum'].numerator if group['sum'].denominator == 1 else exact
        rows.append({'category': category, 'unit': unit, 'value': None if group['reasons'] else value,
                     'known_subtotal': exact, 'unknown_reasons': sorted(group['reasons']), 'source_refs': sorted(group['refs'])})
    return rows


def _economic_attempt_gaps(items, bindings):
    graphs, gaps = {}, set()
    for item in items:
        payload = item['fact']['row']['payload']
        if payload['candidate_kind'] != 'attempt_relation':
            continue
        task = _task_key(payload['task'])
        known = {bound['attempt_id'] for bound in bindings.values() if _task_key(bound['task']) == task}
        if payload['from_attempt'] not in known or payload['to_attempt'] not in known:
            gaps.add('history_gap')
        graphs.setdefault(task, {}).setdefault(payload['from_attempt'], set()).add(payload['to_attempt'])
    for graph in graphs.values():
        visiting, done = set(), set()
        def visit(node):
            if node in visiting:
                return False
            if node in done:
                return True
            visiting.add(node)
            for child in graph.get(node, ()):
                if not visit(child):
                    return False
            visiting.remove(node)
            done.add(node)
            return True
        if not all(visit(node) for node in graph):
            gaps.add('ambiguous')
    return gaps


def _economic_ratio_rows(numerator, denominator, *, numerator_definition, denominator_definition, cohort_definition):
    rows = []
    for source in numerator:
        reasons = set(source['unknown_reasons'])
        if type(denominator) is list:
            matching = next((row for row in denominator if row['basis'] == source['basis']
                             and row['currency'] == source['currency']), None)
            denom = _economic_fraction(matching['value']) if matching and matching['value'] is not None else None
            if matching:
                reasons.update(matching['unknown_reasons'])
            denominator_value = _economic_rational(denom) if denom is not None else None
        else:
            denom = denominator
            denominator_value = denominator
        if denom is None:
            reasons.add('unknown_denominator')
        elif denom == 0:
            reasons.add('zero_denominator')
        subtotal = _economic_fraction(source['known_subtotal']) / denom if denom not in (None, 0) else None
        full = _economic_fraction(source['value']) / denom if source['value'] is not None and denom not in (None, 0) else None
        rows.append({'basis': source['basis'], 'currency': source['currency'],
                     'value': _economic_rational(full) if full is not None and not reasons else None,
                     'known_subtotal': _economic_rational(subtotal) if subtotal is not None else None,
                     'numerator_value': source['value'], 'numerator_known_subtotal': source['known_subtotal'],
                     'denominator': denominator_value, 'numerator_definition': numerator_definition,
                     'denominator_definition': denominator_definition, 'cohort_definition': cohort_definition,
                     'unit': 'currency_per_task' if denominator_definition == 'accepted_tasks' else 'fraction',
                     'unknown_reasons': sorted(reasons), 'source_refs': source['source_refs']})
    return rows


def _economic_basis_gaps(bindings, allocations, contributions, task_keys, bases):
    seen = {(row['basis'], row['operation']['physical_operation_digest']) for row in contributions if row['operation']}
    gaps = {basis: set() for basis in bases}
    for identity, bound in bindings.items():
        shares = allocations.get(identity, [(_task_key(bound['task']), Fraction(1))])
        relevant = _task_key(bound['task']) in task_keys if shares is None else any(
            key in task_keys and weight > 0 for key, weight in shares)
        if relevant:
            for basis in bases:
                if (basis, identity) not in seen:
                    gaps[basis].add('not_observed')
    return gaps


def _economic_task_attempts(task, bindings):
    groups = {}
    for bound in bindings.values():
        if bound['task'] == task:
            group = groups.setdefault((bound['attempt_id'], bound['head']), {'outcomes': set(), 'refs': set()})
            group['outcomes'].add(bound['outcome'])
            group['refs'].add(bound['physical_operation_digest'])
    return [{'attempt_id': attempt, 'head': head,
             'outcome': next(iter(group['outcomes'])) if len(group['outcomes']) == 1 else 'unknown',
             'operation_refs': sorted(group['refs'])}
            for (attempt, head), group in sorted(groups.items(), key=lambda item: (item[0][0] or '', item[0][1] or ''))]


def _economic_friction(items, task_keys, usage, gaps):
    decisions = {item['fact']['row']['payload']['decision_id'] for item in items
                 if item['fact']['row']['payload']['candidate_kind'] == 'human_decision'
                 and _task_key(item['fact']['row']['payload']['task']) in task_keys}
    durations = [row for rows in usage for row in rows if row['unit'] == 'human_ns']
    time_known = bool(durations) and not gaps and all(row['value'] is not None for row in durations)
    minutes = sum((_economic_fraction(row['known_subtotal']) for row in durations), Fraction(0)) / (60 * 10**9)
    reviews = {(item['fact']['row']['payload']['push_event_digest'], item['fact']['row']['payload']['round_index'])
               for item in items if item['fact']['row']['payload']['candidate_kind'] == 'review_for_push'
               and _task_key(item['fact']['row']['payload']['task']) in task_keys}
    return {'human_decision_count': len(decisions) if decisions and not gaps else None,
            'human_decision_known_subtotal': len(decisions), 'human_minutes': _economic_rational(minutes) if time_known else None,
            'human_minutes_known_subtotal': _economic_rational(minutes),
            'review_round_known_subtotal': len(reviews), 'approval_count_per_commit': None,
            'fast_path_coverage': None, 'evidence_added_lines': None, 'defect_catch_latency': None,
            'unknown_reasons': sorted(set(gaps) | ({'not_observed'} if not time_known else set()) | {'history_gap'})}


def _economic_fx(items, requested, views, bases, gaps, basis_gaps=None):
    selected = {item['fact']['row']['event_id']: item for item in items
                if item['fact']['row']['payload']['candidate_kind'] == 'fx'
                and item['fact']['row']['event_id'] in requested}
    pairs = {}
    output = []
    for ref in requested:
        if ref not in selected:
            output.append({'view': 'task_lifetime', 'from_currency': None, 'to_currency': None,
                           'amounts': [], 'source_refs': [ref], 'unknown_reasons': ['not_observed']})
    for item in selected.values():
        payload = item['fact']['row']['payload']
        pairs.setdefault((payload['from_currency'], payload['to_currency']), []).append(item)
    for (source, target), rates in sorted(pairs.items()):
        for view, contributions in views.items():
            converted = []
            reasons = set()
            for contribution, weight, extra in contributions:
                if contribution['currency'] != source:
                    continue
                period = contribution['period']
                matches = [item for item in rates if period is not None
                    and _economic_utc(item['fact']['row']['payload']['validity']['start']) <= _economic_utc(period['start'])
                    and _economic_utc(period['end_exclusive']) <= _economic_utc(item['fact']['row']['payload']['validity']['end_exclusive'])
                    and _economic_utc(item['fact']['row']['payload']['source_published_at'])
                        <= _economic_utc(item['fact']['row']['captured_at'])]
                factors = {Fraction(item['fact']['row']['payload']['numerator'], item['fact']['row']['payload']['denominator'])
                           for item in matches}
                replacement = dict(contribution, currency=target, refs=set(contribution['refs']),
                                   reasons=set(contribution['reasons']))
                if len(factors) == 1:
                    factor = next(iter(factors))
                    replacement['amount'] = contribution['amount'] * factor if contribution['amount'] is not None else None
                    replacement['refs'].update(ref for item in matches for ref in item['refs'])
                else:
                    replacement['amount'] = None
                    replacement['reasons'].add('ambiguous' if factors else 'not_observed')
                    reasons.update(replacement['reasons'])
                converted.append((replacement, weight, extra))
            amounts = _economic_money_rows(converted, bases=bases, gaps=gaps,
                                             currencies={(basis, target) for basis in bases}, basis_gaps=basis_gaps)
            output.append({'view': view, 'from_currency': source, 'to_currency': target, 'amounts': amounts,
                           'source_refs': sorted({ref for item in rates for ref in item['refs']}),
                           'unknown_reasons': sorted(reasons)})
    return output


def _economic_groups(weighted, dimensions, task_rows, bases, currencies, gaps, basis_gaps=None, view='task_lifetime'):
    if not dimensions:
        return []
    dispositions = {_task_key(row['task']): row['disposition'] for row in task_rows}
    groups = {}
    if set(dimensions) <= {'task', 'disposition'}:
        for task in task_rows:
            selected = {dimension: task['task'] if dimension == 'task' else task['disposition'] for dimension in dimensions}
            groups.setdefault(_economic_json(selected), {'dimensions': selected, 'rows': []})
    # Weighted contributions are already scoped to selected tasks. Build each
    # task's rows directly so a shared operation gets each exact share once.
    for task_key, rows in weighted.items():
        for contribution, weight, extra in rows:
            payload = contribution['payload']
            values = {'task': json.loads(task_key), 'provider': payload.get('provider_id'),
                      'model': payload.get('model_id'), 'cache_mode': (payload.get('cache_policy') or {}).get('mode'),
                      'runner_kind': payload.get('runner_kind'), 'disposition': dispositions[task_key]}
            selected = {dimension: values[dimension] for dimension in dimensions}
            key = _economic_json(selected)
            if key not in groups:
                _economic_require(len(groups) < 256)
                groups[key] = {'dimensions': selected, 'rows': []}
            groups[key]['rows'].append((contribution, weight, extra))
    return [{'view': view, 'dimensions': groups[key]['dimensions'],
             'amounts': _economic_money_rows(groups[key]['rows'], bases=bases, gaps=gaps, currencies=currencies,
                                               basis_gaps=basis_gaps)}
            for key in sorted(groups)]


def _economic_cache_pairs(items, requested, contributions, bases, gaps):
    pairs = {item['fact']['row']['event_id']: item for item in items
             if item['fact']['row']['payload']['candidate_kind'] == 'cache_pair'}
    model_ops = {}
    for item in items:
        payload = item['fact']['row']['payload']
        if payload['candidate_kind'] == 'model_usage' and payload['operation'] is not None:
            model_ops[payload['operation']['physical_operation_digest']] = item
    result = []
    for ref in requested:
        if ref not in pairs:
            result.append({'pair_ref': ref, 'basis': None, 'status': 'partial', 'operation_sets_observed': False,
                           'normal': [], 'long': [], 'savings': [], 'unknown_reasons': ['not_observed'], 'source_refs': [ref]})
            continue
        item = pairs[ref]
        pair = item['fact']['row']['payload']
        reasons, providers, sets = set(gaps), set(), {}
        for side in ('normal', 'long'):
            identities = set()
            for operation in pair[side + '_operations']:
                identity = operation['physical_operation_digest']
                identities.add(identity)
                observed = model_ops.get(identity)
                if observed is None:
                    reasons.add('not_observed')
                    continue
                payload = observed['fact']['row']['payload']
                if payload['operation'] != operation or payload['cache_policy']['mode'] != side:
                    reasons.add('ambiguous')
                providers.add((payload['provider_id'], payload['model_id']))
            sets[side] = identities
        if len(providers) != 1:
            reasons.add('ambiguous')
        amounts = {}
        for side in ('normal', 'long'):
            amounts[side] = _economic_money_rows([(row, Fraction(1), set()) for row in contributions
                if row['operation'] is not None and row['operation']['physical_operation_digest'] in sets[side]],
                bases=bases, gaps=reasons)
        keys = {(row['basis'], row['currency']) for side in amounts.values() for row in side}
        savings = []
        for basis, currency in sorted(keys, key=lambda key: (key[0], key[1] or '')):
            normal = next((row for row in amounts['normal'] if row['basis'] == basis and row['currency'] == currency), None)
            long = next((row for row in amounts['long'] if row['basis'] == basis and row['currency'] == currency), None)
            unknown = set(reasons)
            for row in (normal, long):
                unknown.update(row['unknown_reasons'] if row else ['not_observed'])
            subtotal = sum(((_economic_fraction(normal['known_subtotal']) if normal else Fraction(0)),
                            -(_economic_fraction(long['known_subtotal']) if long else Fraction(0))))
            full = (_economic_fraction(normal['value']) - _economic_fraction(long['value'])
                    if normal and long and normal['value'] is not None and long['value'] is not None else None)
            savings.append({'basis': basis, 'currency': currency,
                            'value': _economic_rational(full) if full is not None and not unknown else None,
                            'known_subtotal': _economic_rational(subtotal), 'unknown_reasons': sorted(unknown),
                            'source_refs': sorted(set(normal['source_refs'] if normal else []) | set(long['source_refs'] if long else []))})
        result.append({'pair_ref': ref, 'basis': pair['basis'],
                       'status': 'ok' if not reasons and all(row['value'] is not None for row in savings) else 'partial',
                       'operation_sets_observed': not bool(reasons & {'not_observed', 'ambiguous'}),
                       'normal': amounts['normal'], 'long': amounts['long'], 'savings': savings,
                       'unknown_reasons': sorted(reasons), 'source_refs': sorted(item['refs'])})
    return result


def compute_economics(cut: EconomicsInput, request) -> ReportResult:
    """Calculate on supplied bounded inputs, with no read/import/authority effect.

    Actual host admission, qualified coverage and permission/release remain
    outside this pure function. read_report is deliberately unavailable.
    """
    started = (time.monotonic(), time.process_time())
    try:
        query = parse_report_query(request).as_dict()
    except EconomicsError:
        return _unavailable_economics('invalid_report_query', 'invalid_request')
    try:
        _economic_budget(started)
        cut = _snapshot_economics_input(cut, started)
        _economic_budget(started)
        facts = _known_economics(cut, query)
        items, bindings, conflicts, bad_operations, coalesced = _reconcile_economics(facts, cut['bindings'])
        tasks, selection_gaps = _selected_economic_tasks(cut, query, items)
        task_keys = {_task_key(task) for task in tasks}
        gaps = set(cut['gaps']) | set(selection_gaps) | _economic_attempt_gaps(items, bindings)
        if cut['census'] is None or not task_keys <= {_task_key(task) for task in cut['census']}:
            gaps.add('history_gap')
        if conflicts or bad_operations:
            gaps.add('conflicted')
        allocations, allocation_gaps = _economic_allocations(items, bindings)
        gaps.update(allocation_gaps)
        if any(_task_key(bound['task']) in task_keys and
               (bound['attempt_id'] is None or bound['outcome'] == 'unknown') for bound in bindings.values()):
            gaps.add('history_gap')
        contributions = _economic_contributions(items, started)
        currencies = {(row['basis'], row['currency']) for row in contributions}
        weighted, period_weighted, scope_period, unallocated = [], [], [], []
        by_task = {key: [] for key in task_keys}
        period_by_task = {key: [] for key in task_keys}
        for contribution in contributions:
            _economic_budget(started)
            shares, missing = _economic_shares(contribution['operation'], bindings, allocations)
            total_weight = sum((weight for _, weight in shares), Fraction(0))
            _economic_require(total_weight <= 1)
            extra = {missing} if missing else set()
            # The explicitly unallocated remainder is not silently assigned to
            # the original task or to every task named in a shared operation.
            if total_weight < 1:
                unallocated.append((contribution, 1 - total_weight, extra))
            in_period = _economic_period(contribution['period'], query['accounting_interval'])
            period_extra = {'ambiguous'} if in_period is None else set()
            if in_period is not False:
                scope_period.append((contribution, Fraction(1), period_extra))
            for key, weight in shares:
                if key not in task_keys or weight == 0:
                    continue
                row = (contribution, weight, extra | ({'unallocated'} if total_weight < 1 else set()))
                weighted.append(row)
                by_task[key].append(row)
                if in_period is not False:
                    period_row = (contribution, weight, row[2] | period_extra)
                    period_weighted.append(period_row)
                    period_by_task[key].append(period_row)
        bases = query['money_bases']
        missing_bases = _economic_basis_gaps(bindings, allocations, contributions, task_keys, bases)
        money = _economic_money_rows(weighted, bases=bases, gaps=gaps, currencies=currencies, basis_gaps=missing_bases)
        period_money = _economic_money_rows(period_weighted, bases=bases, gaps=gaps, currencies=currencies, basis_gaps=missing_bases)
        scope_missing = _economic_basis_gaps(bindings, allocations, contributions,
            {_task_key(bound['task']) for bound in bindings.values()}, bases)
        scope_money = _economic_money_rows(scope_period, bases=bases, gaps=gaps, currencies=currencies, basis_gaps=scope_missing)
        task_rows, state_gaps, usage = [], set(), []
        for task in tasks:
            _economic_budget(started)
            key = _task_key(task)
            states, missing = _economic_states(items, task, _economic_utc(query['as_of']))
            state_gaps.update(missing)
            attempts = _economic_task_attempts(task, bindings)
            local_gaps = set(gaps) | missing
            if any(item['attempt_id'] is None or item['outcome'] == 'unknown' for item in attempts):
                local_gaps.add('history_gap')
            measured = _economic_usage(items, key, bindings, allocations, local_gaps)
            usage.append(measured)
            selected_times = sorted(item['selected_at'] for item in cut['selections'] if item['task'] == task)
            task_rows.append({'task': task, 'selected_at': selected_times[0] if selected_times else None,
                              'attempts': attempts, **states,
                              'money': _economic_money_rows(by_task[key], bases=bases, gaps=local_gaps, currencies=currencies,
                                  basis_gaps=_economic_basis_gaps(bindings, allocations, contributions, {key}, bases)),
                              'usage': measured})
        # Source/census gaps and missing explicit dispositions censor the
        # denominator. A merge, completion or receipt never fills it in.
        accepted_known = (cut['census'] is not None and not cut['gaps'] and not selection_gaps and not state_gaps
                          and all(row['disposition'] in ('accepted', 'rejected', 'abandoned', 'revoked', 'reopened')
                                  for row in task_rows)
                          and task_keys <= {_task_key(task) for task in cut['census']})
        accepted_count = sum(row['disposition'] == 'accepted' for row in task_rows) if accepted_known else None
        accepted_keys = {_task_key(row['task']) for row in task_rows if row['disposition'] == 'accepted'}
        rejected_keys = {_task_key(row['task']) for row in task_rows if row['disposition'] in ('rejected', 'abandoned')}
        outcome_gaps = set() if accepted_known else {'outcome_unknown'}
        accepted_money = _economic_money_rows([row for key in accepted_keys for row in by_task[key]],
            bases=bases, gaps=gaps | state_gaps | outcome_gaps, currencies=currencies,
            basis_gaps=_economic_basis_gaps(bindings, allocations, contributions, accepted_keys, bases))
        rejected_money = _economic_money_rows([row for key in rejected_keys for row in by_task[key]],
            bases=bases, gaps=gaps | state_gaps | outcome_gaps, currencies=currencies,
            basis_gaps=_economic_basis_gaps(bindings, allocations, contributions, rejected_keys, bases))
        unsuccessful_rows = [row for key in accepted_keys for row in by_task[key] if row[0]['operation'] is not None
                             and bindings.get(row[0]['operation']['physical_operation_digest'], {}).get('outcome') in ('failed', 'cancelled')]
        unsuccessful_money = _economic_money_rows(unsuccessful_rows, bases=bases,
            gaps=gaps | state_gaps | outcome_gaps, currencies=currencies)
        ratios = {'accepted_tasks': accepted_count,
                  'accepted_task_mean': _economic_ratio_rows(accepted_money, accepted_count,
                      numerator_definition='accepted_task_lifetime_spend', denominator_definition='accepted_tasks',
                      cohort_definition=query['cohort']['kind']),
                  'cohort_spend_per_accepted': _economic_ratio_rows(money, accepted_count,
                      numerator_definition='selected_cohort_lifetime_spend', denominator_definition='accepted_tasks',
                      cohort_definition=query['cohort']['kind']),
                  'rejected_abandoned_share': _economic_ratio_rows(rejected_money, money,
                      numerator_definition='rejected_abandoned_lifetime_spend', denominator_definition='selected_cohort_lifetime_spend',
                      cohort_definition=query['cohort']['kind']),
                  'unsuccessful_attempt_spend': unsuccessful_money,
                  'unsuccessful_attempt_share': _economic_ratio_rows(unsuccessful_money, accepted_money,
                      numerator_definition='failed_cancelled_attempt_spend_inside_accepted_tasks',
                      denominator_definition='accepted_task_lifetime_spend', cohort_definition=query['cohort']['kind']),
                  'reasons': ['unknown_denominator'] if accepted_count is None else ['zero_denominator'] if accepted_count == 0 else []}
        query['snapshot_ref'], requested_snapshot = None, query['snapshot_ref']
        source_refs = sorted({ref for item in items for ref in item['refs']} | set(conflicts)
                             | {cut['source_cut_digest']})
        snapshot = digest({'definition_version': ECONOMICS_DEFINITION, 'query': query,
                           'source_cut_digest': cut['source_cut_digest'], 'facts': facts,
                           'bindings': sorted(cut['bindings'], key=_economic_json),
                           'selections': sorted(cut['selections'], key=_economic_json),
                           'census': sorted(cut['census'], key=_economic_json) if cut['census'] is not None else None,
                           'gaps': cut['gaps']})
        if requested_snapshot is not None and requested_snapshot != snapshot:
            return _unavailable_economics('snapshot_unavailable')
        cache = (_economic_cache_pairs(items, query['cache_pair_refs'], contributions, bases, gaps)
                 if 'cache_comparison' in query['views'] else [])
        friction = _economic_friction(items, task_keys, usage, gaps) if 'friction138' in query['views'] else None
        views = {}
        grouped = []
        if 'task_lifetime' in query['views']:
            views['task_lifetime'] = weighted
            grouped.extend(_economic_groups(by_task, query['group_by'], task_rows, bases, currencies, gaps, missing_bases))
        if 'period_spend' in query['views']:
            views.update(cohort_period_spend=period_weighted, scope_period_spend=scope_period)
            grouped.extend(_economic_groups(period_by_task, query['group_by'], task_rows, bases, currencies, gaps,
                                            missing_bases, view='cohort_period_spend'))
        complete = not gaps and not state_gaps
        if 'task_lifetime' in query['views']:
            complete = (complete and accepted_count is not None and all(row['value'] is not None for row in money)
                        and all(amount['value'] is not None for task in task_rows for amount in task['money']))
        if 'period_spend' in query['views']:
            complete = complete and all(row['value'] is not None for row in period_money + scope_money)
        if 'cache_comparison' in query['views']:
            complete = complete and bool(cache) and all(pair['status'] == 'ok' for pair in cache)
        if 'friction138' in query['views']:
            # No full commit/fast-path/evidence/defect census is supplied yet.
            complete = False
        result = {'definition_version': ECONOMICS_DEFINITION, 'status': 'ok' if complete else 'partial',
                  'calculation_only': True, 'query': query, 'snapshot_ref': snapshot, 'source_refs': source_refs,
                  'coverage': {'complete': complete, 'gaps': sorted(gaps | state_gaps),
                               'census_known': cut['census'] is not None, 'source_cut_digest': cut['source_cut_digest']},
                  'tasks': task_rows if 'task_lifetime' in query['views'] else [],
                  'totals': {'task_lifetime': money if 'task_lifetime' in query['views'] else [],
                             'cohort_period_spend': period_money if 'period_spend' in query['views'] else [],
                             'scope_period_spend': scope_money if 'period_spend' in query['views'] else []},
                  'ratios': ratios if 'task_lifetime' in query['views'] else None,
                  'reconciliation': {'conflict_count': len(conflicts), 'conflict_refs': conflicts,
                                     'coalesced_observations': coalesced,
                                     'unallocated': _economic_money_rows(unallocated, bases=bases, gaps=gaps, currencies=currencies)},
                  'cache_comparison': cache,
                  'fx_totals': _economic_fx(items, query['fx_refs'], views, bases, gaps, missing_bases),
                  'groups': grouped, 'friction138': friction,
                  'limitations': ['protected_read_unavailable', 'actual_producer_integration_pending']}
        prepared = ReportResult(_economic_json(result))
        _economic_budget(started)
        return prepared
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError, RuntimeError) as error:
        if type(error) is EconomicsError and str(error) == 'input_limit':
            return _unavailable_economics('input_limit')
        return _unavailable_economics('input_unavailable')


_RESULT_MONEY_FIELDS = frozenset({'basis', 'currency', 'value', 'known_subtotal', 'unknown_reasons', 'source_refs'})
_RESULT_RATIO_FIELDS = _RESULT_MONEY_FIELDS | {'numerator_value', 'numerator_known_subtotal', 'denominator',
    'numerator_definition', 'denominator_definition', 'cohort_definition', 'unit'}
_RESULT_REASONS = ECONOMICS_UNKNOWN | {'unknown_denominator', 'zero_denominator', 'outcome_unknown', 'unallocated'}


def _validate_money_result(rows, *, ratio=False):
    _economic_require(type(rows) is list and len(rows) <= 32)
    seen = set()
    for row in rows:
        _economic_object(row, _RESULT_RATIO_FIELDS if ratio else _RESULT_MONEY_FIELDS)
        _economic_require(row['basis'] in ('confirmed_billed', 'tariff_estimate')
                          and (row['currency'] is None or row['currency'] in ECONOMICS_CURRENCIES))
        identity = (row['basis'], row['currency'])
        _economic_require(identity not in seen)
        seen.add(identity)
        _economic_require(type(row['unknown_reasons']) is list
                          and all(reason in _RESULT_REASONS for reason in row['unknown_reasons']))
        _economic_require(type(row['source_refs']) is list and len(row['source_refs']) <= 8192)
        for ref in row['source_refs']:
            _economic_digest(ref)
        for key in ('value', 'known_subtotal'):
            if row[key] is not None:
                _economic_fraction(row[key])
        _economic_require(row['value'] is None or not row['unknown_reasons'] and row['currency'] is not None)
        _economic_require(row['value'] is None or row['value'] == row['known_subtotal'])
        if not ratio:
            _economic_fraction(row['known_subtotal'])
        else:
            if row['numerator_value'] is not None:
                _economic_fraction(row['numerator_value'])
            _economic_fraction(row['numerator_known_subtotal'])
            denominator = row['denominator']
            if type(denominator) is dict:
                _economic_fraction(denominator)
            elif denominator is not None:
                _economic_int(denominator, maximum=256)
            _economic_require(row['numerator_definition'] in ('accepted_task_lifetime_spend',
                'selected_cohort_lifetime_spend', 'rejected_abandoned_lifetime_spend',
                'failed_cancelled_attempt_spend_inside_accepted_tasks')
                and row['denominator_definition'] in ('accepted_tasks', 'selected_cohort_lifetime_spend', 'accepted_task_lifetime_spend')
                and row['cohort_definition'] in ('task_ids', 'selection_window', 'verified_pr_ids')
                and row['unit'] == ('currency_per_task' if row['denominator_definition'] == 'accepted_tasks' else 'fraction'))


def _validate_computed_economics(value):
    _economic_object(value, ('definition_version', 'status', 'calculation_only', 'query', 'snapshot_ref', 'source_refs',
        'coverage', 'tasks', 'totals', 'ratios', 'reconciliation', 'cache_comparison', 'friction138', 'fx_totals', 'groups', 'limitations'))
    _economic_require(value['definition_version'] == ECONOMICS_DEFINITION and value['status'] in ('ok', 'partial')
                      and value['calculation_only'] is True)
    _normalize_report_query(value['query'])
    _economic_digest(value['snapshot_ref'])
    _economic_require(type(value['source_refs']) is list and len(value['source_refs']) <= 8193)
    for ref in value['source_refs']:
        _economic_digest(ref)
    coverage = value['coverage']
    _economic_object(coverage, ('complete', 'gaps', 'census_known', 'source_cut_digest'))
    _economic_require(type(coverage['complete']) is bool and type(coverage['census_known']) is bool
                      and type(coverage['gaps']) is list and all(gap in ECONOMICS_UNKNOWN for gap in coverage['gaps']))
    _economic_require((value['status'] == 'ok') == coverage['complete'])
    _economic_digest(coverage['source_cut_digest'])
    _economic_require(type(value['tasks']) is list and len(value['tasks']) <= 256)
    for task in value['tasks']:
        _economic_object(task, ('task', 'selected_at', 'attempts', 'workflow_end', 'completion', 'merged', 'disposition', 'money', 'usage'))
        _economic_task(task['task'])
        if task['selected_at'] is not None:
            _economic_utc(task['selected_at'])
        _economic_require(task['workflow_end'] in (None, 'succeeded', 'failed', 'cancelled', 'unknown')
                          and task['completion'] in (None, 'completed', 'not_completed', 'unknown')
                          and (task['merged'] is None or task['merged'] is True)
                          and task['disposition'] in (None, 'accepted', 'rejected', 'abandoned', 'revoked', 'reopened', 'unknown'))
        _economic_require(type(task['attempts']) is list and len(task['attempts']) <= 4096)
        for attempt in task['attempts']:
            _economic_object(attempt, ('attempt_id', 'head', 'outcome', 'operation_refs'))
            _economic_id(attempt['attempt_id'], optional=True)
            _economic_require(attempt['head'] is None or type(attempt['head']) is str
                              and re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', attempt['head']))
            _economic_require(attempt['outcome'] in ('succeeded', 'failed', 'cancelled', 'unknown'))
            _economic_require(type(attempt['operation_refs']) is list and len(attempt['operation_refs']) <= 4096)
            for ref in attempt['operation_refs']:
                _economic_digest(ref)
        _validate_money_result(task['money'])
        _economic_require(type(task['usage']) is list and len(task['usage']) <= 32)
        for usage in task['usage']:
            _economic_object(usage, ('category', 'unit', 'value', 'known_subtotal', 'unknown_reasons', 'source_refs'))
            _economic_require(usage['category'] in (set(_TARIFF_UNITS) | {'input_total', 'elapsed', 'peak_rss'})
                              and usage['unit'] in ('token', 'cpu_ns', 'gpu_ns', 'elapsed_ns', 'microjoule', 'byte', 'runner_ns', 'human_ns'))
            if type(usage['value']) is dict:
                _economic_fraction(usage['value'])
            elif usage['value'] is not None:
                _economic_int(usage['value'], maximum=ECONOMICS_MAX_INTEGER * 4096)
            _economic_fraction(usage['known_subtotal'])
            _economic_require(type(usage['unknown_reasons']) is list
                              and all(reason in _RESULT_REASONS for reason in usage['unknown_reasons']))
            _economic_require(type(usage['source_refs']) is list)
            for ref in usage['source_refs']:
                _economic_digest(ref)
    _economic_object(value['totals'], ('task_lifetime', 'cohort_period_spend', 'scope_period_spend'))
    for rows in value['totals'].values():
        _validate_money_result(rows)
    ratios = value['ratios']
    if ratios is None:
        _economic_require('task_lifetime' not in value['query']['views'])
    else:
        _economic_require('task_lifetime' in value['query']['views'])
        _economic_object(ratios, ('accepted_tasks', 'accepted_task_mean', 'cohort_spend_per_accepted', 'rejected_abandoned_share',
                                  'unsuccessful_attempt_spend', 'unsuccessful_attempt_share', 'reasons'))
        if ratios['accepted_tasks'] is not None:
            _economic_int(ratios['accepted_tasks'], maximum=256)
        for key in ('accepted_task_mean', 'cohort_spend_per_accepted', 'rejected_abandoned_share', 'unsuccessful_attempt_share'):
            _validate_money_result(ratios[key], ratio=True)
        _validate_money_result(ratios['unsuccessful_attempt_spend'])
        _economic_require(type(ratios['reasons']) is list and all(reason in _RESULT_REASONS for reason in ratios['reasons']))
    reconciliation = value['reconciliation']
    _economic_object(reconciliation, ('conflict_count', 'conflict_refs', 'coalesced_observations', 'unallocated'))
    _economic_int(reconciliation['conflict_count'], maximum=4096)
    _economic_int(reconciliation['coalesced_observations'], maximum=4096)
    _economic_require(type(reconciliation['conflict_refs']) is list
                      and len(reconciliation['conflict_refs']) == reconciliation['conflict_count'])
    for ref in reconciliation['conflict_refs']:
        _economic_digest(ref)
    _validate_money_result(reconciliation['unallocated'])
    friction = value['friction138']
    if friction is None:
        _economic_require('friction138' not in value['query']['views'])
    else:
        _economic_require('friction138' in value['query']['views'])
        _economic_object(friction, ('human_decision_count', 'human_decision_known_subtotal', 'human_minutes',
            'human_minutes_known_subtotal', 'review_round_known_subtotal', 'approval_count_per_commit',
            'fast_path_coverage', 'evidence_added_lines', 'defect_catch_latency', 'unknown_reasons'))
        for key in ('human_decision_count', 'human_decision_known_subtotal', 'review_round_known_subtotal'):
            if friction[key] is not None:
                _economic_int(friction[key], maximum=4096)
        for key in ('human_minutes', 'human_minutes_known_subtotal'):
            if friction[key] is not None:
                _economic_fraction(friction[key])
        _economic_require(all(friction[key] is None for key in ('approval_count_per_commit', 'fast_path_coverage',
                                                               'evidence_added_lines', 'defect_catch_latency')))
        _economic_require(type(friction['unknown_reasons']) is list
                          and all(reason in _RESULT_REASONS for reason in friction['unknown_reasons']))
    _economic_require(type(value['groups']) is list and len(value['groups']) <= 256)
    for group in value['groups']:
        _economic_object(group, ('view', 'dimensions', 'amounts'))
        _economic_require(group['view'] in ('task_lifetime', 'cohort_period_spend'))
        _economic_object(group['dimensions'], value['query']['group_by'])
        for dimension, observed in group['dimensions'].items():
            if dimension == 'task':
                _economic_task(observed)
            elif dimension in ('provider', 'model'):
                _economic_id(observed, optional=True)
            else:
                allowed = {'cache_mode': (None, 'none', 'normal', 'long', 'unknown'),
                           'runner_kind': (None, 'managed', 'self_hosted', 'unknown'),
                           'disposition': (None, 'accepted', 'rejected', 'abandoned', 'revoked', 'reopened', 'unknown')}
                _economic_require(observed in allowed[dimension])
        _validate_money_result(group['amounts'])
    _economic_require(type(value['fx_totals']) is list and len(value['fx_totals']) <= 48)
    for converted in value['fx_totals']:
        _economic_object(converted, ('view', 'from_currency', 'to_currency', 'amounts', 'source_refs', 'unknown_reasons'))
        _economic_require(converted['view'] in value['totals'])
        for key in ('from_currency', 'to_currency'):
            _economic_require(converted[key] is None or converted[key] in ECONOMICS_CURRENCIES)
        _validate_money_result(converted['amounts'])
        _economic_require(type(converted['source_refs']) is list)
        for ref in converted['source_refs']:
            _economic_digest(ref)
        _economic_require(type(converted['unknown_reasons']) is list
                          and all(reason in _RESULT_REASONS for reason in converted['unknown_reasons']))
    _economic_require(type(value['cache_comparison']) is list and len(value['cache_comparison']) <= 16)
    for pair in value['cache_comparison']:
        _economic_object(pair, ('pair_ref', 'basis', 'status', 'operation_sets_observed', 'normal', 'long', 'savings',
                                'unknown_reasons', 'source_refs'))
        _economic_digest(pair['pair_ref'])
        _economic_require(pair['basis'] in (None, 'actual_pair', 'explicit_scenario')
                          and pair['status'] in ('ok', 'partial') and type(pair['operation_sets_observed']) is bool)
        for key in ('normal', 'long', 'savings'):
            _validate_money_result(pair[key])
        _economic_require(type(pair['source_refs']) is list)
        for ref in pair['source_refs']:
            _economic_digest(ref)
        _economic_require(type(pair['unknown_reasons']) is list
                          and all(reason in _RESULT_REASONS for reason in pair['unknown_reasons']))
    _economic_require(value['limitations'] == ['protected_read_unavailable', 'actual_producer_integration_pending'])
    if 'task_lifetime' not in value['query']['views']:
        _economic_require(value['tasks'] == [] and value['totals']['task_lifetime'] == [])
    if 'period_spend' not in value['query']['views']:
        _economic_require(value['totals']['cohort_period_spend'] == [] and value['totals']['scope_period_spend'] == [])
    if 'cache_comparison' not in value['query']['views']:
        _economic_require(value['cache_comparison'] == [])
    if coverage['complete']:
        _economic_require(coverage['census_known'] and not coverage['gaps'])
        if 'task_lifetime' in value['query']['views']:
            _economic_require(ratios is not None and ratios['accepted_tasks'] is not None
                              and bool(value['totals']['task_lifetime'])
                              and all(row['value'] is not None for row in value['totals']['task_lifetime']))
        if 'period_spend' in value['query']['views']:
            _economic_require(bool(value['totals']['cohort_period_spend']) and bool(value['totals']['scope_period_spend'])
                              and all(row['value'] is not None for name in ('cohort_period_spend', 'scope_period_spend')
                                      for row in value['totals'][name]))
        if 'cache_comparison' in value['query']['views']:
            _economic_require(bool(value['cache_comparison']) and all(pair['status'] == 'ok' for pair in value['cache_comparison']))
        _economic_require('friction138' not in value['query']['views'])
