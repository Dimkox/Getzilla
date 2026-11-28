"""Opt-in candidate admission, without settings writes or model dispatch.

Price observations are operator-supplied policy inputs, not attestations. A
native adapter must independently establish current provider facts and enforce
this boundary for every writer, reviewer, auxiliary and fallback call.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation


@dataclass(frozen=True)
class Admission:
    profile: str
    observed_epoch: int
    expires_epoch: int
    # Immutable canonical price facts keep continuation's policy digest bound.
    models: tuple[tuple[str, tuple[tuple[str, str], ...]], ...]


@dataclass(frozen=True)
class LocalAdmission:
    profile: str
    endpoint: str
    client_version: str
    server_version: str
    os: str
    resources: tuple[tuple[str, int], ...]
    models: tuple[tuple[str, tuple[tuple[str, object], ...]], ...]


def _local(value: dict, candidates: tuple) -> LocalAdmission:
    if (set(value) != {'profile', 'endpoint', 'network', 'client', 'client_version',
                      'server_version', 'os', 'resources', 'models'}
            or value['endpoint'] != 'http://127.0.0.1:11434/v1'
            or value['network'] != 'closed' or value['client'] != 'qwen'
            or type(value['os']) is not str
            or value['os'] not in {'linux-x64', 'linux-arm64', 'macos-x64', 'macos-arm64', 'windows-x64'}
            or any(type(value[key]) is not str or not re.fullmatch(r'\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._-]+)?', value[key])
                   for key in ('client_version', 'server_version'))):
        raise ValueError('local_profile_invalid')
    resources = value['resources']
    if (not isinstance(resources, dict) or set(resources) != {'memory_bytes', 'disk_bytes', 'max_output_bytes'}
            or any(type(v) is not int or not 0 < v <= 10**15 for v in resources.values())):
        raise ValueError('local_resource_limit_invalid')
    models = value['models']
    if not isinstance(models, list) or not 1 <= len(models) <= 64:
        raise ValueError('local_models_invalid')
    catalog = {}
    for row in models:
        if (not isinstance(row, dict) or set(row) != {'id', 'digest', 'tokenizer', 'format',
                                                    'quantization', 'context_tokens', 'tools'}
                or type(row['id']) is not str or row['id'] in catalog
                or row['id'].endswith(':cloud')
                or type(row['digest']) is not str or not re.fullmatch(r'[a-f0-9]{64}', row['digest'])
                or type(row['context_tokens']) is not int or not 0 < row['context_tokens'] <= 10**7
                or row['tools'] is not True
                or any(type(row[k]) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', row[k])
                       or row[k] in {'unknown', 'latest'} for k in ('tokenizer', 'format', 'quantization'))):
            raise ValueError('local_model_capability_unknown')
        catalog[row['id']] = tuple(sorted(row.items()))
    if (set(catalog) != {candidate.model for candidate in candidates}
            or any(c.provider != 'ollama' or c.account_ref != 'local' for c in candidates)):
        raise ValueError('local_external_or_unknown_candidate')
    return LocalAdmission('ollama-local-qwen', value['endpoint'], value['client_version'],
                          value['server_version'], value['os'], tuple(sorted(resources.items())),
                          tuple(sorted(catalog.items())))


def _zero(value: object) -> bool:
    if (type(value) is not str or len(value) > 32
            or not re.fullmatch(r'0+(?:\.0+)?', value)):
        return False
    try:
        return Decimal(value).is_finite() and Decimal(value) == 0
    except InvalidOperation:
        return False


def parse_admission(value: object, candidates: tuple) -> Admission | LocalAdmission:
    """Validate the complete candidate set before any continuation reservation.

Require exact free variants and zero prices, including every additional price
component supplied by the provider. Missing mandatory rates remain unknown.
No router alias, caller role or fallback path expands the admitted set.
"""
    if isinstance(value, dict) and value.get('profile') == 'ollama-local-qwen':
        return _local(value, candidates)
    if (not isinstance(value, dict) or set(value) != {
            'profile', 'observed_epoch', 'expires_epoch', 'models'}
            or value['profile'] != 'openrouter-free'):
        raise ValueError('admission_profile_invalid')
    observed, expires = value['observed_epoch'], value['expires_epoch']
    if (type(observed) is not int or type(expires) is not int
            or not 0 < observed < expires <= observed + 300
            or not observed <= time.time() < expires):
        raise ValueError('admission_observation_stale')
    models = value['models']
    if not isinstance(models, list) or not 1 <= len(models) <= 64:
        raise ValueError('admission_models_invalid')
    catalog = {}
    for row in models:
        if (not isinstance(row, dict) or set(row) != {'id', 'pricing'}
                or type(row['id']) is not str or row['id'] in catalog):
            raise ValueError('admission_model_invalid')
        pricing = row['pricing']
        if (not isinstance(pricing, dict) or not {'prompt', 'completion', 'request'} <= set(pricing)
                or len(pricing) > 32
                or any(type(key) is not str or not re.fullmatch(r'[a-z_]{1,64}', key)
                       or not _zero(rate) for key, rate in pricing.items())):
            raise ValueError('admission_price_unknown_or_paid')
        catalog[row['id']] = tuple(sorted(pricing.items()))
    if set(catalog) != {candidate.model for candidate in candidates}:
        raise ValueError('admission_inventory_mismatch')
    if any(candidate.provider != 'openrouter'
           or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*:free', candidate.model)
           for candidate in candidates):
        raise ValueError('admission_candidate_denied')
    return Admission('openrouter-free', observed, expires, tuple(sorted(catalog.items())))


def onboarding_status(root) -> dict:
    """Read declared facts only; never probe settings, models or credentials."""
    from .model_continuation import load_policy
    loaded = load_policy(root)
    admission = loaded.policy.admission if loaded.policy else None
    result = {'schema_version': 1, 'policy_state': loaded.state,
              'profile': admission.profile if admission else None,
              'qualification': 'NOT_TESTED', 'dispatch_permitted': False,
              'network_isolation_verified': False, 'real_task_accepted': False,
              'reason': 'adapter_not_qualified' if admission else loaded.reason}
    if isinstance(admission, LocalAdmission):
        result['declared_matrix'] = {
            'client': 'qwen', 'client_version': admission.client_version,
            'server': 'ollama', 'server_version': admission.server_version,
            'os': admission.os, 'endpoint': admission.endpoint,
            'resources': dict(admission.resources),
            'models': [dict(facts) for _, facts in admission.models]}
    return result


class OpenRouterFixtureTransport:
    """Supply the selected model's scripted price observation and reply without I/O."""

    def price_observation(self, model, step):
        return step['observation']

    def request(self, model, step):
        return step['outcome']


def rehearse_openrouter(root, model: str, steps: list, *, transport=None) -> dict:
    """Replay fixture replies for one selected model. Checkpoints count completed steps."""
    from .model_continuation import load_policy
    policy = load_policy(root).policy
    if (policy is None or not policy.enabled or not isinstance(policy.admission, Admission)
            or model not in {candidate.model for candidate in policy.candidates}):
        raise ValueError('openrouter_free_model_not_configured')
    if type(steps) is not list or not steps:
        raise ValueError('fixture_steps_required')
    result = {'model': model, 'checkpoint': 0, 'requests': 0, 'qualification': 'NOT_TESTED',
              'dispatch_permitted': False, 'reason': 'complete'}
    transport = OpenRouterFixtureTransport() if transport is None else transport
    deadline = time.monotonic() + policy.bounds.deadline_seconds
    for step in steps:
        if result['requests'] >= policy.bounds.max_requests or time.monotonic() >= deadline:
            result['reason'] = 'request_budget_exhausted'
            break
        if (not isinstance(step, dict) or set(step) != {'role', 'observation', 'outcome'}
                or step['role'] not in ('writer', 'helper', 'reviewer', 'fallback')
                or step['outcome'] not in ('ok', '429', 'quota_exhausted', 'cancelled')):
            result['reason'] = 'fixture_request_invalid'
            break
        try:
            facts = parse_admission(transport.price_observation(model, step), policy.candidates)
            if not isinstance(facts, Admission):
                raise ValueError('openrouter_price_required')
        except ValueError as exc:
            result['reason'] = str(exc)
            break
        if time.monotonic() >= deadline:
            result['reason'] = 'request_budget_exhausted'
            break
        result['requests'] += 1
        outcome = transport.request(model, step)
        if outcome != 'ok':
            result['reason'] = outcome if outcome in ('429', 'quota_exhausted', 'cancelled') else 'invalid_reply'
            break
        result['checkpoint'] += 1
    return result
