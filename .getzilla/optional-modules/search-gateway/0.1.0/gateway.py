"""One serialized policy, admission, budget, cache and provenance path for every interface."""
from __future__ import annotations

from typing import TYPE_CHECKING
import json
import math
import re
import time

if TYPE_CHECKING:
    # Immutable source loading composes these reviewed contracts in one namespace.
    from .providers import (PROVIDERS, MAX_RESPONSE_BYTES, eligible,
                            guarded_transport, normalize_results, provider_request, TransportFailure, urlsplit)

from collections import OrderedDict
import copy
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import threading
import uuid


def _integer(value, lower, upper):
    return type(value) is int and lower <= value <= upper


def validate_policy(config):
    allowed = {'schema_version', 'live_enabled', 'project', 'max_attempts', 'max_estimated_cost_microusd',
               'timeout_seconds', 'cache_ttl_seconds', 'cache_entries', 'cache_bytes', 'http_enabled',
               'mcp_enabled', 'providers'}
    if (type(config) is not dict or set(config) != allowed or config['schema_version'] != 1
            or any(type(config[name]) is not bool for name in ('live_enabled', 'http_enabled', 'mcp_enabled'))
            or type(config['project']) is not str or not re.fullmatch(r'[\w.-]{1,128}', config['project'])
            or not _integer(config['max_attempts'], 1, 7)
            or not _integer(config['max_estimated_cost_microusd'], 0, 10**12)
            or type(config['timeout_seconds']) not in (int, float)
            or not math.isfinite(config['timeout_seconds']) or not 0 < config['timeout_seconds'] <= 60
            or not _integer(config['cache_ttl_seconds'], 0, 3600)
            or not _integer(config['cache_entries'], 0, 1024)
            or not _integer(config['cache_bytes'], 0, 16*1024*1024)
            or type(config['providers']) is not list or len(config['providers']) > 7):
        raise ValueError('invalid_policy')
    seen = set()
    for provider in config['providers']:
        if (type(provider) is not dict or not {'id'} <= set(provider)
                or not set(provider) <= {'id', 'credential', 'estimated_unit_cost_microusd', 'endpoint'}
                or provider['id'] not in PROVIDERS or provider['id'] in seen):
            raise ValueError('invalid_policy')
        seen.add(provider['id'])
        if 'credential' in provider and (type(provider['credential']) is not str
                or len(provider['credential']) > 4096 or any(ord(c) < 32 for c in provider['credential'])):
            raise ValueError('invalid_policy')
        if 'estimated_unit_cost_microusd' in provider and not _integer(provider['estimated_unit_cost_microusd'], 0, 10**12):
            raise ValueError('invalid_policy')
        if provider['id'] == 'searxng':
            try:
                endpoint = urlsplit(provider.get('endpoint', ''))
                valid = (endpoint.scheme in ('http', 'https') and endpoint.hostname and not endpoint.username
                         and not endpoint.password and not endpoint.query and not endpoint.fragment
                         and len(provider['endpoint']) <= 2048)
                endpoint.port
            except (ValueError, TypeError):
                valid = False
            if not valid:
                raise ValueError('invalid_policy')
        elif 'endpoint' in provider:
            raise ValueError('invalid_policy')
    return copy.deepcopy(config)


def validate_request(value):
    if type(value) is str:
        value = {'query': value}
    allowed = {'schema_version', 'operation', 'query', 'provider', 'engine', 'limit', 'country', 'language'}
    if type(value) is not dict or set(value) - allowed or 'query' not in value:
        raise ValueError('invalid_request')
    query = value['query']
    if (type(query) is not str or not query.strip() or len(query.encode('utf-8')) > 8192
            or any((ord(c) < 32 and c not in '\n\r\t') or 127 <= ord(c) <= 159 for c in query)
            or value.get('schema_version', 1) != 1 or type(value.get('schema_version', 1)) is not int
            or value.get('operation', 'web_search') != 'web_search'
            or value.get('provider', 'auto') not in (*PROVIDERS, 'auto')
            or value.get('engine', 'auto') not in ('auto', 'google', 'baidu', 'yandex')
            or not _integer(value.get('limit', 5), 1, 10)):
        raise ValueError('invalid_request')
    result = {'query': query, 'provider': value.get('provider', 'auto'), 'engine': value.get('engine', 'auto'),
              'limit': value.get('limit', 5), 'country': value.get('country'), 'language': value.get('language')}
    for field, pattern in (('country', r'[a-z]{2}'), ('language', r'[a-z]{2,3}(?:-[a-z]{2,4})?')):
        item = result[field]
        if item is not None:
            if type(item) is not str or not re.fullmatch(pattern, item.lower()):
                raise ValueError('invalid_request')
            result[field] = item.lower()
    return result


class Gateway:
    def __init__(self, config, *, admission, transport=None, clock=None, live_policy=None):
        self.config = validate_policy(config)
        self.authority_fingerprint = hashlib.sha256(json.dumps(self.config, sort_keys=True).encode()).hexdigest()
        self.live_policy = live_policy or (lambda: True)
        self.admission = admission
        self.transport = transport or guarded_transport
        self.clock = clock or time.monotonic
        self.lock = threading.RLock()
        self.cache = OrderedDict()
        self.health = {}

    def __repr__(self):
        return '<Getzilla search gateway>'

    def web_search(self, value):
        with self.lock:
            return self._search(value)

    def _search(self, value):
        started = self.clock()
        result = {'schema_version': 1, 'request_id': uuid.uuid4().hex, 'status': 'error',
                  'operation': 'web_search', 'results': [], 'attempts': [], 'warnings': [],
                  'cache': {'hit': False, 'fetched_at': None, 'origin_request_id': None},
                  'usage': {'attempted_calls': 0, 'reserved_estimated_cost_microusd': 0,
                            'actual_cost_microusd': None, 'elapsed_ms': 0, 'skipped_providers': []}}
        def finish(error=None):
            result['usage']['elapsed_ms'] = max(0, round((self.clock()-started)*1000))
            if error:
                result['error'] = error
            return result
        try:
            # Admission is checked before query validation, cache lookup and transport.
            if self.admission() is not True:
                return finish('module_unavailable')
            config = validate_policy(self.config)
            if not config['live_enabled']:
                return finish('live_policy_disabled')
            if (hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest() != self.authority_fingerprint
                    or self.live_policy() is not True):
                return finish('live_policy_changed')
            request = validate_request(value)
        except (ValueError, TypeError, UnicodeError):
            return finish('invalid_request')
        except Exception:
            return finish('module_unavailable')
        result.update(query=request['query'], requested_engine=request['engine'],
                      country=request['country'], language=request['language'])
        usage = result['usage']
        usage['limits'] = {name: config[name] for name in ('max_attempts', 'max_estimated_cost_microusd', 'timeout_seconds')}
        # Fingerprint includes operator-owned project, provider order, prices and credentials.
        fingerprint = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
        cache_key = fingerprint + json.dumps(request, ensure_ascii=False, sort_keys=True)
        cached = self.cache.get(cache_key)
        if cached is not None and self.clock() - cached[0] < config['cache_ttl_seconds']:
            self.cache.move_to_end(cache_key)
            evidence = copy.deepcopy(cached[1])
            result.update(status='ok', results=evidence['results'], warnings=evidence['warnings'])
            result['cache'] = {'hit': True, 'fetched_at': evidence['fetched_at'],
                               'origin_request_id': evidence['request_id']}
            return finish()
        plan = []
        for provider in config['providers']:
            name = provider['id']
            reason = None
            if request['provider'] not in ('auto', name) or not eligible(provider, request):
                reason = 'constraint_mismatch'
            elif provider.get('estimated_unit_cost_microusd') is None:
                reason = 'missing_estimate'
            elif name != 'searxng' and not provider.get('credential'):
                reason = 'missing_credentials'
            else:
                health = self.health.get((fingerprint, name))
                if health and (health[0] is None or health[0] > self.clock()):
                    reason = health[1]
            if reason:
                usage['skipped_providers'].append({'provider': name, 'reason': reason})
            else:
                plan.append(provider)
        if not plan:
            return finish('no_eligible_provider')
        deadline = started + config['timeout_seconds']
        for provider in plan:
            estimate = provider['estimated_unit_cost_microusd']
            remaining = deadline - self.clock()
            if (usage['attempted_calls'] >= config['max_attempts']
                    or usage['reserved_estimated_cost_microusd'] + estimate > config['max_estimated_cost_microusd']):
                return finish('budget_exhausted')
            if remaining <= 0:
                return finish('deadline_exhausted')
            try:
                if self.admission() is not True:
                    return finish('module_unavailable')
                if self.live_policy() is not True or not self.config['live_enabled']:
                    return finish('live_policy_changed')
                wire = provider_request(provider, request)
            except Exception:
                return finish('module_unavailable')
            # Admission, policy I/O and wire construction consume the same elapsed budget.
            remaining = deadline - self.clock()
            if remaining <= 0:
                return finish('deadline_exhausted')
            usage['attempted_calls'] += 1
            usage['reserved_estimated_cost_microusd'] += estimate
            attempted = self.clock()
            attempt = {'provider': provider['id'], 'http_status': None, 'outcome': 'transport_error',
                       'reserved_estimated_cost_microusd': estimate, 'actual_cost_microusd': None,
                       'elapsed_ms': 0, 'retryable': False, 'cooldown_seconds': None}
            result['attempts'].append(attempt)
            name = provider['id']
            try:
                status, headers, raw = self.transport(wire, remaining)
                if self.clock() >= deadline:
                    raise TimeoutError()
                attempt['http_status'] = status
                if type(raw) is not bytes or len(raw) > MAX_RESPONSE_BYTES:
                    raise TransportFailure('response_too_large')
                if 300 <= status < 400:
                    raise TransportFailure('redirect_refused')
                if status != 200:
                    attempt['outcome'] = {401:'invalid_credentials', 402:'quota_exhausted', 403:'forbidden',
                                          429:'rate_limited'}.get(status, 'upstream_error' if status >= 500 else 'upstream_rejected')
                    if status in (401, 402):
                        self.health[(fingerprint, name)] = (None, attempt['outcome'])
                    elif status == 429 or status >= 500:
                        cooldown = self._cooldown(headers) if status == 429 else 5
                        self.health[(fingerprint, name)] = (self.clock()+cooldown, attempt['outcome'])
                        attempt.update(retryable=True, cooldown_seconds=cooldown)
                    continue
                fetched_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
                rows, warnings = normalize_results(name, raw, request, wire['engine'], fetched_at)
                result.update(status='ok', results=rows, warnings=warnings)
                result['cache'].update(fetched_at=fetched_at, origin_request_id=result['request_id'])
                attempt['outcome'] = 'ok'
                evidence = {'results': rows, 'warnings': warnings, 'fetched_at': fetched_at,
                            'request_id': result['request_id']}
                self.cache[cache_key] = (self.clock(), copy.deepcopy(evidence))
                while self.cache and (len(self.cache) > config['cache_entries']
                        or sum(len(json.dumps(item).encode()) for item in self.cache.values()) > config['cache_bytes']):
                    self.cache.popitem(last=False)
                return finish()
            except TimeoutError:
                attempt['outcome'] = 'timeout'
                self.health[(fingerprint, name)] = (self.clock()+5, 'timeout')
                attempt['retryable'] = True
            except TransportFailure as error:
                code = error.args[0] if error.args else ''
                attempt['outcome'] = code if code in ('redirect_refused', 'response_too_large', 'invalid_destination') else 'transport_error'
            except (ValueError, TypeError, KeyError, UnicodeError):
                attempt['outcome'] = 'provider_schema_error'
            except Exception:
                attempt['outcome'] = 'transport_error'
                self.health[(fingerprint, name)] = (self.clock()+5, 'transport_error')
                attempt['retryable'] = True
            finally:
                attempt['elapsed_ms'] = max(0, round((self.clock()-attempted)*1000))
        return finish('providers_failed')

    def _cooldown(self, headers):
        value = next((v for k,v in headers.items() if k.lower() == 'retry-after'), '')
        try:
            if type(value) is str and re.fullmatch(r'\d{1,12}', value):
                return int(value)
            parsed = parsedate_to_datetime(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return max(0, (parsed - datetime.now(timezone.utc)).total_seconds())
        except (ValueError, TypeError, OverflowError):
            return 60
