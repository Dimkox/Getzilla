"""Build a bounded text-only Responses request and estimate its reservation.

Live dispatch is disabled until the exact data and recipient are authorized.
The token and rate bounds are operator assertions, not provider price evidence.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, ROUND_CEILING, localcontext


class RequestError(ValueError):
    """A fixed diagnostic that never includes request text."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate_key')
        result[key] = value
    return result


def classify_response(status: int, body: bytes, *, model: str | None = None) -> str:
    """Classify only a complete, bounded HTTP response; never inspect text."""
    if type(status) is not int or type(body) is not bytes or len(body) > 1048576:
        return 'unknown'
    try:
        value = json.loads(body, object_pairs_hook=_unique_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError('constant')))
        if not isinstance(value, dict):
            return 'unknown'
        if status == 200 and isinstance(model, str) and model and value.get('object') == 'response' and value.get('status') == 'completed' and value.get('model') == model and value.get('error') is None:
            output = value.get('output')
            if not isinstance(output, list) or not output:
                return 'unknown'
            saw_message = False
            for item in output:
                if not isinstance(item, dict) or item.get('type') not in {'message', 'reasoning'}:
                    return 'unknown'
                if item['type'] == 'message':
                    saw_message = True
                    content = item.get('content')
                    if item.get('role') != 'assistant' or not isinstance(content, list) or not content:
                        return 'unknown'
                    if any(not isinstance(part, dict) or part.get('type') != 'output_text' or not isinstance(part.get('text'), str) for part in content):
                        return 'unknown'
            return 'success' if saw_message else 'unknown'
        if not isinstance(value.get('error'), dict):
            return 'unknown'
        error = value['error']
        kind, code = error.get('type'), error.get('code')
        if not isinstance(kind, str) or not isinstance(code, str):
            return 'unknown'
        if status in (401, 403) or (status == 429 and code in {'insufficient_quota', 'credit_balance_exhausted',
                'organization_spend_limit_exceeded', 'project_spend_limit_exceeded', 'organization_usage_limit_exceeded'}):
            return 'needs_action'
        if status == 429 and kind == 'rate_limit_error' and code in {'slow_down', 'rate_limit_exceeded'}:
            return 'rate_limit'
        if status == 503 and kind == 'service_unavailable_error' and code == 'server_is_overloaded':
            return 'provider_unavailable'
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return 'unknown'
    return 'unknown'


@dataclass(frozen=True)
class Contract:
    model: str
    account_ref: str
    max_input_bytes: int
    max_input_tokens: int
    max_output_tokens: int
    input_usd_per_million: str
    output_usd_per_million: str
    rate_revision: str
    expires_epoch: int
    schema_version: int = 1


@dataclass(frozen=True, repr=False)
class PreparedRequest:
    body: bytes
    reserved_cost_micros: int


def _rate(value: str) -> Decimal:
    if not isinstance(value, str) or len(value) > 64:
        raise RequestError('invalid_rate')
    try:
        result = Decimal(value)
        if not result.is_finite() or not Decimal('0.000000001') <= result <= 1000000:
            raise RequestError('invalid_rate')
        return result
    except InvalidOperation:
        raise RequestError('invalid_rate') from None


def prepare(contract: Contract, text: str) -> PreparedRequest:
    """Prepare data only; the caller must establish durable live authority."""
    if type(contract) is not Contract or not isinstance(contract.model, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}', contract.model):
        raise RequestError('invalid_model')
    if not isinstance(contract.account_ref, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', contract.account_ref):
        raise RequestError('invalid_account')
    if (contract.schema_version != 1 or type(contract.schema_version) is not int
            or not isinstance(contract.rate_revision, str)
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', contract.rate_revision)
            or type(contract.expires_epoch) is not int or not 0 < contract.expires_epoch <= 253402300799):
        raise RequestError('invalid_rate_contract')
    for value in (contract.max_input_bytes, contract.max_input_tokens, contract.max_output_tokens):
        if type(value) is not int or not 0 < value <= 1_000_000:
            raise RequestError('invalid_bound')
    input_rate = _rate(contract.input_usd_per_million)
    output_rate = _rate(contract.output_usd_per_million)
    if not isinstance(text, str):
        raise RequestError('invalid_input')
    try:
        if len(text.encode('utf-8')) > contract.max_input_bytes:
            raise RequestError('input_too_large')
        body = json.dumps({'model': contract.model, 'input': text,
            'max_output_tokens': contract.max_output_tokens, 'store': False},
            sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    except UnicodeError:
        raise RequestError('invalid_input') from None
    with localcontext() as context:
        context.prec = 128
        cost = input_rate * contract.max_input_tokens + output_rate * contract.max_output_tokens
        micros = int(cost.to_integral_value(rounding=ROUND_CEILING))
    return PreparedRequest(body, micros)


def dispatch(root, binding, contract, request, generation, revision, credential):
    """Refuse before a claim or network access until data admission exists."""
    raise RequestError('data_admission_unavailable')


def _data_admission_available() -> bool:
    """No live data-admission boundary is implemented."""
    return False


def start_rotation(root, binding, contracts, text, budget, credentials):
    """Start a direct text-only chain; no native harness continuation is implied."""
    from . import model_continuation_state as journal
    if not _data_admission_available():
        raise RequestError('data_admission_unavailable')
    if not isinstance(contracts, tuple) or not contracts or len(contracts) > 64 or type(credentials) is not dict:
        raise RequestError('invalid_rotation')
    first = contracts[0]
    request = prepare(first, text)
    credential = credentials.get(first.account_ref)
    _transport_input(request, credential, 1)
    created = journal.create_model_only_chain(root, binding, first, request, budget)
    return _drive_rotation(root, binding, contracts, text, credentials, first, request,
                           created['generation'], created['revision'])


def resume_rotation(root, binding, contracts, text, credentials):
    """Resume only a durably failed attempt; unknown sends are never replayed."""
    from . import model_continuation_state as journal
    if not _data_admission_available():
        raise RequestError('data_admission_unavailable')
    if not isinstance(contracts, tuple) or not contracts or len(contracts) > 64 or type(credentials) is not dict:
        raise RequestError('invalid_rotation')
    chain = journal.inspect_chain(root, binding)
    if chain.get('domain') != 'live_model_only_v1':
        raise RequestError('invalid_rotation')
    state = chain['attempts'][-1]['state']
    if state == 'succeeded':
        return {'state': 'succeeded', 'body': None}
    if state != 'failed':
        return {'state': 'unknown', 'body': None}
    index = chain['generation']
    if index >= len(contracts):
        return {'state': 'exhausted', 'body': None}
    contract = contracts[index]
    request = prepare(contract, text)
    credential = credentials.get(contract.account_ref)
    _transport_input(request, credential, 1)
    reserved = journal.reserve_model_only_next(root, binding, contract, request, chain['revision'])
    if reserved['state'] != 'reserved_unknown':
        return {'state': reserved['reason'], 'body': None}
    return _drive_rotation(root, binding, contracts, text, credentials, contract, request,
                           reserved['generation'], reserved['revision'])


def _drive_rotation(root, binding, contracts, text, credentials, contract, request, generation, revision):
    from . import model_continuation_state as journal
    try:
        _, body = dispatch(root, binding, contract, request, generation, revision, credentials[contract.account_ref])
    except RequestError:
        return {'state': 'unknown', 'body': None}
    chain = journal.inspect_chain(root, binding)
    if chain['attempts'][-1]['state'] == 'succeeded':
        return {'state': 'succeeded', 'body': body}
    if chain['attempts'][-1]['state'] == 'failed':
        return resume_rotation(root, binding, contracts, text, credentials)
    return {'state': 'unknown', 'body': None}


def _transport_input(request: PreparedRequest, credential: str, timeout: float):
    if (type(request) is not PreparedRequest or not isinstance(credential, str)
            or not credential or len(credential) > 4096 or not re.fullmatch(r'[\x21-\x7e]+', credential)
            or type(timeout) not in (int, float) or not 0 < timeout <= 120):
        raise RequestError('invalid_transport_input')


def _retry_delay(headers) -> int | None:
    if not isinstance(headers, list):
        return None
    matches = []
    for item in headers:
        if not isinstance(item, tuple) or len(item) != 2 or not all(isinstance(v, str) for v in item):
            return None
        if item[0].lower() == 'retry-after':
            matches.append(item[1])
    if not matches:
        return 0
    if len(matches) != 1 or not re.fullmatch(r'[0-9]{1,5}', matches[0]):
        return None
    delay = int(matches[0])
    return delay if delay <= 86400 else None
