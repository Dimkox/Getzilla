"""Build a bounded text-only Responses request and estimate its reservation.

Direct dispatch consumes a durable one-shot claim before one HTTPS request.
The token and rate bounds are operator assertions, not provider price evidence.
"""
from __future__ import annotations

import json
import re
import http.client
import time
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, ROUND_CEILING, localcontext


class RequestError(ValueError):
    """A fixed diagnostic that never includes request text."""


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
    """Consume a durable model-only request before one HTTPS attempt.

    This direct text adapter does not authorize native harness continuation.
    """
    from . import model_continuation_state as journal
    _transport_input(request, credential, 1)
    claim = journal.consume_model_only_request(root, binding, contract, request, generation, revision)
    if not claim['claimed']:
        raise RequestError('request_not_admitted')
    if not journal.check_model_only_request(root, binding, contract, request, generation, claim['revision']):
        raise RequestError('request_not_admitted')
    remaining = claim['deadline'] - journal.time.time()
    if remaining <= 0:
        raise RequestError('deadline_exhausted')
    return _post_once(request, credential, min(remaining, 120))


def _transport_input(request: PreparedRequest, credential: str, timeout: float):
    if (type(request) is not PreparedRequest or not isinstance(credential, str)
            or not credential or len(credential) > 4096 or not re.fullmatch(r'[\x21-\x7e]+', credential)
            or type(timeout) not in (int, float) or not 0 < timeout <= 120):
        raise RequestError('invalid_transport_input')


def _post_once(request: PreparedRequest, credential: str, timeout: float):
    """One fixed-destination HTTP operation; callers must first consume admission."""
    _transport_input(request, credential, timeout)
    connection = http.client.HTTPSConnection('api.openai.com', timeout=timeout)
    deadline = time.monotonic() + timeout
    try:
        connection.request('POST', '/v1/responses', body=request.body,
            headers={'Authorization': 'Bearer ' + credential, 'Content-Type': 'application/json'})
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RequestError('transport_unknown')
        sock = connection.sock
        sock.settimeout(remaining)
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise RequestError('redirect_denied')
        chunks = []
        size = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RequestError('transport_unknown')
            sock.settimeout(remaining)
            chunk = response.read1(min(65536, 1048577 - size))
            if not chunk:
                break
            size += len(chunk)
            if size > 1048576:
                raise RequestError('response_too_large')
            chunks.append(chunk)
        return response.status, b''.join(chunks)
    except (OSError, http.client.HTTPException):
        raise RequestError('transport_unknown') from None
    finally:
        connection.close()
