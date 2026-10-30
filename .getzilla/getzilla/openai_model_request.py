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
