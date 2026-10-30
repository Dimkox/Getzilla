"""Bind an offline request preview; never authorize a model data transfer.

The supplied account reference is an unverified label. This module does not
read credentials, validate human consent, or provide a dispatch capability.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from . import model_continuation_state as journal
from . import openai_model_request as requests

_HANDLE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z')


class AdmissionError(ValueError):
    """Fixed diagnostic code with no payload or credential data."""


@dataclass(frozen=True, repr=False)
class AccountReference:
    provider: str
    account_ref: str
    handle: str
    version: str


@dataclass(frozen=True, repr=False)
class AccountResolution:
    reference: AccountReference

    @property
    def account_identity_verified(self) -> bool:
        return False


def _valid_account(account) -> bool:
    return (type(account) is AccountReference and all(isinstance(v, str) and _HANDLE.fullmatch(v)
            and not v.lower().startswith('sk-') for v in asdict(account).values()))


def resolve_account(provider: str, account_ref: str, records: tuple) -> AccountResolution:
    """Resolve a unique metadata mapping, without asserting credential ownership."""
    if type(records) is not tuple or not 1 <= len(records) <= 64 or any(not _valid_account(r) for r in records):
        raise AdmissionError('account_mapping_invalid')
    matches = [r for r in records if r.provider == provider and r.account_ref == account_ref]
    if len(matches) != 1:
        raise AdmissionError('account_mapping_ambiguous')
    return AccountResolution(matches[0])


@dataclass(frozen=True, repr=False)
class Preview:
    root_digest: str
    binding_digest: str
    contract_digest: str
    policy_digest: str
    request_digest: str
    request_bytes: int
    account_digest: str
    generation: int
    issued_epoch: int
    expires_epoch: int
    endpoint: str = 'https://api.openai.com/v1/responses'


def _checked(root: Path, binding, contract, request, account, generation, expires_epoch):
    if not _valid_account(account):
        raise AdmissionError('invalid_account_reference')
    if type(generation) is not int or not 0 < generation <= 64:
        raise AdmissionError('invalid_generation')
    if type(expires_epoch) is not int or not 0 < expires_epoch <= journal.MAX_EPOCH_SECONDS:
        raise AdmissionError('invalid_expiry')
    try:
        directory = journal.fsx.open_dir(root)
        try:
            root_info = journal.fsx.fstat_dir(directory)
            root_digest = journal._digest([root_info.st_dev, root_info.st_ino])
        finally:
            journal.fsx.close_dir(directory)
        policy, policy_digest = journal._policy(root)
        directory = journal.fsx.open_dir(root)
        try:
            after = journal.fsx.fstat_dir(directory)
            if (after.st_dev, after.st_ino) != (root_info.st_dev, root_info.st_ino):
                raise AdmissionError('root_changed')
        finally:
            journal.fsx.close_dir(directory)
        bound = journal._binding(binding)
        if type(contract) is not requests.Contract or type(request) is not requests.PreparedRequest:
            raise AdmissionError('invalid_request')
        if type(request.body) is not bytes or len(request.body) > 4_000_000:
            raise AdmissionError('invalid_request')
        data = json.loads(request.body)
        if not isinstance(data, dict) or set(data) != {'input', 'model', 'max_output_tokens', 'store'}:
            raise AdmissionError('invalid_request')
        checked = requests.prepare(contract, data['input'])
        if checked.body != request.body or checked.reserved_cost_micros != request.reserved_cost_micros:
            raise AdmissionError('invalid_request')
        if generation > len(policy.candidates):
            raise AdmissionError('candidate_denied')
        candidate = policy.candidates[generation - 1]
        if (candidate.provider != 'openai' or candidate.provider != account.provider
                or candidate.account_ref != account.account_ref or contract.account_ref != account.account_ref
                or candidate.model != contract.model):
            raise AdmissionError('candidate_denied')
        now = int(time.time())
        if (now >= expires_epoch or expires_epoch > contract.expires_epoch
                or expires_epoch > now + int(policy.bounds.deadline_seconds)):
            raise AdmissionError('expired_or_unbounded')
        return (root_digest, journal._digest(bound), journal._digest(asdict(contract)), policy_digest,
                hashlib.sha256(request.body).hexdigest(), len(request.body), journal._digest(asdict(account)))
    except (journal.JournalError, requests.RequestError, OSError, KeyError, TypeError, ValueError, UnicodeError, RecursionError):
        raise AdmissionError('preflight_denied') from None


def prepare_preview(root: Path, binding, contract, request, account, generation: int, expires_epoch: int) -> Preview:
    values = _checked(root, binding, contract, request, account, generation, expires_epoch)
    return Preview(*values, generation, int(time.time()), expires_epoch)


def recheck_preview(root: Path, preview, binding, contract, request, account, generation: int) -> dict:
    if (type(preview) is not Preview or preview.endpoint != 'https://api.openai.com/v1/responses'
            or any(type(v) is not int or not 0 < v <= journal.MAX_EPOCH_SECONDS
                   for v in (preview.issued_epoch, preview.expires_epoch, preview.generation, preview.request_bytes))
            or any(not isinstance(v, str) or not re.fullmatch(r'[a-f0-9]{64}', v)
                   for v in (preview.root_digest, preview.binding_digest, preview.contract_digest, preview.policy_digest,
                             preview.request_digest, preview.account_digest))):
        raise AdmissionError('invalid_preview')
    now = int(time.time())
    if now < preview.issued_epoch or now >= preview.expires_epoch:
        raise AdmissionError('expired_or_clock_uncertain')
    values = _checked(root, binding, contract, request, account, generation, preview.expires_epoch)
    expected = (preview.root_digest, preview.binding_digest, preview.contract_digest, preview.policy_digest,
                preview.request_digest, preview.request_bytes, preview.account_digest)
    if values != expected or generation != preview.generation:
        raise AdmissionError('preview_changed')
    return {'state': 'ready_for_review', 'dispatch_permitted': False, 'account_identity_verified': False}
