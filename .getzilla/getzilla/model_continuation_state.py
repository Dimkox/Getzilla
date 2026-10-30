"""Offline durable continuation records. No record grants dispatch authority.

The private qualification boundary deliberately has no implementation. A future
adapter must establish fencing, effect reconciliation and current authorization.
POSIX file and directory fsync are required; Windows admission is unsupported.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import time
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation, ROUND_CEILING, ROUND_FLOOR, localcontext
from pathlib import Path
from typing import Any

from . import fsx
from .model_continuation import classify_failure, load_policy

MAX_BYTES = 512 * 1024
MAX_CHAINS = 64
MAX_EVENTS = 256
MAX_EPOCH_SECONDS = 253402300799  # Last UTC second in year9999; distinct from count limits.
_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z')
_DIGEST = re.compile(r'[a-f0-9]{64}\Z')
_CATEGORIES = frozenset({'rate_limit', 'quota_exhausted', 'provider_unavailable',
    'inference_transport_failure', 'generation_failure', 'inference_deadline',
    'authentication', 'billing', 'cancelled', 'safety_refusal', 'policy_refusal',
    'tool_failure', 'test_failure', 'unknown', 'context_overflow', 'invalid_request',
    'unsupported_tool', 'task_budget_exhausted'})


class JournalError(ValueError):
    """A fixed diagnostic code; never includes caller text or filesystem paths."""


@dataclass(frozen=True)
class Binding:
    chain_id: str
    task_id: str
    owner_id: str
    route_id: str
    session_id: str
    workspace_digest: str
    source_digest: str
    checkpoint_digest: str


@dataclass(frozen=True)
class Usage:
    requests: int
    cost_usd: str


@dataclass(frozen=True)
class TaskBudget:
    max_attempts: int
    max_requests: int
    max_cost_usd: str
    deadline_epoch: int


def money_micros(value: Any, *, ceiling: bool) -> int:
    """Caps round down, reserved/observed charges round up. Reject binary floats."""
    if type(value) not in (str, int, Decimal) or len(str(value)) > 128:
        raise JournalError('invalid_money')
    try:
        amount = Decimal(value)
        if not amount.is_finite() or amount < 0 or amount > Decimal('1000000000'):
            raise JournalError('invalid_money')
        with localcontext() as context:
            context.prec = 160
            result = int((amount * 1000000).to_integral_value(rounding=ROUND_FLOOR if ceiling else ROUND_CEILING))
    except (InvalidOperation, OverflowError):
        raise JournalError('invalid_money') from None
    if ceiling and result == 0:
        raise JournalError('empty_cost_limit')
    return result


def _json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False, default=str).encode('utf-8')


def _digest(value: Any) -> str:
    return hashlib.sha256(_json(value)).hexdigest()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise JournalError('journal_corrupt')
        result[key] = value
    return result


def _integer(value: Any, maximum: int = 1_000_000_000) -> bool:
    return type(value) is int and 0 < value <= maximum


def _binding(binding: Binding) -> dict:
    if type(binding) is not Binding:
        raise JournalError('invalid_binding')
    value = asdict(binding)
    if any(not isinstance(v, str) or not (_DIGEST if k.endswith('_digest') else _ID).fullmatch(v)
           for k, v in value.items()):
        raise JournalError('invalid_binding')
    return value


def _usage(usage: Usage) -> dict:
    if type(usage) is not Usage or not _integer(usage.requests):
        raise JournalError('unknown_usage')
    return {'requests': usage.requests, 'cost_micros': money_micros(usage.cost_usd, ceiling=False)}


def _policy(root: Path):
    loaded = load_policy(root)
    if loaded.policy is None or not loaded.policy.enabled:
        raise JournalError('policy_revoked')
    return loaded.policy, _digest(asdict(loaded.policy))


def _regular(info):
    if (fsx.is_link(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_mode & 0o177 or info.st_size > MAX_BYTES):
        raise JournalError('unsafe_file')


def _identity(info):
    return info.st_dev, info.st_ino


def _read(directory):
    try:
        before = fsx.lstat_at(directory, 'journal.json')
    except FileNotFoundError:
        raise JournalError('journal_missing') from None
    _regular(before)
    fd = fsx.open_at(directory, 'journal.json', os.O_RDONLY | fsx.O_NOFOLLOW | fsx.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        _regular(opened)
        if _identity(opened) != _identity(before):
            raise JournalError('journal_replaced')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(MAX_BYTES + 1)
        after = os.fstat(fd)
        if len(raw) > MAX_BYTES or (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise JournalError('journal_changed')
    finally:
        os.close(fd)
    try:
        envelope = json.loads(raw, object_pairs_hook=_pairs)
        if set(envelope) != {'schema_version', 'chains', 'checksum'} or type(envelope['schema_version']) is not int or envelope['schema_version'] != 1:
            raise JournalError('journal_corrupt')
        chains = envelope['chains']
        if not isinstance(chains, dict) or len(chains) > MAX_CHAINS or envelope['checksum'] != _digest(chains):
            raise JournalError('journal_corrupt')
        for key, chain in chains.items():
            _validate_chain(key, chain)
        return chains
    except (KeyError, TypeError, ValueError, RecursionError):
        raise JournalError('journal_corrupt') from None


def _validate_chain(key, chain):
    fields = {'binding', 'policy_digest', 'revision', 'generation', 'limits', 'last_time', 'state', 'attempts', 'events'}
    if (not isinstance(chain, dict) or set(chain) not in (fields, fields | {'domain', 'domain_version'})
            or chain.get('domain', 'live_unqualified') not in {'live_unqualified', 'controlled_fixture_v1'}
            or ('domain' in chain and (chain['domain'] != 'controlled_fixture_v1' or type(chain['domain_version']) is not int or chain['domain_version'] != 1))
            or _binding(Binding(**chain['binding']))['chain_id'] != key):
        raise JournalError('journal_corrupt')
    if not _DIGEST.fullmatch(chain['policy_digest']) or not _integer(chain['revision']) or not _integer(chain['generation'], 64):
        raise JournalError('journal_corrupt')
    limits = chain['limits']
    if set(limits) != {'attempts', 'requests', 'cost_micros', 'deadline'} or any(not _integer(v, 10**18) for v in limits.values()):
        raise JournalError('journal_corrupt')
    attempts = chain['attempts']
    if not isinstance(attempts, list) or len(attempts) != chain['generation'] or len(attempts) > limits['attempts']:
        raise JournalError('journal_corrupt')
    for index, attempt in enumerate(attempts):
        if set(attempt) != {'candidate', 'requests', 'cost_micros', 'state', 'category'}:
            raise JournalError('journal_corrupt')
        if (type(attempt['candidate']) is not int or attempt['candidate'] != index or not _integer(attempt['requests'])
                or type(attempt['cost_micros']) is not int or not 0 <= attempt['cost_micros'] <= 10**15
                or attempt['state'] not in {'active_unknown', 'reserved_unknown', 'terminal_unknown', 'send_unknown', 'failed', 'succeeded'}
                or attempt['category'] not in _CATEGORIES | {None}):
            raise JournalError('journal_corrupt')
        if attempt['state'] in {'send_unknown', 'failed', 'succeeded'} and chain.get('domain') != 'controlled_fixture_v1':
            raise JournalError('journal_corrupt')
        if chain.get('domain') == 'controlled_fixture_v1':
            if index < len(attempts) - 1 and attempt['state'] != 'failed':
                raise JournalError('journal_corrupt')
            if (attempt['state'] == 'failed') != (attempt['category'] is not None):
                raise JournalError('journal_corrupt')
    if sum(a['requests'] for a in attempts) > limits['requests'] or sum(a['cost_micros'] for a in attempts) > limits['cost_micros']:
        raise JournalError('journal_corrupt')
    if not _integer(chain['last_time'], 10**18) or chain['state'] not in {'open', 'cancelled'}:
        raise JournalError('journal_corrupt')
    if not isinstance(chain['events'], dict) or len(chain['events']) > MAX_EVENTS:
        raise JournalError('journal_corrupt')
    for event, record in chain['events'].items():
        if (not _ID.fullmatch(event) or not isinstance(record, dict)
                or set(record) not in ({'digest', 'result'}, {'digest', 'result', 'evidence'})
                or not _DIGEST.fullmatch(record['digest'])):
            raise JournalError('journal_corrupt')
        result = record['result']
        if set(result) != {'state', 'reason', 'revision', 'generation', 'dispatch_permitted'} or result['dispatch_permitted'] is not False:
            raise JournalError('journal_corrupt')
        allowed_states = {'terminal_unknown', 'reserved_unknown', 'start_intent', 'container_recorded', 'checkpoint_recorded', 'cleanup_started'}
        if chain.get('domain') == 'controlled_fixture_v1':
            allowed_states.update({'fence_recorded', 'request_consumed'})
        if result['state'] not in allowed_states or result['reason'] != 'recorded':
            raise JournalError('journal_corrupt')
        if not _integer(result['revision']) or result['revision'] > chain['revision'] or not _integer(result['generation']) or result['generation'] > chain['generation']:
            raise JournalError('journal_corrupt')
        if 'evidence' in record:
            evidence = record['evidence']
            if not isinstance(evidence, dict):
                raise JournalError('journal_corrupt')
            if evidence.get('kind') == 'native_cleanup_v1':
                intent = chain['events'].get('start_' + str(evidence.get('generation')), {})
                intent_evidence = intent.get('evidence', {}) if isinstance(intent, dict) else {}
                if (chain.get('domain') is not None
                        or set(evidence) != {'kind', 'generation', 'owner_nonce'}
                        or not _integer(evidence['generation'], 64)
                        or evidence['generation'] != result['generation']
                        or event != 'cleanup_' + str(evidence['generation'])
                        or result['state'] != 'cleanup_started'
                        or intent_evidence.get('kind') != 'native_start_v1'
                        or intent_evidence.get('owner_nonce') != evidence['owner_nonce']
                        or record['digest'] != _digest(['native_cleanup_v1', evidence['generation'], evidence['owner_nonce']])):
                    raise JournalError('journal_corrupt')
            elif evidence.get('kind') == 'native_start_v1':
                if (chain.get('domain') is not None
                        or set(evidence) != {'kind', 'generation', 'owner_nonce'}
                        or not _integer(evidence['generation'], 64)
                        or evidence['generation'] != result['generation']
                        or event != 'start_' + str(evidence['generation'])
                        or result['state'] != 'start_intent'
                        or not isinstance(evidence['owner_nonce'], str) or not re.fullmatch(r'[a-f0-9]{32}', evidence['owner_nonce'])
                        or record['digest'] != _digest(['native_start_v1', evidence['generation'], evidence['owner_nonce']])):
                    raise JournalError('journal_corrupt')
            elif evidence.get('kind') == 'native_container_v1':
                start_event = chain['events'].get('start_' + str(evidence.get('generation')), {})
                start_evidence = start_event.get('evidence', {}) if isinstance(start_event, dict) else {}
                if (chain.get('domain') is not None
                        or set(evidence) != {'kind', 'generation', 'container_id', 'image_id', 'owner_nonce'}
                        or not _integer(evidence['generation'], 64)
                        or evidence['generation'] != result['generation']
                        or event != 'container_' + str(evidence['generation'])
                        or result['state'] != 'container_recorded'
                        or not isinstance(evidence['container_id'], str) or not _DIGEST.fullmatch(evidence['container_id'])
                        or not isinstance(evidence['image_id'], str) or not _DIGEST.fullmatch(evidence['image_id'])
                        or not isinstance(evidence['owner_nonce'], str) or not re.fullmatch(r'[a-f0-9]{32}', evidence['owner_nonce'])
                        or start_evidence.get('kind') != 'native_start_v1'
                        or start_evidence.get('owner_nonce') != evidence['owner_nonce']
                        or not isinstance(start_event.get('result'), dict)
                        or type(start_event['result'].get('revision')) is not int
                        or start_event['result']['revision'] >= result['revision']
                        or record['digest'] != _digest(['native_container_v1', evidence['generation'], evidence['container_id'], evidence['image_id'], evidence['owner_nonce']])):
                    raise JournalError('journal_corrupt')
            elif evidence.get('kind') == 'native_checkpoint_v1':
                container_event = chain['events'].get('container_' + str(evidence.get('generation')), {})
                container_evidence = container_event.get('evidence', {}) if isinstance(container_event, dict) else {}
                if (chain.get('domain') is not None
                        or set(evidence) != {'kind', 'generation', 'container_id', 'checkpoint_digest'}
                        or not _integer(evidence['generation'], 64)
                        or evidence['generation'] != result['generation']
                        or event != 'checkpoint_' + str(evidence['generation'])
                        or result['state'] != 'checkpoint_recorded'
                        or not isinstance(evidence['container_id'], str) or not _DIGEST.fullmatch(evidence['container_id'])
                        or not isinstance(evidence['checkpoint_digest'], str) or not _DIGEST.fullmatch(evidence['checkpoint_digest'])
                        or container_evidence.get('kind') != 'native_container_v1'
                        or container_evidence.get('container_id') != evidence['container_id']
                        or not isinstance(container_event.get('result'), dict)
                        or type(container_event['result'].get('revision')) is not int
                        or container_event['result']['revision'] >= result['revision']
                        or record['digest'] != _digest(['native_checkpoint_v1', evidence['generation'], evidence['container_id'], evidence['checkpoint_digest']])):
                    raise JournalError('journal_corrupt')
            elif chain.get('domain') != 'controlled_fixture_v1':
                raise JournalError('journal_corrupt')
            elif evidence.get('kind') == 'controlled_request_v1':
                if (set(evidence) != {'kind', 'generation'} or not _integer(evidence['generation'], 64)
                        or evidence['generation'] != result['generation'] or event != 'request_' + str(evidence['generation'])
                        or result['state'] != 'request_consumed'
                        or record['digest'] != _digest(['controlled_request_v1', evidence['generation']])):
                    raise JournalError('journal_corrupt')
            elif (not isinstance(evidence, dict)
                    or set(evidence) != {'kind', 'generation', 'container_id', 'checkpoint_digest', 'thread_id'}
                    or evidence['kind'] != 'controlled_fence_v2' or not _integer(evidence['generation'], 64)
                    or evidence['generation'] != result['generation'] or event != 'fence_' + str(evidence['generation'])
                    or result['state'] != 'fence_recorded'
                    or not isinstance(evidence['container_id'], str) or not _DIGEST.fullmatch(evidence['container_id'])
                    or not isinstance(evidence['checkpoint_digest'], str) or not _DIGEST.fullmatch(evidence['checkpoint_digest'])
                    or not isinstance(evidence['thread_id'], str) or not _ID.fullmatch(evidence['thread_id'])
                    or record['digest'] != _digest(['controlled_fence_v2', evidence['generation'], evidence['container_id'], evidence['checkpoint_digest'], evidence['thread_id']])):
                raise JournalError('journal_corrupt')
        elif result['state'] in {'fence_recorded', 'start_intent', 'container_recorded', 'checkpoint_recorded', 'cleanup_started'}:
            raise JournalError('journal_corrupt')
        elif result['state'] == 'request_consumed':
            raise JournalError('journal_corrupt')


@contextmanager
def _store(root: Path, *, create=False, fixture=False):
    if fsx.WINDOWS:
        raise JournalError('durability_unsupported')
    try:
        with ExitStack() as stack:
            directory = fsx.open_dir(root)
            stack.callback(fsx.close_dir, directory)
            bindings = []
            for name in ('.getzilla', 'runtime', 'model-continuation-fixture' if fixture else 'model-continuation'):
                if create:
                    try:
                        fsx.mkdir_at(directory, name, 0o700)
                        fsx.fsync_dir(directory)
                    except FileExistsError:
                        pass
                child = fsx.open_dir_at(directory, name)
                stack.callback(fsx.close_dir, child)
                bindings.append((directory, name, child))
                directory = child
            info = fsx.fstat_dir(directory)
            if info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise JournalError('unsafe_directory')
            flags = os.O_RDWR | fsx.O_NOFOLLOW | fsx.O_NONBLOCK
            new_lock = False
            try:
                fd = fsx.open_at(directory, 'lock', flags)
            except FileNotFoundError:
                if not create:
                    raise JournalError('lock_missing') from None
                try:
                    fsx.lstat_at(directory, 'journal.json')
                except FileNotFoundError:
                    pass
                else:
                    raise JournalError('lock_missing')
                try:
                    fd = fsx.open_at(directory, 'lock', flags | os.O_CREAT | os.O_EXCL, 0o600)
                    new_lock = True
                    os.fsync(fd)
                    fsx.fsync_dir(directory)
                except FileExistsError:
                    fd = fsx.open_at(directory, 'lock', flags)
            stack.callback(os.close, fd)
            _regular(os.fstat(fd))
            deadline = time.monotonic() + 1
            while True:
                try:
                    fsx.lock_file(fd, blocking=False)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise JournalError('lock_busy') from None
                    time.sleep(0.01)
            stack.callback(fsx.unlock_file, fd)

            def check():
                for parent, name, handle in bindings:
                    named = fsx.lstat_at(parent, name)
                    if fsx.is_link(named) or _identity(named) != _identity(fsx.fstat_dir(handle)):
                        raise JournalError('directory_replaced')
                locked = os.fstat(fd)
                _regular(locked)
                if _identity(locked) != _identity(fsx.lstat_at(directory, 'lock')):
                    raise JournalError('lock_replaced')

            check()
            try:
                chains = _read(directory)
            except JournalError as error:
                if str(error) != 'journal_missing' or not new_lock:
                    raise
                chains = {}

            def save():
                check()
                for key, chain in chains.items():
                    _validate_chain(key, chain)
                data = _json({'schema_version': 1, 'chains': chains, 'checksum': _digest(chains)})
                if len(data) > MAX_BYTES:
                    raise JournalError('capacity_exhausted')
                name = 'pending-' + secrets.token_hex(12)
                tmp = fsx.open_at(directory, name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | fsx.O_NOFOLLOW, 0o600)
                try:
                    with os.fdopen(tmp, 'wb') as stream:
                        stream.write(data)
                        stream.flush()
                        os.fsync(stream.fileno())
                    check()
                    fsx.replace_at(directory, name, directory, 'journal.json')
                    fsx.fsync_dir(directory)
                    check()
                finally:
                    try:
                        fsx.unlink_at(directory, name)
                    except FileNotFoundError:
                        pass
            if new_lock:
                # Publish a durable empty ledger before business validation. A failed
                # initial publication still leaves the lock and fails closed.
                save()
            yield chains, save
            check()
    except OSError:
        raise JournalError('storage_unavailable') from None


def _result(chain, state='denied', reason='recorded'):
    return {'state': state, 'reason': reason, 'revision': chain['revision'],
            'generation': chain['generation'], 'dispatch_permitted': False}


def _chain(chains, binding):
    expected = _binding(binding)
    chain = chains.get(binding.chain_id)
    if chain is None:
        raise JournalError('chain_missing')
    if chain['binding'] != expected:
        raise JournalError('binding_mismatch')
    return chain


def _clock(chain):
    now = int(time.time())
    if now < chain['last_time']:
        return 'clock_uncertain'
    if now >= chain['limits']['deadline']:
        return 'deadline_exhausted'
    return None


def _current(root, chain):
    if chain['state'] != 'open':
        return 'chain_stopped'
    try:
        _, digest = _policy(root)
    except JournalError:
        return 'policy_revoked'
    return 'policy_changed' if digest != chain['policy_digest'] else _clock(chain)


def _create_chain(root: Path, binding: Binding, original: Usage, budget: TaskBudget, *, controlled: bool) -> dict:
    bound = _binding(binding)
    usage = _usage(original)
    if (type(budget) is not TaskBudget
            or not all(_integer(v) for v in (budget.max_attempts, budget.max_requests))
            or not _integer(budget.deadline_epoch, MAX_EPOCH_SECONDS)):
        raise JournalError('invalid_task_budget')
    with _store(root, create=True, fixture=controlled) as (chains, save):
        if any(c['binding']['task_id'] == binding.task_id for c in chains.values()) or binding.chain_id in chains:
            raise JournalError('task_already_recorded')
        if len(chains) >= MAX_CHAINS:
            raise JournalError('capacity_exhausted')
        policy, digest = _policy(root)
        limits = {'attempts': min(policy.bounds.max_attempts, budget.max_attempts),
                  'requests': min(policy.bounds.max_requests, budget.max_requests),
                  'cost_micros': min(money_micros(str(policy.bounds.max_cost_usd), ceiling=True), money_micros(budget.max_cost_usd, ceiling=True)),
                  'deadline': min(int(time.time()) + int(policy.bounds.deadline_seconds), budget.deadline_epoch)}
        if usage['requests'] > limits['requests'] or usage['cost_micros'] > limits['cost_micros'] or limits['deadline'] <= time.time():
            raise JournalError('initial_budget_exhausted')
        chain = {'binding': bound, 'policy_digest': digest, 'limits': limits, 'revision': 1,
                 'generation': 1, 'last_time': int(time.time()), 'state': 'open', 'events': {},
                 'attempts': [{'candidate': 0, **usage, 'state': 'active_unknown', 'category': None}]}
        if controlled:
            chain['domain'] = 'controlled_fixture_v1'
            chain['domain_version'] = 1
        chains[binding.chain_id] = chain
        save()
        return _result(chain, 'active_unknown')


def create_chain(root: Path, binding: Binding, original: Usage, budget: TaskBudget) -> dict:
    return _create_chain(root, binding, original, budget, controlled=False)


def create_controlled_chain(root: Path, binding: Binding, original: Usage, budget: TaskBudget) -> dict:
    """Create fixture accounting only; this does not authorize any dispatch."""
    return _create_chain(root, binding, original, budget, controlled=True)


def consume_controlled_send(root: Path, binding: Binding, generation: int, expected_revision: int) -> dict:
    """Persist a one-shot fixture observation; never grants live dispatch."""
    if not _integer(generation) or not _integer(expected_revision):
        raise JournalError('invalid_revision')
    with _store(root, fixture=True) as (chains, save):
        chain = _chain(chains, binding)
        if chain.get('domain') != 'controlled_fixture_v1':
            raise JournalError('invalid_domain')
        if chain['attempts'][-1]['state'] == 'send_unknown':
            return {'claimed': False, 'reason': 'already_consumed', 'dispatch_permitted': False}
        problem = _current(root, chain)
        if problem:
            return {'claimed': False, 'reason': problem, 'dispatch_permitted': False}
        if generation != chain['generation'] or expected_revision != chain['revision']:
            return {'claimed': False, 'reason': 'stale_revision', 'dispatch_permitted': False}
        attempt = chain['attempts'][-1]
        if attempt['state'] not in {'active_unknown', 'reserved_unknown'}:
            return {'claimed': False, 'reason': 'outcome_unknown', 'dispatch_permitted': False}
        attempt['state'] = 'send_unknown'
        chain['revision'] += 1
        chain['last_time'] = int(time.time())
        save()
        return {'claimed': True, 'reason': 'recorded', 'generation': chain['generation'],
                'revision': chain['revision'], 'dispatch_permitted': False}


def record_controlled_terminal(root: Path, binding: Binding, generation: int, expected_revision: int, category: str) -> dict:
    """Record fixture facts; callers must establish provenance and effect isolation."""
    if not _integer(generation) or not _integer(expected_revision) or not isinstance(category, str) or category not in _CATEGORIES | {'success'}:
        raise JournalError('invalid_terminal')
    with _store(root, fixture=True) as (chains, save):
        chain = _chain(chains, binding)
        if chain.get('domain') != 'controlled_fixture_v1':
            raise JournalError('invalid_domain')
        if generation != chain['generation'] or expected_revision != chain['revision']:
            return {'state': 'denied', 'reason': 'stale_revision', 'dispatch_permitted': False}
        attempt = chain['attempts'][-1]
        if attempt['state'] != 'send_unknown':
            return {'state': 'denied', 'reason': 'outcome_unknown', 'dispatch_permitted': False}
        state = 'succeeded' if category == 'success' else 'failed'
        attempt.update(state=state, category=None if category == 'success' else category)
        chain['revision'] += 1
        chain['last_time'] = max(chain['last_time'], int(time.time()))
        save()
        return {'state': state, 'revision': chain['revision'], 'dispatch_permitted': False}


def consume_controlled_request(root: Path, binding: Binding, generation: int, expected_revision: int) -> dict:
    """Consume the one request already charged to a synthetic attempt, once."""
    if not _integer(generation) or not _integer(expected_revision):
        raise JournalError('invalid_revision')
    event_id = 'request_' + str(generation)
    with _store(root, fixture=True) as (chains, save):
        chain = _chain(chains, binding)
        if chain.get('domain') != 'controlled_fixture_v1':
            raise JournalError('invalid_domain')
        if event_id in chain['events']:
            return {'claimed': False, 'reason': 'already_consumed', 'dispatch_permitted': False}
        problem = _current(root, chain)
        if problem:
            return {'claimed': False, 'reason': problem, 'dispatch_permitted': False}
        if chain['generation'] != generation or chain['revision'] != expected_revision:
            return {'claimed': False, 'reason': 'stale_revision', 'dispatch_permitted': False}
        if chain['attempts'][-1]['state'] != 'send_unknown':
            return {'claimed': False, 'reason': 'outcome_unknown', 'dispatch_permitted': False}
        if chain['attempts'][-1]['requests'] != 1:
            return {'claimed': False, 'reason': 'request_bound_invalid', 'dispatch_permitted': False}
        if len(chain['events']) >= MAX_EVENTS:
            return {'claimed': False, 'reason': 'capacity_exhausted', 'dispatch_permitted': False}
        evidence = {'kind': 'controlled_request_v1', 'generation': generation}
        _record(chain, event_id, ['controlled_request_v1', generation], 'request_consumed', save, evidence=evidence)
        return {'claimed': True, 'reason': 'recorded', 'generation': generation,
                'revision': chain['revision'], 'dispatch_permitted': False}


def check_controlled_send(root: Path, binding: Binding, generation: int, expected_revision: int) -> str | None:
    """Recheck an existing fixture claim; never creates or reissues a claim."""
    if not _integer(generation) or not _integer(expected_revision):
        raise JournalError('invalid_revision')
    with _store(root, fixture=True) as (chains, _):
        chain = _chain(chains, binding)
        if chain.get('domain') != 'controlled_fixture_v1':
            raise JournalError('invalid_domain')
        problem = _current(root, chain)
        if problem:
            return problem
        if generation != chain['generation'] or expected_revision != chain['revision']:
            return 'stale_revision'
        if chain['attempts'][-1]['state'] != 'send_unknown':
            return 'outcome_unknown'
        return None


def record_controlled_fence(root: Path, binding: Binding, generation: int, expected_revision: int,
                            container_id: str, checkpoint_digest: str, thread_id: str) -> dict:
    """Record synthetic observations; caller facts never grant live authority."""
    if (not _integer(generation) or not _integer(expected_revision)
            or not isinstance(container_id, str) or not _DIGEST.fullmatch(container_id)
            or not isinstance(checkpoint_digest, str) or not _DIGEST.fullmatch(checkpoint_digest)
            or not isinstance(thread_id, str) or not _ID.fullmatch(thread_id)):
        raise JournalError('invalid_fence')
    content = ['controlled_fence_v2', generation, container_id, checkpoint_digest, thread_id]
    event_id = 'fence_' + str(generation)
    with _store(root, fixture=True) as (chains, save):
        chain = _chain(chains, binding)
        if chain.get('domain') != 'controlled_fixture_v1':
            raise JournalError('invalid_domain')
        problem = _current(root, chain)
        if problem:
            return _result(chain, reason=problem)
        duplicate = _event(chain, event_id, content)
        if duplicate:
            return duplicate
        if chain['revision'] != expected_revision or chain['generation'] != generation:
            return _result(chain, reason='stale_revision')
        if chain['attempts'][-1]['state'] != 'failed':
            return _result(chain, reason='outcome_unknown')
        evidence = {'kind': 'controlled_fence_v2', 'generation': generation, 'thread_id': thread_id,
                    'container_id': container_id, 'checkpoint_digest': checkpoint_digest}
        return _record(chain, event_id, content, 'fence_recorded', save, evidence=evidence)


def reserve_fenced_next(root: Path, binding: Binding, expected_revision: int, usage: Usage,
                        container_id: str, checkpoint_digest: str) -> dict:
    return reserve_controlled_next(root, binding, expected_revision, usage,
                                   fence=(container_id, checkpoint_digest))


def reserve_controlled_next(root: Path, binding: Binding, expected_revision: int, usage: Usage, *, fence=None) -> dict:
    """Account a fixture retry without granting authority to send it."""
    if not _integer(expected_revision):
        raise JournalError('invalid_revision')
    reservation = _usage(usage)
    with _store(root, fixture=True) as (chains, save):
        chain = _chain(chains, binding)
        if chain.get('domain') != 'controlled_fixture_v1':
            raise JournalError('invalid_domain')
        problem = _current(root, chain)
        if problem:
            return {'state': 'denied', 'reason': problem, 'dispatch_permitted': False}
        if chain['revision'] != expected_revision:
            return {'state': 'denied', 'reason': 'stale_revision', 'dispatch_permitted': False}
        if fence is not None:
            if (not isinstance(fence, tuple) or len(fence) != 2
                    or any(not isinstance(value, str) or not _DIGEST.fullmatch(value) for value in fence)):
                raise JournalError('invalid_fence')
            record = chain['events'].get('fence_' + str(chain['generation']))
            evidence = record.get('evidence') if record else None
            if (not isinstance(evidence, dict) or evidence.get('container_id') != fence[0]
                    or evidence.get('checkpoint_digest') != fence[1] or record['result']['revision'] != expected_revision):
                return {'state': 'denied', 'reason': 'fence_mismatch', 'dispatch_permitted': False}
        last = chain['attempts'][-1]
        if last['state'] != 'failed' or classify_failure({'schema_version': 1, 'origin': 'model', 'category': last['category']}) != 'eligible':
            return {'state': 'denied', 'reason': 'failure_not_eligible', 'dispatch_permitted': False}
        limits = chain['limits']
        if (len(chain['attempts']) >= limits['attempts']
                or sum(a['requests'] for a in chain['attempts']) + reservation['requests'] > limits['requests']
                or sum(a['cost_micros'] for a in chain['attempts']) + reservation['cost_micros'] > limits['cost_micros']):
            return {'state': 'denied', 'reason': 'budget_exhausted', 'dispatch_permitted': False}
        chain['attempts'].append({'candidate': chain['generation'], **reservation, 'state': 'reserved_unknown', 'category': None})
        chain['generation'] += 1
        chain['revision'] += 1
        chain['last_time'] = int(time.time())
        save()
        return {'state': 'reserved_unknown', 'generation': chain['generation'], 'revision': chain['revision'], 'dispatch_permitted': False}


def inspect_chain(root: Path, binding: Binding) -> dict:
    with _store(root) as (chains, _):
        return _chain(chains, binding)


def claim_native_start(root: Path, binding: Binding, generation: int, expected_revision: int, owner_nonce: str) -> dict:
    """Persist a one-shot ownership intent before creating any Docker resources."""
    if (not _integer(generation, 64) or not _integer(expected_revision) or not isinstance(owner_nonce, str)
            or not re.fullmatch(r'[a-f0-9]{32}', owner_nonce)):
        raise JournalError('invalid_container')
    event = 'start_' + str(generation)
    content = ['native_start_v1', generation, owner_nonce]
    with _store(root) as (chains, save):
        chain = _chain(chains, binding)
        if chain.get('domain') is not None:
            raise JournalError('invalid_domain')
        if event in chain['events']:
            return {**_result(chain, reason='start_already_claimed'), 'claimed': False}
        problem = _current(root, chain)
        if problem:
            return {**_result(chain, reason=problem), 'claimed': False}
        if generation != chain['generation'] or expected_revision != chain['revision']:
            return {**_result(chain, reason='stale_reference'), 'claimed': False}
        if chain['attempts'][-1]['state'] != 'active_unknown':
            return {**_result(chain, reason='outcome_unknown'), 'claimed': False}
        evidence = dict(kind='native_start_v1', generation=generation, owner_nonce=owner_nonce)
        result = _record(chain, event, content, 'start_intent', save, evidence=evidence)
        return {**result, 'claimed': True}


def inspect_native_intent(root: Path, binding: Binding, generation: int) -> dict:
    with _store(root) as (chains, _):
        chain = _chain(chains, binding)
        if chain.get('domain') is not None or generation != chain['generation']:
            raise JournalError('invalid_domain')
        event = chain['events'].get('start_' + str(generation))
        if not event or event.get('evidence', {}).get('kind') != 'native_start_v1':
            raise JournalError('container_unknown')
        return {**event['evidence'], 'revision': chain['revision'], 'dispatch_permitted': False}


def claim_native_cleanup(root: Path, binding: Binding, generation: int, expected_revision: int) -> dict:
    """Durably forbid further allocation before removing any owned resource."""
    if not _integer(generation, 64) or not _integer(expected_revision):
        raise JournalError('invalid_reference')
    with _store(root) as (chains, save):
        chain = _chain(chains, binding)
        if chain.get('domain') is not None or generation != chain['generation']:
            raise JournalError('invalid_domain')
        intent = chain['events'].get('start_' + str(generation), {}).get('evidence', {})
        if intent.get('kind') != 'native_start_v1':
            raise JournalError('container_unknown')
        event = 'cleanup_' + str(generation)
        content = ['native_cleanup_v1', generation, intent['owner_nonce']]
        prior = _event(chain, event, content)
        if prior:
            return prior
        if expected_revision != chain['revision']:
            return _result(chain, reason='stale_reference')
        evidence = dict(kind='native_cleanup_v1', generation=generation, owner_nonce=intent['owner_nonce'])
        return _record(chain, event, content, 'cleanup_started', save, evidence=evidence)


def record_native_container(root: Path, binding: Binding, generation: int, expected_revision: int,
                            container_id: str, image_id: str, owner_nonce: str) -> dict:
    """Bind an isolated local container before it starts; never authorize dispatch."""
    if (not _integer(generation, 64) or not _integer(expected_revision)
            or not isinstance(container_id, str) or not _DIGEST.fullmatch(container_id)
            or not isinstance(image_id, str) or not _DIGEST.fullmatch(image_id)
            or not isinstance(owner_nonce, str) or not re.fullmatch(r'[a-f0-9]{32}', owner_nonce)):
        raise JournalError('invalid_container')
    event = 'container_' + str(generation)
    content = ['native_container_v1', generation, container_id, image_id, owner_nonce]
    with _store(root) as (chains, save):
        chain = _chain(chains, binding)
        if chain.get('domain') is not None:
            raise JournalError('invalid_domain')
        if 'cleanup_' + str(generation) in chain['events']:
            return _result(chain, reason='cleanup_started')
        previous = _event(chain, event, content)
        if previous:
            return previous
        problem = _current(root, chain)
        if problem:
            return _result(chain, reason=problem)
        if generation != chain['generation'] or expected_revision != chain['revision']:
            return _result(chain, reason='stale_reference')
        if chain['attempts'][-1]['state'] != 'active_unknown':
            return _result(chain, reason='outcome_unknown')
        intent = chain['events'].get('start_' + str(generation), {}).get('evidence', {})
        if intent.get('owner_nonce') != owner_nonce:
            return _result(chain, reason='intent_mismatch')
        evidence = dict(kind='native_container_v1', generation=generation, container_id=container_id,
                        image_id=image_id, owner_nonce=owner_nonce)
        return _record(chain, event, content, 'container_recorded', save, evidence=evidence)


def inspect_native_container(root: Path, binding: Binding, expected_revision: int, generation: int) -> dict:
    """Read the durable identity; no returned observation permits dispatch."""
    with _store(root) as (chains, _):
        chain = _chain(chains, binding)
        if chain.get('domain') is not None:
            raise JournalError('invalid_domain')
        if generation != chain['generation'] or expected_revision != chain['revision']:
            raise JournalError('stale_reference')
        event = chain['events'].get('container_' + str(generation))
        if not event or event.get('evidence', {}).get('kind') != 'native_container_v1':
            raise JournalError('container_unknown')
        checkpoint = chain['events'].get('checkpoint_' + str(generation))
        return {**event['evidence'], 'revision': chain['revision'], 'dispatch_permitted': False,
                'checkpoint_digest': checkpoint['evidence']['checkpoint_digest'] if checkpoint else None}


def record_native_checkpoint(root: Path, binding: Binding, generation: int, expected_revision: int,
                             container_id: str, checkpoint_digest: str) -> dict:
    """Record local stopped-volume evidence without qualifying external effects."""
    if (not _integer(generation, 64) or not _integer(expected_revision)
            or not isinstance(container_id, str) or not _DIGEST.fullmatch(container_id)
            or not isinstance(checkpoint_digest, str) or not _DIGEST.fullmatch(checkpoint_digest)):
        raise JournalError('invalid_checkpoint')
    event = 'checkpoint_' + str(generation)
    content = ['native_checkpoint_v1', generation, container_id, checkpoint_digest]
    with _store(root) as (chains, save):
        chain = _chain(chains, binding)
        if chain.get('domain') is not None:
            raise JournalError('invalid_domain')
        if 'cleanup_' + str(generation) in chain['events']:
            return _result(chain, reason='cleanup_started')
        prior = _event(chain, event, content)
        if prior:
            return prior
        if generation != chain['generation'] or expected_revision != chain['revision']:
            return _result(chain, reason='stale_reference')
        prior_container = chain['events'].get('container_' + str(generation), {}).get('evidence', {})
        if prior_container.get('container_id') != container_id:
            return _result(chain, reason='container_mismatch')
        evidence = dict(kind='native_checkpoint_v1', generation=generation, container_id=container_id,
                        checkpoint_digest=checkpoint_digest)
        return _record(chain, event, content, 'checkpoint_recorded', save, evidence=evidence)


def recovery_status(root: Path, binding: Binding, expected_revision: int, expected_generation: int) -> dict:
    """Inspect durable state without granting dispatch or replay."""
    if not _integer(expected_revision) or not _integer(expected_generation):
        raise JournalError('invalid_reference')
    with _store(root) as (chains, _):
        chain = _chain(chains, binding)
        if chain.get('domain') is not None:
            raise JournalError('invalid_domain')
        if chain['revision'] != expected_revision:
            return _result(chain, reason='stale_revision')
        if chain['generation'] != expected_generation:
            return _result(chain, reason='stale_generation')
        if chain['state'] == 'cancelled':
            return _result(chain, 'cancelled')
        problem = _current(root, chain)
        if problem:
            return _result(chain, reason=problem)
        return _result(chain, chain['attempts'][-1]['state'], 'outcome_unknown')


def inspect_controlled_chain(root: Path, binding: Binding) -> dict:
    with _store(root, fixture=True) as (chains, _):
        chain = _chain(chains, binding)
        if chain.get('domain') != 'controlled_fixture_v1':
            raise JournalError('invalid_domain')
        return chain


def _event(chain, event_id, content):
    if not isinstance(event_id, str) or not _ID.fullmatch(event_id):
        raise JournalError('invalid_event')
    previous = chain['events'].get(event_id)
    if previous:
        return previous['result'] if previous['digest'] == _digest(content) else _result(chain, reason='conflicting_event')
    if len(chain['events']) >= MAX_EVENTS:
        return _result(chain, reason='capacity_exhausted')
    return None


def _record(chain, event_id, content, state, save, *, evidence=None):
    chain['revision'] += 1
    chain['last_time'] = int(time.time())
    result = _result(chain, state)
    chain['events'][event_id] = {'digest': _digest(content), 'result': result}
    if evidence is not None:
        chain['events'][event_id]['evidence'] = evidence
    save()
    return result


def record_terminal(root: Path, binding: Binding, generation: int, event_id: str, category: str) -> dict:
    if not _integer(generation) or not isinstance(category, str) or category not in _CATEGORIES:
        raise JournalError('invalid_terminal')
    content = ['terminal', generation, category]
    with _store(root) as (chains, save):
        chain = _chain(chains, binding)
        problem = _current(root, chain)
        if problem:
            return _result(chain, reason=problem)
        duplicate = _event(chain, event_id, content)
        if duplicate:
            return duplicate
        if generation != chain['generation']:
            return _result(chain, reason='stale_generation')
        if chain['attempts'][-1]['state'] == 'terminal_unknown':
            return _result(chain, reason='already_terminal')
        chain['attempts'][-1].update(state='terminal_unknown', category=category)
        return _record(chain, event_id, content, 'terminal_unknown', save)


def _qualified_boundary(root, binding, chain) -> bool:
    """No qualified native adapter/fence/checkpoint/authorization boundary exists."""
    return False


def reserve_next(root: Path, binding: Binding, expected_revision: int, event_id: str, usage: Usage) -> dict:
    if not _integer(expected_revision):
        raise JournalError('invalid_revision')
    reservation = _usage(usage)
    content = ['reserve', expected_revision, reservation]
    with _store(root) as (chains, save):
        chain = _chain(chains, binding)
        problem = _current(root, chain)
        if problem:
            return _result(chain, reason=problem)
        duplicate = _event(chain, event_id, content)
        if duplicate:
            return duplicate
        if expected_revision != chain['revision']:
            return _result(chain, reason='stale_revision')
        previous = chain['attempts'][-1]
        if previous['state'] != 'terminal_unknown':
            return _result(chain, reason='outcome_unknown')
        if classify_failure({'schema_version': 1, 'origin': 'model', 'category': previous['category']}) != 'eligible':
            return _result(chain, reason='failure_not_eligible')
        if not _qualified_boundary(root, binding, chain):
            return _result(chain, reason='adapter_not_qualified')
        problem = _current(root, chain)
        if problem:
            return _result(chain, reason=problem)
        limits = chain['limits']
        if len(chain['attempts']) >= limits['attempts']:
            return _result(chain, reason='attempts_exhausted')
        if sum(a['requests'] for a in chain['attempts']) + reservation['requests'] > limits['requests']:
            return _result(chain, reason='requests_exhausted')
        if sum(a['cost_micros'] for a in chain['attempts']) + reservation['cost_micros'] > limits['cost_micros']:
            return _result(chain, reason='cost_exhausted')
        chain['attempts'].append({'candidate': chain['generation'], **reservation,
                                  'state': 'reserved_unknown', 'category': None})
        chain['generation'] += 1
        return _record(chain, event_id, content, 'reserved_unknown', save)


def _cancel_chain(root: Path, binding: Binding, expected_revision: int, *, fixture: bool) -> dict:
    if not _integer(expected_revision):
        raise JournalError('invalid_revision')
    with _store(root, fixture=fixture) as (chains, save):
        chain = _chain(chains, binding)
        if fixture and chain.get('domain') != 'controlled_fixture_v1':
            raise JournalError('invalid_domain')
        if chain['state'] == 'cancelled':
            return _result(chain, 'cancelled')
        if chain['revision'] != expected_revision:
            return _result(chain, reason='stale_revision')
        chain['state'] = 'cancelled'
        chain['revision'] += 1
        save()
        return _result(chain, 'cancelled')


def cancel_chain(root: Path, binding: Binding, expected_revision: int) -> dict:
    return _cancel_chain(root, binding, expected_revision, fixture=False)


def cancel_controlled_chain(root: Path, binding: Binding, expected_revision: int) -> dict:
    return _cancel_chain(root, binding, expected_revision, fixture=True)
