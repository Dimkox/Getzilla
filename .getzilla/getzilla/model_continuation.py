"""Passive continuation policy. Classification never authorizes dispatch.

Adapters must establish event provenance before classification. A mapping with
origin=model is not proof of a model failure, permission, or a terminal attempt.
No adapter or dispatch implementation is qualified by this module.
"""
from __future__ import annotations

import json
import math
import os
import re
import stat
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import fsx

POLICY_PATH = '.getzilla/config/model-continuation.json'
MAX_POLICY_BYTES = 16 * 1024
HARNESSES = ('grok', 'qwen', 'claude', 'codex', 'gemini', 'copilot')
_REFERENCE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z')
_MODEL = re.compile(r'[A-Za-z0-9][A-Za-z0-9._/:-]{0,127}\Z')
_ELIGIBLE = frozenset({'rate_limit', 'quota_exhausted', 'provider_unavailable',
                       'inference_transport_failure', 'generation_failure', 'inference_deadline'})


@dataclass(frozen=True)
class Candidate:
    provider: str
    account_ref: str
    model: str


@dataclass(frozen=True)
class Bounds:
    max_attempts: int
    max_requests: int
    deadline_seconds: float
    max_cost_usd: float


@dataclass(frozen=True)
class Policy:
    enabled: bool
    candidates: tuple[Candidate, ...] = ()
    bounds: Bounds | None = None


@dataclass(frozen=True)
class PolicyLoad:
    state: str
    reason: str
    policy: Policy | None = None


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate_key')
        result[key] = value
    return result


def _fields(value: Any, fields: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == fields


def _positive(value: Any, *, integer: bool = False) -> bool:
    return (type(value) in ((int,) if integer else (int, float))
            and 0 < value <= 1_000_000_000 and math.isfinite(value))


def _parse(data: bytes) -> Policy:
    value = json.loads(data.decode('utf-8'), object_pairs_hook=_object)
    if (not isinstance(value, dict) or type(value.get('schema_version')) is not int
            or value['schema_version'] != 1 or type(value.get('enabled')) is not bool):
        raise ValueError('schema')
    fields = {'schema_version', 'enabled'}
    if value['enabled'] or 'candidates' in value or 'bounds' in value:
        fields |= {'candidates', 'bounds'}
    if not _fields(value, fields):
        raise ValueError('fields')
    if fields == {'schema_version', 'enabled'}:
        return Policy(False)
    raw_candidates = value['candidates']
    if not isinstance(raw_candidates, list) or not 1 <= len(raw_candidates) <= 64:
        raise ValueError('candidates')
    candidates: list[Candidate] = []
    for candidate in raw_candidates:
        if not _fields(candidate, {'provider', 'account_ref', 'model'}):
            raise ValueError('candidate_fields')
        if any(not isinstance(ref, str) or not (_MODEL if key == 'model' else _REFERENCE).fullmatch(ref)
               or '..' in ref or '//' in ref for key, ref in candidate.items()):
            raise ValueError('reference')
        item = Candidate(**candidate)
        if item in candidates:
            raise ValueError('duplicate_candidate')
        candidates.append(item)
    bounds = value['bounds']
    if not _fields(bounds, {'max_attempts', 'max_requests', 'deadline_seconds', 'max_cost_usd'}):
        raise ValueError('bounds_fields')
    if any(not _positive(v, integer=k in {'max_attempts', 'max_requests'}) for k, v in bounds.items()):
        raise ValueError('bounds')
    if bounds['max_requests'] < bounds['max_attempts'] or bounds['max_attempts'] > len(candidates):
        raise ValueError('inconsistent_bounds')
    return Policy(value['enabled'], tuple(candidates), Bounds(**bounds))


def _read(root: Path) -> bytes:
    # Bind each project-relative directory, refuse links/reparse points, and read
    # only a bounded regular file. Nonblocking open also closes the FIFO swap race.
    with ExitStack() as stack:
        directory = fsx.open_dir(root)
        stack.callback(fsx.close_dir, directory)
        for name in ('.getzilla', 'config'):
            directory = fsx.open_dir_at(directory, name)
            stack.callback(fsx.close_dir, directory)
        name = 'model-continuation.json'
        before = fsx.lstat_at(directory, name)
        if fsx.is_link(before) or not stat.S_ISREG(before.st_mode) or before.st_size > MAX_POLICY_BYTES:
            raise ValueError('unsafe_file')
        fd = fsx.open_at(directory, name, os.O_RDONLY | fsx.O_NOFOLLOW | fsx.O_NONBLOCK)
        stack.callback(os.close, fd)
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)):
            raise ValueError('changed_file')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            data = stream.read(MAX_POLICY_BYTES + 1)
        after = os.fstat(fd)
        if (len(data) > MAX_POLICY_BYTES or (before.st_size, before.st_mtime_ns)
                != (after.st_size, after.st_mtime_ns)):
            raise ValueError('changed_or_large_file')
        return data


def load_policy(root: Path) -> PolicyLoad:
    """Read only the project policy. Errors never contain paths or input bytes."""
    try:
        policy = _parse(_read(root))
    except FileNotFoundError:
        return PolicyLoad('missing', 'policy_missing')
    except (OSError, ValueError, RecursionError, OverflowError):
        return PolicyLoad('invalid', 'policy_invalid')
    return PolicyLoad('configured' if policy.enabled else 'disabled',
                      'policy_configured' if policy.enabled else 'policy_disabled', policy)


def classify_failure(event: Any) -> str:
    """Classify a terminal normalized event from a trusted adapter, never raw text.

    The caller must bind it to an observed model attempt. Eligible is only a
    category: fences, grants, budgets, checkpoint and destination checks remain.
    Extra fields (including native retry signals) are not normalized events.
    """
    if (not _fields(event, {'schema_version', 'origin', 'category'})
            or type(event['schema_version']) is not int or event['schema_version'] != 1
            or event['origin'] != 'model' or not isinstance(event['category'], str)):
        return 'stop'
    if event['category'] in {'authentication', 'billing'}:
        return 'needs_action'
    return 'eligible' if event['category'] in _ELIGIBLE else 'stop'


def startup_status(root: Path, harness: str) -> dict[str, Any]:
    loaded = load_policy(root)
    known = harness in HARNESSES
    return {
        'schema_version': 1,
        'harness': harness if known else 'unknown',
        'policy_state': loaded.state,
        'configured': loaded.policy is not None,
        'requested_enabled': bool(loaded.policy and loaded.policy.enabled),
        'adapter_qualified': False,
        'continuation_available': False,
        'reason': ('adapter_not_qualified' if known else 'harness_unknown')
                  if loaded.state == 'configured' else loaded.reason,
        # Payload fixture coverage is not native runtime/version qualification.
        'startup_visibility': 'unqualified',
    }


def startup_note(root: Path, harness: str) -> str:
    status = startup_status(root, harness)
    return (f"Model continuation: {status['policy_state']}; unavailable "
            f"({status['reason']}); harness={status['harness']}. "
            'No adapter is qualified. Use getzilla status for policy status.')
