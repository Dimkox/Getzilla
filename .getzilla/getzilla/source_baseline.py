"""Canonical source-baseline-v1 manifest bytes and source digest.

Digest = SHA-256 of b"getzilla-source-baseline-v1" + LF + canonical JSON, where the JSON holds
schema_version, path_profile, executable_mode and the entries sorted by UTF-8 path bytes, with
sorted keys, no whitespace and no trailing newline. Timestamps, absolute paths, scans, Git
identity and provenance are not part of it.
"""
from __future__ import annotations

from typing import Sequence

from .source_models import BASELINE_SCHEMA, EXECUTABLE_MODES, PATH_PROFILES, ContractError, SourceEntry, canonical_json
from .source_paths import path_problem

DOMAIN = b'getzilla-source-baseline-v1\n'


def manifest_record(entries: Sequence[SourceEntry], profile: str, executable_mode: str) -> dict:
    if profile not in PATH_PROFILES:
        raise ContractError(f'unsupported path profile: {profile}')
    if executable_mode not in EXECUTABLE_MODES:
        raise ContractError(f'unsupported executable mode: {executable_mode}')
    ordered = sorted(entries, key=lambda entry: entry.path.encode('utf-8'))
    seen: set[str] = set()
    for entry in ordered:
        problem = path_problem(entry.path)
        if problem:
            raise ContractError(f'{problem}: {entry.path!r}')
        if entry.path in seen:
            raise ContractError(f'duplicate path: {entry.path}')
        seen.add(entry.path)
    return {
        'schema_version': BASELINE_SCHEMA,
        'path_profile': profile,
        'executable_mode': executable_mode,
        'entries': [entry.to_dict() for entry in ordered],
    }


def canonical_manifest_bytes(entries: Sequence[SourceEntry], profile: str, executable_mode: str = 'posix-mode') -> bytes:
    return canonical_json(manifest_record(entries, profile, executable_mode))


def source_digest(entries: Sequence[SourceEntry], profile: str, executable_mode: str = 'posix-mode') -> str:
    import hashlib
    return hashlib.sha256(DOMAIN + canonical_manifest_bytes(entries, profile, executable_mode)).hexdigest()
