"""Prospective workflow storage; tracked packages remain readable history."""
from __future__ import annotations
import re
import json
import unicodedata
from typing import Any
import shutil
from pathlib import Path

RUNTIME_CHANGES = '.getzilla/runtime/changes'
LEGACY_CHANGES = 'engineering/changes'
CHANGE_ID = re.compile(r'[A-Za-zА-Яа-яЁё0-9][A-Za-zА-Яа-яЁё0-9_-]{0,127}')


def intake_package_target(value: str) -> bool:
    return value in {'change-spec.yaml', 'requirements.md', 'workflow/projections/intake.json'} or bool(re.fullmatch(
        r'workflow/projections/intake/(?:versions/[0-9a-f]{64}\.json|publications/[0-9a-f]{64}(?:\.json|/state\.json))', value))


def cas_package_write(root: Path, change_id: str, target: str, data: bytes, expected_digest: str) -> str:
    """Closed native publisher; public workflow CAS retains its narrower allowlist."""
    from .state import require_route_owner
    from .workflow_artifacts import _cas_write
    route = require_route_owner(root)
    if route.get('change_id') != change_id or not intake_package_target(target):
        raise ValueError('native package write requires selected owner and closed target')
    return _cas_write(root, change_id, target, data, expected_digest, package_target=True)


def valid_package_path(relative: object, change_id: object) -> bool:
    return (isinstance(change_id, str) and bool(CHANGE_ID.fullmatch(change_id))
            and relative in {f'{RUNTIME_CHANGES}/{change_id}', f'{LEGACY_CHANGES}/{change_id}'})


def change_directory(root: Path, change_id: str, *, writable: bool = False) -> Path:
    if not valid_package_path(f'{RUNTIME_CHANGES}/{change_id}', change_id):
        raise ValueError('invalid change identity')
    runtime = root / RUNTIME_CHANGES / change_id
    legacy = root / LEGACY_CHANGES / change_id
    selected = runtime if runtime.exists() or writable or not legacy.exists() else legacy
    current = root
    for part in selected.relative_to(root).parts:
        current /= part
        if current.is_symlink():
            raise ValueError('workflow package path must not contain symlinks')
    if writable and not runtime.exists() and legacy.exists():
        current = root
        for part in legacy.relative_to(root).parts:
            current /= part
            if current.is_symlink():
                raise ValueError('legacy workflow package path contains symlinks')
        if any(item.is_symlink() for item in legacy.rglob('*')):
            raise ValueError('legacy workflow package contains symlinks')
        shutil.copytree(legacy, runtime)
    return selected


MAX_SOURCE_BYTES = 1_000_000


MAX_DEPTH = 64


MAX_NODES = 20_000


MAX_STRING_LENGTH = 65_536


class WorkflowArtifactError(ValueError):
    def __init__(self, message: str, *, code: str = "invalid") -> None:
        super().__init__(message)
        self.code = code


def canonical_json(value: Any) -> bytes:
    _bounded_walk(value)
    try:
        return (
            json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise WorkflowArtifactError("value is not canonical JSON", code="json") from exc


def _bounded_walk(value: Any) -> None:
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise WorkflowArtifactError("JSON structural limit exceeded", code="limit")
        if isinstance(current, str):
            if len(current) > MAX_STRING_LENGTH or unicodedata.normalize("NFC", current) != current:
                raise WorkflowArtifactError("JSON string is unbounded or non-NFC", code="unicode")
            try:
                current.encode("utf-8")
            except UnicodeError as exc:
                raise WorkflowArtifactError("JSON string is not UTF-8 encodable", code="unicode") from exc
        elif isinstance(current, dict):
            for key, child in current.items():
                if not isinstance(key, str):
                    raise WorkflowArtifactError("JSON object key must be a string", code="json")
                stack.append((key, depth + 1))
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
        elif current is not None and not isinstance(current, (bool, int, float)):
            raise WorkflowArtifactError("unsupported JSON value", code="json")


def _strict_json(raw: bytes, *, limit: int) -> Any:
    if len(raw) > limit or raw.startswith(b"\xef\xbb\xbf"):
        raise WorkflowArtifactError("JSON byte limit or encoding preamble rejected", code="limit")
    try:
        text = raw.decode("utf-8", errors="strict")

        def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in items:
                if key in result:
                    raise WorkflowArtifactError(f"duplicate JSON key: {key}", code="duplicate")
                result[key] = value
            return result

        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                WorkflowArtifactError(f"non-finite JSON value: {token}", code="json")
            ),
        )
    except WorkflowArtifactError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise WorkflowArtifactError("invalid strict JSON", code="json") from exc
    _bounded_walk(value)
    return value


PLACEHOLDER = re.compile(r"(?i)(?:\bUNKNOWN\b|\bTBD\b|\bTODO\b|NEEDS CLARIFICATION|\.\.\.)")
