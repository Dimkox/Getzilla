"""Durable operation journal for Zero-Git adoption, outside the source and the target.

Transitions only move forward through STATES (no skipped stage), are written atomically after
the stage they record has been verified, and one exclusive lock admits a single writer per
operation. A state label is never trusted on its own: resume re-verifies the artifacts.
"""
from __future__ import annotations

import json
import os
import sys
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from . import fsx
from .source_models import OPERATION_ID, STATES, TERMINAL_ERRORS
from .source_snapshot import AdoptionError

SCHEMA = 'adoption-operation-v1'


def default_state_root() -> Path:
    override = os.environ.get('GETZILLA_ADOPTION_STATE')
    if override:
        return Path(override)
    if os.name == 'nt':
        return Path(os.environ.get('LOCALAPPDATA') or Path.home() / 'AppData/Local') / 'Getzilla' / 'adoption'
    if sys.platform == 'darwin':
        return Path.home() / 'Library' / 'Application Support' / 'Getzilla' / 'adoption'
    return Path(os.environ.get('XDG_STATE_HOME') or Path.home() / '.local' / 'state') / 'getzilla' / 'adoption'


def operation_id_for(plan_id: str) -> str:
    return 'op-' + plan_id[:32]


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class OperationState:
    operation_id: str
    plan_id: str
    source: str
    target: str
    staging: str
    timestamp: str
    state: str = 'PLAN_READY'
    history: list[dict[str, str]] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)
    reason_code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {'schema_version': SCHEMA, 'operation_id': self.operation_id, 'plan_id': self.plan_id,
                'source': self.source, 'target': self.target, 'staging': self.staging, 'timestamp': self.timestamp,
                'state': self.state, 'history': self.history, 'artifacts': self.artifacts,
                'reason_code': self.reason_code}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OperationState:
        if data.get('schema_version') != SCHEMA or not OPERATION_ID.fullmatch(str(data.get('operation_id', ''))):
            raise AdoptionError('STATE_CORRUPT', 'unknown or malformed operation state')
        if data['state'] not in STATES and data['state'] not in TERMINAL_ERRORS:
            raise AdoptionError('STATE_CORRUPT', f'unknown state {data["state"]!r}')
        return cls(**{key: data[key] for key in ('operation_id', 'plan_id', 'source', 'target', 'staging', 'timestamp',
                                                  'state', 'history', 'artifacts', 'reason_code')})


class Journal:
    def __init__(self, state_root: Path, operation_id: str) -> None:
        if not OPERATION_ID.fullmatch(operation_id):
            raise AdoptionError('INVALID_ARGUMENTS', 'malformed operation id')
        self.root = state_root / 'operations' / operation_id
        self.path = self.root / 'state.json'

    def exists(self) -> bool:
        return self.path.is_file()

    def load(self) -> OperationState:
        try:
            return OperationState.from_dict(json.loads(self.path.read_text(encoding='utf-8')))
        except FileNotFoundError as exc:
            raise AdoptionError('UNKNOWN_OPERATION', 'no such operation') from exc
        except ValueError as exc:
            raise AdoptionError('STATE_CORRUPT', str(exc)) from exc

    def save(self, state: OperationState) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        if os.name == 'posix':
            os.chmod(self.root, 0o700)
        temporary = self.root / f'.state-{os.urandom(6).hex()}.json'
        temporary.write_text(json.dumps(state.to_dict(), sort_keys=True, indent=2) + '\n', encoding='utf-8', newline='\n')
        os.replace(temporary, self.path)

    def advance(self, state: OperationState, new_state: str, **artifacts: Any) -> None:
        if new_state in TERMINAL_ERRORS:
            state.state = new_state
        else:
            current = STATES.index(state.state) if state.state in STATES else -1
            target = STATES.index(new_state)
            if target != current + 1:
                raise AdoptionError('STATE_CORRUPT', f'illegal transition {state.state} -> {new_state}')
            state.state = new_state
        state.artifacts.update(artifacts)
        state.history.append({'state': new_state, 'at': now()})
        self.save(state)

    def write_json(self, name: str, record: dict[str, Any]) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        path = self.root / name
        temporary = self.root / f'.{name}-{os.urandom(6).hex()}'
        temporary.write_text(json.dumps(record, sort_keys=True, indent=2) + '\n', encoding='utf-8', newline='\n')
        os.replace(temporary, path)
        return path

    @contextmanager
    def lock(self) -> Iterator[None]:
        self.root.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self.root / 'lock', os.O_RDWR | os.O_CREAT | getattr(os, 'O_BINARY', 0), 0o600)
        try:
            try:
                fsx.lock_file(descriptor, exclusive=True, blocking=False)
            except OSError as exc:
                raise AdoptionError('OPERATION_LOCKED', 'another writer owns this operation') from exc
            try:
                yield
            finally:
                fsx.unlock_file(descriptor)
        finally:
            os.close(descriptor)
