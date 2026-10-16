"""Verified private snapshot of the admitted bytes (Zero-Git, SNAPSHOT_VERIFIED).

Each admitted file is read whole into a bounded memory buffer, its digest compared with the
approved plan entry and the same buffer rescanned; only then is that buffer written to the
private content-addressed store. Nothing is spooled to disk before both checks pass, so bytes
swapped in after planning are never written, not even temporarily. After the copy every stored
object is re-hashed and the source is inventoried a second time (quiesced_two_pass); drift
voids the snapshot. The store is tamper-evident (digest-verified), not physically immutable.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .source_admission import classify_entries
from .source_baseline import source_digest
from .source_inventory import inventory_source
from .source_models import AdmissionPlan, IngestPolicy, SourceEntry, domain_digest
from .source_secrets import evaluate, read_entry


class AdoptionError(RuntimeError):
    """A stage refused; `reason_code` is stable and machine-readable."""

    def __init__(self, reason_code: str, message: str = '') -> None:
        super().__init__(f'{reason_code}: {message}' if message else reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True)
class SnapshotReceipt:
    snapshot_id: str
    plan_id: str
    source_digest: str
    store: str
    entries: tuple[SourceEntry, ...]
    total_bytes: int
    consistency: dict[str, Any]
    executable_mode: str = 'posix-mode'

    def to_dict(self) -> dict[str, Any]:
        return {'schema_version': 'source-snapshot-v1', 'snapshot_id': self.snapshot_id, 'plan_id': self.plan_id,
                'source_digest': self.source_digest, 'store': self.store, 'entry_count': len(self.entries),
                'total_bytes': self.total_bytes, 'entries': [entry.to_dict() for entry in self.entries],
                'consistency': self.consistency, 'executable_mode': self.executable_mode}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SnapshotReceipt:
        return cls(snapshot_id=data['snapshot_id'], plan_id=data['plan_id'], source_digest=data['source_digest'],
                   store=data['store'], entries=tuple(SourceEntry.from_dict(item) for item in data['entries']),
                   total_bytes=data['total_bytes'], consistency=data['consistency'],
                   executable_mode=data['executable_mode'])


def _private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if os.name == 'posix':
        os.chmod(path, 0o700)


def object_path(store: Path, digest: str) -> Path:
    return store / 'objects' / digest[:2] / digest


def read_object(store: Path, entry: SourceEntry) -> bytes:
    """Bytes of one stored object, refused unless they still hash to the entry."""
    path = object_path(store, entry.sha256)
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise AdoptionError('STORE_OBJECT_MISSING', entry.path) from exc
    if not path.is_file() or path.is_symlink() or info.st_size != entry.size:
        raise AdoptionError('STORE_OBJECT_MODIFIED', entry.path)
    content = path.read_bytes()
    if hashlib.sha256(content).hexdigest() != entry.sha256:
        raise AdoptionError('STORE_OBJECT_MODIFIED', entry.path)
    return content


def _store_object(store: Path, entry: SourceEntry, content: bytes) -> None:
    final = object_path(store, entry.sha256)
    _private_dir(final.parent)
    if os.path.lexists(final):
        read_object(store, entry)  # an existing object must still be exactly these bytes
        return
    temporary = final.parent / f'.tmp-{os.getpid()}-{os.urandom(8).hex()}'
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0), 0o600)
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.link(temporary, final)  # fails if another writer published the name meanwhile
    except FileExistsError:
        pass
    finally:
        os.unlink(temporary)
    read_object(store, entry)


def create_snapshot(plan: AdmissionPlan, source: Path, store: Path, *, quiesced: bool) -> SnapshotReceipt:
    if not quiesced:
        raise AdoptionError('QUIESCENCE_REQUIRED', 'stop every writer of the source and acknowledge it')
    if plan.status != 'PLAN_READY' or plan.plan_id != plan.compute_id():
        raise AdoptionError('PLAN_NOT_READY', plan.status)
    policy = IngestPolicy.from_dict(plan.policy)
    if policy.digest() != plan.policy_digest:
        raise AdoptionError('STALE_PLAN', 'policy digest mismatch')
    per_file = min(policy.max_file_bytes, policy.max_buffered_file_bytes)
    _private_dir(store)
    total = 0
    for entry in plan.entries:
        if entry.size > policy.max_buffered_file_bytes:
            raise AdoptionError('BUFFER_LIMIT', f'{entry.path} exceeds max_buffered_file_bytes; exclude it explicitly')
        content, problem = read_entry(source, entry, per_file)
        if problem or content is None:
            raise AdoptionError('STALE_PLAN', f'{entry.path}: {problem}')
        findings, opaque = evaluate(entry, content, policy)
        if findings or opaque is not None:
            raise AdoptionError('BLOCKED_SECURITY', entry.path)
        _store_object(store, entry, content)
        total += entry.size
        del content
    for entry in plan.entries:
        read_object(store, entry)
    second = inventory_source(source, policy)
    classified = classify_entries(second, policy)
    second_digest = source_digest(classified.candidates, plan.path_profile, plan.executable_mode)
    if second.blockers or second_digest != plan.source_digest or classified.blockers:
        raise AdoptionError('STALE_PLAN', 'source changed during the snapshot (second pass)')
    consistency = {'mode': 'quiesced_two_pass', 'writers_stopped_acknowledged': True, 'passes': 2,
                   'second_pass_digest': second_digest}
    snapshot_id = domain_digest('getzilla-source-snapshot-v1', {
        'plan_id': plan.plan_id, 'source_digest': plan.source_digest,
        'objects': [[entry.path, entry.sha256] for entry in plan.entries]})
    receipt = SnapshotReceipt(snapshot_id=snapshot_id, plan_id=plan.plan_id, source_digest=plan.source_digest or '',
                              store=str(store), entries=plan.entries, total_bytes=total, consistency=consistency,
                              executable_mode=plan.executable_mode)
    snapshots = store / 'snapshots'
    _private_dir(snapshots)
    record = snapshots / f'{snapshot_id}.json'
    if not record.exists():
        temporary = snapshots / f'.tmp-{os.urandom(8).hex()}'
        temporary.write_text(json.dumps(receipt.to_dict(), sort_keys=True, indent=2) + '\n', encoding='utf-8', newline='\n')
        try:
            os.link(temporary, record)
        except FileExistsError:
            pass
        finally:
            os.unlink(temporary)
    return receipt


def load_snapshot(store: Path, snapshot_id: str) -> SnapshotReceipt:
    record = store / 'snapshots' / f'{snapshot_id}.json'
    receipt = SnapshotReceipt.from_dict(json.loads(record.read_text(encoding='utf-8')))
    if receipt.snapshot_id != snapshot_id:
        raise AdoptionError('STORE_OBJECT_MODIFIED', 'snapshot record id mismatch')
    for entry in receipt.entries:
        read_object(store, entry)
    if source_digest(receipt.entries, 'portable-v1', receipt.executable_mode) != receipt.source_digest:
        raise AdoptionError('STORE_OBJECT_MODIFIED', 'snapshot entries do not reproduce the source digest')
    return receipt

