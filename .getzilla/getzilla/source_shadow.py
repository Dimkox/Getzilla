"""Operation-owned shadow workspace built from the verified snapshot (SHADOW_MATERIALIZED).

The shadow is a fresh directory the operation creates; it never exists before, is never the
source or the final target, and gets independent copies (no hard links or reflinks) of the
verified snapshot objects, so source and shadow can change independently.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from .source_paths import source_target_problem
from .source_snapshot import AdoptionError, SnapshotReceipt, read_object


@dataclass(frozen=True)
class ShadowReceipt:
    path: str
    identity: tuple[int, int]
    snapshot_id: str
    files: int

    def to_dict(self) -> dict:
        return {'path': self.path, 'identity': list(self.identity), 'snapshot_id': self.snapshot_id, 'files': self.files}


def shadow_identity(path: Path) -> tuple[int, int]:
    info = path.lstat()
    return (info.st_dev, info.st_ino)


def materialize_shadow(snapshot: SnapshotReceipt, store: Path, shadow: Path, source: Path) -> ShadowReceipt:
    problem = source_target_problem(source, shadow)
    if problem:
        raise AdoptionError('BLOCKED_UNSAFE_SOURCE', f'shadow: {problem}')
    shadow.mkdir(mode=0o700)  # FileExistsError: an existing directory is never taken over
    identity = shadow_identity(shadow)
    created = 0
    for entry in snapshot.entries:
        content = read_object(store, entry)
        path = shadow.joinpath(*entry.path.split('/'))
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0),
                             0o755 if entry.executable else 0o644)
        try:
            view = memoryview(content)
            while view:
                view = view[os.write(descriptor, view):]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        created += 1
    verify_shadow_files(shadow, snapshot)
    if shadow_identity(shadow) != identity:
        raise AdoptionError('TARGET_CONFLICT', 'shadow directory was replaced')
    return ShadowReceipt(path=str(shadow), identity=identity, snapshot_id=snapshot.snapshot_id, files=created)


def verify_shadow_files(shadow: Path, snapshot: SnapshotReceipt) -> None:
    for entry in snapshot.entries:
        path = shadow.joinpath(*entry.path.split('/'))
        if path.is_symlink() or not path.is_file():
            raise AdoptionError('VERIFICATION_FAILED', f'shadow file missing: {entry.path}')
        if hashlib.sha256(path.read_bytes()).hexdigest() != entry.sha256:
            raise AdoptionError('VERIFICATION_FAILED', f'shadow file differs: {entry.path}')
        if os.name == 'posix' and bool(path.stat().st_mode & 0o111) != entry.executable:
            raise AdoptionError('VERIFICATION_FAILED', f'shadow mode differs: {entry.path}')
