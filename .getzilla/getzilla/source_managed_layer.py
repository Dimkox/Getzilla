"""Getzilla's managed layer in the owned shadow, as a second commit (MANAGED_LAYER_COMMITTED).

The payload comes from the installer's own descriptor-validated `build_payload`; the public
`--materialize-new` contract (absent targets only) is not widened. A payload path that already
exists in the admitted source with different bytes blocks the operation: source-owned files,
including `.gitignore`, `AGENTS.md` and tool configs, are never replaced silently. Getzilla's
local cache ignores go to `.git/info/exclude`, which is not part of any commit.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Sequence

from .source_git import GitEntry, IsolatedGit, commit, expect_tree, tree_entries, write_tree
from .source_models import domain_digest
from .source_provenance import PROVENANCE_PATH, provenance_bytes
from .source_snapshot import AdoptionError

LOCAL_EXCLUDES = '# Getzilla local state (not committed)\n/.getzilla/runtime/\n/.getzilla/index/\n'


@dataclass(frozen=True)
class ManagedLayerReceipt:
    managed_commit: str
    managed_tree: str
    payload_digest: str
    files: int

    def to_dict(self) -> dict:
        return {'managed_commit': self.managed_commit, 'managed_tree': self.managed_tree,
                'payload_digest': self.payload_digest, 'files': self.files}


def load_installer(home: Path) -> ModuleType:
    name = '_getzilla_install_into_for_adoption'
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, home / 'scripts/install_into.py')
    if spec is None or spec.loader is None:
        raise AdoptionError('TOOL_ERROR', 'installer not found in the Getzilla home')
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def payload_entries(home: Path) -> tuple[GitEntry, ...]:
    installer = load_installer(home)
    try:
        payload = installer.build_payload(home)
    except installer.UnsafeInstallTarget as exc:
        raise AdoptionError('TOOL_ERROR', f'Getzilla payload is not safely readable: {exc}') from exc
    return tuple(GitEntry(entry.path, '100755' if entry.mode & 0o111 else '100644', entry.content) for entry in payload)


def payload_digest(entries: Sequence[GitEntry]) -> str:
    return domain_digest('getzilla-managed-payload-v1',
                         [[entry.path, entry.mode, hashlib.sha256(entry.content).hexdigest()] for entry in entries])


def _write(path: Path, content: bytes, executable: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0),
                         0o755 if executable else 0o644)
    try:
        view = memoryview(content)
        while view:
            view = view[os.write(descriptor, view):]
    finally:
        os.close(descriptor)


def plan_managed_layer(shadow: Path, home: Path, source_paths: set[str]) -> tuple[tuple[GitEntry, ...], list[str]]:
    """Payload entries to add, and the source-owned paths they would collide with."""
    entries = payload_entries(home)
    collisions: list[str] = []
    prefixes = {'/'.join(path.split('/')[:depth]) for path in source_paths for depth in range(1, path.count('/') + 1)}
    for entry in entries:
        if entry.path in source_paths:
            if (shadow / entry.path).read_bytes() != entry.content:
                collisions.append(entry.path)
        elif entry.path in prefixes or any(entry.path.startswith(path + '/') for path in source_paths):
            collisions.append(entry.path)
    if PROVENANCE_PATH in source_paths:
        collisions.append(PROVENANCE_PATH)
    return entries, sorted(set(collisions))


def apply_managed_layer(shadow: Path, home: Path, provenance: dict, source_paths: set[str], source_commit: str,
                        *, timestamp: str) -> ManagedLayerReceipt:
    entries, collisions = plan_managed_layer(shadow, home, source_paths)
    if collisions:
        raise AdoptionError('TARGET_CONFLICT', 'source-owned files collide with the Getzilla layer: '
                            + ', '.join(collisions[:20]))
    new_entries = [entry for entry in entries if entry.path not in source_paths]
    for entry in new_entries:
        _write(shadow.joinpath(*entry.path.split('/')), entry.content, entry.mode == '100755')
    record = GitEntry(PROVENANCE_PATH, '100644', provenance_bytes(provenance))
    _write(shadow.joinpath(*PROVENANCE_PATH.split('/')), record.content, False)
    with IsolatedGit(shadow, timestamp=timestamp) as git:
        before = tree_entries(git, git.run('rev-parse', f'{source_commit}^{{tree}}').decode().strip())
        tree = write_tree(git, [*new_entries, record], replace_index=False)
        expected = [GitEntry(path, mode, (shadow / path).read_bytes()) for path, (mode, _oid) in before.items()]
        expect_tree(git, tree, [*expected, *new_entries, record])
        managed = commit(git, tree, 'Add the Getzilla managed layer\n\nGetzilla-Import: managed-layer\n'
                         f'Getzilla-Source-Commit: {source_commit}\n', parent=source_commit)
        exclude = shadow / '.git' / 'info' / 'exclude'
        exclude.parent.mkdir(parents=True, exist_ok=True)
        with exclude.open('ab') as handle:
            handle.write(LOCAL_EXCLUDES.encode('ascii'))
    return ManagedLayerReceipt(managed_commit=managed, managed_tree=tree, payload_digest=payload_digest(entries),
                               files=len(new_entries) + 1)
