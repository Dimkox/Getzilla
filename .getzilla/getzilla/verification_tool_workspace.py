"""Bounded source copies for stateful tools; these are not security sandboxes."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import stat

from .fsx import is_link


MAX_FILES = 20000
MAX_BYTES = 200 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
EXCLUDED = frozenset({'.git', '.venv', 'venv', 'node_modules', '__pycache__', '.pytest_cache',
                      '.hypothesis', '.ruff_cache', '.mypy_cache', '.coverage', 'htmlcov',
                      'coverage', 'mutants', '.mutmut-cache', '.stryker-tmp', 'test-results',
                      'playwright-report'})


class WorkspaceError(ValueError):
    pass


def linked(path: Path) -> bool:
    try:
        return is_link(path.lstat())
    except FileNotFoundError:
        return False


def checked_path(root: Path, relative: str, *, create: bool = False) -> Path:
    """Reject links in each component before inspecting or creating a child."""
    if not relative or '\\' in relative or ':' in relative:
        raise WorkspaceError('path must be a relative project path')
    parts = Path(relative).parts
    if Path(relative).is_absolute() or '..' in parts:
        raise WorkspaceError('path escapes the project')
    current = root
    for part in parts:
        current = current / part
        if linked(current):
            raise WorkspaceError(f'linked/reparse path is not supported: {relative}')
        if create:
            current.mkdir(exist_ok=True)
    return current


def runtime_parent(root: Path) -> Path:
    return checked_path(root, '.getzilla/runtime/verification-tools', create=True)


def _excluded(relative: Path) -> bool:
    name = relative.name
    return (name in EXCLUDED or name.startswith('.coverage.')
            or (name.startswith('.env') and name not in {'.env.example', '.env.sample', '.env.template'})
            or name in {'id_rsa', 'id_ed25519'} or name.endswith(('.pem', '.key'))
            or relative.parts[:2] in {('.getzilla', 'runtime'), ('.getzilla', 'index')}
            or (len(relative.parts) >= 3 and relative.parts[-3] == '.schemathesis' and name == 'cache')
            or relative.parts[-2:] == ('reports', 'mutation'))


def source_files(root: Path):
    """Walk current bytes, including dirty/untracked files, without following links."""
    pending = [Path('.')]
    count = size = 0
    while pending:
        directory = pending.pop()
        for path in sorted((root / directory).iterdir()):
            relative = path.relative_to(root)
            if _excluded(relative):
                continue
            metadata = path.lstat()
            if not is_link(metadata) and stat.S_ISDIR(metadata.st_mode):
                pending.append(relative)
                continue
            count += 1
            length = metadata.st_size
            size += length
            if count > MAX_FILES or size > MAX_BYTES or length > MAX_FILE_BYTES:
                raise WorkspaceError('source exceeds snapshot limits (20000 files, 200 MiB, 16 MiB/file)')
            if not stat.S_ISREG(metadata.st_mode) and not is_link(metadata):
                raise WorkspaceError(f'non-regular source file: {relative}')
            yield relative, metadata


def fingerprint(root: Path) -> str:
    digest = hashlib.sha256()
    for relative, metadata in source_files(root):
        digest.update(os.fsencode(relative.as_posix()) + b'\0' + str(metadata.st_mode).encode() + b'\0')
        path = root / relative
        if is_link(metadata):
            digest.update(os.fsencode(os.readlink(path)))
        else:
            with path.open('rb') as handle:
                content = hashlib.sha256()
                for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                    content.update(chunk)
                digest.update(content.digest())
    return digest.hexdigest()


def copy_source(root: Path, destination: Path, *, link_node_modules: bool = False) -> None:
    destination.mkdir()
    for relative, metadata in source_files(root):
        if is_link(metadata):
            raise WorkspaceError(f'snapshot refuses linked/reparse source: {relative}')
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / relative, target, follow_symlinks=False)
    if link_node_modules:
        # Only dependency directories are shared. Tool caches and source stay in this copy.
        for directory, names, _ in os.walk(root, followlinks=False):
            relative = Path(directory).relative_to(root)
            if 'node_modules' in names:
                dependency = Path(directory) / 'node_modules'
                target = destination / relative / 'node_modules'
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to(dependency.resolve(), target_is_directory=True)
            names[:] = [name for name in names if not _excluded(relative / name)
                        and not linked(Path(directory) / name)]


def read_report(path: Path, boundary: Path) -> bytes:
    try:
        relative = path.relative_to(boundary).as_posix()
    except ValueError as exc:
        raise WorkspaceError('report path is outside this run') from exc
    checked = checked_path(boundary, relative)
    if not stat.S_ISREG(checked.stat().st_mode):
        raise WorkspaceError('report is not a regular file')
    with checked.open('rb') as handle:
        data = handle.read(8 * 1024 * 1024 + 1)
    if len(data) > 8 * 1024 * 1024:
        raise WorkspaceError('report exceeds 8 MiB')
    return data
