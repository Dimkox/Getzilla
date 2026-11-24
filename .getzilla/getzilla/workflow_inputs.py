"""Exact bounded JSON and regular source inputs shared by intake and workflows."""
from __future__ import annotations
import errno
import os
import stat
from pathlib import Path, PurePosixPath
try:
    from .workflow_storage import (  # noqa: F401 exact shared contract exports
        MAX_DEPTH, MAX_NODES, MAX_SOURCE_BYTES, MAX_STRING_LENGTH, PLACEHOLDER, WorkflowArtifactError, _bounded_walk, _strict_json, canonical_json,
    )
    from . import fsx
except ImportError:  # standalone workflow input shares its original platform owner
    import importlib.util as _importlib_util
    import sys as _sys
    def _load_standalone_fsx():
        spec = _importlib_util.spec_from_file_location(
            "_getzilla_workflow_artifacts_fsx", Path(__file__).with_name("fsx.py")
        )
        assert spec is not None and spec.loader is not None
        module = _importlib_util.module_from_spec(spec)
        missing = object()
        previous = _sys.modules.get(spec.name, missing)
        # Deferred dataclass annotations resolve through the real module registry.
        _sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            if _sys.modules.get(spec.name) is module:
                if previous is missing:
                    del _sys.modules[spec.name]
                else:
                    _sys.modules[spec.name] = previous
            raise
        return module

    fsx = _load_standalone_fsx()
    _JSON_SPEC = _importlib_util.spec_from_file_location(
        "_getzilla_workflow_storage", Path(__file__).with_name("workflow_storage.py"))
    assert _JSON_SPEC is not None and _JSON_SPEC.loader is not None
    _json_contract = _importlib_util.module_from_spec(_JSON_SPEC)
    _JSON_SPEC.loader.exec_module(_json_contract)
    MAX_DEPTH = _json_contract.MAX_DEPTH
    MAX_NODES = _json_contract.MAX_NODES
    MAX_SOURCE_BYTES = _json_contract.MAX_SOURCE_BYTES
    MAX_STRING_LENGTH = _json_contract.MAX_STRING_LENGTH
    PLACEHOLDER = _json_contract.PLACEHOLDER
    WorkflowArtifactError = _json_contract.WorkflowArtifactError
    _bounded_walk = _json_contract._bounded_walk
    _strict_json = _json_contract._strict_json
    canonical_json = _json_contract.canonical_json



















def _open_root(root: Path) -> tuple[Path, fsx.DirHandle]:
    canonical = root.resolve(strict=True)
    if fsx.WINDOWS:
        # No directory descriptors: fsx pins path plus identity and refuses links/junctions.
        try:
            return canonical, fsx.open_dir(canonical)
        except OSError as exc:
            raise WorkflowArtifactError("cannot open repository root safely", code="io") from exc
    required = ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK")
    if any(not hasattr(os, name) for name in required) or os.open not in getattr(os, "supports_dir_fd", set()):
        raise WorkflowArtifactError("secure descriptor reads unsupported", code="platform")
    try:
        descriptor = os.open(canonical, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise WorkflowArtifactError("cannot open repository root safely", code="io") from exc
    return canonical, descriptor


def _windows_open_regular(directory: fsx.DirHandle, name: str) -> int | None:
    """Windows stand-in for an ``O_NOFOLLOW`` open: refuse links, then pin the opened identity.

    ``None`` marks an entry that is neither a link nor a regular file: where POSIX
    opens it and the caller's ``S_ISREG`` check rejects it, Windows cannot open it.
    """
    expected = fsx.lstat_at(directory, name)
    if fsx.is_link(expected):
        raise OSError(errno.ELOOP, "refusing to follow a link or reparse point", name)
    if not stat.S_ISREG(expected.st_mode):
        return None
    descriptor = fsx.open_at(directory, name, os.O_RDONLY)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
            raise OSError(errno.ELOOP, "entry changed between inspection and open", name)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _windows_confirm_directories(handles: list[fsx.DirHandle]) -> None:
    """Re-check every pinned Windows directory; a swapped or relinked ancestor fails closed."""
    for handle in handles:
        current = fsx.fstat_dir(handle)
        if (current.st_dev, current.st_ino) != (handle.info.st_dev, handle.info.st_ino):
            raise OSError(errno.ENOTDIR, "directory identity changed", fsx.path_of(handle))


def _read_regular_windows(root: Path, relative: str, *, limit: int) -> bytes:
    _canonical, directory = _open_root(root)
    parts = PurePosixPath(relative).parts
    chain = [directory]
    descriptor: int | None = None
    try:
        for component in parts[:-1]:
            directory = fsx.open_dir_at(directory, component)
            chain.append(directory)
        descriptor = _windows_open_regular(directory, parts[-1])
        if descriptor is None:
            raise WorkflowArtifactError(f"source is not a bounded regular file: {relative}", code="file")
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise WorkflowArtifactError(f"source is not a bounded regular file: {relative}", code="file")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise WorkflowArtifactError(f"source exceeds byte limit: {relative}", code="limit")
        after = os.fstat(descriptor)
        if _stat_identity(before) != _stat_identity(after):
            raise WorkflowArtifactError(f"source changed while reading: {relative}", code="race")
        _windows_confirm_directories(chain)
        return b"".join(chunks)
    except WorkflowArtifactError:
        raise
    except OSError as exc:
        raise WorkflowArtifactError(f"cannot read source safely: {relative}", code="io") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read_regular(root: Path, relative: str, *, limit: int) -> bytes:
    if fsx.WINDOWS:
        return _read_regular_windows(root, relative, limit=limit)
    canonical, root_fd = _open_root(root)
    del canonical
    parts = PurePosixPath(relative).parts
    directory_fd = os.dup(root_fd)
    os.close(root_fd)
    descriptor: int | None = None
    flags_dir = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    flags_file = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    try:
        for component in parts[:-1]:
            next_fd = os.open(component, flags_dir, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        descriptor = os.open(parts[-1], flags_file, dir_fd=directory_fd)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise WorkflowArtifactError(f"source is not a bounded regular file: {relative}", code="file")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise WorkflowArtifactError(f"source exceeds byte limit: {relative}", code="limit")
        after = os.fstat(descriptor)
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        observed = (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if identity != observed:
            raise WorkflowArtifactError(f"source changed while reading: {relative}", code="race")
        return b"".join(chunks)
    except WorkflowArtifactError:
        raise
    except OSError as exc:
        raise WorkflowArtifactError(f"cannot read source safely: {relative}", code="io") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory_fd)


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    # Windows st_ctime is the creation time, which ReplaceFileW copies from the
    # replaced file, not a change clock; the identity omits it there.
    change = 0 if fsx.WINDOWS else value.st_ctime_ns
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, change)
