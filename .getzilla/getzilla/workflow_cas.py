"""Atomic workflow CAS publication; the native facade supplies exact owned operations."""
from __future__ import annotations
import ctypes
import errno
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import threading
import time
import unicodedata
from typing import Any, NamedTuple, TYPE_CHECKING
if TYPE_CHECKING:
    from . import fsx

class _CASContext(NamedTuple):
    bound_cas_lock_attempts: Any
    bound_max_source_bytes: Any
    bound_workflowartifacterror: Any
    bound_cas_recovery_sequence: Any
    bound_acquire_cas_lock: Any
    bound_acquire_cas_lock_once: Any
    bound_cas_identity_at: Any
    bound_cas_write: Any
    bound_dup_dir: Any
    bound_open_root: Any
    bound_post_exchange_identity_matches: Any
    bound_rename_exchange: Any
    bound_rename_noreplace: Any
    bound_renameat2_exchange_call: Any
    bound_stat_identity: Any
    bound_strict_json: Any
    bound_windows_confirm_directories: Any
    bound_windows_open_regular: Any
    bound_canonical_json: Any
    bound_change_directory: Any
    bound_fsx: Any
    bound_validate_convergence_report: Any
    bound_validate_task_graph: Any
    bound_workflow_paths: Any


def _dup_dir(handle: fsx.DirHandle, *, _context) -> fsx.DirHandle:
    """``os.dup`` for a descriptor; a Windows directory handle is an immutable value."""
    if isinstance(handle, _context.bound_fsx.WindowsDirectory):
        return handle
    return os.dup(handle)


def _cas_identity_at(parent_fd: fsx.DirHandle, name: str, *, _context) -> tuple[int, int, int, int, int, int]:
    return _context.bound_stat_identity(_context.bound_fsx.lstat_at(parent_fd, name))


def _post_exchange_identity_matches(observed: tuple[int, int, int, int, int, int], expected: tuple[int, int, int, int, int, int], *, _context) -> bool:
    return observed[:5] == expected[:5] and observed[5] >= expected[5]


def _renameat2_exchange_call(renameat2: Any, parent_fd: int, temporary: str, target: str, *, _context) -> int:
    return renameat2(parent_fd, os.fsencode(temporary), parent_fd, os.fsencode(target), 2)


def _rename_exchange(parent_fd: fsx.DirHandle, temporary: str, target: str, expected_temporary: tuple[int, int, int, int, int, int] | None=None, expected_target: tuple[int, int, int, int, int, int] | None=None, *, _context) -> None:
    if expected_temporary is not None and _context.bound_cas_identity_at(parent_fd, temporary) != expected_temporary:
        raise _context.bound_workflowartifacterror("CAS exchange source identity changed", code="race")
    if expected_target is not None and _context.bound_cas_identity_at(parent_fd, target) != expected_target:
        raise _context.bound_workflowartifacterror("CAS exchange target identity changed", code="race")
    if _context.bound_fsx.WINDOWS:
        # ReplaceFileW + rename stands in for RENAME_EXCHANGE; unlike renameat2 the
        # private temporary name is briefly absent, and a failure between the two
        # steps leaves the displaced bytes at "<temporary>.displaced" (never deleted).
        _context.bound_fsx.exchange_at(parent_fd, temporary, target)
        return
    try:
        renameat2 = _context.bound_fsx.libc_renameat2()  # macOS: renameatx_np(RENAME_SWAP)
    except AttributeError as exc:
        raise _context.bound_workflowartifacterror(
            "atomic exchange is unavailable; existing-target CAS is unsupported on this platform",
            code="platform",
        ) from exc
    if _context.bound_renameat2_exchange_call(renameat2, parent_fd, temporary, target) != 0:
        error = ctypes.get_errno()
        if error in {errno.ENOSYS, errno.EINVAL, errno.ENOTSUP}:
            raise _context.bound_workflowartifacterror(
                "atomic exchange is unavailable; existing-target CAS is unsupported on this platform",
                code="platform",
            )
        raise OSError(error, os.strerror(error))


def _rename_noreplace(parent_fd: fsx.DirHandle, source: str, target: str, target_parent_fd: fsx.DirHandle | None=None, *, _context) -> None:
    if _context.bound_fsx.WINDOWS:
        # MoveFileEx without REPLACE_EXISTING: atomic, fails with FileExistsError on an existing target.
        _context.bound_fsx.rename_noreplace_at(parent_fd, source, parent_fd if target_parent_fd is None else target_parent_fd, target)
        return
    try:
        renameat2 = _context.bound_fsx.libc_renameat2()  # macOS: renameatx_np(RENAME_EXCL)
    except AttributeError as exc:
        raise _context.bound_workflowartifacterror("no-clobber recovery rename is unavailable", code="platform") from exc
    destination_fd = parent_fd if target_parent_fd is None else target_parent_fd
    if renameat2(parent_fd, os.fsencode(source), destination_fd, os.fsencode(target), 1) != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise FileExistsError(error, os.strerror(error), target)
        if error in {errno.ENOSYS, errno.EINVAL, errno.ENOTSUP}:
            raise _context.bound_workflowartifacterror("no-clobber recovery rename is unavailable", code="platform")
        raise OSError(error, os.strerror(error))


def _acquire_cas_lock(root: Path, change_id: str, relative_target: str, *, _context) -> tuple[int, fsx.DirHandle]:
    """Acquire the CAS lock; a transient ENOENT while two writers create its path is retried.

    macOS APFS was seen to answer ENOENT to the second of two concurrent writers. Every step
    is an idempotent mkdir/open/flock that writes no data, so a bounded retry is safe.
    """
    for attempt in range(1, _context.bound_cas_lock_attempts + 1):
        try:
            return _context.bound_acquire_cas_lock_once(root, change_id, relative_target)
        except _context.bound_workflowartifacterror as exc:
            if (exc.code != "io" or not isinstance(exc.__cause__, FileNotFoundError)
                    or attempt == _context.bound_cas_lock_attempts):
                raise
            time.sleep(0.01 * attempt)
    raise AssertionError("unreachable")  # pragma: no cover


def _acquire_cas_lock_once(root: Path, change_id: str, relative_target: str, *, _context) -> tuple[int, fsx.DirHandle]:
    _, root_fd = _context.bound_open_root(root)
    directory_fd = root_fd
    lock_fd: int | None = None
    try:
        for component in (".getzilla", "runtime", "workflow-cas", change_id):
            try:
                _context.bound_fsx.mkdir_at(directory_fd, component, 0o700)
            except FileExistsError:
                pass
            next_fd = _context.bound_fsx.open_dir_at(directory_fd, component, flags=_context.bound_fsx.O_CLOEXEC)
            _context.bound_fsx.close_dir(directory_fd)
            directory_fd = next_fd
        lock_name = hashlib.sha256(relative_target.encode("utf-8")).hexdigest() + ".lock"
        lock_fd = _context.bound_fsx.open_at(
            directory_fd,
            lock_name,
            os.O_RDWR | os.O_CREAT | _context.bound_fsx.O_NOFOLLOW | _context.bound_fsx.O_CLOEXEC | _context.bound_fsx.O_NONBLOCK,
            0o600,
        )
        before = os.fstat(lock_fd)
        if not stat.S_ISREG(before.st_mode):
            raise _context.bound_workflowartifacterror("CAS lock is not a regular file", code="cas")
        if not _context.bound_fsx.WINDOWS:
            os.set_blocking(lock_fd, True)
        # Windows msvcrt.locking retries for about ten seconds, then fails closed as an io error.
        _context.bound_fsx.lock_file(lock_fd)
        current = _context.bound_fsx.lstat_at(directory_fd, lock_name)
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            current.st_dev,
            current.st_ino,
            current.st_mode,
            current.st_size,
            current.st_mtime_ns,
            current.st_ctime_ns,
        ):
            raise _context.bound_workflowartifacterror("CAS lock identity changed", code="race")
        result = (lock_fd, _context.bound_dup_dir(directory_fd))
        lock_fd = None
        return result
    except _context.bound_workflowartifacterror:
        raise
    except OSError as exc:
        raise _context.bound_workflowartifacterror("CAS lock acquisition failed", code="io") from exc
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
        _context.bound_fsx.close_dir(directory_fd)


def cas_write(root: Path, change_id: str, relative_target: str, data: bytes, expected_digest: str, *, _context) -> str:
    return _context.bound_cas_write(root, change_id, relative_target, data, expected_digest)


def _cas_write(root: Path, change_id: str, relative_target: str, data: bytes, expected_digest: str, *, package_target: bool=False, _context) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
        raise _context.bound_workflowartifacterror("expected digest must be lowercase SHA-256", code="cas")
    if len(data) > _context.bound_max_source_bytes:
        raise _context.bound_workflowartifacterror("CAS payload exceeds byte limit", code="limit")
    _context.bound_workflow_paths(root, change_id)
    target_path = PurePosixPath(relative_target)
    target_parts = target_path.parts
    if (
        not target_parts
        or len(target_parts) > 8
        or any(part in {"", ".", ".."} for part in target_parts)
        or len(relative_target) > 512
        or unicodedata.normalize("NFC", relative_target) != relative_target
    ):
        raise _context.bound_workflowartifacterror("invalid workflow write target", code="path")
    direct = relative_target in {"task-graph.json", "convergence-report.json"}
    projected = len(target_parts) >= 2 and target_parts[0] in {"projections", "exports"}
    if package_target:
        from .workflow_storage import intake_package_target
        if not intake_package_target(relative_target):
            raise _context.bound_workflowartifacterror('native package target is not allowlisted', code='path')
    elif not direct and not projected:
        raise _context.bound_workflowartifacterror("workflow write target is not allowlisted", code="path")
    if direct and not package_target:
        derived = _context.bound_strict_json(data, limit=_context.bound_max_source_bytes)
        if relative_target == "task-graph.json":
            _context.bound_validate_task_graph(derived)
        else:
            _context.bound_validate_convergence_report(derived)
        if _context.bound_canonical_json(derived) != data:
            raise _context.bound_workflowartifacterror("derived workflow artifact is not canonical JSON", code="cas")

    package = _context.bound_change_directory(root, change_id, writable=True)
    lock_key = relative_target.removeprefix('workflow/') if package_target and relative_target.startswith('workflow/') else ('package/' + relative_target if package_target else relative_target)
    lock_fd, recovery_dir_fd = _context.bound_acquire_cas_lock(root, change_id, lock_key)
    _, root_fd = _context.bound_open_root(root)
    directory_fd: _context.bound_fsx.DirHandle | None = root_fd
    parent_fd: _context.bound_fsx.DirHandle | None = None
    descriptor: int | None = None
    recovery_token = hashlib.sha256(
        f"{relative_target}\0{os.getpid()}\0{threading.get_ident()}\0{next(_context.bound_cas_recovery_sequence)}".encode()
    ).hexdigest()[:24]
    temporary = f".agb-stage-{recovery_token}"
    recovery = f".agb-recovery-{recovery_token}"
    temporary_exists = False
    temporary_identity: tuple[int, int, int, int, int, int] | None = None
    flags_file = 0 if _context.bound_fsx.WINDOWS else os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    # Windows walks paths, so the pinned directories are re-confirmed before publication.
    windows_chain: list[_context.bound_fsx.DirHandle] = [root_fd, recovery_dir_fd] if _context.bound_fsx.WINDOWS else []

    def entry_identity(fd: _context.bound_fsx.DirHandle, name: str) -> tuple[int, int, int, int, int, int]:
        return _context.bound_cas_identity_at(fd, name)

    def digest_target(fd: _context.bound_fsx.DirHandle, name: str) -> tuple[str, tuple[int, int, int, int, int, int]]:
        source_fd: int | None = None
        try:
            if _context.bound_fsx.WINDOWS:
                source_fd = _context.bound_windows_open_regular(fd, name)
                if source_fd is None:
                    raise _context.bound_workflowartifacterror("CAS target is not a bounded regular file", code="cas")
            else:
                source_fd = os.open(name, flags_file, dir_fd=fd)
            before = os.fstat(source_fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size > _context.bound_max_source_bytes:
                raise _context.bound_workflowartifacterror("CAS target is not a bounded regular file", code="cas")
            digest = hashlib.sha256()
            remaining = _context.bound_max_source_bytes + 1
            while remaining:
                chunk = os.read(source_fd, min(65_536, remaining))
                if not chunk:
                    break
                digest.update(chunk)
                remaining -= len(chunk)
            after = os.fstat(source_fd)
            before_identity = _context.bound_stat_identity(before)
            after_identity = _context.bound_stat_identity(after)
            if before.st_size > _context.bound_max_source_bytes or before_identity != after_identity:
                raise _context.bound_workflowartifacterror("CAS target changed while reading", code="race")
            return digest.hexdigest(), after_identity
        finally:
            if source_fd is not None:
                os.close(source_fd)

    def preserve_temporary() -> str | None:
        nonlocal temporary_exists
        if not temporary_exists or parent_fd is None:
            return None
        try:
            _context.bound_rename_noreplace(parent_fd, temporary, recovery, recovery_dir_fd)
        except FileNotFoundError:
            artifact = None
        except (FileExistsError, OSError, _context.bound_workflowartifacterror):
            artifact = temporary
        else:
            artifact = recovery
        temporary_exists = False
        return artifact

    try:
        base_parts = package.relative_to(root).parts if package_target else (*package.relative_to(root).parts, 'workflow')
        for component in base_parts:
            next_fd = _context.bound_fsx.open_dir_at(directory_fd, component, flags=_context.bound_fsx.O_CLOEXEC)
            _context.bound_fsx.close_dir(directory_fd)
            directory_fd = next_fd
            if _context.bound_fsx.WINDOWS:
                windows_chain.append(next_fd)
        for component in target_parts[:-1]:
            try:
                _context.bound_fsx.mkdir_at(directory_fd, component, 0o700)
            except FileExistsError:
                pass
            next_fd = _context.bound_fsx.open_dir_at(directory_fd, component, flags=_context.bound_fsx.O_CLOEXEC)
            _context.bound_fsx.close_dir(directory_fd)
            directory_fd = next_fd
            if _context.bound_fsx.WINDOWS:
                windows_chain.append(next_fd)
        parent_fd = directory_fd
        directory_fd = None

        try:
            current, current_identity = digest_target(parent_fd, target_parts[-1])
        except FileNotFoundError:
            current = "0" * 64
            current_identity = None
        if current != expected_digest:
            raise _context.bound_workflowartifacterror("CAS expected digest mismatch", code="cas")

        descriptor = _context.bound_fsx.open_at(
            parent_fd,
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _context.bound_fsx.O_NOFOLLOW | _context.bound_fsx.O_CLOEXEC,
            0o600,
        )
        temporary_exists = True
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.fsync(descriptor)
        temporary_stat = os.fstat(descriptor)
        temporary_identity = _context.bound_stat_identity(temporary_stat)
        os.close(descriptor)
        descriptor = None
        if _context.bound_fsx.WINDOWS:
            _context.bound_windows_confirm_directories(windows_chain)
        if current_identity is None:
            try:
                if _context.bound_fsx.WINDOWS:
                    # MoveFileEx without REPLACE_EXISTING publishes atomically and never
                    # clobbers; the staged name is consumed, so no recovery copy remains.
                    _context.bound_fsx.rename_noreplace_at(parent_fd, temporary, parent_fd, target_parts[-1])
                    temporary_exists = False
                else:
                    os.link(
                        temporary,
                        target_parts[-1],
                        src_dir_fd=parent_fd,
                        dst_dir_fd=parent_fd,
                        follow_symlinks=False,
                    )
            except FileExistsError as exc:
                raise _context.bound_workflowartifacterror("CAS target appeared before publication", code="race") from exc
            preserve_temporary()
        else:
            _context.bound_rename_exchange(parent_fd, temporary, target_parts[-1], temporary_identity, current_identity)
            displaced_identity = None
            published_identity = None
            try:
                displaced_identity = entry_identity(parent_fd, temporary)
                published_identity = entry_identity(parent_fd, target_parts[-1])
                identities_valid = _context.bound_post_exchange_identity_matches(
                    displaced_identity, current_identity
                ) and _context.bound_post_exchange_identity_matches(published_identity, temporary_identity)
                displaced_digest = None
                if identities_valid:
                    displaced_digest, hashed_displaced_identity = digest_target(parent_fd, temporary)
                    identities_valid = _context.bound_post_exchange_identity_matches(
                        hashed_displaced_identity, displaced_identity
                    )
                publication_valid = identities_valid and displaced_digest == expected_digest
            except (OSError, _context.bound_workflowartifacterror):
                publication_valid = False
            if not publication_valid:
                rollback_error: BaseException | None = None
                try:
                    _context.bound_rename_exchange(
                        parent_fd,
                        temporary,
                        target_parts[-1],
                        displaced_identity,
                        published_identity,
                    )
                except Exception as exc:  # preserve entries even when platform rollback fails
                    rollback_error = exc
                if rollback_error is None:
                    try:
                        restored_identity = entry_identity(parent_fd, target_parts[-1])
                    except OSError:
                        restored_identity = None
                    try:
                        rollback_temp_identity = entry_identity(parent_fd, temporary)
                    except OSError:
                        rollback_temp_identity = None
                    recovery_artifact = preserve_temporary()
                    restored_changed = displaced_identity is not None and (
                        restored_identity is None
                        or not _context.bound_post_exchange_identity_matches(restored_identity, displaced_identity)
                    )
                    rollback_temp_changed = published_identity is not None and (
                        rollback_temp_identity is None
                        or not _context.bound_post_exchange_identity_matches(rollback_temp_identity, published_identity)
                    )
                    if restored_changed or rollback_temp_changed:
                        raise _context.bound_workflowartifacterror(
                            f"CAS rollback raced; competing entries were preserved for forward recovery at {recovery_artifact}",
                            code="race",
                        )
                    raise _context.bound_workflowartifacterror(
                        f"CAS target changed before atomic publication and was restored; recovery={recovery_artifact}",
                        code="race",
                    )
                recovery_artifact = preserve_temporary()
                raise _context.bound_workflowartifacterror(
                    f"CAS rollback failed closed with entries preserved at {recovery_artifact}: {rollback_error}",
                    code="race",
                )
            preserve_temporary()
        _context.bound_fsx.fsync_dir(parent_fd)
    except _context.bound_workflowartifacterror:
        raise
    except OSError as exc:
        raise _context.bound_workflowartifacterror("CAS publication failed", code="io") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory_fd is not None:
            _context.bound_fsx.close_dir(directory_fd)
        if parent_fd is not None:
            if temporary_exists:
                preserve_temporary()
            _context.bound_fsx.close_dir(parent_fd)
        _context.bound_fsx.unlock_file(lock_fd)
        os.close(lock_fd)
        _context.bound_fsx.close_dir(recovery_dir_fd)
    return hashlib.sha256(data).hexdigest()
