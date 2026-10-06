"""Directory-relative file access that also works on native Windows.

On POSIX every helper is a thin alias for the descriptor-relative call the
engine always used (``dir_fd``, ``O_DIRECTORY``, ``O_NOFOLLOW``), so behaviour
there is unchanged. Windows has no directory descriptors and no ``dir_fd``:
a directory handle is the directory's absolute path plus the identity it had
when it was opened, every entry is checked with ``lstat`` first, and links,
junctions and other reparse points are refused instead of followed. Callers
keep their own before/after identity checks, which on Windows also catch a
path that was swapped between the ``lstat`` and the ``open``.
"""

from __future__ import annotations

import errno
import os
import stat
from typing import Iterator, Union

WINDOWS = os.name == 'nt'

O_DIRECTORY = getattr(os, 'O_DIRECTORY', 0)
O_NOFOLLOW = getattr(os, 'O_NOFOLLOW', 0)
O_NONBLOCK = getattr(os, 'O_NONBLOCK', 0)
O_CLOEXEC = getattr(os, 'O_CLOEXEC', 0)
O_NOCTTY = getattr(os, 'O_NOCTTY', 0)
O_BINARY = getattr(os, 'O_BINARY', 0)
O_NOINHERIT = getattr(os, 'O_NOINHERIT', 0)
FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class WindowsDirectory:
    """A Windows directory handle: absolute path plus its identity at open time."""

    __slots__ = ('path', 'info')

    def __init__(self, path: str, info: os.stat_result) -> None:
        self.path = path
        self.info = info

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f'WindowsDirectory({self.path!r})'


DirHandle = Union[int, WindowsDirectory]


def is_link(info: os.stat_result) -> bool:
    """True for symlinks and, on Windows, for any reparse point (junctions included)."""
    if stat.S_ISLNK(info.st_mode):
        return True
    return bool(getattr(info, 'st_file_attributes', 0) & FILE_ATTRIBUTE_REPARSE_POINT)


def _loop(path: str) -> OSError:
    return OSError(errno.ELOOP, 'refusing to follow a link or reparse point', path)


def _not_directory(path: str) -> OSError:
    return OSError(errno.ENOTDIR, 'not a directory', path)


def _check_name(name: str) -> None:
    if not name or name in {'.', '..'} or '/' in name or '\\' in name or ':' in name:
        raise OSError(errno.EINVAL, 'invalid entry name', name)


def _child_path(parent: WindowsDirectory, name: str) -> str:
    _check_name(name)
    return os.path.join(parent.path, name)


def _windows_directory(path: str) -> WindowsDirectory:
    info = os.lstat(path)
    if is_link(info):
        raise _loop(path)
    if not stat.S_ISDIR(info.st_mode):
        raise _not_directory(path)
    return WindowsDirectory(os.path.abspath(path), info)


def open_dir(path: str | os.PathLike[str], *, flags: int = 0) -> DirHandle:
    """Open a directory without following a final link."""
    if WINDOWS:
        return _windows_directory(os.fspath(path))
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | flags)


def open_dir_at(parent: DirHandle, name: str, *, flags: int = 0) -> DirHandle:
    """Open the child directory ``name`` of ``parent`` without following links."""
    if isinstance(parent, WindowsDirectory):
        return _windows_directory(_child_path(parent, name))
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | flags, dir_fd=parent)


def lstat_at(parent: DirHandle, name: str) -> os.stat_result:
    if isinstance(parent, WindowsDirectory):
        return os.lstat(_child_path(parent, name))
    return os.stat(name, dir_fd=parent, follow_symlinks=False)


def fstat_dir(handle: DirHandle) -> os.stat_result:
    """Current identity of an open directory."""
    if isinstance(handle, WindowsDirectory):
        info = os.lstat(handle.path)
        if is_link(info) or not stat.S_ISDIR(info.st_mode):
            raise _not_directory(handle.path)
        return info
    return os.fstat(handle)


def scandir(handle: DirHandle) -> Iterator[os.DirEntry[str]]:
    if isinstance(handle, WindowsDirectory):
        return os.scandir(handle.path)
    return os.scandir(handle)


def listdir(handle: DirHandle) -> list[str]:
    if isinstance(handle, WindowsDirectory):
        return os.listdir(handle.path)
    return os.listdir(handle)


def open_at(parent: DirHandle, name: str, flags: int, mode: int = 0o777) -> int:
    """``os.open`` relative to ``parent``; on Windows an existing link is refused.

    ``O_NOFOLLOW``/``O_DIRECTORY`` style bits are absent on Windows (they are 0
    here), so callers can pass the same expression on every platform.
    """
    if isinstance(parent, WindowsDirectory):
        path = _child_path(parent, name)
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            info = None
        if info is not None and is_link(info):
            raise _loop(path)
        return os.open(path, flags | O_BINARY | O_NOINHERIT, mode)
    return os.open(name, flags, mode, dir_fd=parent)


def mkdir_at(parent: DirHandle, name: str, mode: int = 0o777) -> None:
    if isinstance(parent, WindowsDirectory):
        os.mkdir(_child_path(parent, name), mode)
        return
    os.mkdir(name, mode, dir_fd=parent)


def unlink_at(parent: DirHandle, name: str) -> None:
    if isinstance(parent, WindowsDirectory):
        path = _child_path(parent, name)
        info = os.lstat(path)
        if stat.S_ISDIR(info.st_mode) and not is_link(info):
            raise IsADirectoryError(errno.EISDIR, 'is a directory', path)
        os.unlink(path)
        return
    os.unlink(name, dir_fd=parent)


def rmdir_at(parent: DirHandle, name: str) -> None:
    if isinstance(parent, WindowsDirectory):
        os.rmdir(_child_path(parent, name))
        return
    os.rmdir(name, dir_fd=parent)


def replace_at(source_parent: DirHandle, source: str, target_parent: DirHandle, target: str) -> None:
    """Atomic rename that replaces an existing target file."""
    if isinstance(source_parent, WindowsDirectory) or isinstance(target_parent, WindowsDirectory):
        assert isinstance(source_parent, WindowsDirectory) and isinstance(target_parent, WindowsDirectory)
        os.replace(_child_path(source_parent, source), _child_path(target_parent, target))
        return
    os.replace(source, target, src_dir_fd=source_parent, dst_dir_fd=target_parent)


def rename_noreplace_at(source_parent: DirHandle, source: str, target_parent: DirHandle, target: str) -> None:
    """Atomic rename that fails with ``FileExistsError`` if the target exists.

    Windows ``MoveFileEx`` without ``MOVEFILE_REPLACE_EXISTING`` (what
    ``os.rename`` uses there) already has exactly this no-replace contract, for
    files and directories alike. POSIX callers keep their own ``renameat2``.
    """
    if not (isinstance(source_parent, WindowsDirectory) and isinstance(target_parent, WindowsDirectory)):
        raise NotImplementedError('rename_noreplace_at is the Windows branch; POSIX uses renameat2')
    os.rename(_child_path(source_parent, source), _child_path(target_parent, target))


def link_at(source_parent: DirHandle, source: str, target_parent: DirHandle, target: str) -> None:
    """Hard link that fails with ``FileExistsError`` when the target exists (NTFS too)."""
    if isinstance(source_parent, WindowsDirectory) or isinstance(target_parent, WindowsDirectory):
        assert isinstance(source_parent, WindowsDirectory) and isinstance(target_parent, WindowsDirectory)
        os.link(_child_path(source_parent, source), _child_path(target_parent, target))
        return
    os.link(source, target, src_dir_fd=source_parent, dst_dir_fd=target_parent, follow_symlinks=False)


def exchange_at(parent: WindowsDirectory, temporary: str, target: str) -> None:
    """Windows stand-in for ``renameat2(RENAME_EXCHANGE)`` on two files.

    ``ReplaceFileW`` atomically puts ``temporary``'s content at ``target`` and
    moves the previous target to a private backup name, which is then renamed
    to ``temporary``. Afterwards ``target`` holds the new bytes and
    ``temporary`` the displaced ones, as with an exchange; only the private
    temporary name is briefly absent.
    """
    import ctypes
    from ctypes import wintypes

    target_path = _child_path(parent, target)
    temporary_path = _child_path(parent, temporary)
    backup_path = _child_path(parent, f'{temporary}.displaced')
    for path in (target_path, temporary_path):
        info = os.lstat(path)
        if is_link(info) or not stat.S_ISREG(info.st_mode):
            raise _loop(path)
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    replace = kernel32.ReplaceFileW
    replace.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, wintypes.LPVOID, wintypes.LPVOID]
    replace.restype = wintypes.BOOL
    if not replace(target_path, temporary_path, backup_path, 0x2, None, None):  # REPLACEFILE_IGNORE_MERGE_ERRORS
        error = ctypes.get_last_error()
        raise OSError(errno.EIO, f'ReplaceFileW failed ({error})', target_path)
    os.rename(backup_path, temporary_path)


def fchmod(descriptor: int, mode: int) -> None:
    """``os.fchmod`` where it exists (POSIX, Windows Python 3.13+: read-only bit only)."""
    function = getattr(os, 'fchmod', None)
    if function is None:
        return
    function(descriptor, mode)


def effective_uid() -> int | None:
    """The effective user id, or ``None`` on Windows where files have no uid owner."""
    function = getattr(os, 'geteuid', None)
    return function() if function is not None else None


def process_group_kwargs() -> dict[str, object]:
    """``subprocess.Popen`` keywords that start a child in its own process group."""
    if WINDOWS:
        import subprocess
        return {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP}
    return {'start_new_session': True}


def kill_process_tree(pid: int) -> None:
    """Forcefully end a child and its descendants (``killpg`` / ``taskkill /T /F``)."""
    if WINDOWS:
        import subprocess
        subprocess.run(['taskkill', '/PID', str(pid), '/T', '/F'], capture_output=True, check=False)
        return
    import signal
    os.killpg(pid, signal.SIGKILL)


def close_dir(handle: DirHandle | None) -> None:
    if handle is None or isinstance(handle, WindowsDirectory):
        return
    os.close(handle)


def path_of(handle: DirHandle) -> str | None:
    """The absolute path behind a Windows handle (POSIX descriptors have none)."""
    return handle.path if isinstance(handle, WindowsDirectory) else None


def fsync_dir(handle: DirHandle) -> None:
    """Flush a directory entry update; Windows has no directory fsync."""
    if isinstance(handle, WindowsDirectory):
        return
    os.fsync(handle)


def lock_file(descriptor: int, *, exclusive: bool = True, blocking: bool = True) -> None:
    """Advisory whole-file lock: ``fcntl.flock`` on POSIX, ``msvcrt.locking`` on Windows."""
    if WINDOWS:
        import msvcrt
        mode = (msvcrt.LK_LOCK if blocking else msvcrt.LK_NBLCK) if exclusive else (msvcrt.LK_RLCK if blocking else msvcrt.LK_NBRLCK)
        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, mode, 1)
        return
    import fcntl
    operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
    if not blocking:
        operation |= fcntl.LOCK_NB
    fcntl.flock(descriptor, operation)


def unlock_file(descriptor: int) -> None:
    if WINDOWS:
        import msvcrt
        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        return
    import fcntl
    fcntl.flock(descriptor, fcntl.LOCK_UN)
