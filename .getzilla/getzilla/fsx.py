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
import functools
import os
import stat
import time
from types import SimpleNamespace
from typing import TYPE_CHECKING, Iterator, Union
import weakref

if TYPE_CHECKING:
    import subprocess

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


def directory_identity(info: os.stat_result, posix_identity: tuple[int, ...]) -> tuple[int, ...]:
    """Identity used to detect a swapped directory.

    POSIX keeps the caller's tuple. NTFS updates a directory's timestamps lazily
    after a child is written or closed, so on Windows only device, file index
    and type identify the directory; a swap or relink still changes them.
    """
    if WINDOWS:
        return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))
    return posix_identity


# renameat2 flags; macOS renameatx_np has the same contracts under other numbers.
RENAME_NOREPLACE = 1
RENAME_EXCHANGE = 2
_DARWIN_RENAME_FLAGS = {RENAME_NOREPLACE: 0x4, RENAME_EXCHANGE: 0x2}  # RENAME_EXCL, RENAME_SWAP


def libc_renameat2():
    """``renameat2(olddirfd, old, newdirfd, new, flags) -> int`` from libc, errno kept.

    Linux has renameat2. macOS has renameatx_np with RENAME_EXCL (no replace) and RENAME_SWAP
    (atomic exchange); the flags are translated. Raises AttributeError where neither exists.
    """
    import ctypes
    import sys

    library = ctypes.CDLL(None, use_errno=True)
    signature = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    if sys.platform == 'darwin':
        native = library.renameatx_np
        native.argtypes, native.restype = signature, ctypes.c_int

        def darwin(olddirfd: int, old: bytes, newdirfd: int, new: bytes, flags: int) -> int:
            translated = 0
            for linux_flag, darwin_flag in _DARWIN_RENAME_FLAGS.items():
                if flags & linux_flag:
                    translated |= darwin_flag
            if flags & ~(RENAME_NOREPLACE | RENAME_EXCHANGE):
                ctypes.set_errno(errno.EINVAL)
                return -1
            return native(olddirfd, old, newdirfd, new, translated)

        return darwin
    native = library.renameat2
    native.argtypes, native.restype = signature, ctypes.c_int
    return native


def system_canonical(path: str | os.PathLike[str], *, max_links: int = 40) -> str:
    """Absolute ``path`` with only system symlinks resolved; any other symlink is left in place.

    A system symlink is owned by root and sits in a root-owned directory that nobody else can
    rewrite, like macOS ``/var`` -> ``/private/var`` or a server's ``/home`` -> ``/data/home``.
    Callers keep refusing every other symlink, so a link a user or an attacker planted is still
    rejected by their own component checks. Windows paths are returned unchanged.
    """
    absolute = os.path.abspath(os.fspath(path))
    if WINDOWS:
        return absolute
    pending = [part for part in absolute.split(os.sep) if part]
    current = os.sep
    links = 0
    while pending:
        part = pending.pop(0)
        if part == '.':
            continue
        if part == '..':
            current = os.path.dirname(current) or os.sep
            continue
        candidate = os.path.join(current, part)
        try:
            info = os.lstat(candidate)
            parent = os.lstat(current)
        except OSError:
            return os.path.join(candidate, *pending)
        trusted = (stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and parent.st_uid == 0
                   and (not parent.st_mode & 0o022 or parent.st_mode & stat.S_ISVTX))
        if not trusted:
            current = candidate
            continue
        links += 1
        if links > max_links:
            return os.path.join(candidate, *pending)
        target = os.readlink(candidate)
        if os.path.isabs(target):
            current = os.sep
        pending = [item for item in target.split(os.sep) if item] + pending
    return current


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
    """``lstat`` of ``name`` in ``parent``.

    On Windows a path lookup serves NTFS's lazily refreshed directory-entry
    copy of the timestamps, so a just-renamed file reports an older change
    time than an open handle does. For a regular file the handle's ``fstat``
    is returned instead, after checking it is the same file the lookup named.
    """
    if not isinstance(parent, WindowsDirectory):
        return os.stat(name, dir_fd=parent, follow_symlinks=False)
    path = _child_path(parent, name)
    named = os.lstat(path)
    if is_link(named) or not stat.S_ISREG(named.st_mode):
        return named
    try:
        descriptor = os.open(path, os.O_RDONLY | O_BINARY | O_NOINHERIT)
    except PermissionError:
        return named
    try:
        opened = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
        raise OSError(errno.ESTALE, 'file replaced during lookup', path)
    return opened


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


JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
_JOB_BASIC_ACCOUNTING_INFORMATION = 1
_JOB_EXTENDED_LIMIT_INFORMATION = 9
_CREATE_SUSPENDED = 0x4
_PROCESS_TERMINATE = 0x0001
_PROCESS_SET_QUOTA = 0x0100
_PROCESS_SUSPEND_RESUME = 0x0800


@functools.cache
def _job_api() -> SimpleNamespace:
    """kernel32/ntdll entry points and structures for Job Objects (Windows only)."""
    import ctypes
    from ctypes import wintypes

    class BasicLimits(ctypes.Structure):
        _fields_ = [
            ('PerProcessUserTimeLimit', ctypes.c_int64), ('PerJobUserTimeLimit', ctypes.c_int64),
            ('LimitFlags', wintypes.DWORD), ('MinimumWorkingSetSize', ctypes.c_size_t),
            ('MaximumWorkingSetSize', ctypes.c_size_t), ('ActiveProcessLimit', wintypes.DWORD),
            ('Affinity', ctypes.c_size_t), ('PriorityClass', wintypes.DWORD),
            ('SchedulingClass', wintypes.DWORD),
        ]

    class ExtendedLimits(ctypes.Structure):
        _fields_ = [
            ('BasicLimitInformation', BasicLimits), ('IoInfo', ctypes.c_uint64 * 6),
            ('ProcessMemoryLimit', ctypes.c_size_t), ('JobMemoryLimit', ctypes.c_size_t),
            ('PeakProcessMemoryUsed', ctypes.c_size_t), ('PeakJobMemoryUsed', ctypes.c_size_t),
        ]

    class Accounting(ctypes.Structure):
        _fields_ = [
            ('TotalUserTime', ctypes.c_int64), ('TotalKernelTime', ctypes.c_int64),
            ('ThisPeriodTotalUserTime', ctypes.c_int64), ('ThisPeriodTotalKernelTime', ctypes.c_int64),
            ('TotalPageFaultCount', wintypes.DWORD), ('TotalProcesses', wintypes.DWORD),
            ('ActiveProcesses', wintypes.DWORD), ('TotalTerminatedProcesses', wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    ntdll = ctypes.WinDLL('ntdll')
    for name, argtypes, restype in (
        ('CreateJobObjectW', [wintypes.LPVOID, wintypes.LPCWSTR], wintypes.HANDLE),
        ('SetInformationJobObject', [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD], wintypes.BOOL),
        ('QueryInformationJobObject',
         [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD], wintypes.BOOL),
        ('AssignProcessToJobObject', [wintypes.HANDLE, wintypes.HANDLE], wintypes.BOOL),
        ('TerminateJobObject', [wintypes.HANDLE, wintypes.UINT], wintypes.BOOL),
        ('OpenProcess', [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE),
        ('CloseHandle', [wintypes.HANDLE], wintypes.BOOL),
    ):
        function = getattr(kernel32, name)
        function.argtypes = argtypes
        function.restype = restype
    ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
    ntdll.NtResumeProcess.restype = ctypes.c_long
    return SimpleNamespace(ctypes=ctypes, kernel32=kernel32, ntdll=ntdll,
                           ExtendedLimits=ExtendedLimits, Accounting=Accounting)


def _win_error(api: SimpleNamespace, function: str) -> OSError:
    error = api.ctypes.get_last_error()
    return OSError(errno.EIO, f'{function} failed ({error})')


class ProcessJob:
    """A Windows Job Object that owns a child and every process it starts.

    The job has ``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`` and no breakaway right,
    so descendants cannot leave it. Terminating the job, or closing its only
    handle (also when this process exits or the job is garbage-collected),
    ends the whole tree, including descendants whose own parent already
    exited: the Windows counterpart of ``killpg`` on a new session.
    """

    def __init__(self) -> None:
        api = _job_api()
        handle = api.kernel32.CreateJobObjectW(None, None)
        if not handle:
            raise _win_error(api, 'CreateJobObjectW')
        self._api = api
        self._handle = handle
        self._close = weakref.finalize(self, api.kernel32.CloseHandle, handle)
        limits = api.ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not api.kernel32.SetInformationJobObject(
                handle, _JOB_EXTENDED_LIMIT_INFORMATION, api.ctypes.byref(limits), api.ctypes.sizeof(limits)):
            error = _win_error(api, 'SetInformationJobObject')
            self.close()
            raise error

    def assign_suspended(self, pid: int) -> None:
        """Put a child created with ``CREATE_SUSPENDED`` in this job, then let it run.

        The child runs no code before it is in the job, so it cannot start a
        descendant outside it. ``NtResumeProcess`` resumes it because
        ``subprocess`` closes the initial thread handle.
        """
        kernel32 = self._api.kernel32
        process = kernel32.OpenProcess(_PROCESS_SET_QUOTA | _PROCESS_TERMINATE | _PROCESS_SUSPEND_RESUME, False, pid)
        if not process:
            raise _win_error(self._api, 'OpenProcess')
        try:
            if not kernel32.AssignProcessToJobObject(self._handle, process):
                raise _win_error(self._api, 'AssignProcessToJobObject')
            status = self._api.ntdll.NtResumeProcess(process)
            if status < 0:
                raise OSError(errno.EIO, f'NtResumeProcess failed (0x{status & 0xFFFFFFFF:08x})')
        finally:
            kernel32.CloseHandle(process)

    def active_processes(self) -> int:
        """Processes still running in the job (zero once it is closed)."""
        if not self._close.alive:
            return 0
        accounting = self._api.Accounting()
        if not self._api.kernel32.QueryInformationJobObject(
                self._handle, _JOB_BASIC_ACCOUNTING_INFORMATION, self._api.ctypes.byref(accounting),
                self._api.ctypes.sizeof(accounting), None):
            raise _win_error(self._api, 'QueryInformationJobObject')
        return int(accounting.ActiveProcesses)

    def terminate(self, timeout: float) -> bool:
        """End every process in the job; True once none is left within ``timeout`` seconds."""
        if not self._close.alive:
            return True
        if not self._api.kernel32.TerminateJobObject(self._handle, 1):
            raise _win_error(self._api, 'TerminateJobObject')
        deadline = time.monotonic() + timeout
        while self.active_processes():
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)
        return True

    def close(self) -> None:
        """Close the job handle; anything still inside the job is killed. Repeated calls are safe."""
        self._close()


_owned_jobs: weakref.WeakKeyDictionary[subprocess.Popen, ProcessJob] = weakref.WeakKeyDictionary()


@functools.cache
def process_jobs_supported() -> bool:
    """Whether this host can create the kill-on-close Job Objects ``owned_popen`` uses (Windows only)."""
    if not WINDOWS:
        return False
    try:
        ProcessJob().close()
    except OSError:
        return False
    return True


def owned_popen(args: list[str], **kwargs: object) -> subprocess.Popen:
    """``subprocess.Popen`` for a child whose whole process tree can be stopped.

    POSIX starts a new session, so ``killpg`` reaches every descendant that
    stays in it. Windows starts the child suspended in a new process group,
    assigns it to a new :class:`ProcessJob` before it runs, then resumes it;
    every descendant inherits the job. ``owned_job`` returns that job, which
    lives as long as the returned ``Popen`` object.
    """
    import subprocess
    if not WINDOWS:
        return subprocess.Popen(args, start_new_session=True, **kwargs)
    job = ProcessJob()
    try:
        process = subprocess.Popen(
            args, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | _CREATE_SUSPENDED, **kwargs,
        )
    except BaseException:
        job.close()
        raise
    try:
        job.assign_suspended(process.pid)
    except BaseException:
        process.kill()
        process.wait()
        job.close()
        raise
    _owned_jobs[process] = job
    return process


def owned_job(process: subprocess.Popen) -> ProcessJob | None:
    """The Job Object ``owned_popen`` started ``process`` in, or ``None`` (POSIX, other processes)."""
    return _owned_jobs.get(process)


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
