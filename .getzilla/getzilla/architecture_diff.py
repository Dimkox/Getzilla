from __future__ import annotations

import hashlib
import json
import os
import queue
import re
import selectors
import shutil
import signal
import stat
# Git is resolved once and invoked only with an argument vector and shell=False.
import subprocess  # nosec B404
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import fsx
from .git_binding_guard import GuardUnavailable, LinuxGitGuard
from .architecture import (
    RULE_COLLECTIONS,
    ArchitectureError,
    ArchitectureSnapshot,
    ContractRecord,
    architecture_digests,
    contract_inventory,
    load_architecture,
    parse_adoption_marker,
)

ADOPTION_BASE_SHA = "25bfbe59ea188d9687b20a9caad19e7db3d031f8"
MAX_GIT_OUTPUT_BYTES = 20_000_000
MAX_CHANGED_PATHS = 20_000
MAX_BATCH_INPUT_BYTES = 65_536
MAX_ANALYZED_FILE_BYTES = 10_000_000
BLOB_STREAM_CHUNK_BYTES = 64 * 1024
# The measured release-archive cleanup processes ~123 MB across both sides.
# Keep a finite aggregate bound; per-blob, stream, path and time limits still apply.
MAX_DIFF_ARTIFACT_BYTES = 128_000_000
MAX_LINE_STAT_LINES = 100_000
_EXACT_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_ADOPTION_PATH = "architecture/adoption.json"
_MODEL_PATHS = ("architecture/system.yaml", "architecture/rules.yaml")
_SCHEMA_PATHS = (
    "schemas/architecture-system.schema.json",
    "schemas/architecture-rules.schema.json",
)
_GIT_EXECUTABLE = shutil.which("git")
_GIT_TIMEOUT_SECONDS = 30.0
_LINE_STAT_TIMEOUT_SECONDS = 2.0
_GIT_FORMAT_CACHE: dict[tuple[object, ...], int] = {}
_GIT_COMMIT_CACHE: dict[tuple[object, ...], bool] = {}
_GIT_BLOB_CACHE: dict[tuple[object, ...], dict[str, bytes | None]] = {}
_MATERIALIZED_STATE_CACHE: dict[tuple[object, ...], "_ArchitectureState | None"] = {}
_GIT_BLOB_CACHE_LIMIT = 512
_MATERIALIZED_STATE_CACHE_LIMIT = 128


def _binding_key(binding: "_GitBinding", guard: LinuxGitGuard | None = None) -> tuple[object, ...]:
    return (
        str(binding.root),
        str(binding.git_directory),
        tuple((str(path), identity[:3] if path == binding.objects_directory or
               (guard is not None and stat.S_ISDIR(identity[2]) and guard.covers(path, identity))
               else identity) for path, identity, _label in binding.registrations),
        tuple(str(path) for path in binding.absent_registrations),
        ("strict",) if guard is None else guard.key(),
    )


def _remember_blob_cache(key: tuple[object, ...], values: dict[str, bytes | None]) -> None:
    if len(_GIT_BLOB_CACHE) >= _GIT_BLOB_CACHE_LIMIT:
        _GIT_BLOB_CACHE.clear()
    _GIT_BLOB_CACHE[key] = values


def _remember_materialized_state(key: tuple[object, ...], value: "_ArchitectureState | None") -> None:
    if len(_MATERIALIZED_STATE_CACHE) >= _MATERIALIZED_STATE_CACHE_LIMIT:
        _MATERIALIZED_STATE_CACHE.clear()
    _MATERIALIZED_STATE_CACHE[key] = value


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _path_text(value: bytes) -> str:
    if b"\0" in value:
        raise ArchitectureError("Git emitted an invalid NUL-bearing path", code="git")
    return os.fsdecode(value)


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if fsx.WINDOWS:
        # taskkill /T ends the child's whole tree; terminate the direct child
        # too in case taskkill raced its exit or is unavailable.
        fsx.kill_process_tree(process.pid)
        if process.poll() is None:
            process.kill()
        process.wait()
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        # macOS refuses killpg on a group whose leader already exited (a zombie).
        if process.poll() is None:
            process.kill()
    process.wait()


class _ThreadedPipes:
    """Windows stand-in for a selector over child pipes, which ``select`` cannot watch there.

    One daemon thread per pipe performs blocking reads into a small bounded queue, so the
    caller keeps the same deadline, output-limit and early-termination decisions.
    """

    def __init__(self, streams: tuple[Any, ...], chunk_bytes: int) -> None:
        self._events: queue.Queue[tuple[Any, bytes | OSError]] = queue.Queue(maxsize=2 * len(streams))
        self._stopped = threading.Event()
        self._threads = [
            threading.Thread(target=self._pump, args=(stream, chunk_bytes), daemon=True)
            for stream in streams
        ]
        for thread in self._threads:
            thread.start()

    def _pump(self, stream: Any, chunk_bytes: int) -> None:
        while not self._stopped.is_set():
            chunk: bytes | OSError
            try:
                chunk = os.read(stream.fileno(), chunk_bytes)
            except OSError as exc:
                chunk = exc
            while not self._stopped.is_set():
                try:
                    self._events.put((stream, chunk), timeout=0.05)
                    break
                except queue.Full:
                    continue
            if isinstance(chunk, OSError) or not chunk:
                return

    def next(self, timeout: float) -> tuple[Any, bytes | OSError] | None:
        try:
            return self._events.get(timeout=max(0.0, timeout))
        except queue.Empty:
            return None

    def close(self) -> None:
        # Callers stop the child first, so blocked reads see end-of-file promptly.
        self._stopped.set()
        for thread in self._threads:
            thread.join(timeout=5.0)


def _collect_threaded(
    process: subprocess.Popen[bytes],
    *,
    stdout_limit: int,
    stderr_limit: int,
    timeout: float,
) -> tuple[int, bytes, bytes]:
    """The Windows half of `_run_capped`: same limits and deadline, thread-fed reads."""
    pipes: _ThreadedPipes | None = None
    try:
        if process.stdout is None or process.stderr is None:  # pragma: no cover - Popen contract
            raise ArchitectureError("bounded process pipes are unavailable", code="io")
        streams = {
            process.stdout: (bytearray(), stdout_limit),
            process.stderr: (bytearray(), stderr_limit),
        }
        try:
            pipes = _ThreadedPipes(tuple(streams), 65_536)
        except Exception as exc:
            raise ArchitectureError(
                f"bounded process setup failed: {exc}", code="io"
            ) from exc
        pending = set(streams)
        deadline = time.monotonic() + timeout
        while pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _stop_process(process)
                raise ArchitectureError("bounded process timeout exceeded", code="timeout")
            event = pipes.next(remaining)
            if event is None:
                continue
            stream, chunk = event
            if isinstance(chunk, OSError):
                raise chunk
            buffer, limit = streams[stream]
            if not chunk:
                pending.discard(stream)
                stream.close()
                continue
            buffer.extend(chunk)
            if len(buffer) > limit:
                _stop_process(process)
                raise ArchitectureError("bounded process output limit exceeded", code="limit")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _stop_process(process)
            raise ArchitectureError("bounded process timeout exceeded", code="timeout")
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            _stop_process(process)
            raise ArchitectureError("bounded process timeout exceeded", code="timeout") from exc
        return returncode, bytes(streams[process.stdout][0]), bytes(streams[process.stderr][0])
    finally:
        if process.poll() is None:
            _stop_process(process)
        if pipes is not None:
            pipes.close()
        for stream in (process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()


def _run_capped(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    stdout_limit: int,
    stderr_limit: int,
    timeout: float,
    stdin_data: bytes | None = None,
) -> tuple[int, bytes, bytes]:
    """Run a process while enforcing limits before output is fully produced."""
    input_stream = tempfile.TemporaryFile() if stdin_data is not None else None
    try:
        if input_stream is not None:
            input_stream.write(stdin_data)
            input_stream.seek(0)
        process = subprocess.Popen(  # nosec B603
            command, cwd=cwd, env=env,
            stdin=input_stream if input_stream is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
            **fsx.process_group_kwargs(),
        )
    except BaseException:
        if input_stream is not None:
            input_stream.close()
        raise
    if fsx.WINDOWS:
        try:
            return _collect_threaded(
                process, stdout_limit=stdout_limit, stderr_limit=stderr_limit, timeout=timeout
            )
        finally:
            if input_stream is not None:
                input_stream.close()
    selector: selectors.BaseSelector | None = None
    streams: dict[Any, tuple[bytearray, int]] = {}
    try:
        if process.stdout is None or process.stderr is None:  # pragma: no cover - Popen contract
            raise ArchitectureError("bounded process pipes are unavailable", code="io")
        streams = {
            process.stdout: (bytearray(), stdout_limit),
            process.stderr: (bytearray(), stderr_limit),
        }
        try:
            selector = selectors.DefaultSelector()
            for stream in streams:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
        except Exception as exc:
            raise ArchitectureError(
                f"bounded process setup failed: {exc}", code="io"
            ) from exc
        deadline = time.monotonic() + timeout
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _stop_process(process)
                raise ArchitectureError("bounded process timeout exceeded", code="timeout")
            events = selector.select(remaining)
            if not events and time.monotonic() >= deadline:
                _stop_process(process)
                raise ArchitectureError("bounded process timeout exceeded", code="timeout")
            for key, _mask in events:
                stream = key.fileobj
                buffer, limit = streams[stream]
                chunk = os.read(stream.fileno(), min(65_536, limit - len(buffer) + 1))
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                buffer.extend(chunk)
                if len(buffer) > limit:
                    _stop_process(process)
                    raise ArchitectureError("bounded process output limit exceeded", code="limit")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _stop_process(process)
            raise ArchitectureError("bounded process timeout exceeded", code="timeout")
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            _stop_process(process)
            raise ArchitectureError("bounded process timeout exceeded", code="timeout") from exc
        return returncode, bytes(streams[process.stdout][0]), bytes(streams[process.stderr][0])
    finally:
        if selector is not None:
            selector.close()
        for stream in (process.stdout, process.stderr):
            if stream is None:
                continue
            if not stream.closed:
                stream.close()
        if process.poll() is None:
            _stop_process(process)
        if input_stream is not None:
            input_stream.close()


def _git_environment() -> dict[str, str]:
    if _GIT_EXECUTABLE is None:
        raise ArchitectureError("Git executable is unavailable", code="git")
    environment = {
        "PATH": str(Path(_GIT_EXECUTABLE).parent),
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    }
    if fsx.WINDOWS and os.environ.get("SYSTEMROOT"):
        # Windows processes need SystemRoot to load system libraries; it names no config.
        environment["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return environment


def _git_command(
    arguments: list[str],
    *,
    safe_directory: Path | None = None,
    git_directory: Path | None = None,
    work_tree: Path | None = None,
) -> list[str]:
    if _GIT_EXECUTABLE is None:
        raise ArchitectureError("Git executable is unavailable", code="git")
    command = [
        _GIT_EXECUTABLE,
        "--no-replace-objects",
    ]
    if git_directory is not None:
        command.append(f"--git-dir={git_directory}")
    if work_tree is not None:
        command.append(f"--work-tree={work_tree}")
    if safe_directory is not None:
        command.extend(("-c", f"safe.directory={safe_directory}"))
    command.extend([
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "core.excludesFile=/dev/null",
        "-c",
        "core.ignoreCase=false",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.pager=cat",
        "-c",
        "diff.algorithm=myers",
        "-c",
        "diff.external=",
        "-c",
        "diff.renames=false",
        *arguments,
    ])
    return command


def _stat_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    # CPython on Windows fills st_ctime by name (os.lstat) with the creation
    # time but by handle (os.fstat) with the NTFS change time, which passes the
    # creation time once a file is written in a later clock tick than it was
    # created (Git under load). Both report the creation time as st_birthtime,
    # so a name can be compared with a handle there.
    created = getattr(info, "st_birthtime_ns", info.st_ctime_ns) if fsx.WINDOWS else info.st_ctime_ns
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, created)


def _git_path_identity(path: Path) -> tuple[int, int, int, int, int, int]:
    return _stat_identity(path.lstat())


def _git_pointer(path: Path) -> bytes:
    """Read Git's small registration files without following a substituted name."""
    if fsx.WINDOWS:
        # No O_NOFOLLOW there: refuse a link or reparse point by lstat; the
        # identity comparison below catches a name swapped before the open.
        if fsx.is_link(path.lstat()):
            raise ArchitectureError("Git registration is not a bounded regular file", code="git")
        flags = os.O_RDONLY | fsx.O_BINARY | fsx.O_NOINHERIT
    else:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > 4_096:
            raise ArchitectureError("Git registration is not a bounded regular file", code="git")
        content = os.read(descriptor, 4_097)
        after = os.fstat(descriptor)
        if (len(content) != before.st_size
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                or _git_path_identity(path) != _stat_identity(before)):
            raise ArchitectureError("Git registration changed while reading", code="git")
        return content
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class _GitBinding:
    root: Path
    git_directory: Path
    registrations: tuple[tuple[Path, tuple[int, int, int, int, int, int], str], ...]
    absent_registrations: tuple[Path, ...] = ()
    common_directory: Path | None = None
    objects_directory: Path | None = None

    def verify(self, guard: LinuxGitGuard | None = None) -> None:
        if guard is not None:
            guard.check()
        for path, identity, label in self.registrations:
            try:
                current = _git_path_identity(path)
            except OSError as exc:
                raise ArchitectureError(f"Git {label} binding is unavailable", code="git") from exc
            # Objects were formerly checked by their strict parent's metadata.
            # Do not turn legitimate loose-object additions into a new refusal.
            stable = path == self.objects_directory
            if guard is not None and stat.S_ISDIR(identity[2]):
                if not guard.covers(path, identity):
                    raise ArchitectureError(f"Git {label} binding guard is incomplete", code="git")
                stable = True
            changed = current[:3] != identity[:3] if stable else current != identity
            if changed:
                raise ArchitectureError(f"Git {label} binding changed", code="git")
        for path in self.absent_registrations:
            try:
                path.lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise ArchitectureError("Git common-directory registration is unavailable", code="git") from exc
            raise ArchitectureError("Git common-directory registration changed", code="git")
        if guard is not None:
            guard.check()


def _qualify_git_configuration(binding: _GitBinding, guard: LinuxGitGuard) -> None:
    """Close a conservative read graph; let Git itself parse configuration syntax."""
    common = binding.common_directory
    objects = binding.objects_directory
    if common is None or objects is None:
        raise GuardUnavailable("read-graph")
    selectors = (
        "HEAD", "packed-refs", "shallow", "index", "ORIG_HEAD", "FETCH_HEAD",
        "MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "REBASE_HEAD", "BISECT_HEAD",
        "AUTO_MERGE", "MERGE_AUTOSTASH",
    )
    reference_files: tuple[Path, ...] = ()
    for directory in dict.fromkeys((common, binding.git_directory)):
        registration = guard.file(directory / "commondir", "common-directory registration")
        if directory != binding.git_directory and registration is not None:
            raise GuardUnavailable("common-registration")
        for name in selectors:
            guard.file(directory / name, "reference registration")
        reference_files = (*reference_files, *guard.tree(directory / "refs", "reference registration"),
                           directory / "HEAD")
        guard.tree(directory / "info", "configuration")
        if guard.file(directory / "config.worktree", "configuration") is not None:
            raise GuardUnavailable("worktree-configuration")
    for path in reference_files:
        info = guard.file(path, "reference registration")
        if info is None:
            continue
        if info.st_size > 4096:
            raise GuardUnavailable("reference-topology")
        content = _git_pointer(path).removesuffix(b"\n")
        if _EXACT_SHA.fullmatch(content.decode("ascii", "replace")) is not None:
            continue
        if content.startswith(b"ref: refs/"):
            target = content[5:]
            if (all(part not in {b"", b".", b".."} for part in target.split(b"/"))
                    and not any(value < 33 or value == 127 for value in target)
                    and b"\\" not in target):
                continue
        raise GuardUnavailable("reference-topology")
    for name in ("info", "pack"):
        paths = guard.tree(objects / name, "object store")
        for path in paths:
            if path.name in {"alternates", "http-alternates"} or path.suffix == ".promisor":
                raise GuardUnavailable("alternate-or-promisor")
    # Git reads common/config, and config.worktree only through an extension.
    # --file=- plus --no-includes prevents this classification command from
    # following any repository-controlled path. Its input was already bound.
    config = common / "config"
    info = guard.file(config, "configuration")
    if info is None:
        return
    if info.st_size > 4096:
        raise GuardUnavailable("configuration-size")
    content = _git_pointer(config)
    guard.check()
    returncode, output, _error = _run_capped(
        _git_command(["config", "--null", "--no-includes", "--list", "--file=-"]),
        cwd=Path("/"), env=_git_environment(), stdout_limit=16_384,
        stderr_limit=16_384, timeout=min(_GIT_TIMEOUT_SECONDS, guard.remaining()), stdin_data=content,
    )
    guard.check()
    if returncode or (output and not output.endswith(b"\0")):
        raise GuardUnavailable("configuration-syntax")
    inert_keys = {
        b"core.filemode", b"core.bare", b"core.logallrefupdates", b"core.ignorecase",
        b"core.precomposeunicode", b"core.symlinks", b"user.name", b"user.email",
    }
    for record in output.split(b"\0")[:-1]:
        key, _separator, value = record.partition(b"\n")
        if key == b"core.repositoryformatversion" and value in {b"0", b"1"}:
            continue
        if key == b"extensions.objectformat" and value in {b"sha1", b"sha256"}:
            continue
        if key in inert_keys:
            continue
        if ((key.startswith(b"remote.") and key.endswith((b".url", b".fetch"))) or
                (key.startswith(b"branch.") and key.endswith((b".remote", b".merge")))):
            continue
        raise GuardUnavailable("configuration")


class _GitOperation:
    """One explicit snapshot and admission point, including pending cache writes."""

    def __init__(self, root: Path, *, relaxed: bool = True) -> None:
        self.root = Path(os.path.abspath(root))
        self.guard: LinuxGitGuard | None = None
        self.binding: _GitBinding | None = None
        self.mode = "strict"
        self.reason = "unavailable"
        self._relaxed = relaxed
        self._owner = threading.get_ident()
        self._closed = False
        self._pending: list[tuple[str, tuple[object, ...], Any]] = []
        self._deadline = time.monotonic() + 120.0

    def __enter__(self) -> "_GitOperation":
        try:
            if not self._relaxed:
                self.reason = "command"
                self.binding = _git_binding(self.root)
                return self
            try:
                self.guard = LinuxGitGuard()
                self.binding = _git_binding(self.root, _guard=self.guard)
                self.mode, self.reason = self.guard.mode, "qualified"
            except GuardUnavailable as exc:
                if self.guard is not None:
                    # Setup uncertainty is not permission to discard a mutation.
                    try:
                        LinuxGitGuard.check(self.guard)
                    finally:
                        LinuxGitGuard.close(self.guard)
                self.guard = None
                self.reason = str(exc)
                self.binding = _git_binding(self.root)  # a fresh strict acquisition
            return self
        except BaseException:
            try:
                if self.guard is not None:
                    LinuxGitGuard.check(self.guard)
            finally:
                if self.guard is not None:
                    LinuxGitGuard.close(self.guard)
                self._closed = True
            raise

    def check(self, root: Path | None = None) -> _GitBinding:
        if (self._closed or self.binding is None or self._owner != threading.get_ident()
                or (root is not None and Path(os.path.abspath(root)) != self.root)):
            raise ArchitectureError("Git operation binding guard is unavailable", code="git")
        if time.monotonic() >= self._deadline:
            raise ArchitectureError("Git operation binding guard limit exceeded", code="git")
        self.binding.verify(self.guard)
        return self.binding

    def remaining(self) -> float:
        self.check()
        return min(_GIT_TIMEOUT_SECONDS, max(0.001, self._deadline - time.monotonic()))

    def key(self) -> tuple[object, ...]:
        return _binding_key(self.check(), self.guard)

    def stage(self, kind: str, key: tuple[object, ...], value: Any) -> None:
        self.check()
        if len(self._pending) >= _GIT_BLOB_CACHE_LIMIT:
            raise ArchitectureError("Git operation binding cache limit exceeded", code="git")
        self._pending.append((kind, key, value))

    def __exit__(self, exception_type, _exception, _traceback) -> None:
        try:
            self.check()
            if exception_type is None:
                # No source read occurs after this admission check.
                for kind, key, value in self._pending:
                    if kind == "format":
                        _GIT_FORMAT_CACHE[key] = value
                    elif kind == "commit":
                        _GIT_COMMIT_CACHE[key] = value
                    elif kind == "blobs":
                        _remember_blob_cache(key, value)
                    elif kind == "state":
                        _remember_materialized_state(key, value)
        finally:
            self._pending.clear()
            self._closed = True
            if self.guard is not None:
                LinuxGitGuard.close(self.guard)


def _reported_git_paths_match(output: bytes, git_directory: Path, repository: Path) -> bool:
    expected = [os.fsencode(git_directory), os.fsencode(repository), b"false"]
    if not fsx.WINDOWS:
        return output.splitlines() == expected
    # Git for Windows reports forward slashes; compare the way Windows compares paths.
    lines = output.splitlines()
    if len(lines) != 3 or lines[2] != b"false":
        return False
    try:
        reported = [os.path.normcase(os.fsdecode(line)) for line in lines[:2]]
    except UnicodeDecodeError:
        return False
    return reported == [os.path.normcase(str(git_directory)), os.path.normcase(str(repository))]


def _git_binding(root: Path, *, _guard: LinuxGitGuard | None = None) -> _GitBinding:
    try:
        named_root = Path(os.path.abspath(root))
        if not stat.S_ISDIR(named_root.lstat().st_mode):
            raise ArchitectureError("Git worktree root must be a non-symlink directory", code="git")
        repository = (named_root.resolve(strict=True) if _guard is None else
                      _guard.directory(named_root, "worktree root"))
        dot_git = repository / ".git"
        if _guard is not None:
            _guard.protect(repository, ".git", "worktree registration")
        registration = dot_git.lstat()
        registrations = [
            (repository, _git_path_identity(repository), "worktree root"),
            (dot_git, _git_path_identity(dot_git),
             "directory" if stat.S_ISDIR(registration.st_mode) else "worktree registration"),
        ]
        absent_registrations: tuple[Path, ...] = ()
        if stat.S_ISDIR(registration.st_mode):
            git_directory = (dot_git if _guard is None else _guard.directory(dot_git, "directory"))
            common_directory = git_directory
            absent_registrations = (dot_git / "commondir",)
            if _guard is not None:
                _guard.protect(dot_git, "commondir", "common-directory registration")
        elif stat.S_ISREG(registration.st_mode):
            content = _git_pointer(dot_git)
            if not content.startswith(b"gitdir: ") or not content.endswith(b"\n") or b"\0" in content:
                raise ArchitectureError("Git worktree registration is invalid", code="git")
            target = Path(os.fsdecode(content[8:-1]))
            git_directory = ((repository / target).resolve(strict=True) if _guard is None else
                             _guard.directory(repository / target, "directory"))
            backlink = git_directory / "gitdir"
            common_registration = git_directory / "commondir"
            if _guard is not None:
                _guard.protect(git_directory, "gitdir", "worktree backlink")
                _guard.protect(git_directory, "commondir", "common-directory registration")
            registrations.extend((
                (git_directory, _git_path_identity(git_directory), "directory"),
                (backlink, _git_path_identity(backlink), "worktree backlink"),
                (common_registration, _git_path_identity(common_registration), "common-directory registration"),
            ))
            common_content = _git_pointer(common_registration)
            if not common_content.endswith(b"\n") or b"\0" in common_content:
                raise ArchitectureError("Git common-directory registration is invalid", code="git")
            common_path = git_directory / Path(os.fsdecode(common_content[:-1]))
            common_directory = (common_path.resolve(strict=True) if _guard is None else
                                _guard.directory(common_path, "common directory"))
            if git_directory.parent.name != "worktrees" or common_directory != git_directory.parent.parent:
                raise ArchitectureError("Git common-directory relationship does not match registered worktree", code="git")
            registrations.append((common_directory, _git_path_identity(common_directory), "common directory"))
            backlink_content = _git_pointer(backlink)
            if not backlink_content.endswith(b"\n") or b"\0" in backlink_content:
                raise ArchitectureError("Git worktree backlink is invalid", code="git")
            backlink_path = Path(os.fsdecode(backlink_content[:-1]))
            if _guard is not None:
                _guard.directory((git_directory / backlink_path).parent, "worktree root")
            if (git_directory / backlink_path).resolve(strict=True) != dot_git:
                raise ArchitectureError("Git worktree backlink does not match root", code="git")
        else:
            raise ArchitectureError("Git worktree registration is not a directory or regular file", code="git")
        if not stat.S_ISDIR(git_directory.lstat().st_mode):
            raise ArchitectureError("Git directory is not a non-symlink directory", code="git")
        objects_directory = common_directory / "objects"
        if _guard is not None:
            objects_directory = _guard.directory(objects_directory, "object store")
        if not stat.S_ISDIR(objects_directory.lstat().st_mode):
            raise ArchitectureError("Git object store is not a non-symlink directory", code="git")
        bound_registrations = (*registrations,
                               (objects_directory, _git_path_identity(objects_directory), "object store"))
        binding = _GitBinding(repository, git_directory, bound_registrations, absent_registrations,
                              common_directory, objects_directory)
        binding.verify(_guard)
        if _guard is not None:
            _qualify_git_configuration(binding, _guard)
            binding.verify(_guard)
            _guard.seal()
        returncode, output, _error = _run_capped(
            _git_command(["rev-parse", "--absolute-git-dir", "--show-toplevel", "--is-bare-repository"],
                         safe_directory=repository, git_directory=git_directory),
            cwd=repository, env=_git_environment(), stdout_limit=16_384,
            stderr_limit=65_536, timeout=_GIT_TIMEOUT_SECONDS,
        )
        binding.verify(_guard)
        if returncode or not _reported_git_paths_match(output, git_directory, repository):
            raise ArchitectureError("Git directory/worktree relationship does not match root", code="git")
        return binding
    except ArchitectureError:
        raise
    except (OSError, ValueError) as exc:
        raise ArchitectureError("Git worktree binding is unavailable", code="git") from exc


def _guarded_git_arguments(arguments: list[str], stdin_data: bytes | None) -> bool:
    """Only closed read forms may omit directory times; other forms stay strict.

    In particular, arbitrary one-level pseudorefs are administrative filenames,
    not harmless neighbors. Never infer their absence from a fixed name list.
    """
    literal = bool(arguments and arguments[0] == "--literal-pathspecs")
    values = arguments[1:] if literal else arguments
    if not values:
        return False
    command, tail = values[0], values[1:]
    if command == "rev-parse":
        return tail in (["HEAD"], ["--verify", "HEAD^{commit}"], ["--show-object-format"])
    if command == "cat-file":
        if len(tail) == 2 and tail[0] in {"-t", "blob", "-e"}:
            value = tail[1].removesuffix("^{commit}") if tail[0] == "-e" else tail[1]
            return _EXACT_SHA.fullmatch(value) is not None
        if (tail == ["--batch=%(objectname) %(objecttype) %(objectsize)"]
                and stdin_data and len(stdin_data) <= MAX_CHANGED_PATHS * 65 and stdin_data.endswith(b"\n")):
            return all(_EXACT_SHA.fullmatch(value.decode("ascii", "replace")) is not None
                       for value in stdin_data.split(b"\n")[:-1])
        return False
    if command == "ls-tree":
        split = tail.index("--") if "--" in tail else len(tail)
        options, paths = tail[:split], tail[split + 1:]
        if (not options or _EXACT_SHA.fullmatch(options[-1]) is None or
                any(value not in {"-l", "-r", "-lr", "-z", "--full-tree", "--name-only"}
                    for value in options[:-1])):
            return False
        return literal or all(not value.startswith(":") and not any(char in value for char in "*?[\\")
                              for value in paths)
    if command == "merge-base":
        commits = tail[1:] if tail and tail[0] == "--is-ancestor" else tail
        return len(commits) == 2 and all(_EXACT_SHA.fullmatch(value) is not None for value in commits)
    if command == "diff" and tail and tail[-1] == "--":
        options = {"--no-ext-diff", "--no-textconv", "--no-renames", "--name-only", "--numstat", "--shortstat", "-z"}
        commits = [value for value in tail[:-1] if value not in options]
        return ("--no-ext-diff" in tail and "--no-textconv" in tail and len(commits) in {1, 2}
                and all(_EXACT_SHA.fullmatch(value) is not None for value in commits))
    return False


def run_git_bounded(
    root: Path,
    arguments: list[str],
    *,
    allow_failure: bool = False,
    limit: int = MAX_GIT_OUTPUT_BYTES,
    stdin_data: bytes | None = None,
    _scope: _GitOperation | None = None,
) -> bytes | None:
    guarded = _guarded_git_arguments(arguments, stdin_data)
    if _scope is None:
        with _GitOperation(root, relaxed=guarded) as scope:
            return run_git_bounded(root, arguments, allow_failure=allow_failure, limit=limit,
                                   stdin_data=stdin_data, _scope=scope)
    binding = _scope.check(root)
    if _scope.guard is not None and not guarded:
        raise ArchitectureError("Git operation binding read graph is unsupported", code="git")
    try:
        returncode, output, error = _run_capped(
            _git_command(arguments, safe_directory=binding.root,
                         git_directory=binding.git_directory, work_tree=binding.root),
            cwd=binding.root, env=_git_environment(), stdout_limit=limit,
            stderr_limit=65_536, timeout=_scope.remaining(), stdin_data=stdin_data,
        )
    except OSError as exc:
        raise ArchitectureError("Git object operation is unavailable", code="git") from exc
    finally:
        _scope.check()
    if returncode:
        if allow_failure:
            return None
        message = error.decode("utf-8", "replace").strip()
        raise ArchitectureError(f"Git object operation failed: {message}", code="git")
    return output


def _git(
    root: Path,
    arguments: list[str],
    *,
    allow_failure: bool = False,
    limit: int = MAX_GIT_OUTPUT_BYTES,
    stdin_data: bytes | None = None,
    _scope: _GitOperation | None = None,
) -> bytes | None:
    return run_git_bounded(root, arguments, allow_failure=allow_failure,
                           limit=limit, stdin_data=stdin_data, _scope=_scope)


def _required_output(value: bytes | None, *, operation: str) -> bytes:
    if value is None:
        raise ArchitectureError(f"required Git output missing: {operation}", code="git")
    return value


def _required_head(value: str | None) -> str:
    if value is None:
        raise ArchitectureError("commit diff is missing exact head_sha", code="git")
    return value


def _exact_commit(root: Path, value: str, *, label: str, _scope: _GitOperation | None = None) -> str:
    if _scope is None:
        with _GitOperation(root) as scope:
            return _exact_commit(root, value, label=label, _scope=scope)
    binding = _scope.check(root)
    object_id_length = _git_object_id_length(root, _scope=_scope)
    if not isinstance(value, str) or len(value) != object_id_length or _EXACT_SHA.fullmatch(value) is None:
        raise ArchitectureError(f"{label} must match the exact repository commit format", code="git")
    key = (*_scope.key(), "commit", value)
    if _GIT_COMMIT_CACHE.get(key) is True:
        _scope.check()
        return value
    try:
        returncode, kind, _error = _run_capped(
            _git_command(["cat-file", "-t", value], safe_directory=binding.root,
                         git_directory=binding.git_directory, work_tree=binding.root),
            cwd=binding.root, env=_git_environment(), stdout_limit=64,
            stderr_limit=65_536, timeout=_scope.remaining(),
        )
    except OSError as exc:
        raise ArchitectureError("Git object operation is unavailable", code="git") from exc
    finally:
        _scope.check()
    if returncode:
        kind = None
    if kind != b"commit\n":
        raise ArchitectureError(f"{label} is not an available commit object", code="git")
    _scope.stage("commit", key, True)
    return value


def _git_object_id_length(root: Path, *, _scope: _GitOperation | None = None) -> int:
    if _scope is None:
        with _GitOperation(root) as scope:
            return _git_object_id_length(root, _scope=scope)
    _scope.check(root)
    key = (*_scope.key(), "object-format")
    cached = _GIT_FORMAT_CACHE.get(key)
    if cached is not None:
        _scope.check()
        return cached
    value = _required_output(run_git_bounded(root, ["rev-parse", "--show-object-format"],
                                            limit=32, _scope=_scope),
                             operation="resolve Git object format")
    if value == b"sha1\n":
        _scope.stage("format", key, 40)
        return 40
    if value == b"sha256\n":
        _scope.stage("format", key, 64)
        return 64
    raise ArchitectureError("unsupported Git object format", code="git")


def _head_commit(root: Path, *, _scope: _GitOperation | None = None) -> str:
    if _scope is None:
        with _GitOperation(root) as scope:
            return _head_commit(root, _scope=scope)
    _scope.check(root)
    value = _required_output(
        _git(root, ["rev-parse", "--verify", "HEAD^{commit}"], limit=128, _scope=_scope),
        operation="resolve HEAD",
    )
    return _exact_commit(root, value.decode("ascii").strip(), label="head_sha", _scope=_scope)


def _git_blob(root: Path, sha: str, path: str, *, required: bool = False,
              _scope: _GitOperation | None = None) -> bytes | None:
    value = _git_blobs(root, sha, (path,), _scope=_scope)[path]
    if value is None and required:
        raise ArchitectureError(f"required Git object path is missing: {path}", code="missing")
    return value


@dataclass(frozen=True)
class ArchitectureBaseSelection:
    route_base_sha: str
    comparison_base_sha: str
    base_kind: str
    bootstrap_baseline: bool


def select_architecture_comparison_base(
    root: Path,
    route: dict[str, Any] | None,
) -> ArchitectureBaseSelection:
    candidate = (route or {}).get("base_commit")
    route_base = _exact_commit(
        root,
        candidate if isinstance(candidate, str) else _head_commit(root),
        label="architecture_route_base_sha",
    )
    marker_present = _git_blob(root, route_base, _ADOPTION_PATH) is not None
    model_present = tuple(
        _git_blob(root, route_base, path) is not None for path in _MODEL_PATHS
    )
    if model_present not in {(False, False), (True, True)}:
        raise ArchitectureError(
            "route-base architecture model is partially missing",
            code="missing",
        )
    if marker_present and model_present == (False, False):
        raise ArchitectureError(
            "route-base adopted architecture model is missing",
            code="missing",
        )
    if model_present == (True, True):
        marker_value = _git_blob(root, route_base, _ADOPTION_PATH, required=True)
        parse_adoption_marker(
            _required_output(marker_value, operation="read route-base adoption marker")
        )
    if model_present == (True, True):
        comparison_base = route_base
        base_kind = "route_model"
        bootstrap_baseline = False
    else:
        bootstrap_baseline = True
        try:
            comparison_base = _exact_commit(
                root,
                ADOPTION_BASE_SHA,
                label="architecture_base_sha",
            )
            base_kind = "frozen_adoption"
        except ArchitectureError:
            comparison_base = route_base
            base_kind = "route_pre_adoption"
    return ArchitectureBaseSelection(
        route_base_sha=route_base,
        comparison_base_sha=comparison_base,
        base_kind=base_kind,
        bootstrap_baseline=bootstrap_baseline,
    )


def _worktree_open_flags() -> tuple[int, int, int]:
    """Descriptor-relative no-follow flags, or a refusal before any path is touched."""
    if fsx.WINDOWS:
        # Windows has no such flags or dir_fd: fsx lstat-checks every component
        # and refuses links and reparse points instead (the flags are 0 there).
        return fsx.O_NOFOLLOW, fsx.O_DIRECTORY, fsx.O_NONBLOCK
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    if (
        not isinstance(no_follow, int)
        or no_follow == 0
        or not isinstance(directory_flag, int)
        or directory_flag == 0
        or not isinstance(nonblock, int)
        or os.open not in getattr(os, "supports_dir_fd", set())
    ):
        raise ArchitectureError("worktree analysis requires O_NOFOLLOW", code="io")
    return no_follow, directory_flag, nonblock


def _worktree_blob(root: Path, path: str) -> bytes | None:
    parts = path.split("/")
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ArchitectureError(f"invalid worktree path: {path}", code="path")
    no_follow, directory_flag, nonblock = _worktree_open_flags()
    directory: fsx.DirHandle | None = None
    descriptor = -1
    try:
        directory, descriptor = _open_worktree_file(
            root, parts, directory_flag=directory_flag, no_follow=no_follow, nonblock=nonblock
        )
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ArchitectureError(f"worktree path is not a regular file: {path}", code="io")
        if before.st_size > MAX_ANALYZED_FILE_BYTES:
            raise ArchitectureError(f"worktree file exceeds analysis limit: {path}", code="limit")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        value = b"".join(chunks)
        after = os.fstat(descriptor)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ArchitectureError(f"worktree file read failed: {path}: {exc}", code="io") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        fsx.close_dir(directory)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise ArchitectureError(f"worktree file changed during analysis: {path}", code="io")
    if len(value) != before.st_size:
        raise ArchitectureError(f"worktree file was truncated during analysis: {path}", code="io")
    return value


def _open_worktree_file(
    root: Path,
    parts: list[str],
    *,
    directory_flag: int,
    no_follow: int,
    nonblock: int,
) -> tuple[fsx.DirHandle, int]:
    """Walk `parts` from `root` with O_NOFOLLOW on every step; return open (dir, file) fds.

    On Windows the directory is an fsx handle and every step refuses links and
    reparse points instead.
    """

    directory: fsx.DirHandle | None = None
    try:
        directory = fsx.open_dir(root, flags=directory_flag | no_follow)
        for component in parts[:-1]:
            child = fsx.open_dir_at(directory, component, flags=directory_flag | no_follow)
            fsx.close_dir(directory)
            directory = child
        descriptor = fsx.open_at(directory, parts[-1], os.O_RDONLY | nonblock | no_follow)
    except OSError:
        fsx.close_dir(directory)
        raise
    return directory, descriptor


@dataclass(frozen=True)
class _BlobProfile:
    """Size, SHA-256 and binary marker for one side of a diff; `content` is None when the
    object was too large to buffer and was hashed from a stream instead."""

    size: int
    digest: str
    binary: bool
    content: bytes | None


def _profile_worktree_blob(root: Path, path: str) -> _BlobProfile | None:
    parts = path.split("/")
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ArchitectureError(f"invalid worktree path: {path}", code="path")
    no_follow, directory_flag, nonblock = _worktree_open_flags()
    try:
        directory, descriptor = _open_worktree_file(
            root, parts, directory_flag=directory_flag, no_follow=no_follow, nonblock=nonblock
        )
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ArchitectureError(f"worktree file read failed: {path}: {exc}", code="io") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ArchitectureError(f"worktree path is not a regular file: {path}", code="io")
        keep = before.st_size <= MAX_ANALYZED_FILE_BYTES
        chunks: list[bytes] = [] if keep else []
        digest = hashlib.sha256()
        total = 0
        binary = False
        while True:
            chunk = os.read(descriptor, BLOB_STREAM_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
            if keep:
                chunks.append(chunk)
            if not binary and b"\0" in chunk:
                binary = True
        after = os.fstat(descriptor)
    except OSError as exc:
        raise ArchitectureError(f"worktree file read failed: {path}: {exc}", code="io") from exc
    finally:
        try:
            os.close(descriptor)
        finally:
            fsx.close_dir(directory)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise ArchitectureError(f"worktree file changed during analysis: {path}", code="io")
    if total != before.st_size:
        raise ArchitectureError(f"worktree file was truncated during analysis: {path}", code="io")
    return _BlobProfile(
        size=total,
        digest=digest.hexdigest(),
        binary=binary,
        content=b"".join(chunks) if keep else None,
    )


def _stream_git_blob(root: Path, object_id: str, expected_size: int, path: str,
                     *, _scope: _GitOperation | None = None) -> tuple[str, bool]:
    """Hash one Git blob without buffering it, enforcing the same deadline and output caps as
    `_run_capped`; returns the SHA-256 and whether a NUL byte appeared anywhere in the object."""

    if _scope is None:
        try:
            with _GitOperation(root, relaxed=_EXACT_SHA.fullmatch(object_id) is not None) as scope:
                return _stream_git_blob(root, object_id, expected_size, path, _scope=scope)
        except ArchitectureError as exc:
            if exc.code == "io" and "bounded process setup failed" in str(exc):
                raise ArchitectureError("streamed blob setup failed", code="io") from exc
            raise
    binding = _scope.check(root)
    if _scope.guard is not None and _EXACT_SHA.fullmatch(object_id) is None:
        raise ArchitectureError("Git operation binding read graph is unsupported", code="git")
    timeout = _scope.remaining()
    try:
        process = subprocess.Popen(  # nosec B603
            _git_command(["cat-file", "blob", object_id], safe_directory=binding.root,
                         git_directory=binding.git_directory, work_tree=binding.root),
            cwd=binding.root,
            env=_git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            **fsx.process_group_kwargs(),
        )
        if fsx.WINDOWS:
            returncode, digest, total, binary, stderr = _drain_blob_threaded(
                process, expected_size=expected_size, path=path, timeout=timeout
            )
        else:
            returncode, digest, total, binary, stderr = _drain_blob_selector(
                process, expected_size=expected_size, path=path, timeout=timeout
            )
    except OSError as exc:
        raise ArchitectureError("Git blob stream is unavailable", code="git") from exc
    finally:
        _scope.check()
    if returncode:
        detail = bytes(stderr).decode("utf-8", "replace").strip()
        raise ArchitectureError(
            f"Git blob stream failed for {path}: {detail or f'exit {returncode}'}", code="git"
        )
    if total != expected_size:
        raise ArchitectureError(
            f"Git blob stream was truncated for {path}: {total} of {expected_size} bytes",
            code="io",
        )
    return digest.hexdigest(), binary


def _drain_blob_selector(
    process: subprocess.Popen[bytes], *, expected_size: int, path: str, timeout: float | None = None
) -> tuple[int, Any, int, bool, bytearray]:
    selector: selectors.BaseSelector | None = None
    digest = hashlib.sha256()
    total = 0
    binary = False
    stderr = bytearray()
    try:
        if process.stdout is None or process.stderr is None:
            raise ArchitectureError("streamed blob pipes are unavailable", code="io")
        try:
            selector = selectors.DefaultSelector()
            for stream in (process.stdout, process.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
        except Exception as exc:
            raise ArchitectureError(
                f"streamed blob setup failed: {path}: {exc}", code="io"
            ) from exc
        deadline = time.monotonic() + (_GIT_TIMEOUT_SECONDS if timeout is None else timeout)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ArchitectureError(f"Git blob stream timed out: {path}", code="timeout")
            for key, _mask in selector.select(remaining):
                chunk = os.read(key.fileobj.fileno(), BLOB_STREAM_CHUNK_BYTES)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if key.fileobj is process.stderr:
                    stderr.extend(chunk[: max(0, 65_536 - len(stderr))])
                    continue
                total += len(chunk)
                if total > expected_size:
                    raise ArchitectureError(f"Git blob stream exceeded its size: {path}", code="limit")
                digest.update(chunk)
                if not binary and b"\0" in chunk:
                    binary = True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ArchitectureError(f"Git blob stream timed out: {path}", code="timeout")
        returncode = process.wait(timeout=remaining)
    except ArchitectureError:
        _stop_process(process)
        raise
    except (OSError, subprocess.TimeoutExpired) as exc:
        _stop_process(process)
        raise ArchitectureError(f"Git blob stream failed: {path}: {exc}", code="io") from exc
    finally:
        if selector is not None:
            selector.close()
        for stream in (process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()
        if process.poll() is None:
            _stop_process(process)
    return returncode, digest, total, binary, stderr


def _drain_blob_threaded(
    process: subprocess.Popen[bytes], *, expected_size: int, path: str, timeout: float | None = None
) -> tuple[int, Any, int, bool, bytearray]:
    """The Windows half of the streamed blob read: same caps and deadline, thread-fed."""
    pipes: _ThreadedPipes | None = None
    digest = hashlib.sha256()
    total = 0
    binary = False
    stderr = bytearray()
    try:
        if process.stdout is None or process.stderr is None:
            raise ArchitectureError("streamed blob pipes are unavailable", code="io")
        try:
            pipes = _ThreadedPipes((process.stdout, process.stderr), BLOB_STREAM_CHUNK_BYTES)
        except Exception as exc:
            raise ArchitectureError(
                f"streamed blob setup failed: {path}: {exc}", code="io"
            ) from exc
        pending = {process.stdout, process.stderr}
        deadline = time.monotonic() + (_GIT_TIMEOUT_SECONDS if timeout is None else timeout)
        while pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ArchitectureError(f"Git blob stream timed out: {path}", code="timeout")
            event = pipes.next(remaining)
            if event is None:
                continue
            stream, chunk = event
            if isinstance(chunk, OSError):
                raise chunk
            if not chunk:
                pending.discard(stream)
                stream.close()
                continue
            if stream is process.stderr:
                stderr.extend(chunk[: max(0, 65_536 - len(stderr))])
                continue
            total += len(chunk)
            if total > expected_size:
                raise ArchitectureError(f"Git blob stream exceeded its size: {path}", code="limit")
            digest.update(chunk)
            if not binary and b"\0" in chunk:
                binary = True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ArchitectureError(f"Git blob stream timed out: {path}", code="timeout")
        returncode = process.wait(timeout=remaining)
    except ArchitectureError:
        _stop_process(process)
        raise
    except (OSError, subprocess.TimeoutExpired) as exc:
        _stop_process(process)
        raise ArchitectureError(f"Git blob stream failed: {path}: {exc}", code="io") from exc
    finally:
        if process.poll() is None:
            _stop_process(process)
        if pipes is not None:
            pipes.close()
        for stream in (process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()
    return returncode, digest, total, binary, stderr


def _git_blob_entry(root: Path, sha: str, path: str,
                    *, _scope: _GitOperation | None = None) -> tuple[str, int] | None:
    if _scope is None:
        with _GitOperation(root) as scope:
            return _git_blob_entry(root, sha, path, _scope=scope)
    _scope.check(root)
    _exact_commit(root, sha, label="commit_sha", _scope=_scope)
    encoded = os.fsencode(path)
    if b"\0" in encoded:
        raise ArchitectureError("invalid Git blob path", code="path")
    raw = _required_output(
        _git(
            root,
            [
                "--literal-pathspecs",
                "ls-tree",
                "-l",
                "-z",
                "--full-tree",
                sha,
                "--",
                path,
            ],
            allow_failure=True,
            limit=min(MAX_GIT_OUTPUT_BYTES, 4_096 + len(encoded)),
            _scope=_scope,
        ),
        operation="read Git blob metadata",
    )
    if not raw:
        return None
    record = raw.split(b"\0", 1)[0]
    if b"\t" not in record:
        raise ArchitectureError("invalid Git blob metadata", code="git")
    metadata, returned_path = record.split(b"\t", 1)
    fields = metadata.split()
    if _path_text(returned_path) != path or len(fields) != 4:
        raise ArchitectureError(f"unexpected Git tree entry for {path}", code="git")
    mode, kind, object_id, size_raw = fields
    if kind != b"blob" or mode not in {b"100644", b"100755"}:
        raise ArchitectureError(f"Git object path is not a regular file: {path}", code="io")
    if len(object_id) != len(sha) or _EXACT_SHA.fullmatch(object_id.decode("ascii", "replace")) is None:
        raise ArchitectureError(f"invalid Git blob identity for {path}", code="git")
    if not size_raw.isdigit():
        raise ArchitectureError(f"invalid Git blob size for {path}", code="git")
    return object_id.decode("ascii"), int(size_raw)


def _profile_git_blob(root: Path, sha: str, path: str,
                      *, _scope: _GitOperation | None = None) -> _BlobProfile | None:
    if _scope is None:
        with _GitOperation(root) as scope:
            return _profile_git_blob(root, sha, path, _scope=scope)
    _scope.check(root)
    entry = _git_blob_entry(root, sha, path, _scope=_scope)
    if entry is None:
        return None
    object_id, size = entry
    if size <= MAX_ANALYZED_FILE_BYTES:
        value = _git_blob(root, sha, path, _scope=_scope)
        if value is None:
            raise ArchitectureError(f"Git blob vanished during analysis: {path}", code="io")
        return _BlobProfile(
            size=len(value),
            digest=hashlib.sha256(value).hexdigest(),
            binary=b"\0" in value,
            content=value,
        )
    # A tracked release ZIP only ever needs a digest and a size here, so it is hashed from a
    # bounded pipe instead of being buffered whole and tripping the analysis limit.
    digest, binary = _stream_git_blob(root, object_id, size, path, _scope=_scope)
    return _BlobProfile(size=size, digest=digest, binary=binary, content=None)


def _profile_blob_value(value: bytes | None) -> _BlobProfile | None:
    if value is None:
        return None
    return _BlobProfile(
        size=len(value),
        digest=hashlib.sha256(value).hexdigest(),
        binary=b"\0" in value,
        content=value,
    )


def _batch_git_profiles(root: Path, sha: str, paths: tuple[str, ...]) -> dict[str, _BlobProfile | None] | None:
    try:
        blobs = _git_blobs(root, sha, paths)
    except ArchitectureError as exc:
        if exc.code == "limit":
            return None
        raise
    return {path: _profile_blob_value(value) for path, value in blobs.items()}


@dataclass(frozen=True)
class _ArchitectureState:
    snapshot: ArchitectureSnapshot
    contracts: tuple[ContractRecord, ...]
    adoption_state: str
    adoption_digest: str


def _materialized_state(
    root: Path,
    sha: str,
    *,
    adoption_base: bool = False,
    bootstrap_baseline: bool = False,
    _scope: _GitOperation | None = None,
) -> _ArchitectureState | None:
    if _scope is None:
        with _GitOperation(root) as scope:
            return _materialized_state(root, sha, adoption_base=adoption_base,
                                       bootstrap_baseline=bootstrap_baseline, _scope=scope)
    _scope.check(root)
    cache_key = (
        *_scope.key(),
        "materialized-state",
        sha,
        adoption_base,
        bootstrap_baseline,
        ADOPTION_BASE_SHA,
    )
    if cache_key in _MATERIALIZED_STATE_CACHE:
        _scope.check()
        return _MATERIALIZED_STATE_CACHE[cache_key]
    model_values = tuple(_git_blob(root, sha, path, _scope=_scope) for path in _MODEL_PATHS)
    marker_value = _git_blob(root, sha, _ADOPTION_PATH, _scope=_scope)
    if model_values == (None, None):
        if marker_value is not None:
            raise ArchitectureError(
                "architecture adoption marker exists without the model", code="missing"
            )
        if (adoption_base and sha == ADOPTION_BASE_SHA) or bootstrap_baseline:
            _scope.stage("state", cache_key, None)
            return None
        raise ArchitectureError("architecture model is missing outside the adoption base", code="missing")
    if any(value is None for value in model_values):
        raise ArchitectureError("architecture model is partially missing", code="missing")
    if marker_value is None:
        raise ArchitectureError("architecture adoption marker is missing", code="missing")
    adoption = parse_adoption_marker(marker_value)
    schema_values = tuple(_git_blob(root, sha, path, required=True, _scope=_scope) for path in _SCHEMA_PATHS)
    with tempfile.TemporaryDirectory(prefix="adaptive-architecture-object-") as directory:
        materialized = Path(directory)
        for path, value in zip((*_MODEL_PATHS, *_SCHEMA_PATHS), (*model_values, *schema_values)):
            target = materialized / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(_required_output(value, operation=f"materialize {path}"))
        snapshot = load_architecture(materialized)
        for contract in snapshot.system["contracts"]:
            value = _git_blob(root, sha, contract["path"], required=True, _scope=_scope)
            target = materialized / contract["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(_required_output(value, operation=f"materialize {contract['path']}"))
        records = contract_inventory(materialized, snapshot)
    if adoption["architecture_id"] != snapshot.system["architecture_id"]:
        raise ArchitectureError(
            "architecture adoption marker id does not match the model", code="schema"
        )
    state = _ArchitectureState(
        snapshot=snapshot,
        contracts=records,
        adoption_state="adopted",
        adoption_digest=adoption["digest"],
    )
    _scope.stage("state", cache_key, state)
    return state


def _worktree_state(root: Path) -> _ArchitectureState:
    snapshot = load_architecture(root)
    marker_value = _worktree_blob(root, _ADOPTION_PATH)
    if marker_value is None:
        raise ArchitectureError("architecture adoption marker is missing", code="missing")
    adoption = parse_adoption_marker(marker_value)
    if adoption["architecture_id"] != snapshot.system["architecture_id"]:
        raise ArchitectureError(
            "architecture adoption marker id does not match the model", code="schema"
        )
    return _ArchitectureState(
        snapshot=snapshot,
        contracts=contract_inventory(root, snapshot),
        adoption_state="adopted",
        adoption_digest=adoption["digest"],
    )


@dataclass(frozen=True)
class ArchitectureChange:
    kind: str
    id: str
    change: str
    before_digest: str | None
    after_digest: str | None


@dataclass(frozen=True)
class ChangedArtifact:
    path: str
    status: str
    added_lines: int | None
    deleted_lines: int | None
    base_size: int
    head_size: int
    base_digest: str | None
    head_digest: str | None


@dataclass(frozen=True)
class ArchitectureDiff:
    base_sha: str
    head_sha: str | None
    head_kind: str
    baseline_introduced: bool
    changed_paths: tuple[str, ...]
    changes: tuple[ArchitectureChange, ...]
    artifacts: tuple[ChangedArtifact, ...]
    base_architecture_digest: str | None
    head_architecture_digest: str
    base_adoption_state: str
    head_adoption_state: str
    base_adoption_digest: str | None
    head_adoption_digest: str
    repository_inventory_digest: str
    digest: str
    _base_state: _ArchitectureState | None = field(repr=False, compare=False)
    _head_state: _ArchitectureState = field(repr=False, compare=False)


def _object_digest(value: Any) -> str:
    if isinstance(value, ContractRecord):
        projected = {key: getattr(value, key) for key in ("id", "kind", "path", "version", "role", "compatibility")}
        projected["document_digest"] = value.digest
        return _digest(projected)
    return _digest(value)


def _change_records(
    base: _ArchitectureState | None, head: _ArchitectureState
) -> tuple[ArchitectureChange, ...]:
    def indexed(values: list[dict[str, Any]]) -> dict[str, Any]:
        return {value["id"]: value for value in values}

    def indexed_rules(rules: dict[str, Any]) -> dict[str, Any]:
        return {item["id"]: item for collection in RULE_COLLECTIONS for item in rules.get(collection, [])}

    base_system = base.snapshot.system if base else {}
    head_system = head.snapshot.system
    collections: list[tuple[str, dict[str, Any], dict[str, Any]]] = [
        (
            "system",
            {"ARCHITECTURE": {key: base_system[key] for key in ("schema_version", "architecture_id")}}
            if base else {},
            {"ARCHITECTURE": {key: head_system[key] for key in ("schema_version", "architecture_id")}},
        ),
        (
            "runtime",
            {item["id"]: item["runtime"] for item in base_system.get("nodes", [])},
            {item["id"]: item["runtime"] for item in head_system["nodes"]},
        ),
        (
            "contract",
            {item.id: item for item in (base.contracts if base else ())},
            {item.id: item for item in head.contracts},
        ),
    ]
    for kind, key in (
        ("trust_domain", "trust_domains"), ("signal", "signals"), ("node", "nodes"),
        ("edge", "edges"), ("classification", "data_classifications"),
        ("secret", "secret_classes"),
    ):
        collections.append((kind, indexed(base_system.get(key, [])), indexed(head_system[key])))
    base_rules = base.snapshot.rules if base else {}
    head_rules = head.snapshot.rules
    collections.extend((
        (
            "rules",
            {"ARCHITECTURE": {key: base_rules[key] for key in ("schema_version", "architecture_id")}}
            if base else {},
            {"ARCHITECTURE": {key: head_rules[key] for key in ("schema_version", "architecture_id")}},
        ),
        ("rule", indexed_rules(base_rules), indexed_rules(head_rules)),
    ))
    changes: list[ArchitectureChange] = []
    for kind, before, after in collections:
        for identity in set(before) | set(after):
            old = before.get(identity)
            new = after.get(identity)
            if old is None:
                change = "added"
            elif new is None:
                change = "removed"
            elif _object_digest(old) != _object_digest(new):
                change = "changed"
            else:
                continue
            changes.append(ArchitectureChange(
                kind, identity, change,
                None if old is None else _object_digest(old),
                None if new is None else _object_digest(new),
            ))
    return tuple(sorted(changes, key=lambda item: (item.kind, item.id, item.change)))


def _changed_paths(root: Path, base: str, head: str | None, *, worktree: bool) -> tuple[str, ...]:
    arguments = [
        "diff", "--name-only", "-z", "--no-renames", "--no-ext-diff", "--no-textconv", base
    ]
    if not worktree:
        arguments.append(_required_head(head))
    raw = _required_output(_git(root, arguments), operation="list changed paths")
    values = [_path_text(item) for item in raw.split(b"\0") if item]
    if worktree:
        untracked = _required_output(
            _git(root, ["ls-files", "--others", "--exclude-standard", "-z"]),
            operation="list untracked paths",
        )
        values.extend(_path_text(item) for item in untracked.split(b"\0") if item)
    unique = tuple(sorted(set(values)))
    if len(unique) > MAX_CHANGED_PATHS:
        raise ArchitectureError("changed path limit exceeded", code="limit")
    return unique


def _line_stats(old: bytes | None, new: bytes | None) -> tuple[int | None, int | None]:
    before = old or b""
    after = new or b""
    if len(before) > MAX_ANALYZED_FILE_BYTES or len(after) > MAX_ANALYZED_FILE_BYTES:
        raise ArchitectureError("line-stat byte limit exceeded", code="limit")
    if b"\0" in before or b"\0" in after:
        return None, None
    try:
        before_lines = before.decode("utf-8").splitlines()
        after_lines = after.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return None, None
    if len(before_lines) > MAX_LINE_STAT_LINES or len(after_lines) > MAX_LINE_STAT_LINES:
        raise ArchitectureError("line-stat line limit exceeded", code="limit")
    with tempfile.TemporaryDirectory(prefix="adaptive-line-stat-") as directory:
        root = Path(directory)
        (root / "before").write_bytes(before)
        (root / "after").write_bytes(after)
        returncode, output, error = _run_capped(
            _git_command(
                [
                    "diff",
                    "--no-index",
                    "--numstat",
                    "--no-renames",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--",
                    "before",
                    "after",
                ]
            ),
            cwd=root,
            env=_git_environment(),
            stdout_limit=4_096,
            stderr_limit=65_536,
            timeout=_LINE_STAT_TIMEOUT_SECONDS,
        )
    if returncode not in {0, 1}:
        message = error.decode("utf-8", "replace").strip()
        raise ArchitectureError(f"exact line-stat operation failed: {message}", code="git")
    if returncode == 0:
        if output:
            raise ArchitectureError("unchanged line-stat operation emitted output", code="git")
        return 0, 0
    records = output.rstrip(b"\n").split(b"\n")
    if len(records) != 1:
        raise ArchitectureError("unexpected exact line-stat output", code="git")
    fields = records[0].split(b"\t", 2)
    if len(fields) != 3 or fields[0] == b"-" or fields[1] == b"-":
        raise ArchitectureError("exact text line-stat output is unavailable", code="git")
    try:
        return int(fields[0]), int(fields[1])
    except ValueError as exc:
        raise ArchitectureError("invalid exact line-stat counts", code="git") from exc


def read_diff_file(root: Path, diff: ArchitectureDiff, path: str, side: str = "head") -> bytes | None:
    repository = Path(root).resolve(strict=True)
    if side not in {"base", "head"}:
        raise ArchitectureError("diff file side must be base or head", code="invalid")
    if side == "base":
        return _git_blob(repository, diff.base_sha, path)
    if diff.head_kind == "worktree":
        return _worktree_blob(repository, path)
    return _git_blob(repository, _required_head(diff.head_sha), path)


def _git_blobs(root: Path, sha: str, paths: tuple[str, ...],
               *, _scope: _GitOperation | None = None) -> dict[str, bytes | None]:
    if _scope is None:
        with _GitOperation(root) as scope:
            return _git_blobs(root, sha, paths, _scope=scope)
    _scope.check(root)
    requested = tuple(sorted(set(paths)))
    if len(requested) > MAX_CHANGED_PATHS:
        raise ArchitectureError("diff file batch path limit exceeded", code="limit")
    if not requested:
        return {}
    _exact_commit(root, sha, label="commit_sha", _scope=_scope)
    cache_key = (*_scope.key(), "blobs", sha, requested)
    cached = _GIT_BLOB_CACHE.get(cache_key)
    if cached is not None:
        _scope.check()
        return dict(cached)
    encoded = tuple(os.fsencode(path) for path in requested)
    if any(b"\0" in path for path in encoded) or sum(map(len, encoded)) > MAX_BATCH_INPUT_BYTES:
        raise ArchitectureError("diff file batch path input limit exceeded", code="limit")
    raw = _required_output(
        _git(
            root,
            ["--literal-pathspecs", "ls-tree", "-lr", "-z", "--full-tree", sha, "--", *requested],
            limit=min(MAX_GIT_OUTPUT_BYTES, 4_096 + sum(map(len, encoded))),
            _scope=_scope,
        ),
        operation="read Git batch tree metadata",
    )
    entries: dict[str, tuple[bytes, int]] = {}
    for record in (item for item in raw.split(b"\0") if item):
        if b"\t" not in record:
            raise ArchitectureError("invalid Git batch tree metadata", code="git")
        metadata, returned_path = record.split(b"\t", 1)
        fields = metadata.split()
        path = _path_text(returned_path)
        if path not in requested or len(fields) != 4 or path in entries:
            raise ArchitectureError(f"unexpected Git tree entry for {path}", code="git")
        mode, kind, object_id, size_raw = fields
        if kind != b"blob" or mode not in {b"100644", b"100755"}:
            raise ArchitectureError(f"Git object path is not a regular file: {path}", code="io")
        if len(object_id) != len(sha) or _EXACT_SHA.fullmatch(object_id.decode("ascii", "replace")) is None:
            raise ArchitectureError(f"invalid Git blob identity for {path}", code="git")
        if not size_raw.isdigit():
            raise ArchitectureError(f"invalid Git blob size for {path}", code="git")
        size = int(size_raw)
        if size > MAX_ANALYZED_FILE_BYTES:
            raise ArchitectureError(f"Git blob exceeds analysis limit: {path}", code="limit")
        entries[path] = object_id, size
    present = tuple(path for path in requested if path in entries)
    total = sum(entries[path][1] for path in present)
    if total > MAX_GIT_OUTPUT_BYTES:
        raise ArchitectureError("Git blob batch exceeds analysis limit", code="limit")
    if not present:
        return {path: None for path in requested}
    specs = b"".join(entries[path][0] + b"\n" for path in present)
    output = _required_output(
        _git(
            root,
            ["cat-file", "--batch=%(objectname) %(objecttype) %(objectsize)"],
            limit=total + 128 * len(present),
            stdin_data=specs,
            _scope=_scope,
        ),
        operation="read Git blob batch",
    )
    values: dict[str, bytes | None] = {path: None for path in requested}
    cursor = 0
    for path in present:
        end = output.find(b"\n", cursor)
        if end < 0:
            raise ArchitectureError(f"truncated Git blob batch header for {path}", code="git")
        fields = output[cursor:end].split()
        object_id, size = entries[path]
        if fields != [object_id, b"blob", str(size).encode("ascii")]:
            raise ArchitectureError(f"unexpected Git blob batch header for {path}", code="git")
        start = end + 1
        finish = start + size
        if finish >= len(output) or output[finish:finish + 1] != b"\n":
            raise ArchitectureError(f"truncated Git blob batch content for {path}", code="git")
        values[path] = output[start:finish]
        cursor = finish + 1
    if cursor != len(output):
        raise ArchitectureError("unexpected trailing Git blob batch output", code="git")
    _scope.stage("blobs", cache_key, dict(values))
    return values


def read_diff_files(
    root: Path, diff: ArchitectureDiff, paths: tuple[str, ...], side: str = "head"
) -> dict[str, bytes | None]:
    """Read a bounded exact set of paths, batching immutable Git blob content."""
    repository = Path(root).resolve(strict=True)
    if side not in {"base", "head"}:
        raise ArchitectureError("diff file side must be base or head", code="invalid")
    requested = tuple(sorted(set(paths)))
    encoded = tuple(os.fsencode(path) for path in requested)
    if len(requested) > MAX_CHANGED_PATHS or sum(map(len, encoded)) > MAX_BATCH_INPUT_BYTES:
        raise ArchitectureError("diff file batch path limit exceeded", code="limit")
    if side == "head" and diff.head_kind == "worktree":
        values: dict[str, bytes | None] = {}
        total = 0
        for path in requested:
            values[path] = _worktree_blob(repository, path)
            total += len(values[path] or b"")
            if total > MAX_GIT_OUTPUT_BYTES:
                raise ArchitectureError("worktree blob batch exceeds analysis limit", code="limit")
        return values
    sha = diff.base_sha if side == "base" else _required_head(diff.head_sha)
    return _git_blobs(repository, sha, requested)


def git_tree_paths(root: Path, sha: str, prefixes: tuple[str, ...]) -> tuple[str, ...]:
    _exact_commit(root, sha, label="commit_sha")
    raw = _required_output(
        _git(root, ["ls-tree", "-r", "--name-only", "-z", "--full-tree", sha]),
        operation="list Git tree paths",
    )
    paths = tuple(
        sorted(
            path
            for path in (_path_text(item) for item in raw.split(b"\0") if item)
            if any(not prefix or path == prefix or path.startswith(prefix + "/") for prefix in prefixes)
        )
    )
    if len(paths) > MAX_CHANGED_PATHS:
        raise ArchitectureError("Git tree path limit exceeded", code="limit")
    return paths


def _tree_inventory_digest(
    root: Path,
    sha: str | None,
    *,
    worktree: bool,
    artifacts: tuple[ChangedArtifact, ...] = (),
) -> str:
    if worktree:
        raw = _required_output(
            _git(root, ["ls-files", "-s", "-z"]), operation="read worktree index"
        )
        untracked = _required_output(
            _git(root, ["ls-files", "--others", "--exclude-standard", "-z"]),
            operation="read worktree untracked inventory",
        )
        return _digest(
            {
                "tracked_index": os.fsdecode(raw),
                "untracked": os.fsdecode(untracked),
                "worktree_changes": [
                    {
                        "path": item.path,
                        "status": item.status,
                        "head_digest": item.head_digest,
                        "head_size": item.head_size,
                    }
                    for item in artifacts
                ],
            }
        )
    exact_sha = _required_head(sha)
    raw = _required_output(
        _git(root, ["ls-tree", "-r", "-z", "--full-tree", exact_sha]),
        operation="read Git tree inventory",
    )
    return _digest(os.fsdecode(raw))


def diff_architecture(
    root: Path | str,
    *,
    base_sha: str,
    head_sha: str | None = None,
    worktree: bool = False,
    _trusted_base_selection: ArchitectureBaseSelection | None = None,
) -> ArchitectureDiff:
    repository = Path(root).resolve(strict=True)
    base = _exact_commit(repository, base_sha, label="base_sha")
    bootstrap_baseline = False
    if _trusted_base_selection is not None:
        verified_selection = select_architecture_comparison_base(
            repository,
            {"base_commit": _trusted_base_selection.route_base_sha},
        )
        if verified_selection != _trusted_base_selection:
            raise ArchitectureError("architecture base selection is stale", code="git")
        if base != _trusted_base_selection.comparison_base_sha:
            raise ArchitectureError(
                "architecture base selection does not match base_sha",
                code="git",
            )
        bootstrap_baseline = _trusted_base_selection.bootstrap_baseline
    if worktree:
        if head_sha is not None:
            raise ArchitectureError("worktree diff cannot also name head_sha", code="git")
        head = None
        head_state = _worktree_state(repository)
        head_kind = "worktree"
    else:
        head = _head_commit(repository) if head_sha is None else _exact_commit(
            repository, head_sha, label="head_sha"
        )
        head_state = _materialized_state(repository, head)
        if head_state is None:
            raise ArchitectureError("head architecture model is missing", code="missing")
        head_kind = "commit"
    base_state = _materialized_state(
        repository,
        base,
        adoption_base=True,
        bootstrap_baseline=bootstrap_baseline,
    )
    paths = _changed_paths(repository, base, head, worktree=worktree)
    base_profiles = _batch_git_profiles(repository, base, paths)
    head_profiles = (
        None if worktree else _batch_git_profiles(repository, _required_head(head), paths)
    )
    artifacts: list[ChangedArtifact] = []
    artifact_bytes = 0
    head_side = None if worktree else _required_head(head)
    for path in paths:
        base_profile = (
            base_profiles[path]
            if base_profiles is not None
            else _profile_git_blob(repository, base, path)
        )
        head_profile = (
            _profile_worktree_blob(repository, path)
            if worktree
            else (
                head_profiles[path]
                if head_profiles is not None
                else _profile_git_blob(repository, head_side, path)
            )
        )
        artifact_bytes += (base_profile.size if base_profile else 0) + (
            head_profile.size if head_profile else 0
        )
        if artifact_bytes > MAX_DIFF_ARTIFACT_BYTES:
            raise ArchitectureError("aggregate changed artifact byte limit exceeded", code="limit")
        status = "added" if base_profile is None and head_profile is not None else (
            "deleted" if base_profile is not None and head_profile is None else "modified"
        )
        oversized_text = any(
            profile is not None and profile.content is None and not profile.binary
            for profile in (base_profile, head_profile)
        )
        if oversized_text:
            raise ArchitectureError(f"text file exceeds analysis limit: {path}", code="limit")
        if any(profile.binary for profile in (base_profile, head_profile) if profile is not None):
            added, deleted = None, None
        else:
            added, deleted = _line_stats(
                base_profile.content if base_profile else None,
                head_profile.content if head_profile else None,
            )
        artifacts.append(
            ChangedArtifact(
                path=path,
                status=status,
                added_lines=added,
                deleted_lines=deleted,
                base_size=base_profile.size if base_profile else 0,
                head_size=head_profile.size if head_profile else 0,
                base_digest=base_profile.digest if base_profile else None,
                head_digest=head_profile.digest if head_profile else None,
            )
        )
    changes = _change_records(base_state, head_state)
    base_digest = None if base_state is None else architecture_digests(base_state.snapshot)[
        "architecture_digest"
    ]
    head_digest = architecture_digests(head_state.snapshot)["architecture_digest"]
    payload = {
        "contract": "adaptive-grok.architecture-diff",
        "contract_version": 1,
        "base_sha": base,
        "head_sha": head,
        "head_kind": head_kind,
        "baseline_introduced": base_state is None,
        "base_architecture_digest": base_digest,
        "head_architecture_digest": head_digest,
        "base_adoption_state": "bootstrap_absent" if base_state is None else base_state.adoption_state,
        "head_adoption_state": head_state.adoption_state,
        "base_adoption_digest": None if base_state is None else base_state.adoption_digest,
        "head_adoption_digest": head_state.adoption_digest,
        "changed_paths": paths,
        "changes": [
            {
                "kind": item.kind,
                "id": item.id,
                "change": item.change,
                "before_digest": item.before_digest,
                "after_digest": item.after_digest,
            }
            for item in changes
        ],
    }
    return ArchitectureDiff(
        base_sha=base,
        head_sha=head,
        head_kind=head_kind,
        baseline_introduced=base_state is None,
        changed_paths=paths,
        changes=changes,
        artifacts=tuple(artifacts),
        base_architecture_digest=base_digest,
        head_architecture_digest=head_digest,
        base_adoption_state="bootstrap_absent" if base_state is None else base_state.adoption_state,
        head_adoption_state=head_state.adoption_state,
        base_adoption_digest=None if base_state is None else base_state.adoption_digest,
        head_adoption_digest=head_state.adoption_digest,
        repository_inventory_digest=_tree_inventory_digest(
            repository, head, worktree=worktree, artifacts=tuple(artifacts)
        ),
        digest=_digest(payload),
        _base_state=base_state,
        _head_state=head_state,
    )
