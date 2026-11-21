"""Linux pinned-local-v1: one on-demand supervisor per existing registry attempt.

Private pipes carry the one-use dispatch capability. The only durable state is
execution_store. A PID/user/network namespace contains all command descendants;
the host supervisor owns its namespace launcher through --die-with-parent.
"""

from __future__ import annotations
from contextlib import ExitStack
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import selectors
import subprocess
import stat
import sys
import time

from . import STACK_DIR, execution, execution_store as store, fsx, managed_execution as managed, state

PROFILE = "linux-pinned-local-v1"
MAX_HANDOFF = 8192
_HANDLES = {}


def _host_identity(pid):
    raw = Path(f"/proc/{pid}/stat").read_bytes().rsplit(b")", 1)[1].split()
    if raw[0] == b"Z":
        raise ValueError("process ended")
    return raw[19].decode("ascii")


def reap():
    for identity, process in list(_HANDLES.items()):
        if process.poll() is not None:
            del _HANDLES[identity]


def is_live(value):
    reap()
    try:
        return (
            type(value) is dict
            and value["profile"] == PROFILE
            and _host_identity(value["host_pid"]) == value["start_ticks"]
        )
    except (OSError, ValueError, KeyError, TypeError):
        return False


def _environment(session):
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "GETZILLA_SESSION_ID": session,
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def _script():
    return str(STACK_DIR.parent / "scripts/getzilla_execution.py")


def _read_handoff():
    descriptor = sys.stdin.fileno()
    if not stat.S_ISFIFO(os.fstat(descriptor).st_mode):
        raise execution.ExecutionError("supervisor_handoff_unavailable")
    os.set_blocking(descriptor, False)
    chunks, total, end = [], 0, time.monotonic() + 3
    with selectors.DefaultSelector() as selector:
        selector.register(descriptor, selectors.EVENT_READ)
        while True:
            remaining = end - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise execution.ExecutionError("supervisor_handoff_unavailable")
            chunk = os.read(descriptor, min(4096, MAX_HANDOFF + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_HANDOFF:
                raise execution.ExecutionError("supervisor_handoff_unavailable")
    raw = b"".join(chunks)
    value = managed._json(raw)
    if set(value) != {"root", "tool_id", "session", "admission", "request", "deadline", "supervisor"}:
        raise execution.ExecutionError("supervisor_handoff_unavailable")
    return value


class Backend(managed.Backend):
    supervised = True

    def dispatch(self, root, admission, request):
        # Admission is consumed in the worker, once, before its acknowledgement.
        caller = execution.trusted_caller(root)
        tool = managed._tool(root, request.arguments["tool_id"])
        managed._policy(root, tool)
        with ExitStack() as stack:
            binary = managed.Binary(root, tool.executable, tool.digest)
            stack.callback(binary.close)
            bootstrap = managed.qualified_python(root)
            stack.callback(bootstrap.close)
            live = execution._LIVE[(str(root.resolve()), admission.execution_id)]
            process = fsx.owned_popen(
                [bootstrap.path, "-I", "-S", _script(), "--supervisor"],
                executable=f"/proc/self/fd/{bootstrap.fd}",
                pass_fds=(bootstrap.fd,),
                cwd=root,
                env=_environment(caller.session_id),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            _HANDLES[admission.execution_id] = process
            supervisor = {"profile": PROFILE, "host_pid": process.pid, "start_ticks": _host_identity(process.pid)}
            envelope = {
                "root": str(root.resolve()),
                "tool_id": tool.id,
                "session": caller.session_id,
                "admission": {
                    "execution_id": admission.execution_id,
                    "execution_generation": admission.execution_generation,
                    "revision": admission.revision,
                    "token": admission.token,
                },
                "request": {
                    "intent_key": request.intent_key,
                    "argument_bytes": request.argument_bytes.decode(),
                    "hard_timeout_seconds": request.hard_timeout_seconds,
                    "label": request.label,
                    "operation_id": request.operation_id,
                    "mcp_request_id": request.mcp_request_id,
                    "remote_task_id": request.remote_task_id,
                },
                "deadline": live[1],
                "supervisor": supervisor,
            }
            raw = json.dumps(envelope).encode()
            if len(raw) > MAX_HANDOFF:
                process.terminate()
                raise execution.ExecutionError("supervisor_handoff_unavailable")
            os.set_blocking(process.stdin.fileno(), False)
            try:
                if os.write(process.stdin.fileno(), raw) != len(raw):
                    raise execution.ExecutionError("supervisor_handoff_unavailable")
            finally:
                process.stdin.close()
            selector = selectors.DefaultSelector()
            try:
                selector.register(process.stdout, selectors.EVENT_READ)
                if not selector.select(min(3, max(0.01, live[1] - time.monotonic()))):
                    raise execution.ExecutionError("supervisor_start_unconfirmed")
                if process.stdout.read(1) != b"R":
                    raise execution.ExecutionError("supervisor_start_unconfirmed")
            finally:
                selector.close()
                process.stdout.close()
            return None


def start(root, *, tool_id, intent_key, hard_timeout_seconds):
    """Native boundary: callers supply a source-pinned tool ID, never a principal."""
    if type(hard_timeout_seconds) is not int or not 1 <= hard_timeout_seconds <= 300:
        raise execution.ExecutionError("invalid_supervisor_budget")
    if not managed.supported() or not Path("/usr/bin/bwrap").is_file():
        raise execution.ExecutionError("supervisor_host_unsupported")
    root = root.resolve()
    caller = execution.trusted_caller(root)
    tool = managed._tool(root, tool_id)
    managed._policy(root, tool)
    return execution.submit(
        root,
        caller,
        execution.SubmitRequest(intent_key, {"tool_id": tool_id}, hard_timeout_seconds, label="managed-local"),
        backend=Backend(),
    )


def cancel(root, execution_id):
    caller = execution.trusted_caller(root, execution_id=execution_id)
    return execution.cancel(root, caller, execution_id, backend=managed.Backend())


def observe(root, execution_id, *, wait_seconds=None):
    process = _HANDLES.get(execution_id)
    if process is not None and process.poll() is not None:
        del _HANDLES[execution_id]
    caller = execution.trusted_caller(root, execution_id=execution_id)
    return (
        execution.get(root, caller, execution_id)
        if wait_seconds is None
        else execution.wait(root, caller, execution_id, wait_seconds)
    )


class NamespaceBackend(managed.Backend):
    def __init__(self, *arguments, supervisor, sandbox, **keywords):
        super().__init__(*arguments, **keywords)
        self.supervisor, self.sandbox = supervisor, sandbox

    def launcher_digest(self):
        return hashlib.sha256((PROFILE + self.sandbox.digest + self.bootstrap.digest).encode()).hexdigest()

    def started(self, root, admission, instance):
        def register(registry):
            record = execution._managed_record(root, registry, admission, instance)
            record["supervisor"] = self.supervisor
            record["revision"] += 1

        store.mutate_registry(root, register)
        sys.stdout.buffer.write(b"R")
        sys.stdout.buffer.flush()
        sys.stdout.close()

    def cleanup(self, process):
        managed._cleanup(process)
        end = time.monotonic() + 2
        while time.monotonic() < end:
            try:
                child, _ = os.waitpid(-1, os.WNOHANG)
                if child == 0:
                    time.sleep(0.01)
            except ChildProcessError:
                # Subreaper custody plus dead namespace init: all owned
                # children, including a detached descendant, are now reaped.
                return process.returncode is not None
        return False

    def progress(self, root, admission, instance, tail, observed):
        text = tail.decode("utf-8", "ignore")
        retained = len(text.encode())

        def update(registry):
            record = execution._managed_record(root, registry, admission, instance)
            record["output"] = execution.normalize_output(
                {
                    "preview": text,
                    "observed_bytes": observed,
                    "retained_bytes": retained,
                    "dropped_bytes": observed - retained,
                    "truncated": observed != retained,
                    "complete_output": False,
                }
            )
            record["output"]["complete_output"] = False
            record["revision"] += 1

        store.mutate_registry(root, update)

    def spawn(self, root):
        # Binary descriptors were checked in the host's UID namespace. bwrap
        # mounts those exact open bytes; no mapped-UID custody exception exists.
        command = [
            "/usr/bin/bwrap",
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--die-with-parent",
            "--ro-bind",
            "/",
            "/",
            "--bind",
            str(root),
            str(root),
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/run",
            "--ro-bind",
            f"/proc/self/fd/{self.binary.fd}",
            "/run/getzilla-executable",
            "--block-fd",
            "0",
            "--chdir",
            str(root),
            "/run/getzilla-executable",
            *self.tool.arguments,
        ]
        return fsx.owned_popen(
            command,
            executable=f"/proc/self/fd/{self.sandbox.fd}",
            pass_fds=(self.sandbox.fd, self.binary.fd),
            cwd=root,
            env=managed._ENVIRONMENT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )


def supervise():
    """Host owner survives CLI exit, but lives only as long as its one job."""
    value = _read_handoff()
    root = Path(value["root"]).resolve()
    state.bind_session(value["session"])
    if (
        state.current_session() != os.environ.get("GETZILLA_SESSION_ID")
        or value["supervisor"]["host_pid"] != os.getpid()
        or value["supervisor"]["start_ticks"] != _host_identity(os.getpid())
    ):
        raise execution.ExecutionError("execution_forbidden")
    execution.trusted_caller(root)
    admission = execution.Admission(**value["admission"])
    request = execution.AdmittedRequest(
        **{**value["request"], "argument_bytes": value["request"]["argument_bytes"].encode()}
    )
    record = execution._find(store.load_registry(root), admission.execution_id)
    remaining = (
        datetime.fromisoformat(record["deadline"]["hard_deadline_at"]) - execution.SYSTEM_CLOCK.utcnow()
    ).total_seconds()
    deadline = min(value["deadline"], time.monotonic() + max(0, remaining))
    execution._LIVE[(str(root), admission.execution_id)] = (
        execution.SYSTEM_CLOCK,
        deadline,
        admission.execution_generation,
    )
    tool = managed._tool(root, value["tool_id"])
    managed._policy(root, tool)
    import ctypes

    if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
        raise execution.ExecutionError("supervisor_subreaper_unavailable")
    allowed = sorted(os.sched_getaffinity(0))
    os.sched_setaffinity(0, set(allowed[:2]))
    import resource

    resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (request.hard_timeout_seconds + 4, request.hard_timeout_seconds + 4))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    with ExitStack() as stack:
        binary = managed.Binary(root, tool.executable, tool.digest)
        stack.callback(binary.close)
        bootstrap = managed.qualified_python(root)
        stack.callback(bootstrap.close)
        sandbox = managed.Binary(root, "/usr/bin/bwrap")
        stack.callback(sandbox.close)
        NamespaceBackend(tool, binary, bootstrap, supervisor=value["supervisor"], sandbox=sandbox).dispatch(
            root, admission, request
        )
