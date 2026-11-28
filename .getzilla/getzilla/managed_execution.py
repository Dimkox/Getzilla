"""Opt-in pinned local execution through the existing attempt authority.

Linux pidfds and an unreaped owned leader bound process-group cleanup. This is
not an OS sandbox: descendants can escape a POSIX group. Other hosts refuse.
No configuration is enabled by importing this module.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import time

from . import continuity, execution, execution_store, fsx, policy, state
from .execution_output import PREVIEW_BYTES
from .spec import _bounded_walk, _pairs_object, _reject_constant
from .supply_chain import PublicSourceError, read_public_source

_ENVIRONMENT = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
_LAUNCHER = (
    "import os,sys\n"
    "os.close(int(sys.argv[1]))\n"
    "gate=os.read(0,1)\n"
    "if gate!=b'R': sys.exit(125)\n"
    "os.close(0)\n"
    "os.open('/dev/null',os.O_RDONLY)\n"
    "fd=int(sys.argv[2])\n"
    "os.set_inheritable(fd,False)\n"
    "os.execve(fd,sys.argv[3:],{'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'})\n"
)
_MAX_BINARY = 64 * 1024 * 1024
_STOP_GRACE_SECONDS = 1.0


def supported():
    return (sys.platform == 'linux' and hasattr(os, 'pidfd_open') and hasattr(os, 'P_PIDFD')
            and os.execve in os.supports_fd)


def _json(raw):
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs_object,
                           parse_constant=_reject_constant)
        _bounded_walk(value)
        if not isinstance(value, dict):
            raise ValueError('object required')
        return value
    except (ValueError, UnicodeError, RecursionError, TypeError):
        raise execution.ExecutionError('managed_config_unavailable') from None


@dataclass(frozen=True)
class Tool:
    id: str
    executable: str
    digest: str
    arguments: tuple[str, ...]
    config_digest: str


def _tool(root, tool_id):
    if not isinstance(tool_id, str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,128}', tool_id):
        raise execution.ExecutionError('invalid_managed_tool')
    try:
        raw = read_public_source(root.resolve(), '.getzilla/config/toolchain.json', 262144)
        config = _json(raw)
        tools = config.get('tools')
        if (config.get('schema_version') != 1 or not isinstance(tools, list) or len(tools) > 128
                or any(not isinstance(item, dict) for item in tools)):
            raise ValueError('invalid tools')
        matches = [item for item in tools if item.get('id') == tool_id]
        if len(matches) != 1 or 'managed' not in matches[0]:
            raise execution.ExecutionError('managed_tool_unsupported')
        spec = matches[0]['managed']
        if not isinstance(spec, dict) or set(spec) != {'executable', 'sha256', 'argv'}:
            raise ValueError('invalid pin')
        executable, digest, arguments = spec['executable'], spec['sha256'], spec['argv']
        if (not isinstance(executable, str) or not Path(executable).is_absolute() or len(executable) > 4096
                or '..' in Path(executable).parts or '\x00' in executable
                or not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest)
                or not isinstance(arguments, list) or len(arguments) > 32
                or any(not isinstance(arg, str) or len(arg.encode()) > 1024
                       or any(ord(character) < 32 for character in arg) for arg in arguments)
                or not isinstance(matches[0].get('commands'), list)
                or Path(executable).name not in matches[0]['commands']):
            raise ValueError('invalid pin')
        return Tool(tool_id, executable, digest, tuple(arguments), hashlib.sha256(raw).hexdigest())
    except execution.ExecutionError:
        raise
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, PublicSourceError):
        raise execution.ExecutionError('managed_config_unavailable') from None


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _directory_identity(info):
    return fsx.directory_identity(info, (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid))


class Binary:
    """A checked open ELF descriptor. Never execute a re-resolved command path."""
    def __init__(self, root, path, expected=None):
        self.path = path
        self.stack = ExitStack()
        try:
            owner = root.lstat().st_uid
            target = Path(path)
            if not target.is_absolute() or '..' in target.parts:
                raise ValueError('absolute path required')
            directory = fsx.open_dir(target.anchor, flags=fsx.O_CLOEXEC)
            self.stack.callback(fsx.close_dir, directory)
            bindings = []
            for component in target.parts[1:-1]:
                parent = directory
                directory = fsx.open_dir_at(parent, component, flags=fsx.O_CLOEXEC)
                self.stack.callback(fsx.close_dir, directory)
                info = fsx.fstat_dir(directory)
                if (info.st_uid not in {0, owner} or info.st_mode & 0o022
                        and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX)):
                    raise ValueError('unsafe executable ancestry')
                bindings.append((parent, component, _directory_identity(info)))
            self.fd = fsx.open_at(directory, target.name,
                                  os.O_RDONLY | fsx.O_NOFOLLOW | fsx.O_NONBLOCK | fsx.O_CLOEXEC)
            self.stack.callback(os.close, self.fd)
            info = os.fstat(self.fd)
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) not in {0o555, 0o755}
                    or info.st_uid not in {0, owner} or info.st_nlink != 1 or not 4 <= info.st_size <= _MAX_BINARY):
                raise ValueError('unqualified executable')
            self.identity = _identity(info)
            hasher, size, magic = hashlib.sha256(), 0, b''
            while True:
                chunk = os.read(self.fd, min(65536, _MAX_BINARY - size + 1))
                if not chunk:
                    break
                if not magic:
                    magic = chunk[:4]
                size += len(chunk)
                if size > _MAX_BINARY or _identity(os.fstat(self.fd)) != self.identity:
                    raise ValueError('executable changed')
                hasher.update(chunk)
            if (magic != b'\x7fELF' or size != info.st_size or _identity(os.fstat(self.fd)) != self.identity
                    or _identity(fsx.lstat_at(directory, target.name)) != self.identity):
                raise ValueError('executable changed')
            for parent, component, identity in bindings:
                observed = fsx.lstat_at(parent, component)
                if _directory_identity(observed) != identity:
                    raise ValueError('ancestry changed')
            self.digest = hasher.hexdigest()
            if expected is not None and self.digest != expected:
                raise ValueError('wrong executable pin')
        except (OSError, ValueError):
            self.stack.close()
            raise execution.ExecutionError('managed_executable_unqualified') from None

    def close(self):
        self.stack.close()


def qualified_python(root):
    host_python = str(Path(sys.executable).resolve())
    try:
        return Binary(root, host_python)
    except execution.ExecutionError:
        system_python = str(Path('/usr/bin/python3').resolve())
        if system_python == host_python:
            raise
        return Binary(root, system_python)


@state.serialized_task
def _policy(root, tool):
    import shlex
    try:
        route = state.get_active_route(root)
        if route is None or continuity.scope_gaps(root, route):
            raise execution.ExecutionError('managed_scope_unqualified')
        _json(read_public_source(root.resolve(), '.getzilla/config/policy.json', 262144))
        permitted, _ = policy.evaluate_pre_tool(root, {
            'tool_name': 'Bash', 'tool_input': {'command': shlex.join([tool.executable, *tool.arguments])}},
            execution_cwd=root.resolve())
        if not permitted:
            raise execution.ExecutionError('managed_policy_denied')
    except execution.ExecutionError:
        raise
    except (PublicSourceError, OSError, ValueError):
        raise execution.ExecutionError('managed_policy_denied') from None


def _start_identity(process, pidfd):
    # Public kernel process metadata; no process arguments or environment are read.
    raw = Path(f'/proc/{process.pid}/stat').read_bytes()
    start = raw.rsplit(b')', 1)[1].split()[19].decode('ascii')
    return f'linux:{os.fstat(pidfd).st_ino}:{start}'


def _spawn(root, binary, bootstrap, tool):
    return fsx.owned_popen(
        [bootstrap.path, '-I', '-S', '-c', _LAUNCHER, str(bootstrap.fd),
         str(binary.fd), tool.executable, *tool.arguments],
        executable=f'/proc/self/fd/{bootstrap.fd}', pass_fds=(bootstrap.fd, binary.fd),
        cwd=root, env=_ENVIRONMENT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _done(pidfd):
    return os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None


def _request_group_stop(process, drain):
    # Keep the leader unreaped for the entire grace period, even if a
    # descendant takes longer than its leader to finish its TERM handler.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except OSError:
        return  # The finally block still forces and verifies cleanup.
    deadline = time.monotonic() + _STOP_GRACE_SECONDS
    while (remaining := deadline - time.monotonic()) > 0:
        drain(remaining)


def _cleanup(process):
    # Do not poll()/reap before killpg: the unreaped owned leader prevents PGID reuse.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        return False
    try:
        process.wait(timeout=2)
    except (subprocess.TimeoutExpired, OSError):
        return False
    try:
        os.killpg(process.pid, 0)  # Observation only; never kill a reaped/restarted PID.
    except ProcessLookupError:
        return True
    except OSError:
        pass
    return False


class Backend:
    kind = 'managed-local'
    external_mutations = False
    cooperative_admission = True

    def __init__(self, tool=None, binary=None, bootstrap=None):
        self.tool, self.binary, self.bootstrap = tool, binary, bootstrap

    def cancel(self, root, admission):
        admission.consume(root)
        return True  # Durable request accepted; only the owning runner confirms cleanup.

    def launcher_digest(self):
        return hashlib.sha256((_LAUNCHER + self.bootstrap.digest).encode()).hexdigest()

    def started(self, root, admission, instance):
        pass

    def progress(self, root, admission, instance, tail, observed):
        pass

    def cleanup(self, process):
        return _cleanup(process)

    def spawn(self, root):
        return _spawn(root, self.binary, self.bootstrap, self.tool)

    def dispatch(self, root, admission, request):
        admission.consume(root, request)
        instance = secrets.token_hex(16)
        digest = self.launcher_digest()
        execution._begin_managed(root, admission, instance, digest, self.binary.digest)
        self.started(root, admission, instance)
        process, pidfd = None, None
        tail, observed = b'', 0
        last_progress = execution.SYSTEM_CLOCK.monotonic()
        status, reason, confirmed = 'failed', 'managed_authority_unavailable', True
        selector = selectors.DefaultSelector()
        def drain(timeout=0):
            nonlocal tail, observed
            for key, _ in selector.select(timeout):
                for _ in range(16):
                    try:
                        chunk = os.read(key.fd, 65536)
                    except BlockingIOError:
                        break
                    if not chunk:
                        selector.unregister(key.fileobj)
                        break
                    observed = min(2**63 - 1, observed + len(chunk))
                    tail = (tail + chunk)[-PREVIEW_BYTES:]
        def recheck():
            if _tool(root, self.tool.id) != self.tool:
                raise execution.ExecutionError('managed_config_changed')
            _policy(root, self.tool)
            for old, path, expected in ((self.binary, self.tool.executable, self.tool.digest),
                                        (self.bootstrap, self.bootstrap.path, self.bootstrap.digest)):
                candidate = Binary(root, path, expected)
                try:
                    if candidate.identity != old.identity or _identity(os.fstat(old.fd)) != old.identity:
                        raise execution.ExecutionError('managed_executable_changed')
                finally:
                    candidate.close()
        try:
            watcher = execution._managed_watch(root, admission, instance)
            if watcher != 'running':
                raise execution.ExecutionError('execution_deadline_elapsed' if watcher == 'deadline'
                                               else 'execution_stopped')
            recheck()
            process = self.spawn(root)
            pidfd = os.pidfd_open(process.pid)
            start = _start_identity(process, pidfd)
            for stream in (process.stdout, process.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            execution._register_managed(root, admission, instance, process.pid, start)
            def release(check_deadline):
                # A fresh empty pipe accepts one byte without waiting for the child.
                os.set_blocking(process.stdin.fileno(), False)
                check_deadline()
                if os.write(process.stdin.fileno(), b'R') != 1:
                    raise OSError('gate write failed')
                process.stdin.close()
            execution._release_managed(root, admission, instance, recheck, release)
            while True:
                watcher = execution._managed_watch(root, admission, instance)
                if watcher != 'running':
                    status, reason = ('timed_out', 'managed_deadline') if watcher == 'deadline' else (
                        'cancelled', 'managed_stop')
                    _request_group_stop(process, drain)
                    break
                if _done(pidfd):
                    status, reason = 'succeeded', 'managed_exit'
                    break
                drain(.05)
                current = execution.SYSTEM_CLOCK.monotonic()
                if observed and current - last_progress >= .25:
                    self.progress(root, admission, instance, tail, observed)
                    last_progress = current
        except execution.ExecutionError as error:
            if error.code == 'execution_stopped':
                status, reason = 'cancelled', 'managed_stop_before_release'
            elif error.code == 'execution_deadline_elapsed':
                status, reason = 'timed_out', 'managed_deadline'
            else:
                status, reason = 'failed', 'managed_admission_unavailable'
        except (OSError, ValueError, KeyError, execution_store.RegistryError):
            status, reason = 'failed', 'managed_authority_unavailable'
        finally:
            if process is not None:
                confirmed = self.cleanup(process)
                if status == 'succeeded' and process.returncode != 0:
                    status, reason = 'failed', 'managed_exit_nonzero'
                drain()
                for stream in (process.stdin, process.stdout, process.stderr):
                    stream.close()
            selector.close()
            if pidfd is not None:
                os.close(pidfd)
        text = tail.decode('utf-8', 'ignore')
        retained = len(text.encode())
        execution._finish_managed(root, admission, instance, {
            'execution_status': status, 'terminal_reason': reason,
            'cleanup_status': 'confirmed' if confirmed else 'unconfirmed',
            'operation_outcome': 'not_applicable',
            'output': {'preview': text, 'observed_bytes': observed, 'retained_bytes': retained,
                       'dropped_bytes': observed - retained, 'truncated': observed != retained,
                       'complete_output': observed == retained},
        })
        return None


def run(root, caller, *, tool_id, intent_key, hard_timeout_seconds):
    if not supported():
        raise execution.ExecutionError('managed_host_unsupported')
    tool = _tool(root, tool_id)
    _policy(root, tool)
    with ExitStack() as stack:
        binary = Binary(root, tool.executable, tool.digest)
        stack.callback(binary.close)
        bootstrap = qualified_python(root)
        stack.callback(bootstrap.close)
        return execution.submit(root, caller, execution.SubmitRequest(
            intent_key, {'tool_id': tool.id}, hard_timeout_seconds, label='managed-local'),
            backend=Backend(tool, binary, bootstrap))
