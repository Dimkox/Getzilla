"""Small bounded child runner, not a job scheduler. Remote work currently requires POSIX."""
from __future__ import annotations

import os
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Event
from typing import Mapping, Sequence


@dataclass(frozen=True)
class ProcessResult:
    returncode: int | None
    stdout: bytes = b''
    stderr: bytes = b''
    status: str = 'completed'


def bounded_run(argv: Sequence[str], *, cwd: Path, env: Mapping[str, str],
                input_data: bytes = b'', timeout: float = 30, max_output: int = 2 * 1024 * 1024,
                cancel: Event | None = None) -> ProcessResult:
    """Bound combined output *before* decoding; terminate the owned process group.

    stdin is nonblocking too. Descendants retaining pipes cannot extend the wall
    deadline. No shell, retries, output logging or caller environment mutation.
    Windows fails explicitly until equivalent owned-job cleanup is implemented.
    """
    if not 0 < timeout <= 300 or not 1 <= max_output <= 8 * 1024 * 1024 or len(input_data) > 256 * 1024:
        raise ValueError('process limits outside supported bounds')
    if not argv or any(not isinstance(arg, str) or '\0' in arg for arg in argv):
        raise ValueError('invalid process arguments')
    if cancel is not None and cancel.is_set():
        return ProcessResult(None, status='cancelled')
    if os.name != 'posix':
        return ProcessResult(None, status='unsupported_os')
    try:
        process = subprocess.Popen(list(argv), cwd=cwd, env=dict(env), stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    except FileNotFoundError:
        return ProcessResult(None, status='missing_tool')
    except OSError:
        return ProcessResult(None, status='start_failed')
    output = {'stdout': bytearray(), 'stderr': bytearray()}
    total = 0
    offset = 0
    status = 'completed'
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    try:
        for stream, name in ((process.stdout, 'stdout'), (process.stderr, 'stderr')):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        if input_data:
            os.set_blocking(process.stdin.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE, 'stdin')
        else:
            process.stdin.close()
        while selector.get_map() or process.poll() is None:
            if cancel is not None and cancel.is_set():
                status = 'cancelled'
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                status = 'timeout'
                break
            for key, _ in selector.select(min(remaining, 0.05)):
                stream, name = key.fileobj, key.data
                if name == 'stdin':
                    try:
                        offset += os.write(stream.fileno(), input_data[offset:offset + 65536])
                    except BrokenPipeError:
                        offset = len(input_data)
                    except BlockingIOError:
                        continue
                    if offset == len(input_data):
                        selector.unregister(stream)
                        stream.close()
                    continue
                try:
                    chunk = os.read(stream.fileno(), min(65536, max_output - total + 1))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                allowed = max_output - total
                output[name].extend(chunk[:allowed])
                total += min(len(chunk), allowed)
                if len(chunk) > allowed:
                    status = 'output_limit'
                    break
            if status != 'completed':
                break
    except KeyboardInterrupt:
        status = 'cancelled'
    except OSError:
        status = 'io_error'
    finally:
        # Also reap descendants if the main CLI exited but left a pipe open.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        selector.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            if not stream.closed:
                stream.close()
        process.wait(timeout=2)
    return ProcessResult(process.returncode, bytes(output['stdout']), bytes(output['stderr']), status)
