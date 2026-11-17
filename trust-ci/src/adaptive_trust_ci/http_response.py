"""Finite HTTP response body reads shared by the GitHub and human CLI transports."""
from __future__ import annotations

import socket
import threading
import time
import urllib.error

MAX_RESPONSE_BYTES = 1024 * 1024
RESPONSE_SECONDS = 30


class ResponseLimitError(OSError):
    pass


def read_response(response, *, deadline: float, maximum: int = MAX_RESPONSE_BYTES,
                  clock=time.monotonic) -> bytes:
    """Bound bytes before decode; interrupt even slow HTTP chunk framing at the deadline.

    urllib's HTTPError wraps the same HTTPResponse. A stream without the standard
    socket/read1 capability is refused before reading, never treated as bounded.
    The caller owns closing the response. This does not qualify DNS/open latency.
    """
    stream = response.fp if isinstance(response, urllib.error.HTTPError) else response
    sock = getattr(getattr(getattr(stream, 'fp', None), 'raw', None), '_sock', None)
    if (not callable(getattr(stream, 'read1', None)) or
            not callable(getattr(sock, 'settimeout', None)) or
            not callable(getattr(sock, 'shutdown', None))):
        raise ResponseLimitError('response deadline capability unavailable')
    if maximum <= 0:
        raise ValueError('response byte budget must be positive')

    def remaining():
        value = deadline - clock()
        if value <= 0:
            raise ResponseLimitError('response elapsed budget exceeded')
        return value

    def interrupt():
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    timer = threading.Timer(remaining(), interrupt)
    timer.daemon = True
    timer.start()
    try:
        blocks, length = [], 0
        while True:
            sock.settimeout(remaining())
            requested = min(65536, maximum - length + 1)
            block = stream.read1(requested)
            remaining()  # Reject EOF or partial data returned after interruption.
            if not isinstance(block, bytes) or len(block) > requested:
                raise ResponseLimitError('invalid bounded response stream')
            length += len(block)
            if length > maximum:
                raise ResponseLimitError('response byte budget exceeded')
            if not block:
                return b''.join(blocks)
            blocks.append(block)
    finally:
        timer.cancel()
        timer.join()


# The fixed worker owns DNS, connect, header parsing and body reads. Its parent
# can reap it even when urllib's per-socket timeout cannot bound those stages.
_MAX_INPUT = 2 * MAX_RESPONSE_BYTES
_MAX_OUTPUT = 2 * MAX_RESPONSE_BYTES


def exchange(request, *, opener=None, deadline, clock=time.monotonic):
    """Worker-only exchange; preserves an HTTP error even when its body is refused."""
    import urllib.request

    open_request = opener or urllib.request.urlopen
    remaining = deadline - clock()
    if remaining <= 0:
        raise ResponseLimitError('request elapsed budget exceeded; effect unknown')
    try:
        with open_request(request, timeout=remaining) as response:
            return response.status, read_response(response, deadline=deadline, clock=clock)
    except urllib.error.HTTPError as exc:
        with exc:
            try:
                return exc.code, read_response(exc, deadline=deadline, clock=clock)
            except OSError as read_exc:
                return exc.code, f'response body unavailable: {read_exc}'.encode('utf-8')[:4096]


def _run_owned(command, payload: bytes, *, deadline: float) -> bytes:
    """One owned request process; finite input/output, no inherited terminal or retry."""
    import subprocess
    import tempfile

    if len(payload) > _MAX_INPUT:
        raise ResponseLimitError('request IPC byte budget exceeded')
    if deadline - time.monotonic() <= 0.2:
        raise ResponseLimitError('request elapsed budget exceeded; effect unknown')
    proc = None
    with tempfile.TemporaryFile() as output:
        try:
            proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=output,
                                    stderr=subprocess.DEVNULL, close_fds=True)
            remaining = deadline - time.monotonic() - 0.2  # reserve kill/reap time
            if remaining <= 0:
                raise ResponseLimitError('request elapsed budget exceeded; effect unknown')
            try:
                proc.communicate(payload, timeout=remaining)
            except subprocess.TimeoutExpired as exc:
                raise ResponseLimitError('request elapsed budget exceeded; effect unknown; no retry') from exc
            if proc.returncode != 0:
                raise ResponseLimitError('request worker failed; effect unknown; no retry')
            if time.monotonic() >= deadline:
                raise ResponseLimitError('request elapsed budget exceeded; effect unknown')
            output.seek(0)
            result = output.read(_MAX_OUTPUT + 1)
            if len(result) > _MAX_OUTPUT:
                raise ResponseLimitError('response IPC byte budget exceeded')
            return result
        finally:
            if proc is not None:
                if proc.poll() is None:
                    proc.kill()
                proc.communicate()  # always reap, close stdin, and release owned FDs


def request_bytes(request, *, deadline=None):
    """Bound the entire request, including acquisition, with one fixed child."""
    import base64
    import json
    import sys
    from pathlib import Path

    deadline = time.monotonic() + RESPONSE_SECONDS if deadline is None else deadline
    payload = json.dumps({'method': request.get_method(), 'url': request.full_url,
                          'headers': dict(request.header_items()),
                          'body': base64.b64encode(request.data).decode('ascii')
                          if request.data is not None else None,
                          'seconds': min(RESPONSE_SECONDS, deadline - time.monotonic())}).encode('utf-8')
    command = [sys.executable, str(Path(__file__).resolve())]
    raw = _run_owned(command, payload, deadline=deadline)
    try:
        value = json.loads(raw)
        if (type(value) is not dict or set(value) != {'status', 'body'} or
                type(value['status']) is not int or not 100 <= value['status'] <= 599):
            raise ValueError('invalid response envelope')
        body = base64.b64decode(value['body'], validate=True)
        if len(body) > MAX_RESPONSE_BYTES:
            raise ValueError('response byte budget exceeded')
        if time.monotonic() >= deadline:
            raise ResponseLimitError('request elapsed budget exceeded; effect unknown')
        return value['status'], body
    except (ValueError, TypeError, KeyError) as exc:
        raise ResponseLimitError('invalid bounded response IPC; effect unknown') from exc


def _worker(*, exchange_request=exchange):
    import base64
    import json
    import sys
    import urllib.request

    # No authority, key files, project state or authentication policy is loaded.
    raw = sys.stdin.buffer.read(_MAX_INPUT + 1)
    if len(raw) > _MAX_INPUT:
        return 1
    value = json.loads(raw)
    seconds = value['seconds']
    if not isinstance(seconds, (int, float)) or not 0 < seconds <= RESPONSE_SECONDS:
        return 1
    deadline = time.monotonic() + seconds
    request = urllib.request.Request(value['url'], method=value['method'], headers=value['headers'],
                                     data=base64.b64decode(value['body'], validate=True)
                                     if value['body'] is not None else None)
    status, body = exchange_request(request, deadline=deadline)
    output = json.dumps({'status': status, 'body': base64.b64encode(body).decode('ascii')}).encode('utf-8')
    if len(output) > _MAX_OUTPUT or time.monotonic() >= deadline:
        return 1
    sys.stdout.buffer.write(output)
    return 0


if __name__ == '__main__':
    raise SystemExit(_worker())
