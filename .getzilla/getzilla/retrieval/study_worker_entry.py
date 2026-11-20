"""Fixed stdlib-only container waiter. Host owns operation/resource admission.

This private pipe is data/control, not a transport for opaque native references.
No package/model loader runs until its owning supervisor releases a stage on the
held nonce/sequence channel after checking actual current admission and readback.
"""
from __future__ import annotations

import json
import os
import re
import sys

MAX_FRAME = 1048576


def _inside_readback(state=None):
    if '/worker' not in sys.path:
        sys.path.insert(0, '/worker')
    from getzilla.retrieval.study_waiter_kernel import read_inside_kernel
    roots = {}
    for path in ('/model', '/software', '/worker'):
        info = os.stat(path, follow_symlinks=False)
        roots[path] = [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid]
    return {'pid': os.getpid(), 'uid': os.getuid(), 'gid': os.getgid(),
            'python': list(sys.version_info[:3]), 'cache_tag': sys.implementation.cache_tag,
            'machine': os.uname().machine, 'byteorder': sys.byteorder,
            'bits': 64 if sys.maxsize > 2**32 else 32, 'roots': roots,
            'kernel': read_inside_kernel(),
            'native_child': (state['native'].identity() if state and 'native' in state else None),
            'gpu_devices': sorted(name for name in os.listdir('/dev')
                                  if name.startswith(('nvidia', 'dri')) or name == 'kfd')}


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate')
        result[key] = value
    return result


def _dispatch(request, state):
    # PID1 never imports native packages. Its one owned child remains separately
    # killable even when a native extension blocks the child's Python runtime.
    if '/worker' not in sys.path:
        sys.path.insert(0, '/worker')
    from getzilla.retrieval.study_waiter_process import NativeProcess
    if 'native' not in state:
        state['native'] = NativeProcess(state['nonce'], state['deadline'])
    result = state['native'].request(request, state['incoming'])
    if result.get('status') != 'ok' or set(result) != {'sequence', 'status', 'result'}:
        raise ValueError('native unavailable')
    return result['result']


def serve(nonce, incoming, outgoing, *, deadline=None):
    import time
    if '/worker' not in sys.path:
        sys.path.insert(0, '/worker')
    from getzilla.retrieval.study_waiter_process import FrameInput, heartbeat
    deadline = time.monotonic() + 14400 if deadline is None else deadline
    reader = FrameInput(incoming)
    state = {'nonce': nonce, 'deadline': deadline, 'incoming': reader}
    def emit(value):
        raw = json.dumps(value, allow_nan=False, separators=(',', ':')).encode() + b'\n'
        if len(raw) > MAX_FRAME:
            raise ValueError('frame exceeded')
        outgoing.write(raw)
        outgoing.flush()
    try:
        emit({'phase': 'waiting', 'nonce': nonce, 'pid': os.getpid(),
              'inside': _inside_readback()})
        expected, last_heartbeat, readback_counter = 1, time.monotonic(), 0
        while True:
            request = reader.next(min(deadline, last_heartbeat + 5))
            if heartbeat(request, nonce, expected - 1):
                last_heartbeat = time.monotonic()
                continue
            if (type(request) is dict and set(request) == {'nonce', 'resource_readback'}
                    and request['nonce'] == nonce and type(request['resource_readback']) is int
                    and request['resource_readback'] == readback_counter + 1):
                readback_counter += 1
                emit({'phase': 'resource-readback', 'nonce': nonce, 'counter': readback_counter,
                      'facts': _inside_readback(state)})
                last_heartbeat = time.monotonic()
                continue
            if (type(request) is not dict or request.get('nonce') != nonce
                    or type(request.get('sequence')) is not int or request['sequence'] != expected
                    or type(request.get('op')) is not str):
                return 125
            expected += 1
            last_heartbeat = time.monotonic()
            if request['op'] == 'stop' and set(request) == {'nonce', 'sequence', 'op'}:
                emit({'sequence': request['sequence'], 'status': 'stopped'})
                return 0
            result = _dispatch(request, state)
            emit({'sequence': request['sequence'], 'status': 'ok', 'result': result})
    except Exception:
        # No adapter error, source snippet, path, prompt or credential is emitted.
        try:
            emit({'status': 'unavailable', 'reason': 'owned_worker_unavailable'})
        except Exception:
            pass
        return 125
    finally:
        if 'native' in state:
            state['native'].close()


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    import math
    import time
    if (len(argv) != 4 or argv[0] != '--nonce' or not re.fullmatch('[0-9a-f]{64}', argv[1])
            or argv[2] != '--deadline'
            or os.getpid() != 1 or os.getuid() != 65532 or os.getgid() != 65532
            or sys.stdin.isatty() or sys.stdout.isatty()):
        return 125
    try:
        deadline = float(argv[3])
        if not math.isfinite(deadline) or not time.monotonic() < deadline <= time.monotonic() + 14400:
            return 125
    except ValueError:
        return 125
    return serve(argv[1], sys.stdin.buffer, sys.stdout.buffer, deadline=deadline)


if __name__ == '__main__':
    raise SystemExit(main())
