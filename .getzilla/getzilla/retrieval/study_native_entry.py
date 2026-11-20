"""Fixed child bootstrap; imports native code only after its stdlib parent gate."""
from __future__ import annotations

import json
import os
import re
import sys


def _released():
    # Read exactly two bytes, never prefetch a following command into a Python
    # buffered reader that the nonblocking framed transport cannot observe.
    return os.read(0, 1) == b'R' and os.read(0, 1) == b'\n'


def _dispatch(request, state):
    if '/worker' not in sys.path:
        sys.path.insert(0, '/worker')
    if '/software' not in sys.path:
        sys.path.append('/software')
    from getzilla.retrieval.study_worker_dispatch import dispatch
    return dispatch(request, state)


def serve(nonce, incoming, outgoing):
    if '/worker' not in sys.path:
        sys.path.insert(0, '/worker')
    from getzilla.retrieval.study_waiter_process import FrameInput
    reader, expected, state = FrameInput(incoming), 1, {}
    try:
        while True:
            # PID1 independently enforces the real absolute deadline and kills
            # this child. This read cannot grant or extend that deadline.
            request = reader.next(float('inf'))
            if (type(request) is not dict or request.get('nonce') != nonce
                    or type(request.get('sequence')) is not int or request['sequence'] != expected):
                return 125
            expected += 1
            result = _dispatch(request, state)
            raw = json.dumps({'sequence': request['sequence'], 'status': 'ok', 'result': result},
                             allow_nan=False, separators=(',', ':')).encode() + b'\n'
            if len(raw) > 1048576:
                return 125
            outgoing.write(raw)
            outgoing.flush()
    except Exception:
        return 125


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if (len(argv) != 2 or argv[0] != '--nonce' or not re.fullmatch('[0-9a-f]{64}', argv[1])
            or os.getpid() <= 1 or os.getppid() != 1
            or os.getuid() != 65532 or os.getgid() != 65532):
        return 125
    raw = json.dumps({'phase': 'native-waiting', 'nonce': argv[1], 'pid': os.getpid()},
                     separators=(',', ':')).encode() + b'\n'
    os.write(1, raw)
    if not _released():
        return 125
    return serve(argv[1], sys.stdin.buffer, sys.stdout.buffer)


if __name__ == '__main__':
    raise SystemExit(main())
