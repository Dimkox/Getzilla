"""Stdlib-only PID1 owns one native child; native GIL cannot block its timers.

The host owns stage authority. Heartbeats are private-channel liveness only and
never change an absolute global, source or stage deadline. On any fault PID1
exits after cleanup; kernel PID-namespace teardown kills escaped descendants.
"""
from __future__ import annotations

import json
import hashlib
import math
import os
import select
import signal
import subprocess
import sys
import time

MAX_FRAME = 1048576
HEARTBEAT_SECONDS = 5
STAGE_SECONDS = {'native-import': 180, 'load-tokenizer': 180, 'windows': 2,
                 'load-model': 180, 'encode': 2, 'score': 2, 'release': 2}


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate')
        result[key] = value
    return result


def decode(raw):
    def reject(value):
        raise ValueError('nonfinite')
    return json.loads(raw, object_pairs_hook=_pairs, parse_constant=reject)


class FrameInput:
    def __init__(self, stream):
        self.stream, self.buffer = stream, bytearray()
        try:
            self.fd = stream.fileno()
            os.set_blocking(self.fd, False)
        except (OSError, ValueError):
            self.fd = None  # Inert byte-stream fixtures; production main uses real stdin.

    def pending(self):
        return b'\n' in self.buffer

    def next(self, deadline):
        while True:
            end = self.buffer.find(b'\n')
            if end >= 0:
                if end > MAX_FRAME:
                    raise ValueError('frame exceeded')
                raw = bytes(self.buffer[:end])
                del self.buffer[:end + 1]
                return decode(raw)
            if len(self.buffer) > MAX_FRAME or time.monotonic() >= deadline:
                raise ValueError('channel deadline')
            if self.fd is None:
                raw = self.stream.readline(MAX_FRAME + 1)
            else:
                if not select.select([self.fd], [], [],
                                     max(0, min(.25, deadline - time.monotonic())))[0]:
                    continue
                raw = os.read(self.fd, 65536)
            if not raw:
                raise ValueError('owner channel closed')
            self.buffer.extend(raw)


def heartbeat(request, nonce, sequence):
    return (type(request) is dict and set(request) == {'nonce', 'heartbeat'}
            and request['nonce'] == nonce and type(request['heartbeat']) is int
            and request['heartbeat'] == sequence)


def stage_deadline(request, *, global_deadline, now=None):
    now = time.monotonic() if now is None else now
    supplied = request.get('absolute_deadline')
    if (request.get('op') not in STAGE_SECONDS or type(supplied) not in {int, float}
            or not math.isfinite(supplied)):
        raise ValueError('stage unavailable')
    return min(global_deadline, supplied, now + STAGE_SECONDS[request['op']])


class NativeProcess:
    def __init__(self, nonce, global_deadline):
        self.nonce, self.global_deadline = nonce, global_deadline
        self.process, self.pidfd, self.closed = None, None, False
        self.output, self.error = bytearray(), bytearray()
        self.last_heartbeat = time.monotonic()
        self.identity_binding = None

    def _start(self):
        command = [sys.executable, '-I', '-S', '-B',
                   '/worker/getzilla/retrieval/study_native_entry.py', '--nonce', self.nonce]
        self.process = subprocess.Popen(command, start_new_session=True, close_fds=True,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
                 'OMP_NUM_THREADS': '1', 'OPENBLAS_NUM_THREADS': '1',
                 'MKL_NUM_THREADS': '1', 'NUMEXPR_NUM_THREADS': '1',
                 'VECLIB_MAXIMUM_THREADS': '1', 'RAYON_NUM_THREADS': '1',
                 'CUDA_VISIBLE_DEVICES': '-1', 'NVIDIA_VISIBLE_DEVICES': 'void'})
        self.pidfd = os.pidfd_open(self.process.pid)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            os.set_blocking(stream.fileno(), False)

    def _alive(self):
        return not select.select([self.pidfd], [], [], 0)[0]

    def identity(self):
        if self.process is None:
            return None
        if not self._alive():
            raise ValueError('native child exited')
        def text(path):
            with open(path, 'rb') as stream:
                raw = stream.read(65537)
            if len(raw) > 65536:
                raise ValueError('native identity unavailable')
            return raw
        pid = self.process.pid
        raw = text(f'/proc/{pid}/stat')
        binding = {'pid': pid, 'start_ticks': raw.rsplit(b')', 1)[1].split()[19].decode('ascii'),
            'uid': os.stat(f'/proc/{pid}').st_uid,
            'cgroup': text(f'/proc/{pid}/cgroup').decode('ascii'),
            'argv_sha256': hashlib.sha256(text(f'/proc/{pid}/cmdline')).hexdigest(),
            'namespaces': {name: os.readlink(f'/proc/{pid}/ns/{name}')
                           for name in ('net', 'mnt', 'pid', 'cgroup', 'time', 'user')}}
        if self.identity_binding is not None and binding != self.identity_binding:
            raise ValueError('native identity changed')
        return binding

    def _pump(self, incoming, sequence, deadline):
        limit = min(deadline, self.global_deadline, self.last_heartbeat + HEARTBEAT_SECONDS)
        if time.monotonic() >= limit or not self._alive():
            raise ValueError('native deadline')
        sources = [self.process.stdout.fileno(), self.process.stderr.fileno()]
        if incoming.fd is not None:
            sources.append(incoming.fd)
        if incoming.pending():
            ready = [incoming.fd]
        else:
            ready = select.select(sources, [], [], min(.05, limit - time.monotonic()))[0]
        for descriptor in ready:
            if descriptor == incoming.fd:
                request = incoming.next(min(limit, time.monotonic() + .05))
                if not heartbeat(request, self.nonce, sequence):
                    raise ValueError('unexpected owner frame')
                self.last_heartbeat = time.monotonic()
                continue
            raw = os.read(descriptor, 65536)
            if not raw:
                raise ValueError('native channel closed')
            target = self.output if descriptor == self.process.stdout.fileno() else self.error
            maximum = MAX_FRAME if target is self.output else 65536
            if len(target) + len(raw) > maximum:
                raise ValueError('native capture exceeded')
            target.extend(raw)

    def _line(self, incoming, sequence, deadline):
        while b'\n' not in self.output:
            self._pump(incoming, sequence, deadline)
        end = self.output.index(b'\n')
        raw = bytes(self.output[:end])
        del self.output[:end + 1]
        return decode(raw)

    def _write(self, raw, incoming, sequence, deadline):
        offset = 0
        while offset < len(raw):
            if time.monotonic() >= deadline:
                raise ValueError('native deadline')
            try:
                count = os.write(self.process.stdin.fileno(), raw[offset:])
                if count <= 0:
                    raise ValueError('native channel closed')
                offset += count
            except BlockingIOError:
                self._pump(incoming, sequence, deadline)

    def request(self, request, incoming):
        deadline = stage_deadline(request, global_deadline=self.global_deadline)
        sequence = request['sequence']
        self.last_heartbeat = time.monotonic()
        try:
            if time.monotonic() >= deadline:
                raise ValueError('native deadline')
            if self.process is None:
                self._start()
                greeting = self._line(incoming, sequence, deadline)
                if (greeting != {'phase': 'native-waiting', 'nonce': self.nonce,
                                 'pid': self.process.pid}):
                    raise ValueError('native identity changed')
                # Same UID, executable, cgroup and namespaces are checked by
                # this stdlib parent before the first native import release.
                pid = self.process.pid
                for name in ('net', 'mnt', 'pid', 'cgroup', 'time'):
                    if os.readlink(f'/proc/{pid}/ns/{name}') != os.readlink(f'/proc/self/ns/{name}'):
                        raise ValueError('native namespace changed')
                with open(f'/proc/{pid}/cgroup', encoding='ascii') as child_group, \
                        open('/proc/self/cgroup', encoding='ascii') as parent_group:
                    same_group = child_group.read(65537) == parent_group.read(65537)
                if not same_group or os.stat(f'/proc/{pid}').st_uid != os.getuid():
                    raise ValueError('native cgroup changed')
                self.identity_binding = self.identity()
                self._write(b'R\n', incoming, sequence, deadline)
            raw = json.dumps(request, allow_nan=False, separators=(',', ':')).encode() + b'\n'
            if len(raw) > MAX_FRAME:
                raise ValueError('native frame exceeded')
            self._write(raw, incoming, sequence, deadline)
            result = self._line(incoming, sequence, deadline)
            if type(result) is not dict or result.get('sequence') != sequence:
                raise ValueError('native response changed')
            return result
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.process is not None:
            # Never poll/reap before killpg: keep the owned group leader reserved.
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass  # PID1 exits next; namespace teardown kills the whole tree.
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                stream.close()
        if self.pidfd is not None:
            os.close(self.pidfd)
            self.pidfd = None
