"""Owned bounded Docker CLI transport. No public execution or resource issuer.

The study supervisor supplies its genuine operation ref, held executable and
fixed commands. This transport never accepts a shell, follows caller Docker
contexts, pulls an image, or treats Docker metadata as a resource capability.
"""
from __future__ import annotations

import os
import selectors
import subprocess
import time
import tempfile
import stat

from .budget import RetrievalError

MAX_STDOUT = 1048576
MAX_STDERR = 65536


def _spawn(root, binary, arguments):
    from .. import fsx
    return fsx.owned_popen(
        [binary.path, '--config', binary.config_directory,
         '--host', 'unix:///var/run/docker.sock', *arguments],
        executable=f'/proc/self/fd/{binary.fd}', pass_fds=(binary.fd,), cwd=root,
        env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'},
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class DockerBinary:
    def __init__(self, projection):
        from ..managed_execution import Binary
        self.path = projection.docker_executable
        self._binary = Binary(projection.root, self.path, projection.docker_sha256)
        self.fd = self._binary.fd
        self._temporary = None
        try:
            parent = projection.root / '.getzilla/runtime'
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
                raise RetrievalError('study_docker_config_unavailable')
            self._temporary = tempfile.TemporaryDirectory(prefix='study-docker-client-', dir=parent)
            self.config_directory = self._temporary.name
            os.chmod(self.config_directory, 0o700)
        except BaseException:
            self.close()
            raise

    def close(self):
        self._binary.close()
        if self._temporary is not None:
            self._temporary.cleanup()
            self._temporary = None


class OwnedCommand:
    """Hold unreaped leader/pidfd until process-group cleanup is complete."""
    def __init__(self, root, binary, arguments):
        self.process = None
        self.pidfd = None
        self.closed = False
        self.stdout, self.stderr = bytearray(), bytearray()
        self._selector = selectors.DefaultSelector()
        try:
            self.process = _spawn(root, binary, arguments)
            self.pidfd = os.pidfd_open(self.process.pid)
            for name in ('stdin', 'stdout', 'stderr'):
                os.set_blocking(getattr(self.process, name).fileno(), False)
            self._selector.register(self.process.stdout, selectors.EVENT_READ, 'stdout')
            self._selector.register(self.process.stderr, selectors.EVENT_READ, 'stderr')
        except BaseException:
            self.close()
            raise

    def done(self):
        if self.closed or self.pidfd is None:
            return True
        return os.waitid(os.P_PIDFD, self.pidfd,
                         os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None

    def drain(self, seconds):
        for key, _ in self._selector.select(max(0, min(.05, seconds))):
            raw = os.read(key.fileobj.fileno(), 65536)
            if not raw:
                self._selector.unregister(key.fileobj)
                continue
            target = self.stdout if key.data == 'stdout' else self.stderr
            cap = MAX_STDOUT if key.data == 'stdout' else MAX_STDERR
            if len(target) + len(raw) > cap:
                raise RetrievalError('study_worker_output_exceeded')
            target.extend(raw)

    def write(self, raw, deadline):
        if self.closed or type(raw) is not bytes or len(raw) > MAX_STDOUT:
            raise RetrievalError('study_worker_channel_unavailable')
        position = 0
        while position < len(raw):
            if self.done() or time.monotonic() >= deadline:
                raise RetrievalError('study_worker_deadline')
            try:
                count = os.write(self.process.stdin.fileno(), raw[position:])
                if count <= 0:
                    raise RetrievalError('study_worker_channel_unavailable')
                position += count
            except BlockingIOError:
                self.drain(min(.01, deadline - time.monotonic()))

    def read_line(self, deadline, *, limit=1048576):
        while True:
            end = self.stdout.find(b'\n')
            if end >= 0:
                if end > limit:
                    raise RetrievalError('study_worker_output_exceeded')
                raw = bytes(self.stdout[:end])
                del self.stdout[:end + 1]
                return raw
            if len(self.stdout) > limit:
                raise RetrievalError('study_worker_output_exceeded')
            if self.done() or time.monotonic() >= deadline:
                raise RetrievalError('study_worker_deadline')
            self.drain(deadline - time.monotonic())

    def finish(self, deadline):
        while not self.done() or self._selector.get_map():
            if time.monotonic() >= deadline:
                raise RetrievalError('study_docker_deadline')
            self.drain(deadline - time.monotonic())
        raw = bytes(self.stdout)
        self.close()
        if not self.confirmed or self.process.returncode != 0:
            raise RetrievalError('study_docker_unavailable')
        return raw

    def close(self):
        if self.closed:
            return getattr(self, 'confirmed', False)
        self.closed = True
        self.confirmed = True
        if self.process is not None:
            from ..managed_execution import _cleanup
            self.confirmed = _cleanup(self.process)
            for name in ('stdin', 'stdout', 'stderr'):
                stream = getattr(self.process, name, None)
                if stream is not None:
                    stream.close()
        self._selector.close()
        if self.pidfd is not None:
            os.close(self.pidfd)
            self.pidfd = None
        return self.confirmed
