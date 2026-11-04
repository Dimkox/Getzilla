"""Bounded byte-preserving local Git reads; no shell, network, hooks or project code."""
from __future__ import annotations

import subprocess
import threading
import time
from pathlib import Path

from .. import fsx
from ..project_ingestion import _env
from ..python_test_runner import _stop


class HistoryReadError(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class GitReader:
    def __init__(self, root: Path, *, max_bytes: int, max_seconds: float):
        self.root = root
        self.remaining = max_bytes
        self.deadline = time.monotonic() + max_seconds
        self.bytes_read = 0
        self.peak_buffer_bytes = 0
        self.commands = 0
        self.git_dir: Path | None = None

    def read(self, *args: str, allowed_codes: tuple[int, ...] = (0,), bare: bool = False) -> tuple[int, bytes]:
        if self.remaining <= 0:
            raise HistoryReadError('BYTE_BUDGET')
        if time.monotonic() >= self.deadline:
            raise HistoryReadError('TIME_BUDGET')
        command = ['git', '--no-optional-locks', '--no-pager', '-c', 'core.fsmonitor=false',
                   '-c', 'core.untrackedCache=false', '-c', 'protocol.allow=never',
                   '-c', 'core.hooksPath=', '-c', 'diff.external=',
                   *(['--git-dir=' + str(self.git_dir), '--bare', '--work-tree=' + str(self.git_dir)] if bare and self.git_dir is not None
                     else ['-C', str(self.root)]), *args]
        if bare and self.git_dir is None:
            raise HistoryReadError('GIT_READ_INCOMPLETE')
        try:
            process = fsx.owned_popen(command, cwd=self.git_dir if bare else self.root, env=_env(), stdin=subprocess.DEVNULL,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError:
            raise HistoryReadError('GIT_UNAVAILABLE') from None
        self.commands += 1
        output = bytearray()
        overflow = threading.Event()
        done = [threading.Event(), threading.Event()]
        captured = [0]
        capture_lock = threading.Lock()
        read_error: list[BaseException] = []
        limit = self.remaining

        def collect(stream, keep, completed):
            try:
                while True:
                    chunk = stream.read(min(65536, limit + 1))
                    if not chunk:
                        return
                    with capture_lock:
                        allowance = max(0, limit + 1 - captured[0])
                        if keep:
                            output.extend(chunk[:allowance])
                        captured[0] += len(chunk)
                        if captured[0] > limit:
                            overflow.set()
                            return
            except (OSError, ValueError) as error:
                read_error.append(error)
            finally:
                completed.set()

        readers = []
        reason = None
        try:
            try:
                for stream, keep, completed in ((process.stdout, True, done[0]), (process.stderr, False, done[1])):
                    reader = threading.Thread(target=collect, args=(stream, keep, completed),
                                              name='getzilla-history-git', daemon=True)
                    readers.append(reader)
                    reader.start()
            except RuntimeError:
                raise HistoryReadError('LOCAL_RESOURCE_UNAVAILABLE') from None
            while not (all(item.is_set() for item in done) and process.poll() is not None):
                if overflow.is_set():
                    reason = 'BYTE_BUDGET'
                    break
                if time.monotonic() >= self.deadline:
                    reason = 'TIME_BUDGET'
                    break
                overflow.wait(0.005)
            if overflow.is_set():
                reason = 'BYTE_BUDGET'
        finally:
            # Shared owned-tree cleanup also runs for KeyboardInterrupt/SystemExit.
            try:
                _stop(process)
            finally:
                for reader in readers:
                    if reader.ident is not None:
                        reader.join(timeout=2)
                process.stdout.close()
                process.stderr.close()
        if any(reader.is_alive() for reader in readers) or read_error:
            raise HistoryReadError('GIT_READ_INCOMPLETE')
        self.bytes_read += captured[0]
        self.remaining -= captured[0]
        self.peak_buffer_bytes = max(self.peak_buffer_bytes, len(output))
        if reason:
            raise HistoryReadError(reason)
        if process.returncode not in allowed_codes:
            # Git diagnostics can contain private paths/config. Never publish them.
            raise HistoryReadError('GIT_READ_FAILED')
        return process.returncode, bytes(output)
