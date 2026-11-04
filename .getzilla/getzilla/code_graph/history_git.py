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
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        except OSError:
            raise HistoryReadError('GIT_UNAVAILABLE') from None
        self.commands += 1
        output = bytearray()
        done, overflow = threading.Event(), threading.Event()
        read_error: list[BaseException] = []
        limit = self.remaining

        def collect():
            try:
                while True:
                    chunk = process.stdout.read(min(65536, limit - len(output) + 1))
                    if not chunk:
                        return
                    output.extend(chunk)
                    if len(output) > limit:
                        overflow.set()
                        return
            except (OSError, ValueError) as error:
                read_error.append(error)
            finally:
                done.set()

        reader = threading.Thread(target=collect, name='getzilla-history-git', daemon=True)
        reader_started = False
        reason = None
        try:
            try:
                reader.start()
                reader_started = True
            except RuntimeError:
                raise HistoryReadError('LOCAL_RESOURCE_UNAVAILABLE') from None
            while not (done.is_set() and process.poll() is not None):
                if overflow.is_set():
                    reason = 'BYTE_BUDGET'
                    break
                if time.monotonic() >= self.deadline:
                    reason = 'TIME_BUDGET'
                    break
                done.wait(0.005)
            if overflow.is_set():
                reason = 'BYTE_BUDGET'
        finally:
            # Shared owned-tree cleanup also runs for KeyboardInterrupt/SystemExit.
            try:
                _stop(process)
            finally:
                if reader_started:
                    reader.join(timeout=2)
                process.stdout.close()
        if reader.is_alive() or read_error:
            raise HistoryReadError('GIT_READ_INCOMPLETE')
        self.bytes_read += len(output)
        self.remaining -= len(output)
        self.peak_buffer_bytes = max(self.peak_buffer_bytes, len(output))
        if reason:
            raise HistoryReadError(reason)
        if process.returncode not in allowed_codes:
            # Git diagnostics can contain private paths/config. Never publish them.
            raise HistoryReadError('GIT_READ_FAILED')
        return process.returncode, bytes(output)
