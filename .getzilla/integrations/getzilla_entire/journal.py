"""Durable, fail-closed request deduplication; ambiguous writes are never replayed."""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from contextlib import contextmanager
from pathlib import Path

from getzilla import fsx
from .client import EntireError, decode_json


class RequestJournal:
    def __init__(self, root: Path):
        self.root = root

    @contextmanager
    def directory(self):
        handles = []
        try:
            handles.append(fsx.open_dir(self.root, flags=fsx.O_NOFOLLOW))
            for name in ('.getzilla', 'runtime', 'entire-requests'):
                try:
                    fsx.mkdir_at(handles[-1], name, 0o700)
                    fsx.fsync_dir(handles[-1])
                except FileExistsError:
                    pass
                handles.append(fsx.open_dir_at(handles[-1], name, flags=fsx.O_NOFOLLOW))
            yield handles[-1]
        except OSError as exc:
            raise EntireError('unsafe_journal', 'cannot safely open the Entire request journal') from exc
        finally:
            for handle in reversed(handles):
                fsx.close_dir(handle)

    @staticmethod
    def binding(request_id: str, intent: dict) -> tuple[str, str]:
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{7,95}', request_id):
            raise EntireError('request_id', 'request ID must contain 8–96 letters, digits, underscores or hyphens')
        payload = json.dumps(intent, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
        return request_id + '.json', hashlib.sha256(payload).hexdigest()

    @staticmethod
    def read(directory, name: str) -> dict:
        fd = fsx.open_at(directory, name, os.O_RDONLY | fsx.O_NOFOLLOW | fsx.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 65536:
                raise EntireError('unsafe_journal', 'Entire request record is unsafe or oversized')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                data = stream.read(65537)
            if len(data) > 65536:
                raise EntireError('unsafe_journal', 'Entire request record is oversized')
            return decode_json(data)
        finally:
            os.close(fd)

    @staticmethod
    def write(directory, name: str, value: dict) -> None:
        payload = json.dumps(value, sort_keys=True, ensure_ascii=True).encode() + b'\n'
        if len(payload) > 65536:
            raise EntireError('unsafe_journal', 'Entire result exceeds journal limits')
        fd = fsx.open_at(directory, name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | fsx.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
        fsx.fsync_dir(directory)

    def begin(self, request_id: str, intent: dict) -> dict | None:
        name, digest = self.binding(request_id, intent)
        with self.directory() as directory:
            try:
                self.write(directory, name, {'schema_version': 1, 'digest': digest, 'status': 'started'})
                return None
            except FileExistsError:
                previous = self.read(directory, name)
            if previous.get('schema_version') != 1 or previous.get('digest') != digest:
                raise EntireError('request_conflict', 'request ID is already bound to a different operation')
            if previous.get('status') == 'succeeded' and isinstance(previous.get('result'), dict):
                return previous['result']
            raise EntireError('reconciliation_required', 'previous request may have reached Entire; reconcile its outcome before any new write')

    def finish(self, request_id: str, intent: dict, status: str, result: dict) -> None:
        if status not in {'succeeded', 'unknown'}:
            raise ValueError('unsupported journal outcome')
        name, digest = self.binding(request_id, intent)
        with self.directory() as directory:
            previous = self.read(directory, name)
            if previous.get('digest') != digest or previous.get('status') != 'started':
                raise EntireError('request_conflict', 'request journal changed during the operation')
            temporary = f'.{secrets.token_hex(16)}.tmp'
            self.write(directory, temporary, {'schema_version': 1, 'digest': digest, 'status': status, 'result': result})
            try:
                fsx.replace_at(directory, temporary, directory, name)
                fsx.fsync_dir(directory)
            finally:
                try:
                    fsx.unlink_at(directory, temporary)
                except FileNotFoundError:
                    pass
