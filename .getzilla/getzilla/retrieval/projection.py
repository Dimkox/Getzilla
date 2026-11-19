"""Private content-free generation pointer, never an authority or source reader.

The trusted native composition supplies an already-open owned0700 directory FD.
This initial POSIX-only metadata projection deliberately cannot restore payloads,
permissions, task handles, embeddings or a live Generation from disk.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
import secrets
import stat
import threading

from .. import fsx
from .budget import RetrievalError
from .contracts import checked_identity, hex_digest


class PrivateProjectionStore:
    def __init__(self, directory_fd):
        self.fd = None
        self._lifecycle = threading.Lock()
        owned = None
        try:
            if os.name != 'posix' or type(directory_fd) is not int:
                raise ValueError
            owned = os.dup(directory_fd)
            self._directory(owned)
            self.fd = owned
        except (OSError, ValueError):
            if owned is not None:
                os.close(owned)
            raise RetrievalError('unsafe_projection') from None

    def __enter__(self):
        with self._lifecycle:
            if self.fd is None:
                raise RetrievalError('projection_closed')
        return self

    def __exit__(self, *args):
        with self._lifecycle:
            if self.fd is not None:
                descriptor, self.fd = self.fd, None
                os.close(descriptor)

    @staticmethod
    def _directory(descriptor):
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise RetrievalError('unsafe_projection')

    @contextmanager
    def _operation(self):
        # Closing the store cannot close or redirect an in-flight operation's
        # duplicate. Every relative operation, including cleanup, uses it.
        with self._lifecycle:
            if self.fd is None:
                raise RetrievalError('projection_closed')
            descriptor = None
            try:
                descriptor = os.dup(self.fd)
                self._directory(descriptor)
            except (OSError, ValueError):
                if descriptor is not None:
                    os.close(descriptor)
                raise RetrievalError('unsafe_projection') from None
        try:
            yield descriptor
        finally:
            os.close(descriptor)

    def _regular(self, descriptor):
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 65536):
            raise RetrievalError('unsafe_projection')

    def read_active(self):
        with self._operation() as directory_fd:
            return self._read_active(directory_fd)

    def _read_active(self, directory_fd):
        try:
            descriptor = os.open('active.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        except FileNotFoundError:
            return None
        except OSError:
            raise RetrievalError('unsafe_projection') from None
        try:
            self._regular(descriptor)
            raw = os.read(descriptor, 65537)
            value = json.loads(raw)
            if (set(value) != {'schema_version', 'generation_id', 'source_snapshot', 'chunks', 'authority'}
                    or type(value['schema_version']) is not int or value['schema_version'] != 1
                    or not hex_digest(value['generation_id'])
                    or type(value['chunks']) is not int or not 0 <= value['chunks'] <= 8192
                    or value['authority'] != 'metadata_only'):
                raise ValueError
            checked_identity(value['source_snapshot'])
            return value
        except (ValueError, TypeError, OSError):
            raise RetrievalError('unsafe_projection') from None
        finally:
            os.close(descriptor)

    def publish(self, generation, *, expected_active):
        with self._operation() as directory_fd:
            return self._publish(generation, expected_active=expected_active, directory_fd=directory_fd)

    def _publish(self, generation, *, expected_active, directory_fd):
        lock, temporary = None, None
        try:
            lock = os.open('publish.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                0o600, dir_fd=directory_fd)
            self._regular(lock)
            fsx.lock_file(lock, blocking=False)
            current = self._read_active(directory_fd)
            if (current['generation_id'] if current else None) != expected_active:
                raise RetrievalError('generation_conflict')
            raw = (json.dumps({'schema_version': 1, 'generation_id': generation.identity,
                'source_snapshot': dict(generation.source_snapshot), 'chunks': len(generation.chunks),
                'authority': 'metadata_only'}, sort_keys=True) + '\n').encode()
            if len(raw) > 65536:
                raise RetrievalError('projection_bytes_exceeded')
            temporary = 'pending-' + secrets.token_hex(16)
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600, dir_fd=directory_fd)
            try:
                self._regular(descriptor)
                if os.write(descriptor, raw) != len(raw):
                    raise OSError
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, 'active.json', src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            temporary = None
            os.fsync(directory_fd)
        except BlockingIOError:
            raise RetrievalError('projection_busy') from None
        except OSError:
            raise RetrievalError('unsafe_projection') from None
        finally:
            if temporary is not None:
                os.unlink(temporary, dir_fd=directory_fd)
            if lock is not None:
                fsx.unlock_file(lock)
                os.close(lock)
