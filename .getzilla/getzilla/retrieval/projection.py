"""Private content-free generation pointer, never an authority or source reader.

The trusted native composition supplies an already-open owned0700 directory FD.
This initial POSIX-only metadata projection deliberately cannot restore payloads,
permissions, task handles, embeddings or a live Generation from disk.
"""
from __future__ import annotations

import json
import os
import secrets
import stat

from .. import fsx
from .budget import RetrievalError
from .contracts import checked_identity, hex_digest


class PrivateProjectionStore:
    def __init__(self, directory_fd):
        self.fd = None
        try:
            if os.name != 'posix' or type(directory_fd) is not int:
                raise ValueError
            info = os.fstat(directory_fd)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError
            self.fd = os.dup(directory_fd)
        except (OSError, ValueError):
            raise RetrievalError('unsafe_projection') from None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def _regular(self, descriptor):
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 65536):
            raise RetrievalError('unsafe_projection')

    def read_active(self):
        try:
            descriptor = os.open('active.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
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
        lock, temporary = None, None
        try:
            lock = os.open('publish.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                0o600, dir_fd=self.fd)
            self._regular(lock)
            fsx.lock_file(lock, blocking=False)
            current = self.read_active()
            if (current['generation_id'] if current else None) != expected_active:
                raise RetrievalError('generation_conflict')
            raw = (json.dumps({'schema_version': 1, 'generation_id': generation.identity,
                'source_snapshot': dict(generation.source_snapshot), 'chunks': len(generation.chunks),
                'authority': 'metadata_only'}, sort_keys=True) + '\n').encode()
            if len(raw) > 65536:
                raise RetrievalError('projection_bytes_exceeded')
            temporary = 'pending-' + secrets.token_hex(16)
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600, dir_fd=self.fd)
            try:
                self._regular(descriptor)
                if os.write(descriptor, raw) != len(raw):
                    raise OSError
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, 'active.json', src_dir_fd=self.fd, dst_dir_fd=self.fd)
            temporary = None
            os.fsync(self.fd)
        except BlockingIOError:
            raise RetrievalError('projection_busy') from None
        except OSError:
            raise RetrievalError('unsafe_projection') from None
        finally:
            if temporary is not None:
                os.unlink(temporary, dir_fd=self.fd)
            if lock is not None:
                fsx.unlock_file(lock)
                os.close(lock)
