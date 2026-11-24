"""Bounded, clone-local shadow observations. Disk content is never admission evidence."""
from __future__ import annotations

from contextlib import contextmanager
import json
import math
import os
from pathlib import Path
import re
import stat
import time
import uuid

MAX_ENTRY_BYTES = 256 * 1024
MAX_ENTRIES = 128
MAX_TOTAL_BYTES = 32 * 1024 * 1024
TTL_SECONDS = 24 * 60 * 60
KEY_FIELDS = frozenset({'repository_id', 'local_account_id', 'commit_sha', 'base_sha', 'package', 'tool_id',
    'tool_version', 'sdk_identity', 'input_digest', 'config_digest', 'dependency_digest', 'policy_digest',
    'requested_scope', 'scope', 'files', 'argv', 'executor_identity', 'implementation_digest', 'platform',
    'sandbox', 'effective_cpus'})
OBSERVATION_FIELDS = frozenset({'reported_status', 'summary', 'diagnostics', 'claimed_source_evidence_digest'})


def cache_key(binding: dict) -> str:
    from .core import digest
    if not isinstance(binding, dict) or set(binding) != KEY_FIELDS or any(value is None for value in binding.values()):
        raise ValueError('cache requires every current execution binding')
    return digest({'cache_schema': 1, 'adapter_abi': 1, **binding})


def _key(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r'[a-f0-9]{64}', value):
        raise ValueError('invalid cache key')
    return value + '.json'


def _regular(info) -> None:
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > MAX_ENTRY_BYTES):
        raise ValueError('unsafe cache entry')


def _observation(value: dict) -> dict:
    from .core import safe_path
    if not isinstance(value, dict) or set(value) != OBSERVATION_FIELDS:
        raise ValueError('cache cannot contain authority fields')
    if value['reported_status'] not in ('PASS', 'FAIL'):
        raise ValueError('cache only records completed lint observations')
    if not isinstance(value['summary'], str) or len(value['summary']) > 2048:
        raise ValueError('invalid cached summary')
    _key(value['claimed_source_evidence_digest'])
    diagnostics = value['diagnostics']
    if not isinstance(diagnostics, list) or len(diagnostics) > 1000:
        raise ValueError('invalid cached diagnostics')
    for item in diagnostics:
        if not isinstance(item, dict) or set(item) != {'severity', 'code', 'message', 'path', 'line', 'column'}:
            raise ValueError('invalid cached diagnostic fields')
        if item['severity'] not in ('error', 'warning', 'info'):
            raise ValueError('invalid cached diagnostic severity')
        for name, limit in (('code', 256), ('message', 8192)):
            if not isinstance(item[name], str) or len(item[name]) > limit:
                raise ValueError('invalid cached diagnostic text')
        if item['path'] is not None:
            safe_path(item['path'])
            if len(item['path']) > 1024:
                raise ValueError('cached path exceeds bound')
        for name in ('line', 'column'):
            if item[name] is not None and (type(item[name]) is not int or not 1 <= item[name] <= 2**31):
                raise ValueError('invalid cached diagnostic position')
    return {name: value[name] for name in OBSERVATION_FIELDS}


class ShadowCache:
    def __init__(self, root: Path, *, clock=time.time):
        self.root = root
        self.clock = clock

    @contextmanager
    def _directory(self, *, create: bool):
        # Descriptor traversal prevents symlink swaps from redirecting writes.
        # The lock is nonblocking; contention disables reuse for this invocation.
        import fcntl
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for index, part in enumerate(('.getzilla', 'runtime', 'lqg', 'cache-v1')):
                if create:
                    try:
                        os.mkdir(part, 0o700, dir_fd=fd)
                    except FileExistsError:
                        pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
                info = os.fstat(fd)
                if info.st_uid != os.getuid() or (index >= 2 and stat.S_IMODE(info.st_mode) != 0o700):
                    raise ValueError('cache directory is not private to this account')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield fd
        finally:
            os.close(fd)

    def read(self, key: str) -> tuple[dict | None, str]:
        from .core import _closed, digest
        try:
            name = _key(key)
            with self._directory(create=False) as directory:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                with os.fdopen(fd, 'rb') as source:
                    before = os.fstat(source.fileno())
                    _regular(before)
                    payload = source.read(MAX_ENTRY_BYTES + 1)
                    after = os.fstat(source.fileno())
                    if (len(payload) > MAX_ENTRY_BYTES or len(payload) != before.st_size
                            or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                        raise ValueError('cache entry changed during read')
            entry = json.loads(payload, object_pairs_hook=_closed)
            fields = OBSERVATION_FIELDS | {'schema_version', 'key_digest', 'created_at', 'payload_digest'}
            if not isinstance(entry, dict) or set(entry) != fields or type(entry['schema_version']) is not int or entry['schema_version'] != 1:
                raise ValueError('invalid cache schema')
            created = entry['created_at']
            if type(created) not in (int, float) or not math.isfinite(created) or not 0 <= self.clock() - created <= TTL_SECONDS:
                raise ValueError('expired or future cache observation')
            if entry['key_digest'] != key or entry['payload_digest'] != digest({k: v for k, v in entry.items() if k != 'payload_digest'}):
                raise ValueError('cache key or payload mismatch')
            return _observation({name: entry[name] for name in OBSERVATION_FIELDS}), 'hit-unverified'
        except FileNotFoundError:
            return None, 'miss'
        except (OSError, ValueError, TypeError, ImportError, AttributeError, UnicodeError):
            return None, 'miss-invalid'

    def write(self, key: str, observation: dict) -> str:
        from .core import digest
        temporary = None
        try:
            name = _key(key)
            entry = {'schema_version': 1, 'key_digest': key, 'created_at': self.clock(), **_observation(observation)}
            entry['payload_digest'] = digest(entry)
            payload = json.dumps(entry, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
            if len(payload) > min(MAX_ENTRY_BYTES, MAX_TOTAL_BYTES):
                raise ValueError('cache observation exceeds bound')
            with self._directory(create=True) as directory:
                try:
                    entries = []
                    with os.scandir(directory) as scan:
                        for item in scan:
                            if len(entries) >= MAX_ENTRIES or not re.fullmatch(r'[a-f0-9]{64}\.json', item.name):
                                raise ValueError('cache inventory exceeds bound or contains foreign files')
                            info = item.stat(follow_symlinks=False)
                            _regular(info)
                            entries.append((info.st_mtime_ns, item.name, info.st_size))
                    remaining = [item for item in sorted(entries) if item[1] != name]
                    total = sum(item[2] for item in remaining)
                    while remaining and (len(remaining) >= MAX_ENTRIES or total + len(payload) > MAX_TOTAL_BYTES):
                        _, old, size = remaining.pop(0)
                        os.unlink(old, dir_fd=directory)
                        total -= size
                    temporary = '.pending-' + uuid.uuid4().hex
                    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                    with os.fdopen(fd, 'wb') as writer:
                        writer.write(payload)
                        writer.flush()
                    os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
                    temporary = None
                finally:
                    if temporary:
                        os.unlink(temporary, dir_fd=directory)
            return 'written'
        except (OSError, ValueError, TypeError, ImportError, AttributeError, UnicodeError):
            return 'write-error'
