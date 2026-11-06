"""Best-effort last-reported Core pytest slots, never execution authority."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

from . import fsx

MAX_WORKERS = 64
MAX_SLOT_BYTES = 2048
_FIELDS = {'version', 'nonce', 'worker', 'sequence', 'state', 'path', 'key'}


def _node_identity(nodeid: str) -> tuple[str | None, str | None]:
    # Parameters are arbitrary values. Strip them before validation or hashing.
    canonical = nodeid.partition('[')[0].replace('\\', '/')
    parts = canonical.split('::')
    path = parts[0]
    if (len(canonical) > 512 or not 2 <= len(parts) <= 3 or len(path) > 256
            or not re.fullmatch(r'tests/[A-Za-z0-9_./-]+\.py', path)
            or any(part in {'', '.', '..'} for part in path.split('/'))
            or any(not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', part) for part in parts[1:])):
        return None, None
    return path, hashlib.sha256(canonical.encode('ascii')).hexdigest()


def _private_directory(path: Path):
    before = path.lstat()
    if (fsx.is_link(before) or not stat.S_ISDIR(before.st_mode)
            or (os.name != 'nt' and (before.st_mode & 0o077
                                    or before.st_uid != os.getuid()))):
        raise OSError('unavailable progress directory')
    handle = fsx.open_dir(path)
    try:
        after = fsx.fstat_dir(handle)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise OSError('changed progress directory')
    except OSError:
        fsx.close_dir(handle)
        raise
    return handle


def _regular(info: os.stat_result) -> bool:
    return (stat.S_ISREG(info.st_mode) and not fsx.is_link(info) and info.st_nlink == 1
            and (os.name == 'nt' or (info.st_uid == os.getuid() and not info.st_mode & 0o077)))


class _WorkerProgress:
    def __init__(self, directory: Path, nonce: str, worker: int):
        self.handle = _private_directory(directory)
        self.nonce, self.worker, self.sequence = nonce, worker, 0
        self.slot = f'worker-{worker}.json'
        self.temporary = f'worker-{worker}.tmp'
        self.identity: tuple[int, int] | None = None
        self.disabled = False

    def _publish(self, nodeid: str, state: str) -> None:
        if self.disabled:
            return
        self.sequence += 1
        path, key = _node_identity(nodeid)
        document = {'version': 1, 'nonce': self.nonce, 'worker': self.worker,
                    'sequence': self.sequence, 'state': state, 'path': path, 'key': key}
        content = json.dumps(document, separators=(',', ':'), sort_keys=True).encode('ascii')
        try:
            if len(content) > MAX_SLOT_BYTES:
                raise OSError('unavailable progress record')
            descriptor = fsx.open_at(self.handle, self.temporary,
                                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | fsx.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'wb') as output:
                output.write(content)
            fsx.replace_at(self.handle, self.temporary, self.handle, self.slot)
            info = fsx.lstat_at(self.handle, self.slot)
            self.identity = (info.st_dev, info.st_ino)
        except OSError:
            self.disabled = True
            # If possible invalidate only our previous record. A remaining tmp
            # also makes the parent refuse this worker's observation.
            try:
                info = fsx.lstat_at(self.handle, self.slot)
                if self.identity == (info.st_dev, info.st_ino):
                    fsx.unlink_at(self.handle, self.slot)
            except OSError:
                pass

    def pytest_runtest_logstart(self, nodeid, location):
        self._publish(nodeid, 'active')

    def pytest_runtest_logfinish(self, nodeid, location):
        self._publish(nodeid, 'idle')

    def pytest_unconfigure(self, config):
        try:
            fsx.close_dir(self.handle)
        except OSError:
            pass
        else:
            self.handle = None


def pytest_addoption(parser):
    group = parser.getgroup('getzilla-core-progress')
    for name in ('dir', 'nonce', 'workers'):
        group.addoption('--getzilla-progress-' + name, default=None)


def pytest_configure(config):
    directory = config.getoption('getzilla_progress_dir')
    nonce = config.getoption('getzilla_progress_nonce')
    workers = config.getoption('getzilla_progress_workers')
    if (not isinstance(directory, str) or not Path(directory).is_absolute()
            or not isinstance(nonce, str) or not re.fullmatch('[0-9a-f]{32}', nonce)
            or not isinstance(workers, str) or not re.fullmatch('[1-9][0-9]?', workers)
            or not 1 <= int(workers) <= MAX_WORKERS):
        raise ValueError('invalid closed Core progress options')
    worker = getattr(config, 'workerinput', {}).get('workerid')
    if not isinstance(worker, str) or not re.fullmatch(r'gw(?:0|[1-9][0-9]?)', worker):
        return
    ordinal = int(worker[2:])
    if ordinal >= int(workers):
        return
    try:
        writer = _WorkerProgress(Path(directory), nonce, ordinal)
    except OSError:
        return  # Observation IO must never change the primary test verdict.
    config.pluginmanager.register(writer, 'getzilla-core-progress-slot')


def _read_slot(handle, ordinal: int, nonce: str) -> dict[str, object]:
    # An incomplete replacement means this worker's prior record is unknown.
    try:
        fsx.lstat_at(handle, f'worker-{ordinal}.tmp')
    except FileNotFoundError:
        pass
    else:
        raise ValueError('incomplete progress slot')
    name = f'worker-{ordinal}.json'
    before = fsx.lstat_at(handle, name)
    if not _regular(before) or before.st_size > MAX_SLOT_BYTES:
        raise ValueError('unavailable progress slot')
    descriptor = fsx.open_at(handle, name, os.O_RDONLY | fsx.O_NOFOLLOW | fsx.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        after = os.fstat(source.fileno())
        if not _regular(after) or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise ValueError('changed progress slot')
        content = source.read(MAX_SLOT_BYTES + 1)
    if len(content) > MAX_SLOT_BYTES:
        raise ValueError('oversized progress slot')
    pairs = json.loads(content, object_pairs_hook=list)
    if (not isinstance(pairs, list) or len(pairs) != len(_FIELDS)
            or any(not isinstance(pair, tuple) for pair in pairs)):
        raise ValueError('invalid progress object')
    document = dict(pairs)
    if (set(document) != _FIELDS or document['version'] != 1 or type(document['version']) is not int
            or document['nonce'] != nonce or type(document['worker']) is not int
            or document['worker'] != ordinal or type(document['sequence']) is not int
            or not 1 <= document['sequence'] <= 2**63 - 1 or document['state'] not in {'active', 'idle'}):
        raise ValueError('invalid progress identity')
    path, key = document['path'], document['key']
    if not ((path is None and key is None) or (
            isinstance(path, str) and len(path) <= 256 and re.fullmatch(r'tests/[A-Za-z0-9_./-]+\.py', path)
            and not any(part in {'', '.', '..'} for part in path.split('/'))
            and isinstance(key, str) and re.fullmatch('[0-9a-f]{64}', key))):
        raise ValueError('invalid progress source key')
    return {name: document[name] for name in ('worker', 'sequence', 'state', 'path', 'key')}


def read_progress(directory: Path, nonce: str, workers: int) -> dict[str, object]:
    report: dict[str, object] = {'status': 'not_supported', 'selected_workers': workers,
                                 'observed_workers': 0, 'omitted_workers': workers, 'slots': []}
    if type(workers) is not int or not 1 <= workers <= MAX_WORKERS:
        return report
    report['status'] = 'unavailable'
    handle = None
    slots = []
    try:
        handle = _private_directory(directory)
        for ordinal in range(workers):
            try:
                slots.append(_read_slot(handle, ordinal, nonce))
            except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
                continue
    except OSError:
        pass
    finally:
        fsx.close_dir(handle)
    report.update(status='observed' if len(slots) == workers else 'partial' if slots else 'unavailable',
                  observed_workers=len(slots), omitted_workers=workers - len(slots), slots=slots)
    return report
