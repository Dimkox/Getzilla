"""Best-effort last-reported Core pytest slots, never execution authority."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

from . import fsx

MAX_WORKERS = 64
MAX_SLOT_BYTES = 2048
MAX_FAILURE_BYTES = 2048
MAX_FAILURE_EVENTS = 4
MAX_PHASE_BYTES = 1024
_PHASES = ('configured', 'collection_finished', 'first_test_start')
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


class _PhaseWitness:
    """At most three actor-local observations on one exclusive held inode."""
    def __init__(self, handle, nonce, worker):
        self.handle, self.nonce, self.worker = handle, nonce, worker
        self.name = ('controller' if worker is None else f'worker-{worker}') + '.phases.jsonl'
        self.fd = None
        self.identity = None
        self.written = 0
        self.marks = []
        self.started = self.previous = None
        self.disabled = False

    def _append(self, row):
        content = json.dumps(row, separators=(',', ':'), sort_keys=True).encode('ascii') + b'\n'
        held, named = os.fstat(self.fd), fsx.lstat_at(self.handle, self.name)
        if (not _regular(held) or not _regular(named)
                or (held.st_dev, held.st_ino) != self.identity
                or (named.st_dev, named.st_ino) != self.identity
                or held.st_size != self.written or named.st_size != self.written
                or self.written + len(content) > MAX_PHASE_BYTES):
            raise OSError('unavailable phase witness')
        if os.write(self.fd, content) != len(content):
            raise OSError('incomplete phase witness')
        self.written += len(content)

    def mark(self, phase):
        if self.disabled or phase in self.marks:
            return
        try:
            if len(self.marks) >= 3 or phase != _PHASES[len(self.marks)]:
                raise ValueError('unordered phase witness')
            current = time.monotonic_ns()
            if (type(current) is not int or not 0 <= current <= 2**63 - 1
                    or self.previous is not None and current < self.previous):
                raise ValueError('invalid phase clock')
            if self.fd is None:
                self.started = current
                self.fd = fsx.open_at(self.handle, self.name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | fsx.O_NOFOLLOW, 0o600)
                info = os.fstat(self.fd)
                self.identity = (info.st_dev, info.st_ino)
                self._append({'version': 1, 'kind': 'core-phase-witness', 'nonce': self.nonce, 'worker': self.worker})
            self._append({'phase': phase, 'elapsed_ns': current - self.started})
            self.marks.append(phase)
            self.previous = current
        except Exception:
            self.disabled = True
            self.close()

    def close(self):
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None


class _WorkerProgress:
    def __init__(self, directory: Path, nonce: str, worker: int):
        self.handle = _private_directory(directory)
        self.nonce, self.worker, self.sequence = nonce, worker, 0
        self.slot = f'worker-{worker}.json'
        self.temporary = f'worker-{worker}.tmp'
        self.identity: tuple[int, int] | None = None
        self.disabled = False
        self.failure_fd = None
        self.failure_identity = None
        self.failure_written = 0
        self.failure_sequence = 0
        self.failure_rows = 0
        self.failure_dropped = False
        self.failure_overflow = False
        self.failure_disabled = False
        self.phases = None

    def configure_phases(self):
        self.phases = _PhaseWitness(self.handle, self.nonce, self.worker)
        self.phases.mark('configured')

    def pytest_collection_finish(self, session):
        if self.phases is not None:
            self.phases.mark('collection_finished')

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

    def _failure_write(self, record, reserve):
        content = json.dumps(record, separators=(',', ':'), ensure_ascii=True).encode('ascii') + b'\n'
        info = os.fstat(self.failure_fd)
        if (not _regular(info) or (info.st_dev, info.st_ino) != self.failure_identity
                or info.st_size != self.failure_written
                or self.failure_written + len(content) + reserve > MAX_FAILURE_BYTES):
            raise OSError('unavailable failure stream')
        # One bounded append to the exclusively-created, held inode. No named
        # replacement, reopen, truncate or unlink can clobber a substituted name.
        if os.write(self.failure_fd, content) != len(content):
            raise OSError('incomplete failure append')
        self.failure_written += len(content)

    def _failure_append(self, record):
        if self.failure_fd is None:
            self.failure_fd = fsx.open_at(self.handle, f'worker-{self.worker}.failures.jsonl',
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | fsx.O_NOFOLLOW, 0o600)
            info = os.fstat(self.failure_fd)
            self.failure_identity = (info.st_dev, info.st_ino)
            self._failure_write({'version': 1, 'kind': 'core-failed-reports', 'nonce': self.nonce,
                                 'worker': self.worker}, 128)
        reserve = (64 if not self.failure_dropped else 0) + 64 if record['kind'] == 'failure' else (
            64 if record['kind'] == 'dropped' else 0)
        self._failure_write(record, reserve)

    def pytest_runtest_logreport(self, report):
        if self.failure_disabled or self.failure_overflow:
            return
        try:
            if report.failed is not True:
                return
            if self.failure_sequence >= 2**63 - 1:
                raise ValueError('failure serial exhausted')
            self.failure_sequence += 1
            serial = self.failure_sequence
            if self.failure_rows >= MAX_FAILURE_EVENTS:
                self._failure_append({'kind': 'overflow', 'ordinal': serial})
                self.failure_overflow = True
                return
            phase, node = report.when, report.nodeid
            path, key = _node_identity(node) if type(node) is str else (None, None)
            if phase not in ('setup', 'call', 'teardown') or path is None:
                if not self.failure_dropped:
                    self._failure_append({'kind': 'dropped', 'ordinal': serial})
                    self.failure_dropped = True
                return
            self._failure_append({'kind': 'failure', 'ordinal': serial, 'phase': phase, 'path': path, 'key': key})
            self.failure_rows += 1
        except Exception:
            # This optional diagnostic must never replace a primary test error.
            # Keep any complete prefix, including a possible torn final row.
            self.failure_disabled = True
            if self.failure_fd is not None:
                try:
                    os.close(self.failure_fd)
                except OSError:
                    pass
                self.failure_fd = None

    def pytest_runtest_logstart(self, nodeid, location):
        if self.phases is not None:
            self.phases.mark('first_test_start')
        self._publish(nodeid, 'active')

    def pytest_runtest_logfinish(self, nodeid, location):
        self._publish(nodeid, 'idle')

    def pytest_unconfigure(self, config):
        if self.phases is not None:
            self.phases.close()
        if self.failure_fd is not None:
            try:
                os.close(self.failure_fd)
            except OSError:
                pass
            self.failure_fd = None
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
    if not hasattr(config, 'workerinput'):
        handle = None
        try:
            handle = _private_directory(Path(directory))
            phase = _PhaseWitness(handle, nonce, None)
            phase.mark('configured')
            phase.close()
        except OSError:
            pass
        finally:
            fsx.close_dir(handle)
        return
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
    writer.configure_phases()


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


def _failure_json(content):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate failure field')
            result[key] = value
        return result
    value = json.loads(content.decode('utf-8', 'strict'), object_pairs_hook=pairs)
    if type(value) is not dict:
        raise ValueError('invalid failure record')
    return value


def _read_failure_prefix(handle, ordinal, nonce):
    name = f'worker-{ordinal}.failures.jsonl'
    before = fsx.lstat_at(handle, name)
    if not _regular(before) or before.st_size > MAX_FAILURE_BYTES:
        raise ValueError('unavailable failure stream')
    descriptor = fsx.open_at(handle, name, os.O_RDONLY | fsx.O_NOFOLLOW | fsx.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        held = os.fstat(source.fileno())
        if not _regular(held) or (before.st_dev, before.st_ino) != (held.st_dev, held.st_ino):
            raise ValueError('changed failure stream')
        content = source.read(MAX_FAILURE_BYTES + 1)
        after = os.fstat(source.fileno())
    named = fsx.lstat_at(handle, name)
    def identity(info):
        return info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_nlink
    if (not _regular(named) or identity(before) != identity(after) or identity(after) != identity(named)
            or len(content) != after.st_size or len(content) > MAX_FAILURE_BYTES):
        raise ValueError('changed failure stream')
    lines = content.split(b'\n')
    tail = lines.pop()
    if not lines:
        raise ValueError('incomplete failure header')
    header = _failure_json(lines.pop(0))
    if (set(header) != {'version', 'kind', 'nonce', 'worker'}
            or type(header['version']) is not int or header['version'] != 1
            or header['kind'] != 'core-failed-reports' or type(header['nonce']) is not str
            or not re.fullmatch('[0-9a-f]{32}', header['nonce']) or header['nonce'] != nonce
            or type(header['worker']) is not int or header['worker'] != ordinal or len(lines) > 6):
        raise ValueError('invalid failure header')
    events, serial, dropped, overflow = [], 0, False, False
    for line in lines:
        row = _failure_json(line)
        kind, number = row.get('kind'), row.get('ordinal')
        if overflow or type(number) is not int or not serial < number <= 2**63 - 1:
            raise ValueError('invalid failure serial')
        serial = number
        if kind == 'failure':
            if (set(row) != {'kind', 'ordinal', 'phase', 'path', 'key'} or len(events) >= MAX_FAILURE_EVENTS
                    or row['phase'] not in ('setup', 'call', 'teardown')
                    or type(row['path']) is not str or len(row['path']) > 256
                    or not re.fullmatch(r'tests/[A-Za-z0-9_./-]+\.py', row['path'])
                    or any(part in {'', '.', '..'} for part in row['path'].split('/'))
                    or type(row['key']) is not str or not re.fullmatch('[0-9a-f]{64}', row['key'])):
                raise ValueError('invalid failure source')
            events.append({key: row[key] for key in ('ordinal', 'phase', 'path', 'key')})
        elif kind == 'dropped' and set(row) == {'kind', 'ordinal'} and not dropped:
            dropped = True
        elif kind == 'overflow' and set(row) == {'kind', 'ordinal'} and len(events) == MAX_FAILURE_EVENTS:
            overflow = True
        else:
            raise ValueError('invalid failure fact')
    if not serial:
        raise ValueError('failure header has no observation')
    return {'worker': ordinal, 'sequence': serial, 'overflow': overflow, 'dropped': dropped,
            'partial_tail': bool(tail), 'events': events}


def phase_witness_details(value, workers):
    """Closed revalidation at both the file reader and report consumer."""
    unknown = {'version': 1, 'status': 'unavailable', 'observation': 'REPORTED_ACTOR_PHASES_ONLY', 'actors': []}
    if (type(workers) is not int or not 1 <= workers <= MAX_WORKERS or type(value) is not dict
            or set(value) != {'version', 'actors'} or type(value['version']) is not int or value['version'] != 1
            or type(value['actors']) is not list or len(value['actors']) > workers + 1):
        return unknown
    actors, seen = [], set()
    for row in value['actors']:
        if type(row) is not dict or set(row) != {'worker', 'elapsed_ns'}:
            return unknown
        worker, elapsed = row['worker'], row['elapsed_ns']
        if (worker is not None and (type(worker) is not int or not 0 <= worker < workers)
                or worker in seen or type(elapsed) is not dict or set(elapsed) != set(_PHASES)):
            return unknown
        values = [elapsed[name] for name in _PHASES]
        if (type(values[0]) is not int or values[0] != 0
                or any(number is not None and (type(number) is not int or not 0 <= number <= 2**63 - 1) for number in values)
                or values[1] is None and values[2] is not None
                or values[1] is not None and values[2] is not None and values[2] < values[1]
                or worker is None and values[1:] != [None, None]):
            return unknown
        seen.add(worker)
        actors.append({'worker': worker, 'elapsed_ns': dict(zip(_PHASES, values))})
    return {**unknown, 'status': 'reported' if actors else 'unavailable', 'actors': actors}


def _read_phase(handle, worker, nonce):
    name = ('controller' if worker is None else f'worker-{worker}') + '.phases.jsonl'
    before = fsx.lstat_at(handle, name)
    if not _regular(before) or before.st_size > MAX_PHASE_BYTES:
        raise ValueError('unavailable phase witness')
    fd = fsx.open_at(handle, name, os.O_RDONLY | fsx.O_NOFOLLOW | fsx.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        held = os.fstat(source.fileno())
        if not _regular(held) or (held.st_dev, held.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError('changed phase witness')
        content = source.read(MAX_PHASE_BYTES + 1)
        after = os.fstat(source.fileno())
    named = fsx.lstat_at(handle, name)
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_uid,
                info.st_nlink, info.st_mtime_ns, info.st_ctime_ns)
    if (not _regular(named) or identity(before) != identity(after) or identity(after) != identity(named)
            or len(content) != after.st_size or len(content) > MAX_PHASE_BYTES or not content.endswith(b'\n')):
        raise ValueError('changed phase witness')
    lines = content.splitlines()
    if not 2 <= len(lines) <= 4:
        raise ValueError('invalid phase prefix')
    header = _failure_json(lines[0])
    if (set(header) != {'version', 'kind', 'nonce', 'worker'} or type(header['version']) is not int
            or header['version'] != 1 or header['kind'] != 'core-phase-witness' or header['nonce'] != nonce
            or type(header['nonce']) is not str or not re.fullmatch('[0-9a-f]{32}', header['nonce'])
            or type(header['worker']) is not type(worker) or header['worker'] != worker):
        raise ValueError('invalid phase identity')
    elapsed = dict.fromkeys(_PHASES)
    for index, line in enumerate(lines[1:]):
        row = _failure_json(line)
        if set(row) != {'phase', 'elapsed_ns'} or row['phase'] != _PHASES[index]:
            raise ValueError('invalid phase order')
        elapsed[row['phase']] = row['elapsed_ns']
    result = {'worker': worker, 'elapsed_ns': elapsed}
    if phase_witness_details({'version': 1, 'actors': [result]}, MAX_WORKERS)['status'] != 'reported':
        raise ValueError('invalid phase values')
    return result


def read_progress(directory: Path, nonce: str, workers: int) -> dict[str, object]:
    report: dict[str, object] = {'status': 'not_supported', 'selected_workers': workers,
                                 'observed_workers': 0, 'omitted_workers': workers, 'slots': [],
                                 'failure_events': {'version': 1, 'status': 'not_supported', 'workers': []}}
    if type(workers) is not int or not 1 <= workers <= MAX_WORKERS:
        return report
    report['status'] = 'unavailable'
    handle = None
    slots, failures, phases = [], [], []
    try:
        handle = _private_directory(directory)
        for actor in [None, *range(workers)]:
            try:
                phases.append(_read_phase(handle, actor, nonce))
            except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
                pass
        for ordinal in range(workers):
            try:
                slots.append(_read_slot(handle, ordinal, nonce))
            except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
                pass
            try:
                failures.append(_read_failure_prefix(handle, ordinal, nonce))
            except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
                pass
    except OSError:
        pass
    finally:
        fsx.close_dir(handle)
    report.update(status='observed' if len(slots) == workers else 'partial' if slots else 'unavailable',
                  observed_workers=len(slots), omitted_workers=workers - len(slots), slots=slots)
    complete = len(failures) == workers and not any(
        row['overflow'] or row['dropped'] or row['partial_tail'] for row in failures)
    report['failure_events'] = {'version': 1, 'status': 'observed' if complete else 'partial' if failures else 'unavailable',
                                'workers': failures}
    if phases:
        report['phase_witness'] = {'version': 1, 'actors': phases}
    return report
