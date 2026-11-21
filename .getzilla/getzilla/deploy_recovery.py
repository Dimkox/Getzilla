"""Non-authorizing recovery metadata and a shared, retained kernel lease.

The persistent mkdir barrier excludes legacy mkdir clients. It is never removed.
Unknown legacy/partial initialization requires coordinated inspection, not takeover.
Journal hashes and owner UID are consistency facts, never execution authority.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import math
import os
from pathlib import Path
import re
import stat
import threading
import time
import uuid

from . import fsx
from .component_state import BoundRoot, ComponentStateError
from .deploy_preflight import PreflightError, _public_path, _strict_json

SCHEMA = 'getzilla-deploy-recovery-journal-v1'
MAX_FRAMES = 32
MAX_JOURNAL_BYTES = 65536
MAX_FRAME_BYTES = 2048
MAX_ATTEMPTS = 2
WORK_SECONDS = 10
STAGES = frozenset({'prepared', 'effect_pending', 'applied', 'verified',
                    'rollback_pending', 'rolled_back', 'unknown'})
CODES = frozenset({
    'INPUT_INVALID', 'PATH_UNSAFE', 'ROOT_UNSAFE', 'ROOT_CHANGED', 'MODE_UNSUPPORTED',
    'LEGACY_OWNER_UNKNOWN', 'LEASE_BUSY', 'LEASE_CHANGED', 'FILE_UNSAFE', 'FILE_CHANGED',
    'JOURNAL_INVALID', 'JOURNAL_INCOMPLETE', 'JOURNAL_LIMIT', 'JOURNAL_IO', 'READ_ONLY',
    'INTENT_CONFLICT', 'INVALID_TRANSITION', 'TARGET_CHANGED', 'ATTEMPT_LIMIT',
    'OUTCOME_UNKNOWN', 'CLOCK_UNCERTAIN', 'BUDGET_EXCEEDED', 'INTERNAL_ERROR',
})
_SHA = re.compile(r'[0-9a-f]{64}\Z')
_NONCE = re.compile(r'[0-9a-f]{32}\Z')


class RecoveryError(ValueError):
    def __init__(self, code: str):
        self.code = code if type(code) is str and code in CODES else 'INTERNAL_ERROR'
        super().__init__(self.code)


def canonical(value) -> bytes:
    import json
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(',', ':'), allow_nan=False).encode('ascii')


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def identity(info) -> tuple[int, int, int]:
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)


def _hash(value) -> bool:
    return type(value) is str and _SHA.fullmatch(value) is not None


@dataclass(frozen=True, repr=False)
class Intent:
    operation_sha256: str
    binding_sha256: str
    before_sha256: str
    after_sha256: str

    def to_dict(self):
        values = dict(operation_sha256=self.operation_sha256, binding_sha256=self.binding_sha256,
                      before_sha256=self.before_sha256, after_sha256=self.after_sha256)
        if type(self) is not Intent or not all(_hash(v) for v in values.values()):
            raise RecoveryError('INPUT_INVALID')
        return values


class RecoverySession:
    """Explicit context owner. Closing descriptors never deletes or unlocks a child's OFD."""

    def __init__(self, root: Path, name='.release.lock', *, create=False, writable=False, deadline=None):
        started = time.monotonic()
        if type(started) not in (int, float) or not math.isfinite(started):
            raise RecoveryError('CLOCK_UNCERTAIN')
        self._started, self._deadline = started, started + WORK_SECONDS
        if deadline is not None:
            if type(deadline) not in (int, float) or not math.isfinite(deadline):
                raise RecoveryError('CLOCK_UNCERTAIN')
            self._deadline = min(self._deadline, deadline)
        self._owner = os.getpid(), threading.get_ident()
        self._entered = False
        self._root, self._name = root, name
        self._create, self._writable = create, writable
        self._binding = None
        self._directory = self._lease = self._journal = None
        self._intent = None
        self._records = []
        self._marker = b''
        self._lease_identity = self._journal_identity = None
        self._generation = uuid.uuid4().hex

    def _budget(self):
        now = time.monotonic()
        if type(now) not in (int, float) or not math.isfinite(now) or now < self._started:
            raise RecoveryError('CLOCK_UNCERTAIN')
        if now >= self._deadline:
            raise RecoveryError('BUDGET_EXCEEDED')

    def _regular(self, descriptor, name, *, empty=False):
        opened = os.fstat(descriptor)
        named = fsx.lstat_at(self._directory, name)
        if (not stat.S_ISREG(opened.st_mode) or stat.S_IMODE(opened.st_mode) != 0o600
                or opened.st_uid != os.getuid() or opened.st_nlink != 1
                or (empty and opened.st_size != 0)):
            raise RecoveryError('FILE_UNSAFE')
        if identity(opened) != identity(named) or fsx.is_link(named):
            raise RecoveryError('FILE_CHANGED')
        return opened

    def _open(self, name, *, create=False, readonly=False):
        flags = os.O_RDONLY if readonly else os.O_RDWR
        flags |= os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        if name == 'journal.jsonl' and not readonly:
            flags |= os.O_APPEND
        if create:
            flags |= os.O_CREAT | os.O_EXCL
        descriptor = fsx.open_at(self._directory, name, flags, 0o600)
        try:
            self._regular(descriptor, name, empty=name == 'lease')
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _read(self, descriptor, name, maximum):
        self._budget()
        before = self._regular(descriptor, name)
        if before.st_size > maximum:
            raise RecoveryError('JOURNAL_LIMIT')
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks, size = [], 0
        while True:
            chunk = os.read(descriptor, min(8192, maximum + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > maximum:
                raise RecoveryError('JOURNAL_LIMIT')
        after = self._regular(descriptor, name)
        def fields(info):
            return identity(info), info.st_size, info.st_mtime_ns, info.st_ctime_ns
        if fields(before) != fields(after):
            raise RecoveryError('FILE_CHANGED')
        self._budget()
        return b''.join(chunks)

    def _verify(self):
        if self._owner != (os.getpid(), threading.get_ident()) or self._binding is None:
            raise RecoveryError('LEASE_CHANGED')
        self._budget()
        self._binding.check()
        named = fsx.lstat_at(self._binding.handle, self._name)
        if fsx.is_link(named) or identity(named) != identity(os.fstat(self._directory)):
            raise RecoveryError('ROOT_CHANGED')
        if identity(self._regular(self._lease, 'lease', empty=True)) != self._lease_identity:
            raise RecoveryError('LEASE_CHANGED')
        if identity(self._regular(self._journal, 'journal.jsonl')) != self._journal_identity:
            raise RecoveryError('FILE_CHANGED')
        descriptor = self._open('protocol.json', readonly=True)
        try:
            if self._read(descriptor, 'protocol.json', MAX_FRAME_BYTES) != self._marker:
                raise RecoveryError('FILE_CHANGED')
        finally:
            os.close(descriptor)

    def __enter__(self):
        if self._entered:
            raise RecoveryError('LEASE_CHANGED')
        self._entered = True
        try:
            if self._owner != (os.getpid(), threading.get_ident()):
                raise RecoveryError('LEASE_CHANGED')
            self._budget()
            if fsx.WINDOWS or not hasattr(os, 'O_NOFOLLOW'):
                raise RecoveryError('MODE_UNSUPPORTED')
            if (not isinstance(self._root, Path) or type(self._name) is not str
                    or '/' in self._name or type(self._create) is not bool or type(self._writable) is not bool
                    or self._create and not self._writable):
                raise RecoveryError('INPUT_INVALID')
            _public_path(self._name)
            self._binding = BoundRoot(self._root)
            info = os.fstat(self._binding.handle)
            if info.st_uid != os.getuid() or info.st_mode & 0o022:
                raise RecoveryError('ROOT_UNSAFE')
            created = False
            if self._create:
                try:
                    fsx.mkdir_at(self._binding.handle, self._name, 0o700)
                    created = True
                except FileExistsError:
                    pass
            self._directory = fsx.open_dir_at(self._binding.handle, self._name, flags=os.O_CLOEXEC)
            directory = os.fstat(self._directory)
            if directory.st_uid != os.getuid() or stat.S_IMODE(directory.st_mode) != 0o700:
                raise RecoveryError('FILE_UNSAFE')
            if not created:
                try:
                    fsx.lstat_at(self._directory, 'protocol.json')
                except FileNotFoundError:
                    raise RecoveryError('LEGACY_OWNER_UNKNOWN') from None
            self._lease = self._open('lease', create=created, readonly=not self._writable)
            try:
                fsx.lock_file(self._lease, blocking=False)
            except BlockingIOError:
                raise RecoveryError('LEASE_BUSY') from None
            self._regular(self._lease, 'lease', empty=True)
            self._journal = self._open('journal.jsonl', create=created, readonly=not self._writable)
            if created:
                marker = canonical(dict(schema_version=SCHEMA, nonce=uuid.uuid4().hex,
                                        root_identity=list(identity(info)),
                                        lease_identity=list(identity(os.fstat(self._lease))),
                                        journal_identity=list(identity(os.fstat(self._journal)))))
                descriptor = self._open('protocol.json', create=True)
                try:
                    self._write_all(descriptor, marker)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                os.fsync(self._directory)
                fsx.fsync_dir(self._binding.handle)
            descriptor = self._open('protocol.json', readonly=True)
            try:
                self._marker = self._read(descriptor, 'protocol.json', MAX_FRAME_BYTES)
            finally:
                os.close(descriptor)
            marker = _strict_json(self._marker)
            if (type(marker) is not dict or set(marker) != {'schema_version', 'nonce', 'root_identity',
                                                          'lease_identity', 'journal_identity'}
                    or marker['schema_version'] != SCHEMA or type(marker['nonce']) is not str
                    or _NONCE.fullmatch(marker['nonce']) is None
                    or any(type(marker[k]) is not list or len(marker[k]) != 3
                           or any(type(i) is not int or i < 0 for i in marker[k])
                           for k in ('root_identity', 'lease_identity', 'journal_identity'))
                    or marker['root_identity'] != list(identity(info))
                    or marker['lease_identity'] != list(identity(os.fstat(self._lease)))
                    or marker['journal_identity'] != list(identity(os.fstat(self._journal)))):
                raise RecoveryError('JOURNAL_INVALID')
            self._lease_identity = tuple(marker['lease_identity'])
            self._journal_identity = tuple(marker['journal_identity'])
            self._verify()
            self._records = self._load()
            return self
        except RecoveryError:
            self.close()
            raise
        except (OSError, ComponentStateError, PreflightError, ValueError):
            self.close()
            raise RecoveryError('FILE_UNSAFE') from None
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _write_all(descriptor, content):
        offset = 0
        while offset < len(content):
            count = os.write(descriptor, content[offset:])
            if count <= 0:
                raise RecoveryError('JOURNAL_IO')
            offset += count

    def _load(self):
        raw = self._read(self._journal, 'journal.jsonl', MAX_JOURNAL_BYTES)
        if raw and not raw.endswith(b'\n'):
            raise RecoveryError('JOURNAL_INCOMPLETE')
        lines = raw.splitlines()
        if len(lines) > MAX_FRAMES:
            raise RecoveryError('JOURNAL_LIMIT')
        previous, records = sha256(self._marker), []
        keys = {'seq', 'intent', 'stage', 'current_sha256', 'attempt', 'rollback_attempt', 'generation'}
        for index, line in enumerate(lines, 1):
            if len(line) + 1 > MAX_FRAME_BYTES:
                raise RecoveryError('JOURNAL_LIMIT')
            try:
                envelope = _strict_json(line)
                if type(envelope) is not dict or set(envelope) != {'record', 'previous', 'sha256'}:
                    raise RecoveryError('JOURNAL_INVALID')
                record = envelope['record']
                if (type(record) is not dict or set(record) != keys or type(record['seq']) is not int
                        or record['seq'] != index or type(record['intent']) is not dict
                        or set(record['intent']) != set(Intent('a' * 64, 'b' * 64, 'c' * 64, 'd' * 64).to_dict())
                        or any(not _hash(v) for v in record['intent'].values())
                        or type(record['stage']) is not str or record['stage'] not in STAGES
                        or record['current_sha256'] is not None and not _hash(record['current_sha256'])
                        or any(type(record[k]) is not int or not 0 <= record[k] <= MAX_ATTEMPTS
                               for k in ('attempt', 'rollback_attempt'))
                        or type(record['generation']) is not str or _NONCE.fullmatch(record['generation']) is None
                        or envelope['previous'] != previous
                        or envelope['sha256'] != sha256(canonical([previous, record]))):
                    raise RecoveryError('JOURNAL_INVALID')
                self._validate_step(records[-1] if records else None, record)
            except (PreflightError, KeyError, TypeError, ValueError):
                raise RecoveryError('JOURNAL_INVALID') from None
            previous = envelope['sha256']
            records.append(record)
        return records

    @staticmethod
    def _validate_step(previous, record):
        if previous is None or previous['intent'] != record['intent']:
            if record['stage'] != 'prepared' or record['attempt'] or record['rollback_attempt']:
                raise RecoveryError('INVALID_TRANSITION')
            if previous and previous['stage'] not in {'verified', 'rolled_back'}:
                raise RecoveryError('INTENT_CONFLICT')
            return
        allowed = {
            'prepared': {'effect_pending', 'rollback_pending', 'unknown'},
            'effect_pending': {'effect_pending', 'applied', 'rollback_pending', 'unknown'},
            'applied': {'verified', 'rollback_pending', 'unknown'},
            'verified': {'rollback_pending'},
            'rollback_pending': {'rollback_pending', 'rolled_back', 'unknown'},
            'rolled_back': set(), 'unknown': set(),
        }
        if record['stage'] not in allowed[previous['stage']]:
            raise RecoveryError('INVALID_TRANSITION')
        for field, stage in (('attempt', 'effect_pending'), ('rollback_attempt', 'rollback_pending')):
            expected = previous[field] + int(record['stage'] == stage)
            if record[field] != expected:
                raise RecoveryError('INVALID_TRANSITION')
        intent = record['intent']
        required = {'applied': intent['after_sha256'], 'verified': intent['after_sha256'],
                    'rolled_back': intent['before_sha256']}.get(record['stage'])
        if required is not None and record['current_sha256'] != required:
            raise RecoveryError('TARGET_CHANGED')

    @property
    def records(self):
        return tuple(copy.deepcopy(self._records))

    @property
    def journal_sha256(self):
        self._verify()
        return sha256(self._read(self._journal, 'journal.jsonl', MAX_JOURNAL_BYTES))

    def begin(self, intent):
        if type(intent) is not Intent:
            raise RecoveryError('INPUT_INVALID')
        value = intent.to_dict()
        self._verify()
        matches = [r for r in self._records if r['intent']['operation_sha256'] == intent.operation_sha256]
        if matches and any(r['intent'] != value for r in matches):
            raise RecoveryError('INTENT_CONFLICT')
        if self._records and self._records[-1]['intent'] != value:
            if matches or self._records[-1]['stage'] not in {'verified', 'rolled_back'}:
                raise RecoveryError('INTENT_CONFLICT')
        self._intent = intent
        if not self._records or self._records[-1]['intent'] != value:
            self.advance('prepared', intent.before_sha256)

    def advance(self, stage, current_sha256):
        if not self._writable:
            raise RecoveryError('READ_ONLY')
        if self._intent is None or type(stage) is not str or stage not in STAGES:
            raise RecoveryError('INPUT_INVALID')
        if current_sha256 is not None and not _hash(current_sha256):
            raise RecoveryError('INPUT_INVALID')
        self._verify()
        if self._load() != self._records:
            raise RecoveryError('FILE_CHANGED')
        previous = self._records[-1] if self._records else None
        value = self._intent.to_dict()
        if (previous and previous['intent'] == value and previous['stage'] == stage
                and previous['current_sha256'] == current_sha256
                and (stage not in {'effect_pending', 'rollback_pending'}
                     or previous['generation'] == self._generation)):
            return
        record = dict(seq=len(self._records) + 1, intent=value, stage=stage,
                      current_sha256=current_sha256, generation=self._generation,
                      attempt=(previous['attempt'] if previous and previous['intent'] == value else 0),
                      rollback_attempt=(previous['rollback_attempt'] if previous and previous['intent'] == value else 0))
        for field, pending in (('attempt', 'effect_pending'), ('rollback_attempt', 'rollback_pending')):
            record[field] += int(stage == pending)
            if record[field] > MAX_ATTEMPTS:
                raise RecoveryError('ATTEMPT_LIMIT')
        self._validate_step(previous, record)
        raw = self._read(self._journal, 'journal.jsonl', MAX_JOURNAL_BYTES)
        chain = sha256(self._marker) if not raw else _strict_json(raw.splitlines()[-1])['sha256']
        frame = canonical(dict(record=record, previous=chain, sha256=sha256(canonical([chain, record])))) + b'\n'
        if len(self._records) >= MAX_FRAMES or len(frame) > MAX_FRAME_BYTES or len(raw) + len(frame) > MAX_JOURNAL_BYTES:
            raise RecoveryError('JOURNAL_LIMIT')
        os.lseek(self._journal, 0, os.SEEK_END)
        self._write_all(self._journal, frame)
        os.fsync(self._journal)
        self._verify()
        loaded = self._load()
        if loaded != [*self._records, record]:
            raise RecoveryError('JOURNAL_INVALID')
        self._records = loaded

    def plan(self, current_sha256):
        if self._intent is None or not _hash(current_sha256):
            raise RecoveryError('INPUT_INVALID')
        self._verify()
        stage = self._records[-1]['stage']
        before, after = self._intent.before_sha256, self._intent.after_sha256
        if stage == 'unknown':
            return 'inspect_unknown'
        if current_sha256 not in {before, after}:
            return 'inspect_target'
        return {
            'prepared': 'apply' if current_sha256 == before else 'inspect_target',
            'effect_pending': 'retry_effect' if current_sha256 == before else 'verify_effect',
            'applied': 'verify_effect' if current_sha256 == after else 'inspect_target',
            'verified': 'done' if current_sha256 == after else 'inspect_target',
            'rollback_pending': 'verify_rollback' if current_sha256 == before else 'retry_rollback',
            'rolled_back': 'done_rollback' if current_sha256 == before else 'inspect_target',
        }[stage]

    def inherit_lease(self):
        self._verify()
        return os.dup(self._lease)

    def close(self):
        # No LOCK_UN: a child retaining this OFD must continue to exclude peers.
        for field in ('_journal', '_lease', '_directory'):
            descriptor = getattr(self, field, None)
            if descriptor is not None:
                setattr(self, field, None)
                os.close(descriptor)
        if self._binding is not None:
            binding, self._binding = self._binding, None
            binding.close()

    def __exit__(self, *_args):
        self.close()
