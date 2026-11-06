"""Offline snapshot storage with exact bytes, coverage and a 72-hour clock.

The caller owns acquisition. This module has no network client. Content hashes
and unsigned local acquisition metadata bind data; they do not establish an
independent publisher identity or grant merge authority. OSV archives are
validated here. Other registered feeds also require their source-specific
evaluator to validate their body schema, counts and publication dates.

Each source has one atomically replaced manifest. It names an immutable object
by digest, never by an input path. The legacy all.zip export is not authoritative.

Snapshot I/O requires POSIX directory descriptors and a physical, non-symlink
database path. The updater/runner must exclusively control this directory tree;
directories must belong to the current UID or root and forbid group/other writes
(only sticky ancestors, such as /tmp, may be shared).
Descriptors cannot stop another process with the same UID or root privilege
from renaming an already opened directory. Every operation checks held directory
and regular-file identities before/after use. Windows path/lstat fallbacks are
not qualified for this boundary: I/O fails explicitly, while pure validation
and structural no-source results remain available.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import math
import os
import re
import stat
import uuid
import zipfile
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from . import fsx

MAX_AGE_SECONDS = 259200
MAX_PAYLOAD_BYTES = 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 65536
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 4 * 1024 * 1024 * 1024
DESCRIPTOR_IO_AVAILABLE = (
    os.name == 'posix'
    and all(hasattr(os, name) for name in ('O_DIRECTORY', 'O_NOFOLLOW', 'O_CLOEXEC', 'O_NONBLOCK'))
    and all(function in getattr(os, 'supports_dir_fd', set()) for function in
            (os.open, os.stat, os.mkdir, os.unlink, os.rename))
    and os.stat in getattr(os, 'supports_follow_symlinks', set())
)
OSV_ECOSYSTEMS = ('PyPI', 'npm', 'Go', 'crates.io', 'Packagist', 'RubyGems', 'Maven')
OSV_BUCKET = 'https://osv-vulnerabilities.storage.googleapis.com'
SOURCE_URLS = {f'osv:{ecosystem}': f'{OSV_BUCKET}/{ecosystem}/all.zip' for ecosystem in OSV_ECOSYSTEMS}
SOURCE_URLS.update({
    'kev': 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    'epss': 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz',
    'malicious-packages': 'https://github.com/ossf/malicious-packages',
})


class SecurityDataError(RuntimeError):
    """Snapshot cannot supply the requested offline evidence."""


def _clock(now: datetime | None) -> datetime:
    current = datetime.now(timezone.utc) if now is None else now
    if not isinstance(current, datetime) or current.tzinfo is None or current.utcoffset() is None:
        raise SecurityDataError('snapshot clock must be a known timezone-aware UTC datetime')
    return current.astimezone(timezone.utc)


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise SecurityDataError('unknown last_verified_sync_utc; refresh the snapshot')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return _clock(parsed)
    except (ValueError, OverflowError) as exc:
        raise SecurityDataError('invalid last_verified_sync_utc; refresh the snapshot') from exc


def _source_directory(database: Path, source_id: str) -> Path:
    if source_id not in SOURCE_URLS:
        raise SecurityDataError(f'unsupported security source: {source_id!r}')
    if source_id.startswith('osv:'):
        return Path(database) / source_id.removeprefix('osv:')
    return Path(database) / 'feeds' / source_id


def _json(data: bytes) -> dict[str, Any]:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f'duplicate JSON key: {key}')
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError(f'nonfinite JSON value: {value}')

    result = json.loads(data.decode('utf-8'), object_pairs_hook=unique, parse_constant=invalid_constant)
    if not isinstance(result, dict):
        raise ValueError('expected a JSON object')
    return result


def osv_aliases(record: dict[str, Any]) -> list[str]:
    """Validate identifiers used for exception and CVE matching without coercion."""
    if not isinstance(record, dict):
        raise SecurityDataError('OSV aliases require a record object')
    aliases = record.get('aliases', [])
    if aliases is None:
        return []
    if (not isinstance(aliases, list) or not all(
            isinstance(alias, str) and re.fullmatch(r'[A-Za-z0-9:_.-]+', alias) for alias in aliases)):
        raise SecurityDataError('OSV aliases must be an array of valid vulnerability identifiers')
    return list(aliases)


def _https_repository(value: Any) -> bool:
    """Recognize a bounded repository identity without fetching or rewriting it."""
    if not isinstance(value, str) or len(value) > 2048:
        return False
    match = re.fullmatch(
        r'https://([a-zA-Z0-9.-]+)(?::([1-9][0-9]{0,4}))?((?:/[A-Za-z0-9._~-]+)*)', value)
    if not match:
        return False
    host, port, path = match.groups()
    return (len(host) <= 253 and all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                                     for label in host.split('.'))
            and (port is None or int(port) <= 65535)
            and not any(segment in {'.', '..'} for segment in path.split('/')))


def qualified_packagist(ecosystem: Any) -> bool:
    """A custom repository is a member of the feed family, not the default registry."""
    return (isinstance(ecosystem, str) and ecosystem.startswith('Packagist:')
            and _https_repository(ecosystem.removeprefix('Packagist:')))


def _git_supplement(item: dict) -> bool:
    ranges, versions = item.get('ranges'), item.get('versions', [])
    if (not isinstance(versions, list) or not all(isinstance(v, str) and v for v in versions)
            or not isinstance(ranges, list) or not ranges):
        return False
    for span in ranges:
        if not isinstance(span, dict) or span.get('type') != 'GIT' or not _https_repository(span.get('repo')):
            return False
        events = span.get('events')
        if not isinstance(events, list) or not events:
            return False
        kinds = set()
        for event in events:
            if not isinstance(event, dict) or len(event) != 1:
                return False
            role, value = next(iter(event.items()))
            if (role not in {'introduced', 'fixed', 'last_affected', 'limit'} or not isinstance(value, str)
                    or not (role == 'introduced' and value == '0' or re.fullmatch(r'(?:[a-f0-9]{40}|[a-f0-9]{64})', value))):
                return False
            kinds.add(role)
        if 'introduced' not in kinds or {'fixed', 'last_affected'} <= kinds:
            return False
    return True


def osv_coverage(payload: bytes, ecosystem: str) -> dict[str, Any]:
    """Derive OSV archive coverage from every complete JSON member and CRC."""
    if ecosystem not in OSV_ECOSYSTEMS:
        raise SecurityDataError(f'unsupported OSV ecosystem: {ecosystem!r}')
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_PAYLOAD_BYTES:
        raise SecurityDataError('OSV snapshot payload is empty or exceeds the size limit')
    current_member = current_id = None
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            members = archive.infolist()
            if len(members) > 1000000 or sum(member.file_size for member in members) > MAX_UNCOMPRESSED_BYTES:
                raise ValueError('OSV archive exceeds validation limits')
            names = set()
            record_ids = set()
            covered = False
            for member in members:
                current_member, current_id = member.filename, None
                name = PurePosixPath(member.filename)
                if name.is_absolute() or '..' in name.parts or '\\' in member.filename or member.filename in names:
                    raise ValueError('unsafe or duplicate OSV archive member')
                names.add(member.filename)
                if member.is_dir():
                    continue
                if not member.filename.endswith('.json') or member.file_size > MAX_MEMBER_BYTES:
                    raise ValueError('OSV archive member is not bounded JSON')
                try:
                    record = _json(archive.read(member))
                except (OSError, ValueError, KeyError, UnicodeError, EOFError, RuntimeError,
                        zipfile.BadZipFile, zlib.error):
                    raise ValueError('cannot read complete valid OSV record JSON') from None
                identifier = record.get('id')
                current_id = identifier if isinstance(identifier, str) else None
                if not isinstance(identifier, str) or not identifier.strip() or identifier in record_ids:
                    raise ValueError('OSV record requires a unique nonempty id')
                record_ids.add(identifier)
                osv_aliases(record)
                if 'withdrawn' in record:
                    withdrawn = record['withdrawn']
                    if not isinstance(withdrawn, str) or re.fullmatch(
                            r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}'
                            r'(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})', withdrawn) is None:
                        raise ValueError('OSV withdrawn must be a timezone-aware RFC 3339 timestamp')
                    _timestamp(withdrawn)
                affected = record.get('affected', [])
                if affected is None and 'withdrawn' in record:
                    affected = []
                if not isinstance(affected, list) or (not affected and not record.get('withdrawn')):
                    raise ValueError('OSV record lacks affected package coverage')
                matches = default_match = named_evidence = supplement = False
                for item in affected:
                    if isinstance(item, dict) and 'package' not in item and _git_supplement(item):
                        supplement = True
                        continue
                    if not isinstance(item, dict) or not isinstance(item.get('package'), dict):
                        raise ValueError('malformed OSV affected package')
                    package = item['package']
                    if not isinstance(package.get('name'), str) or not package['name'] or not isinstance(package.get('ecosystem'), str):
                        raise ValueError('OSV package needs name and ecosystem')
                    versions, ranges = item.get('versions', []), item.get('ranges', [])
                    if not isinstance(versions, list) or not all(isinstance(value, str) and value for value in versions):
                        raise ValueError('malformed OSV versions')
                    if not isinstance(ranges, list) or not all(isinstance(value, dict) for value in ranges):
                        raise ValueError('malformed OSV ranges')
                    if not versions and not ranges and not record.get('withdrawn'):
                        raise ValueError('OSV affected package has neither versions nor ranges')
                    exact = package['ecosystem'] == ecosystem
                    family = exact or (ecosystem == 'Packagist' and qualified_packagist(package['ecosystem']))
                    if package['ecosystem'].startswith('Packagist:') and not qualified_packagist(package['ecosystem']):
                        raise ValueError('unsupported OSV Packagist registry identity')
                    matches = matches or family
                    default_match = default_match or exact
                    if family and (versions or any(span.get('type') in ('ECOSYSTEM', 'SEMVER')
                                                   and isinstance(span.get('events'), list)
                                                   and any(isinstance(e, dict) and isinstance(e.get('introduced'), str)
                                                           and e['introduced'] for e in span['events']) for span in ranges)):
                        named_evidence = True
                if supplement and not named_evidence:
                    raise ValueError('supplementary Git row lacks named affected ecosystem coverage')
                if not matches and not record.get('withdrawn'):
                    raise ValueError(f'OSV record has no {ecosystem} coverage')
                covered = covered or default_match
            current_member = current_id = None
            if not record_ids or not covered:
                raise ValueError(f'empty OSV archive or missing {ecosystem} coverage')
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile, zlib.error, EOFError, RuntimeError) as exc:
        location = ''.join(f' {label}_sha256={hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()}'
                           for label, value in (('member', current_member), ('id', current_id)) if value is not None)
        raise SecurityDataError(f'invalid OSV snapshot for {ecosystem}: {exc}{location}') from exc
    return {'scopes': [ecosystem], 'complete': True, 'record_count': len(record_ids), 'schema': 'osv-1'}


def _coverage(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {'scopes', 'complete', 'record_count', 'schema'}:
        raise SecurityDataError('snapshot coverage requires scopes, complete, record_count and schema')
    scopes = value['scopes']
    if not isinstance(scopes, list) or not scopes or not all(isinstance(scope, str) and scope for scope in scopes):
        raise SecurityDataError('snapshot coverage scopes must be nonempty strings')
    if len(scopes) != len(set(scopes)) or value['complete'] is not True:
        raise SecurityDataError('snapshot coverage is incomplete or ambiguous')
    if type(value['record_count']) is not int or value['record_count'] < 0:
        raise SecurityDataError('snapshot coverage record_count must be a nonnegative integer')
    if not isinstance(value['schema'], str) or not value['schema'].strip():
        raise SecurityDataError('snapshot coverage schema is missing')
    return {'scopes': sorted(scopes), 'complete': True, 'record_count': value['record_count'], 'schema': value['schema']}


def _acquisition(value: Any) -> dict[str, Any]:
    required = {'last_verified_sync_utc', 'retrieval_kind'}
    allowed = required | {'producer', 'source_revision', 'source_published_at'}
    if not isinstance(value, dict) or not required <= set(value) or set(value) - allowed:
        raise SecurityDataError('snapshot acquisition requires last_verified_sync_utc and retrieval_kind')
    if value['retrieval_kind'] not in {'download', 'revalidated'}:
        raise SecurityDataError('snapshot acquisition must describe original download or revalidation')
    acquired = _timestamp(value['last_verified_sync_utc'])
    result = {**value, 'last_verified_sync_utc': acquired.isoformat(),
              'producer': value.get('producer', 'getzilla-security-data-v1')}
    for name in ('producer', 'source_revision', 'source_published_at'):
        if name in result and (not isinstance(result[name], str) or not result[name].strip() or len(result[name]) > 1024):
            raise SecurityDataError(f'invalid snapshot acquisition {name}')
    return result


def _validate(document: dict[str, Any], payload: bytes, source_id: str, *, now: datetime,
              required_scope: set[str] | None) -> dict[str, Any]:
    fields = {'schema_version', 'source_id', 'source_url', 'content_sha256', 'payload_size', 'acquisition', 'coverage'}
    if set(document) != fields or type(document['schema_version']) is not int or document['schema_version'] != 1:
        raise SecurityDataError('unsupported snapshot manifest schema; refresh the snapshot')
    if document['source_id'] != source_id or document['source_url'] != SOURCE_URLS[source_id]:
        raise SecurityDataError('snapshot source identity does not match the fixed source')
    digest = document['content_sha256']
    if not isinstance(digest, str) or re.fullmatch('[0-9a-f]{64}', digest) is None:
        raise SecurityDataError('snapshot content digest is invalid')
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_PAYLOAD_BYTES:
        raise SecurityDataError('snapshot payload is empty or exceeds the size limit')
    if type(document['payload_size']) is not int or document['payload_size'] != len(payload):
        raise SecurityDataError('snapshot payload size does not match its manifest')
    if hashlib.sha256(payload).hexdigest() != digest:
        raise SecurityDataError('snapshot payload SHA-256 mismatch')
    acquisition = _acquisition(document['acquisition'])
    age = (now - _timestamp(acquisition['last_verified_sync_utc'])).total_seconds()
    if not math.isfinite(age) or age < 0:
        raise SecurityDataError(f'{source_id} snapshot has a future or unknown verified sync; refresh the snapshot')
    if age > MAX_AGE_SECONDS:
        raise SecurityDataError(f'{source_id} snapshot is stale ({age:g}s > {MAX_AGE_SECONDS}s); refresh the snapshot')
    coverage = _coverage(document['coverage'])
    if required_scope is not None and (
            not isinstance(required_scope, (set, frozenset)) or
            not all(isinstance(scope, str) and scope for scope in required_scope) or
            not required_scope <= set(coverage['scopes'])):
        raise SecurityDataError(f'{source_id} snapshot does not cover the required scope')
    payload_validation = 'source-evaluator-required'
    if source_id.startswith('osv:'):
        actual = osv_coverage(payload, source_id.removeprefix('osv:'))
        if actual != coverage:
            raise SecurityDataError('OSV payload coverage does not match its manifest')
        payload_validation = 'osv-archive'
    return {**document, 'acquisition': acquisition, 'coverage': coverage,
            'age_seconds': age, 'checked_at_utc': now.isoformat(), 'payload_validation': payload_validation}


def _directory_identity(metadata: os.stat_result) -> tuple:
    return metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid, metadata.st_gid


def _file_identity(metadata: os.stat_result) -> tuple:
    return (*_directory_identity(metadata), metadata.st_nlink, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


@dataclass(frozen=True)
class _Directory:
    descriptor: int
    parent: int | None
    name: str | None
    identity: tuple


@dataclass(frozen=True)
class _File:
    descriptor: int
    parent: int
    name: str
    identity: tuple


class _SnapshotStore:
    """Hold the physical ancestry and all consumed files until final confirmation."""

    def __init__(self, database: Path, *, create: bool = False):
        self.database = database
        self.create = create
        self.directories: list[_Directory] = []
        self.relative: dict[tuple[str, ...], _Directory] = {}
        self.files: dict[tuple[int, str], _File] = {}

    def __enter__(self):
        if not DESCRIPTOR_IO_AVAILABLE:
            raise SecurityDataError('secure snapshot directory descriptors are unavailable; use a qualified POSIX updater/evaluator; Windows snapshot I/O is not qualified')
        raw = os.fspath(self.database)
        if not isinstance(raw, str) or len(raw) > 4096 or '..' in Path(raw).parts:
            raise SecurityDataError('snapshot database needs a bounded physical path without parent traversal')
        absolute = Path(os.path.abspath(raw))  # Never resolve a caller-controlled link.
        if len(absolute.parts) > 128 or len(absolute.parts) < 2:
            raise SecurityDataError('snapshot database needs a bounded dedicated directory path')
        try:
            descriptor = fsx.open_dir(absolute.anchor, flags=os.O_CLOEXEC)
            try:
                node = _Directory(descriptor, None, None, _directory_identity(os.fstat(descriptor)))
            except BaseException:
                os.close(descriptor)
                raise
            self.directories.append(node)
            for position, name in enumerate(absolute.parts[1:], start=1):
                node = self._open_directory(node, name, create=self.create,
                                            owned=position == len(absolute.parts) - 1)
            self.relative[()] = node
            self.confirm()
            return self
        except BaseException:
            self.close()
            raise

    def __exit__(self, kind, value, traceback):
        try:
            if kind is None:
                self.confirm()
        finally:
            self.close()

    def close(self):
        for file in self.files.values():
            os.close(file.descriptor)
        self.files.clear()
        for node in reversed(self.directories):
            fsx.close_dir(node.descriptor)
        self.directories.clear()
        self.relative.clear()

    def confirm(self):
        for node in self.directories:
            opened = os.fstat(node.descriptor)
            if not stat.S_ISDIR(opened.st_mode) or opened.st_nlink < 1 or _directory_identity(opened) != node.identity:
                raise SecurityDataError('snapshot directory identity changed while held')
            if node.parent is not None:
                named = fsx.lstat_at(node.parent, node.name)
                if not stat.S_ISDIR(named.st_mode) or _directory_identity(named) != node.identity:
                    raise SecurityDataError('snapshot directory path was replaced or linked while held')
        for file in self.files.values():
            opened = os.fstat(file.descriptor)
            named = fsx.lstat_at(file.parent, file.name)
            if (not stat.S_ISREG(named.st_mode) or _file_identity(opened) != file.identity
                    or _file_identity(named) != file.identity):
                raise SecurityDataError('snapshot regular file changed or was replaced while held')

    def _open_directory(self, parent: _Directory, name: str, *, create: bool, owned: bool) -> _Directory:
        self.confirm()
        try:
            before = fsx.lstat_at(parent.descriptor, name)
        except FileNotFoundError:
            if not create:
                raise
            try:
                fsx.mkdir_at(parent.descriptor, name, 0o700)
            except FileExistsError:
                pass
            fsx.fsync_dir(parent.descriptor)
            self.confirm()
            before = fsx.lstat_at(parent.descriptor, name)
        if not stat.S_ISDIR(before.st_mode):
            raise SecurityDataError('snapshot path contains a link or non-directory; use its physical directory path')
        shared_ancestor = not owned and bool(before.st_mode & stat.S_ISVTX)
        if before.st_uid not in {0, os.geteuid()} or (before.st_mode & 0o022 and not shared_ancestor):
            raise SecurityDataError('snapshot directory must be owned by the updater or root and not writable by group/others')
        descriptor = fsx.open_dir_at(parent.descriptor, name, flags=os.O_CLOEXEC)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISDIR(opened.st_mode) or _directory_identity(opened) != _directory_identity(before):
                raise SecurityDataError('snapshot directory changed during descriptor open')
            node = _Directory(descriptor, parent.descriptor, name, _directory_identity(opened))
        except BaseException:
            os.close(descriptor)
            raise
        self.directories.append(node)
        self.confirm()
        return node

    def directory(self, parts: tuple[str, ...], *, create: bool = False) -> _Directory:
        if len(parts) > 8 or any(not name or name in {'.', '..'} or '/' in name or '\\' in name for name in parts):
            raise SecurityDataError('snapshot relative directory is outside the closed layout')
        self.confirm()
        for size in range(1, len(parts) + 1):
            prefix = parts[:size]
            if prefix not in self.relative:
                self.relative[prefix] = self._open_directory(self.relative[prefix[:-1]], prefix[-1], create=create, owned=True)
        return self.relative[parts]

    def _pin_file(self, parent: _Directory, name: str, maximum: int) -> _File:
        self.confirm()
        key = parent.descriptor, name
        if key not in self.files:
            before = fsx.lstat_at(parent.descriptor, name)
            if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
                raise SecurityDataError('snapshot file is not a bounded regular file')
            descriptor = fsx.open_at(parent.descriptor, name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            try:
                opened = os.fstat(descriptor)
                if not stat.S_ISREG(opened.st_mode) or _file_identity(opened) != _file_identity(before):
                    raise SecurityDataError('snapshot file changed during descriptor open')
                self.files[key] = _File(descriptor, parent.descriptor, name, _file_identity(opened))
            except BaseException:
                os.close(descriptor)
                raise
        file = self.files[key]
        if os.fstat(file.descriptor).st_size > maximum:
            raise SecurityDataError('snapshot file exceeds the bounded read limit')
        return file

    def read(self, parts: tuple[str, ...], maximum: int) -> bytes:
        parent = self.directory(parts[:-1])
        file = self._pin_file(parent, parts[-1], maximum)
        os.lseek(file.descriptor, 0, os.SEEK_SET)
        chunks, remaining = [], maximum + 1
        while remaining:
            chunk = os.read(file.descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        if not remaining:
            raise SecurityDataError('snapshot file exceeds the bounded read limit')
        self.confirm()
        return b''.join(chunks)

    def write(self, parts: tuple[str, ...], payload: bytes):
        parent = self.directory(parts[:-1], create=True)
        name, key = parts[-1], (parent.descriptor, parts[-1])
        try:
            previous = self._pin_file(parent, name, MAX_PAYLOAD_BYTES)
        except FileNotFoundError:
            previous = None
        temporary = f'.{name}.{uuid.uuid4().hex}.partial'
        descriptor = fsx.open_at(parent.descriptor, temporary,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600)
        try:
            self.confirm()
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, memoryview(payload)[offset:offset + 1024 * 1024])
                if written < 1:
                    raise OSError('incomplete snapshot temporary write')
                offset += written
            os.fsync(descriptor)
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size != len(payload):
                raise SecurityDataError('snapshot temporary is not the expected regular file')
            os.lseek(descriptor, 0, os.SEEK_SET)
            digest, size = hashlib.sha256(), 0
            while chunk := os.read(descriptor, min(1024 * 1024, len(payload) + 1 - size)):
                digest.update(chunk)
                size += len(chunk)
                if size > len(payload):
                    break
            named = fsx.lstat_at(parent.descriptor, temporary)
            if (size != len(payload) or digest.digest() != hashlib.sha256(payload).digest()
                    or _file_identity(os.fstat(descriptor)) != _file_identity(before)
                    or _file_identity(named) != _file_identity(before)):
                raise SecurityDataError('snapshot temporary changed before publication')
            self.confirm()
            if previous is None:
                try:
                    fsx.lstat_at(parent.descriptor, name)
                except FileNotFoundError:
                    pass
                else:
                    raise SecurityDataError('snapshot target appeared during publication')
            fsx.replace_at(parent.descriptor, temporary, parent.descriptor, name)
            temporary = None
            if key in self.files:
                os.close(self.files.pop(key).descriptor)
            after = os.fstat(descriptor)
            self.files[key] = _File(os.dup(descriptor), parent.descriptor, name, _file_identity(after))
            self.confirm()
            fsx.fsync_dir(parent.descriptor)
        finally:
            if temporary is not None:
                with contextlib.suppress(OSError):
                    named = fsx.lstat_at(parent.descriptor, temporary)
                    opened = os.fstat(descriptor)
                    if stat.S_ISREG(named.st_mode) and (named.st_dev, named.st_ino) == (opened.st_dev, opened.st_ino):
                        fsx.unlink_at(parent.descriptor, temporary)
            os.close(descriptor)


def publish_snapshot(database: Path, source_id: str, payload: bytes, *, acquisition: dict[str, Any],
                     coverage: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    """Commit the authoritative pointer after its object; pre-commit failures keep the old pointer."""
    folder = _source_directory(database, source_id)
    current = _clock(now)
    if not isinstance(payload, bytes):
        raise SecurityDataError('snapshot payload must be bytes')
    document = {'schema_version': 1, 'source_id': source_id, 'source_url': SOURCE_URLS[source_id],
                'content_sha256': hashlib.sha256(payload).hexdigest(), 'payload_size': len(payload),
                'acquisition': _acquisition(acquisition), 'coverage': _coverage(coverage)}
    evidence = _validate(document, payload, source_id, now=current, required_scope=None)
    serialized = (json.dumps(document, sort_keys=True) + '\n').encode('utf-8')
    if len(serialized) > MAX_MANIFEST_BYTES:
        raise SecurityDataError('snapshot manifest is too large')
    source_parts = folder.relative_to(Path(database)).parts
    target = ('.snapshots', 'sha256', document['content_sha256'])
    try:
        with _SnapshotStore(database, create=True) as store:
            # Bind both trees before creating an object or committing a pointer.
            store.directory(source_parts, create=True)
            store.directory(target[:-1], create=True)
            try:
                existing = store.read(target, len(payload))
            except FileNotFoundError:
                store.write(target, payload)
            else:
                if existing != payload:
                    raise SecurityDataError('existing immutable snapshot object differs; repair the cache')
            store.write((*source_parts, 'snapshot.json'), serialized)
            if source_id.startswith('osv:'):
                # Non-authoritative compatibility export, after pointer commit.
                # A safe I/O failure does not erase the committed snapshot.
                try:
                    store.write((*source_parts, 'all.zip'), payload)
                except OSError as exc:
                    store.confirm()
                    evidence['compatibility_export_warning'] = str(exc)
    except OSError as exc:
        raise SecurityDataError(f'snapshot publication failed: {exc}') from exc
    return evidence


def read_snapshot(database: Path, source_id: str, *, now: datetime | None = None,
                  required_scope: set[str] | None = None) -> tuple[bytes, dict[str, Any]]:
    """Return the exact validated bytes and evidence; never fall back to a raw ZIP."""
    folder = _source_directory(database, source_id)
    current = _clock(now)
    source_parts = folder.relative_to(Path(database)).parts
    try:
        with _SnapshotStore(database) as store:
            raw = store.read((*source_parts, 'snapshot.json'), MAX_MANIFEST_BYTES)
            document = _json(raw)
            digest = document.get('content_sha256')
            if not isinstance(digest, str) or re.fullmatch('[0-9a-f]{64}', digest) is None:
                raise SecurityDataError('snapshot content digest is invalid')
            payload = store.read(('.snapshots', 'sha256', digest), MAX_PAYLOAD_BYTES)
            evidence = _validate(document, payload, source_id, now=current, required_scope=required_scope)
            return payload, evidence
    except (OSError, ValueError, KeyError, TypeError, SecurityDataError) as exc:
        legacy = f' (legacy {source_id.removeprefix("osv:")}/all.zip is insufficient)' if source_id.startswith('osv:') else ''
        refresh = ('refresh with python3 scripts/getzilla_security.py --root ROOT --database DIR '
                   '--artifacts ARTIFACTS --tools TOOLS --json-out REPORT --refresh '
                   'on a network-enabled host, then copy the complete snapshot directory') if source_id.startswith('osv:') else (
                       f'refresh {source_id} through its configured updater, then copy manifest and content objects')
        raise SecurityDataError(f'{source_id} snapshot unavailable or malformed{legacy}: {exc}; {refresh}') from exc


def copy_snapshot(source_database: Path, destination_database: Path, source_id: str, *,
                  now: datetime | None = None, required_scope: set[str] | None = None) -> dict[str, Any]:
    """Copy a valid snapshot without refreshing its original acquisition time."""
    current = _clock(now)
    payload, evidence = read_snapshot(source_database, source_id, now=current, required_scope=required_scope)
    return publish_snapshot(destination_database, source_id, payload, acquisition=evidence['acquisition'],
                            coverage=evidence['coverage'], now=current)
