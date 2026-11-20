"""Offline snapshot storage with exact bytes, coverage and a 72-hour clock.

The caller owns acquisition. This module has no network client. Content hashes
and unsigned local acquisition metadata bind data; they do not establish an
independent publisher identity or grant merge authority. OSV archives are
validated here. Other registered feeds also require their source-specific
evaluator to validate their body schema, counts and publication dates.

Each source has one atomically replaced manifest. It names an immutable object
by digest, never by an input path. The legacy all.zip export is not authoritative.

POSIX snapshot I/O requires directory descriptors and a physical, non-symlink
database path. The updater/runner must exclusively control this directory tree;
directories must belong to the current UID or root and forbid group/other writes
(only sticky ancestors, such as /tmp, may be shared).
Descriptors cannot stop another process with the same UID or root privilege
from renaming an already opened directory. Every operation checks held directory
and regular-file identities before/after use. Windows uses a separate native
held-handle store on supported local NTFS volumes, never a path/lstat fallback.
Pure validation and structural no-source results require neither backend.
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
import uuid as uuid
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
MAX_ARCHIVE_MEMBERS = 1000000
MAX_CENTRAL_DIRECTORY_BYTES = 128 * 1024 * 1024
MAX_STORE_READ_BYTES = 2 * MAX_PAYLOAD_BYTES + 8 * MAX_MANIFEST_BYTES
DESCRIPTOR_IO_AVAILABLE = (
    os.name == 'posix'
    and all(hasattr(os, name) for name in ('O_DIRECTORY', 'O_NOFOLLOW', 'O_CLOEXEC', 'O_NONBLOCK'))
    and all(function in getattr(os, 'supports_dir_fd', set()) for function in
            (os.open, os.stat, os.mkdir, os.unlink, os.rename))
    and os.stat in getattr(os, 'supports_follow_symlinks', set())
)
OSV_ECOSYSTEMS = ('PyPI', 'npm', 'Go', 'crates.io', 'Packagist', 'RubyGems', 'Maven')
OSV_BUCKET = 'https://osv-vulnerabilities.storage.googleapis.com'
OSV_QUERY_SOURCE = 'osv-query:native'
SOURCE_URLS = {f'osv:{ecosystem}': f'{OSV_BUCKET}/{ecosystem}/all.zip' for ecosystem in OSV_ECOSYSTEMS}
SOURCE_URLS.update({
    OSV_QUERY_SOURCE: 'https://api.osv.dev/v1/querybatch',
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
    if source_id == OSV_QUERY_SOURCE:
        return Path(database) / 'queries' / 'native'
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

    try:
        result = json.loads(data.decode('utf-8'), object_pairs_hook=unique, parse_constant=invalid_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('invalid bounded snapshot JSON') from None
    if not isinstance(result, dict):
        raise ValueError('expected a JSON object')
    return result


def osv_aliases(record: dict[str, Any]) -> list[str]:
    """Retain exact provider strings; transport shape is not decision authority."""
    from .security_osv_diagnostics import alias_rejection
    def rejected(index=None):
        detail = alias_rejection(record, index)
        error = SecurityDataError('OSV aliases must be an array of strings' + '; ' + json.dumps(detail, sort_keys=True))
        error.osv_alias_detail = detail
        return error
    if not isinstance(record, dict):
        raise rejected()
    aliases = record.get('aliases')
    if aliases is None:
        return []
    if not isinstance(aliases, list):
        raise rejected()
    for index, alias in enumerate(aliases):
        if not isinstance(alias, str):
            raise rejected(index)
    return list(aliases)


CVE_ID = re.compile(r'CVE-[0-9]{4}-[0-9]{4,19}\Z')


def osv_decision_ids(record: dict[str, Any]) -> list[str]:
    """Revalidate retained raw identities before any matched lookup or waiver.

    Existing non-CVE identifier syntax remains supported. Other provider text
    stays opaque. A caller-supplied safe projection cannot hide uncertain CVEs.
    """
    from .security_osv_diagnostics import alias_rejection
    aliases = osv_aliases(record)
    if 'raw_aliases' in record and not isinstance(record['raw_aliases'], list):
        raise SecurityDataError('OSV retained raw aliases must be an array')
    raw = osv_aliases({'aliases': record['raw_aliases']}) if 'raw_aliases' in record else aliases
    primary = record.get('id')
    if not isinstance(primary, str) or not re.fullmatch(r'[A-Za-z0-9:_.-]+', primary):
        raise SecurityDataError('OSV decision primary identifier is malformed')
    for values in ([primary], raw, aliases):
        for index, value in enumerate(values):
            if re.search(r'(?i)(?<![A-Za-z0-9])cve(?=[^A-Za-z]|$)', value) and not CVE_ID.fullmatch(value):
                detail = alias_rejection({'id': primary, 'aliases': values}, index)
                error = SecurityDataError('OSV decision identifier is malformed; ' + json.dumps(detail, sort_keys=True))
                error.osv_alias_detail = detail
                raise error
    return list(dict.fromkeys(value for values in ([primary], raw) for value in values
                              if re.fullmatch(r'[A-Za-z0-9:_.-]+', value)))


def osv_alias_text(aliases: list[str]) -> str:
    """Only the human projection is bounded/escaped; retained raw data is exact."""
    return json.dumps([value[:160] for value in aliases[:3]], ensure_ascii=True)


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


def _archive_census(payload: bytes, *, max_members: int = MAX_ARCHIVE_MEMBERS,
                    max_expanded: int = MAX_UNCOMPRESSED_BYTES,
                    max_directory: int = MAX_CENTRAL_DIRECTORY_BYTES) -> None:
    """Bound central-directory entries before ZipFile allocates its member list."""
    try:
        if any(type(value) is not int or value < 0 for value in (max_members, max_expanded, max_directory)):
            raise ValueError('invalid archive census bound')
        max_members = min(max_members, MAX_ARCHIVE_MEMBERS)
        max_expanded = min(max_expanded, MAX_UNCOMPRESSED_BYTES)
        max_directory = min(max_directory, MAX_CENTRAL_DIRECTORY_BYTES)
        end = zipfile._EndRecData(io.BytesIO(payload))
        if end is None:
            raise ValueError('missing ZIP directory')
        count, size = end[zipfile._ECD_ENTRIES_TOTAL], end[zipfile._ECD_SIZE]
        if (end[zipfile._ECD_DISK_NUMBER] != 0 or end[zipfile._ECD_DISK_START] != 0
                or count > max_members or size > max_directory):
            raise ValueError('archive census exceeds bound')
        start = end[zipfile._ECD_LOCATION] - size
        if end[zipfile._ECD_SIGNATURE] == zipfile.stringEndArchive64:
            start -= zipfile.sizeEndCentDir64 + zipfile.sizeEndCentDir64Locator
        if start < 0 or start + size > len(payload):
            raise ValueError('invalid ZIP directory extent')
        position, observed, expanded = start, 0, 0
        while position < start + size:
            observed += 1
            if observed > max_members:
                raise ValueError('archive census exceeds bound')
            header = payload[position:position + 46]
            if len(header) != 46 or header[:4] != b'PK\x01\x02':
                raise ValueError('invalid ZIP central record')
            expanded += int.from_bytes(header[24:28], 'little')
            if (int.from_bytes(header[24:28], 'little') > MAX_MEMBER_BYTES
                    or expanded > max_expanded):
                raise ValueError('archive expanded bytes exceed bound')
            position += 46 + sum(int.from_bytes(header[a:a + 2], 'little') for a in (28, 30, 32))
        if observed != count or position != start + size:
            raise ValueError('incomplete ZIP directory census')
    except (OSError, ValueError, IndexError, TypeError, zipfile.BadZipFile):
        raise SecurityDataError('OSV archive central directory is invalid or exceeds bounds') from None


def osv_coverage(payload: bytes, ecosystem: str) -> dict[str, Any]:
    """Derive OSV archive coverage from every complete JSON member and CRC."""
    if ecosystem not in OSV_ECOSYSTEMS:
        raise SecurityDataError(f'unsupported OSV ecosystem: {ecosystem!r}')
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_PAYLOAD_BYTES:
        raise SecurityDataError('OSV snapshot payload is empty or exceeds the size limit')
    _archive_census(payload)
    current_member = current_id = None
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            members = archive.infolist()
            if len(members) > MAX_ARCHIVE_MEMBERS or sum(member.file_size for member in members) > MAX_UNCOMPRESSED_BYTES:
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
                    # OSV permits named rows without version bounds. Retain
                    # them as unknown coverage; a matching query must refuse
                    # rather than interpreting missing bounds as all or none.
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
        from .security_osv_diagnostics import snapshot_alias_message
        alias_message = snapshot_alias_message(ecosystem, exc, current_member, current_id)
        if alias_message is not None:
            error = SecurityDataError(alias_message)
            # Retain the original bounded hash-only record across exception
            # wrapping, before the updater's smaller human log projection.
            error.osv_snapshot_detail = json.loads(alias_message.removeprefix('aliases: '))
            raise error from exc
        location = ''.join(f' {label}_sha256={hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()}'
                           for label, value in (('member', current_member), ('id', current_id)) if value is not None)
        category = 'OSV aliases' if isinstance(exc, SecurityDataError) and str(exc).startswith('OSV aliases') else 'OSV snapshot'
        raise SecurityDataError(f'invalid {category} for {ecosystem}{location}') from None
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
    age = _freshness(acquisition, source_id, now)
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
    elif source_id == OSV_QUERY_SOURCE:
        from .security_osv_query import validate_transcript
        replay = validate_transcript(payload)
        if replay['coverage'] != coverage or replay['started_at_utc'] != acquisition['last_verified_sync_utc']:
            raise SecurityDataError('query coverage or earliest request clock differs from its manifest')
        if _timestamp(replay['completed_at_utc']) > now:
            raise SecurityDataError('query completion clock is in the future')
        payload_validation = 'osv-query-transcript'
    return {**document, 'acquisition': acquisition, 'coverage': coverage,
            'age_seconds': age, 'checked_at_utc': now.isoformat(), 'payload_validation': payload_validation}


def _freshness(acquisition: dict[str, Any], source_id: str, now: datetime) -> float:
    age = (now - _timestamp(acquisition['last_verified_sync_utc'])).total_seconds()
    if not math.isfinite(age) or age < 0:
        raise SecurityDataError(f'{source_id} snapshot has a future or unknown verified sync; refresh the snapshot')
    if age > MAX_AGE_SECONDS:
        raise SecurityDataError(f'{source_id} snapshot is stale; refresh the snapshot')
    return age


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
        self.absent: set[tuple[int, str]] = set()
        self.read_bytes = 0
        self.last_replaced: tuple[str, ...] | None = None
        self.before_replace = None

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
        self.absent.clear()

    def confirm(self):
        for parent, name in self.absent:
            try:
                fsx.lstat_at(parent, name)
            except FileNotFoundError:
                pass
            else:
                raise SecurityDataError('snapshot commit_unknown; publication appeared during consumption')
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


    def expect_absent(self, parts: tuple[str, ...]) -> None:
        parent = self.directory(parts[:-1])
        self.absent.add((parent.descriptor, parts[-1]))
        self.confirm()

    def _pin_file(self, parent: _Directory, name: str, maximum: int) -> _File:
        self.confirm()
        key = parent.descriptor, name
        if key not in self.files:
            before = fsx.lstat_at(parent.descriptor, name)
            if (not stat.S_ISREG(before.st_mode) or before.st_size > maximum or before.st_nlink != 1
                    or before.st_uid not in {0, os.geteuid()} or before.st_mode & 0o022):
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
        if self.read_bytes + os.fstat(file.descriptor).st_size > MAX_STORE_READ_BYTES:
            raise SecurityDataError('snapshot remaining aggregate read budget is insufficient')
        os.lseek(file.descriptor, 0, os.SEEK_SET)
        chunks, remaining = [], maximum + 1
        while remaining:
            chunk = os.read(file.descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            self.read_bytes += len(chunk)
            if self.read_bytes > MAX_STORE_READ_BYTES:
                raise SecurityDataError('snapshot aggregate read budget exceeded')
            remaining -= len(chunk)
        if not remaining:
            raise SecurityDataError('snapshot file exceeds the bounded read limit')
        self.confirm()
        return b''.join(chunks)




def _snapshot_reader(database: Path):
    if os.name == 'nt':
        from .security_data_windows import SnapshotReader
        return SnapshotReader(database)
    return _SnapshotStore(database)


def _snapshot_store(database: Path, *, create: bool = False):
    if os.name == 'nt':
        from .security_data_windows import SnapshotStore
        return SnapshotStore(database, create=create)
    from .security_publication import SnapshotWriter
    return SnapshotWriter(database, create=create)


def publish_snapshot(database: Path, source_id: str, payload: bytes, *, acquisition: dict[str, Any],
                     coverage: dict[str, Any], now: datetime | None = None, before_commit=None) -> dict[str, Any]:
    """Commit the authoritative pointer after its object; pre-commit failures keep the old pointer."""
    from .security_publication import publish_snapshot as implementation
    return implementation(database, source_id, payload, acquisition=acquisition, coverage=coverage, now=now, before_commit=before_commit)


def read_snapshot(database: Path, source_id: str, *, now: datetime | None = None,
                  required_scope: set[str] | None = None) -> tuple[bytes, dict[str, Any]]:
    """Return the exact validated bytes and evidence; never fall back to a raw ZIP."""
    folder = _source_directory(database, source_id)
    source_parts = folder.relative_to(Path(database)).parts
    try:
        with _snapshot_reader(database) as store:
            pending = (*source_parts, '.publication-pending.json')
            try:
                store.read(pending, MAX_MANIFEST_BYTES)
            except FileNotFoundError:
                store.expect_absent(pending)
            else:
                raise SecurityDataError('snapshot commit_unknown; checked reconciliation is required')
            raw = store.read((*source_parts, 'snapshot.json'), MAX_MANIFEST_BYTES)
            document = _json(raw)
            digest = document.get('content_sha256')
            if not isinstance(digest, str) or re.fullmatch('[0-9a-f]{64}', digest) is None:
                raise SecurityDataError('snapshot content digest is invalid')
            payload = store.read(('.snapshots', 'sha256', digest), MAX_PAYLOAD_BYTES)
            # A real clock is sampled after the actual content read. An
            # explicitly injected test instant retains its exact semantics.
            evidence = _validate(document, payload, source_id, now=_clock(now), required_scope=required_scope)
            checked = _clock(now)
            evidence['age_seconds'] = _freshness(evidence['acquisition'], source_id, checked)
            evidence['checked_at_utc'] = checked.isoformat()
            store.confirm()
            evidence['manifest_sha256'] = hashlib.sha256(raw).hexdigest()
            evidence['custody_sha256'] = _custody_digest(store)
            return payload, evidence
    except (OSError, ValueError, KeyError, TypeError, SecurityDataError) as exc:
        legacy = f' (legacy {source_id.removeprefix("osv:")}/all.zip is insufficient)' if source_id.startswith('osv:') else ''
        command = ('python3 scripts/getzilla_security.py --root ROOT --database DIR '
                   '--artifacts ARTIFACTS --tools TOOLS')
        refresh = (f'declare current profile with {command} --write-input-profile PROFILE --json-out PROFILE_REPORT; '
                   f'refresh with {command} --input-profile PROFILE --prepare-inputs --refresh --json-out REPORT '
                   'on a network-enabled host, then copy the complete snapshot directory; '
                   'preparation remains UNVERIFIED and may refuse incomplete inputs; '
                   f'OSV-only alternative: python3 scripts/getzilla_vulns.py --download-db DIR --ecosystem {source_id.removeprefix("osv:")}') if source_id.startswith('osv:') else (
                       f'refresh {source_id} through its configured updater, then copy manifest and content objects')
        if source_id in {'kev', 'epss'}:
            refresh = f'refresh with {command} --refresh --json-out REPORT on a network-enabled host, then copy the complete snapshot directory'
        if source_id == OSV_QUERY_SOURCE:
            refresh = 'refresh with python3 scripts/getzilla_vulns.py --online --db DIR on the selected ROOT; retain the complete inventory-bound query snapshot'
        raise SecurityDataError(f'{source_id} snapshot unavailable or malformed{legacy}: {exc}; {refresh}') from exc


def _custody_identity(identity: tuple) -> list:
    """Serialize held stat/NTFS facts only; never alter their comparison identity."""
    if type(identity) is tuple and len(identity) in {5, 9} and all(type(v) is int for v in identity):
        return list(identity)  # Preserve the established POSIX JSON bytes.
    def integer(value, minimum, maximum):
        return type(value) is int and minimum <= value <= maximum
    def sid(value):
        return type(value) is str and 0 < len(value) <= 184
    valid = type(identity) is tuple and len(identity) in {4, 8}
    if valid:
        file_id, attributes, directory, security = identity[:4]
        valid = (type(file_id) is tuple and len(file_id) == 2
                 and integer(file_id[0], 0, 2**64 - 1) and type(file_id[1]) is bytes
                 and len(file_id[1]) == 16 and any(file_id[1])
                 and integer(attributes, 0, 2**32 - 1) and type(directory) is bool
                 and len(identity) == (4 if directory else 8)
                 and type(security) is tuple and len(security) in {2, 3})
    if valid:
        owner, aces = security[:2]
        valid = (sid(owner) and type(aces) is tuple and len(aces) <= 4096
                 and (len(security) == 2 or type(security[2]) is bool)
                 and all(type(ace) is tuple and len(ace) == 4
                         and integer(ace[0], 0, 1) and integer(ace[1], 0, 255)
                         and integer(ace[2], 0, 2**32 - 1) and sid(ace[3]) for ace in aces))
        if not directory:
            valid = valid and (identity[4] == 1 and type(identity[4]) is int
                               and integer(identity[5], 0, 2**63 - 1)
                               and all(integer(v, -(2**63), 2**63 - 1) for v in identity[6:]))
    if not valid:
        raise SecurityDataError('snapshot custody identity has an unsupported native shape')
    return [['ntfs-file-id/v1', file_id[0], file_id[1].hex()], *identity[1:]]


def _custody_digest(store: _SnapshotStore) -> str:
    directory_ids = {getattr(node, 'descriptor', getattr(node, 'handle', None)): node.identity for node in store.directories}
    custody = {'directories': [_custody_identity(node.identity) for node in store.directories],
               'files': sorted((file.name, _custody_identity(directory_ids[file.parent]), _custody_identity(file.identity))
                               for file in store.files.values())}
    return hashlib.sha256(json.dumps(custody, sort_keys=True).encode('utf-8')).hexdigest()


def confirm_snapshots(database: Path, evidence: list[dict[str, Any]], *, now: datetime | None = None) -> None:
    """Jointly hold current manifest/object identities, then check every clock.

    This final metadata fence supplements already validated exact payloads; it
    does not qualify caller-supplied evidence or reread multi-gigabyte archives.
    Only the fixed OSV source layout is consulted, never paths from a report.
    """
    if not isinstance(evidence, list) or not 0 < len(evidence) <= len(OSV_ECOSYSTEMS):
        raise SecurityDataError('final snapshot evidence is missing or exceeds the source bound')
    seen, held = set(), []
    try:
        with contextlib.ExitStack() as stack:
            for proof in evidence:
                if not isinstance(proof, dict):
                    raise SecurityDataError('final snapshot evidence is invalid')
                source_id = proof.get('source_id')
                if source_id not in {OSV_QUERY_SOURCE, *(f'osv:{name}' for name in OSV_ECOSYSTEMS)} or source_id in seen:
                    raise SecurityDataError('final snapshot source is invalid or repeated')
                seen.add(source_id)
                store = stack.enter_context(_snapshot_reader(database))
                parts = _source_directory(database, source_id).relative_to(Path(database)).parts
                try:
                    store.read((*parts, '.publication-pending.json'), MAX_MANIFEST_BYTES)
                except FileNotFoundError:
                    store.expect_absent((*parts, '.publication-pending.json'))
                else:
                    raise SecurityDataError('snapshot commit_unknown; checked reconciliation is required')
                raw = store.read((*parts, 'snapshot.json'), MAX_MANIFEST_BYTES)
                document = _json(raw)
                if (hashlib.sha256(raw).hexdigest() != proof.get('manifest_sha256')
                        or any(document.get(key) != proof.get(key) for key in document)
                        or re.fullmatch('[0-9a-f]{64}', str(document.get('content_sha256'))) is None):
                    raise SecurityDataError('snapshot manifest changed before final consumption')
                parent = store.directory(('.snapshots', 'sha256'))
                store._pin_file(parent, document['content_sha256'], MAX_PAYLOAD_BYTES)
                if _custody_digest(store) != proof.get('custody_sha256'):
                    raise SecurityDataError('snapshot custody changed before final consumption')
                held.append((store, source_id, _acquisition(document['acquisition'])))
            for store, _, _ in held:
                store.confirm()
            checked = _clock(now)
            for _, source_id, acquisition in held:
                _freshness(acquisition, source_id, checked)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SecurityDataError('snapshot unavailable during final consumption') from exc


def copy_snapshot(source_database: Path, destination_database: Path, source_id: str, *,
                  now: datetime | None = None, required_scope: set[str] | None = None) -> dict[str, Any]:
    """Copy a valid snapshot without refreshing its original acquisition time."""
    from .security_publication import copy_snapshot as implementation
    return implementation(source_database, destination_database, source_id, now=now, required_scope=required_scope)
