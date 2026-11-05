"""Current operator authority. Diagnostic objects and request bodies never grant access."""
from __future__ import annotations

import copy
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import threading
import time

from .models import Actor
from .settings import read_private_file, SettingsError


class AccessError(ValueError):
    """Fixed public code only; no credentials or operator file contents."""


_IDENTITY = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z')
_SOURCE_FIELDS = {'tenant', 'project', 'provider', 'site', 'resource'}


def _closed(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise AccessError('invalid_access_authority')


def _identity(value):
    if type(value) is not str or not _IDENTITY.fullmatch(value):
        raise AccessError('invalid_access_authority')
    return value


def _strings(value, maximum=256):
    if type(value) is not list or len(value) > maximum:
        raise AccessError('invalid_access_authority')
    result = tuple(_identity(item) for item in value)
    if len(set(result)) != len(result):
        raise AccessError('invalid_access_authority')
    return result


def source_key(value):
    _closed(value, _SOURCE_FIELDS)
    return tuple(_identity(value[key]) for key in ('tenant', 'project', 'provider', 'site', 'resource'))


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise AccessError('invalid_access_authority')
        result[key] = value
    return result


def _file_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _private(path, limit):
    try:
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_uid != os.geteuid() or before.st_nlink != 1):
            raise AccessError('access_authority_unavailable')
        raw = read_private_file(path, limit, single_link=True)
        if _file_identity(before) != _file_identity(path.lstat()) or len(raw) != before.st_size:
            raise AccessError('access_authority_unavailable')
        return raw, _file_identity(before)
    except (OSError, SettingsError):
        raise AccessError('access_authority_unavailable') from None


def _parent_identity(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


@contextmanager
def _instance_update(lock, deadline):
    if not lock.acquire(timeout=max(0, deadline - time.monotonic())):
        raise AccessError('access_authority_unavailable')
    try:
        yield
    finally:
        lock.release()


@contextmanager
def _publication_guard(path, deadline=None):
    """One stable private lock for native loaders/publishers of this actors file.

    The lock is coordination only, never policy. All IO/waits are outside SOURCE.
    Uncooperative same-user mutation of this private parent remains unsupported.
    """
    deadline = time.monotonic() + 2 if deadline is None else deadline
    parent = descriptor = None
    try:
        import fcntl
        # Reuse the private no-follow ancestry and single-link custody check.
        _private(path, 1_048_576)
        before = path.parent.lstat()
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        if _parent_identity(os.fstat(parent)) != _parent_identity(before):
            raise AccessError('access_authority_unavailable')
        name = '.access-publication-' + hashlib.sha256(path.name.encode()).hexdigest() + '.lock'
        descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=parent)
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_size != 0):
            raise AccessError('access_authority_unavailable')
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AccessError('access_authority_unavailable') from None
                time.sleep(min(0.01, remaining))
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (_file_identity(named) != _file_identity(info)
                or _parent_identity(path.parent.lstat()) != _parent_identity(before)):
            raise AccessError('access_authority_unavailable')
        yield
    except (OSError, ImportError):
        raise AccessError('access_authority_unavailable') from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent is not None:
            os.close(parent)


@dataclass(frozen=True, repr=False)
class AccessSession:
    _issuer: object
    _boot: object
    _actor: str
    _principal: str
    _tenant: str
    _credential: bytes
    _generation: int


@dataclass(frozen=True)
class _Snapshot:
    revision: int
    permission_digest: str
    actors: dict
    records: dict
    credentials: dict
    sources: dict
    groups: tuple
    destinations: dict


def _snapshot(payload):
    _closed(payload, {'schema_version', 'revision', 'actors', 'groups', 'sources', 'destinations'})
    if payload['schema_version'] != 2 or type(payload['schema_version']) is not int:
        raise AccessError('invalid_access_authority')
    if type(payload['revision']) is not int or not 1 <= payload['revision'] < 2**63:
        raise AccessError('invalid_access_authority')
    if type(payload['actors']) is not list or not 1 <= len(payload['actors']) <= 256:
        raise AccessError('invalid_access_authority')
    records, actors, credentials = {}, {}, {}
    fields = {'actor_id', 'kind', 'scopes', 'repositories', 'token_file', 'credential_generation',
              'principal_id', 'tenant_id', 'projects', 'delegation_owner', 'delegation_expires_at'}
    for incoming in payload['actors']:
        _closed(incoming, fields)
        record = copy.deepcopy(incoming)
        name = _identity(record['actor_id'])
        if (name in records or type(record['kind']) is not str
                or record['kind'] not in {'client', 'worker', 'operator', 'validator', 'adjudicator'}):
            raise AccessError('invalid_access_authority')
        _identity(record['principal_id'])
        _identity(record['tenant_id'])
        scopes = _strings(record['scopes'])
        repositories = record['repositories']
        if repositories == ['*']:
            repositories = ('*',)
        else:
            repositories = _strings(repositories)
        generation = record['credential_generation']
        if type(generation) is not int or not 1 <= generation < 2**63:
            raise AccessError('invalid_access_authority')
        if type(record['projects']) is not list or len(record['projects']) > 256:
            raise AccessError('invalid_access_authority')
        projects = set()
        for project in record['projects']:
            _closed(project, {'project_id', 'repository_id'})
            binding = _identity(project['project_id']), _identity(project['repository_id'])
            if binding in projects:
                raise AccessError('invalid_access_authority')
            projects.add(binding)
        owner, expires = record['delegation_owner'], record['delegation_expires_at']
        if owner is not None:
            _identity(owner)
            if type(expires) is not int or not 0 < expires <= 253402300799:
                raise AccessError('invalid_access_authority')
        elif expires is not None or record['kind'] == 'worker':
            raise AccessError('invalid_access_authority')
        if type(record['token_file']) is not str:
            raise AccessError('invalid_access_authority')
        raw, _metadata = _private(Path(record['token_file']), 4096)
        try:
            credential = raw.decode('utf-8').strip()
        except UnicodeError:
            raise AccessError('invalid_access_authority') from None
        if len(credential) < 16 or any(character.isspace() for character in credential):
            raise AccessError('invalid_access_authority')
        digest = hashlib.sha256(credential.encode()).digest()
        if digest in credentials:
            raise AccessError('invalid_access_authority')
        credentials[digest] = name
        record['_projects'] = frozenset(projects)
        record['_credential_identity'] = _metadata
        records[name] = record
        actors[name] = Actor(name, record['kind'], frozenset(scopes), frozenset(repositories))
    for record in records.values():
        if record['principal_id'] not in records or (
                record['delegation_owner'] is not None and record['delegation_owner'] not in records):
            raise AccessError('invalid_access_authority')
    groups = payload['groups']
    if type(groups) is not list or len(groups) > 256:
        raise AccessError('invalid_access_authority')
    seen = set()
    for group in groups:
        _closed(group, {'tenant_id', 'group_id', 'members'})
        binding = _identity(group['tenant_id']), _identity(group['group_id'])
        members = _strings(group['members'])
        if binding in seen or any(member not in actors for member in members):
            raise AccessError('invalid_access_authority')
        seen.add(binding)
    sources = {}
    if type(payload['sources']) is not list or len(payload['sources']) > 4096:
        raise AccessError('invalid_access_authority')
    for source in payload['sources']:
        _closed(source, {'key', 'repository_id', 'version', 'deleted', 'readers', 'groups', 'public'})
        key = source_key(source['key'])
        _identity(source['repository_id'])
        _identity(source['version'])
        if key in sources or type(source['deleted']) is not bool or type(source['public']) is not bool:
            raise AccessError('invalid_access_authority')
        _strings(source['readers'])
        _strings(source['groups'])
        sources[key] = copy.deepcopy(source)
    destinations = {}
    if type(payload['destinations']) is not list or len(payload['destinations']) > 256:
        raise AccessError('invalid_access_authority')
    for destination in payload['destinations']:
        _closed(destination, {'destination_id', 'tenant_id', 'project_id', 'repository_id', 'readers', 'public', 'revision'})
        name = _identity(destination['destination_id'])
        for field in ('tenant_id', 'project_id', 'repository_id'):
            _identity(destination[field])
        _strings(destination['readers'])
        if (name in destinations or type(destination['public']) is not bool
                or type(destination['revision']) is not int or destination['revision'] < 1):
            raise AccessError('invalid_access_authority')
        destinations[name] = copy.deepcopy(destination)
    permissions = copy.deepcopy(payload)
    permissions.pop('revision')
    for record in permissions['actors']:
        for field in ('token_file', 'credential_generation'):
            record.pop(field)
    digest = hashlib.sha256(json.dumps(permissions, sort_keys=True, separators=(',', ':'),
                                       allow_nan=False).encode()).hexdigest()
    return _Snapshot(payload['revision'], digest, actors, records, credentials, sources,
                     tuple(copy.deepcopy(groups)), destinations)


class AccessAuthority:
    """One current operator snapshot; SOURCE protects only native memory operations."""

    def __init__(self, path, payload, *, _expected_identity):
        self.path = Path(path)
        self._source = threading.RLock()
        self._updates = threading.Lock()
        self._issuer, self._boot = object(), object()
        self._snapshot = _snapshot(payload)
        _raw, self._identity = _private(self.path, 1_048_576)
        self._parent = _parent_identity(self.path.parent.lstat())
        if self._identity != _expected_identity:
            raise AccessError('access_authority_unavailable')

    @classmethod
    def load(cls, path):
        path = Path(path)
        with _publication_guard(path):
            raw, _metadata = _private(path, 1_048_576)
            try:
                payload = json.loads(raw, object_pairs_hook=_pairs,
                                     parse_constant=lambda _value: (_ for _ in ()).throw(AccessError('invalid_access_authority')))
            except (ValueError, UnicodeError, RecursionError):
                raise AccessError('invalid_access_authority') from None
            return cls(path, payload, _expected_identity=_metadata)

    @property
    def permission_digest(self):
        with self._source:
            if self._snapshot is None:
                raise AccessError('access_authority_unavailable')
            return self._snapshot.permission_digest

    def _live(self):
        # Filesystem work is deliberately outside SOURCE; native updates own the publication cut.
        try:
            if (_file_identity(self.path.lstat()) != self._identity
                    or _parent_identity(self.path.parent.lstat()) != self._parent):
                raise AccessError('access_authority_unavailable')
        except OSError:
            raise AccessError('access_authority_unavailable') from None

    def open_session(self, authorization, scope):
        self._live()
        if (type(authorization) is not str or len(authorization) > 4096
                or not authorization.startswith('Bearer ')):
            raise AccessError('access_denied')
        candidate = hashlib.sha256(authorization[7:].encode()).digest()
        with self._source:
            snapshot = self._snapshot
            if snapshot is None:
                raise AccessError('access_authority_unavailable')
            name = next((actor for digest, actor in snapshot.credentials.items()
                         if hmac.compare_digest(candidate, digest)), None)
            if name is None:
                raise AccessError('access_denied')
            if scope not in snapshot.actors[name].scopes:
                raise AccessError('access_scope_denied')
            record = snapshot.records[name]
            session = AccessSession(self._issuer, self._boot, name, record['principal_id'],
                                    record['tenant_id'], candidate, record['credential_generation'])
        self._credential_live(session)
        return session

    def _credential_live(self, session):
        with self._source:
            _snapshot, record, _principal = self._current(session)
            path, expected = record['token_file'], record['_credential_identity']
        try:
            if _file_identity(Path(path).lstat()) != expected:
                raise AccessError('access_authority_unavailable')
        except OSError:
            raise AccessError('access_authority_unavailable') from None

    def _current(self, session):
        snapshot = self._snapshot
        if (snapshot is None or type(session) is not AccessSession or session._issuer is not self._issuer
                or session._boot is not self._boot or snapshot.credentials.get(session._credential) != session._actor):
            raise AccessError('access_denied')
        record = snapshot.records[session._actor]
        if (record['credential_generation'] != session._generation
                or record['principal_id'] != session._principal or record['tenant_id'] != session._tenant):
            raise AccessError('access_denied')
        return snapshot, record, snapshot.records[record['principal_id']]

    def actor(self, session):
        self._live()
        self._credential_live(session)
        with self._source:
            snapshot, record, _principal = self._current(session)
            return snapshot.actors[record['actor_id']]

    def _authorize(self, session, key, version, scope):
        snapshot, record, principal = self._current(session)
        source = snapshot.sources.get(key)
        if source is None or source['deleted'] or source['version'] != version:
            return False
        subjects = [record, principal]
        if record['delegation_owner'] is not None:
            if record['delegation_expires_at'] <= time.time():
                return False
            subjects.append(snapshot.records[record['delegation_owner']])
        for subject in subjects:
            actor = snapshot.actors[subject['actor_id']]
            if (scope not in actor.scopes or subject['tenant_id'] != key[0]
                    or ('*' not in actor.repositories and source['repository_id'] not in actor.repositories)
                    or (key[1], source['repository_id']) not in subject['_projects']):
                return False
        return bool(source['public'] or principal['actor_id'] in source['readers'] or any(
            group['tenant_id'] == key[0] and group['group_id'] in source['groups']
            and principal['actor_id'] in group['members'] for group in snapshot.groups))

    def authorize(self, session, source, version, scope):
        try:
            self._live()
            self._credential_live(session)
            key = source_key(source)
            if scope not in {'source:read', 'source:release'}:
                return False
            with self._source:
                return self._authorize(session, key, version, scope)
        except AccessError:
            return False

    def _release_binding(self, session, lineage, destination_id):
        """Pure, bounded current-state checks. Caller holds SOURCE."""
        snapshot, record, principal = self._current(session)
        destination = snapshot.destinations.get(destination_id)
        if (destination is None or not 1 <= len(lineage) <= 128
                or len(destination['readers']) > 16
                or not destination['public'] and principal['actor_id'] not in destination['readers']):
            raise AccessError('access_denied')
        for key, version, _digest in lineage:
            if (not self._authorize(session, key, version, 'source:release')
                    or (destination['tenant_id'], destination['project_id']) != key[:2]
                    or destination['repository_id'] != snapshot.sources[key]['repository_id']):
                raise AccessError('access_denied')
            source = snapshot.sources[key]
            if destination['public'] and not source['public']:
                raise AccessError('access_denied')
            for recipient in destination['readers']:
                subject = snapshot.records.get(recipient)
                if subject is None or subject['principal_id'] != recipient:
                    raise AccessError('access_denied')
                credential = next(digest for digest, name in snapshot.credentials.items() if name == recipient)
                audience_session = AccessSession(self._issuer, self._boot, recipient, recipient,
                    subject['tenant_id'], credential, subject['credential_generation'])
                if not self._authorize(audience_session, key, version, 'source:read'):
                    raise AccessError('access_denied')
        return (snapshot.revision, snapshot.permission_digest, destination['revision'], principal['actor_id'])

    def release_binding(self, session, lineage, destination_id):
        self._live()
        self._credential_live(session)
        with self._source:
            started = time.monotonic()
            binding = self._release_binding(session, lineage, destination_id)
            if time.monotonic() - started > 0.005:
                raise AccessError('access_authority_unavailable')
            return binding

    def _queue_cut(self, prepared, queue, entry=None):
        # Fixed native queue code only. No callbacks, DB, file or transport work in SOURCE.
        from .access_release import _NativeQueue, _Prepared
        if type(prepared) is not _Prepared or type(queue) is not _NativeQueue:
            raise AccessError('access_denied')
        self._live()
        self._credential_live(prepared.session)
        with self._source:
            started = time.monotonic()
            current = self._release_binding(prepared.session, prepared.lineage, prepared.destination)
            if current != prepared.authority or time.monotonic() - started > 0.005:
                raise AccessError('access_denied')
            return queue._cut(prepared, entry)

    def update(self, session, expected_revision, payload):
        # Serialize operator mutations, never block SOURCE on file IO or credential acquisition.
        deadline = time.monotonic() + 2
        with _instance_update(self._updates, deadline), _publication_guard(self.path, deadline):
            self._live()
            self._credential_live(session)
            with self._source:
                old, record, _principal = self._current(session)
                actor = old.actors[record['actor_id']]
                if actor.kind != 'operator' or 'factory:access-admin' not in actor.scopes:
                    raise AccessError('access_denied')
                if type(expected_revision) is not int or expected_revision != old.revision:
                    raise AccessError('stale_access_revision')
            try:
                raw = json.dumps(payload, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
                if len(raw) > 1_048_576:
                    raise AccessError('invalid_access_authority')
                owned = json.loads(raw, object_pairs_hook=_pairs)
            except (ValueError, TypeError, UnicodeError, RecursionError):
                raise AccessError('invalid_access_authority') from None
            proposed = _snapshot(owned)
            if proposed.revision != expected_revision + 1:
                raise AccessError('stale_access_revision')
            for name, prior in old.records.items():
                current = proposed.records.get(name)
                if current is None:
                    continue
                old_digest = next(key for key, value in old.credentials.items() if value == name)
                new_digest = next(key for key, value in proposed.credentials.items() if value == name)
                changed = (old_digest != new_digest or prior['token_file'] != current['token_file']
                           or prior['principal_id'] != current['principal_id'] or prior['tenant_id'] != current['tenant_id'])
                if (current['credential_generation'] < prior['credential_generation'] or changed
                        and current['credential_generation'] <= prior['credential_generation']):
                    raise AccessError('stale_credential_generation')
            descriptor, temporary = tempfile.mkstemp(prefix='.access-update-', dir=self.path.parent)
            replaced = False
            try:
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, 'wb') as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                if _file_identity(self.path.lstat()) != self._identity:
                    raise AccessError('access_authority_unavailable')
                os.replace(temporary, self.path)
                replaced = True
                directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
                _raw, identity = _private(self.path, 1_048_576)
                if _raw != raw or _parent_identity(self.path.parent.lstat()) != self._parent:
                    raise AccessError('access_authority_unavailable')
                with self._source:
                    self._snapshot = proposed
                    self._identity = identity
                return proposed.revision
            except (OSError, AccessError):
                if replaced:
                    with self._source:
                        self._snapshot = None
                raise AccessError('access_authority_unavailable') from None
            finally:
                if not replaced:
                    try:
                        os.unlink(temporary)
                    except FileNotFoundError:
                        pass
