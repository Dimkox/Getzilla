"""Snapshot publication owner. Readers import this leaf only on a write call."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any
from . import security_data as reader

SecurityDataError = reader.SecurityDataError


class SnapshotWriter(reader._SnapshotStore):
    def lock_publication(self) -> None:
        """Serialize supported publishers without waiting on another writer."""
        try:
            import fcntl
        except ImportError:
            raise reader.SecurityDataError('snapshot publication locking is unavailable') from None
        parent = self.directory(())
        name = '.publication.lock'
        try:
            descriptor = reader.fsx.open_at(parent.descriptor, name,
                reader.os.O_RDWR | reader.os.O_CREAT | reader.os.O_EXCL | reader.os.O_NOFOLLOW | reader.os.O_CLOEXEC, 0o600)
        except FileExistsError:
            pass
        else:
            reader.os.close(descriptor)
        file = self._pin_file(parent, name, reader.MAX_MANIFEST_BYTES)
        try:
            fcntl.flock(file.descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise reader.SecurityDataError('snapshot publication is busy or locking is unavailable') from None
        self.confirm()

    def write(self, parts: tuple[str, ...], payload: bytes):
        parent = self.directory(parts[:-1], create=True)
        name, key = parts[-1], (parent.descriptor, parts[-1])
        try:
            previous = self._pin_file(parent, name, reader.MAX_PAYLOAD_BYTES)
        except FileNotFoundError:
            previous = None
        temporary = f'.{name}.{reader.uuid.uuid4().hex}.partial'
        descriptor = reader.fsx.open_at(parent.descriptor, temporary,
            reader.os.O_RDWR | reader.os.O_CREAT | reader.os.O_EXCL | reader.os.O_NOFOLLOW | reader.os.O_NONBLOCK | reader.os.O_CLOEXEC, 0o600)
        try:
            self.confirm()
            offset = 0
            while offset < len(payload):
                written = reader.os.write(descriptor, memoryview(payload)[offset:offset + 1024 * 1024])
                if written < 1:
                    raise OSError('incomplete snapshot temporary write')
                offset += written
            reader.os.fsync(descriptor)
            before = reader.os.fstat(descriptor)
            if not reader.stat.S_ISREG(before.st_mode) or before.st_size != len(payload):
                raise reader.SecurityDataError('snapshot temporary is not the expected regular file')
            reader.os.lseek(descriptor, 0, reader.os.SEEK_SET)
            digest, size = reader.hashlib.sha256(), 0
            while chunk := reader.os.read(descriptor, min(1024 * 1024, len(payload) + 1 - size)):
                self.read_bytes += len(chunk)
                if self.read_bytes > reader.MAX_STORE_READ_BYTES:
                    raise reader.SecurityDataError('snapshot aggregate read budget exceeded')
                digest.update(chunk)
                size += len(chunk)
                if size > len(payload):
                    break
            named = reader.fsx.lstat_at(parent.descriptor, temporary)
            if (size != len(payload) or digest.digest() != reader.hashlib.sha256(payload).digest()
                    or reader._file_identity(reader.os.fstat(descriptor)) != reader._file_identity(before)
                    or reader._file_identity(named) != reader._file_identity(before)):
                raise reader.SecurityDataError('snapshot temporary changed before publication')
            self.confirm()
            if previous is None:
                try:
                    reader.fsx.lstat_at(parent.descriptor, name)
                except FileNotFoundError:
                    pass
                else:
                    raise reader.SecurityDataError('snapshot target appeared during publication')
            if self.before_replace is not None:
                self.before_replace()
                self.confirm()
            reader.fsx.replace_at(parent.descriptor, temporary, parent.descriptor, name)
            self.last_replaced = parts
            temporary = None
            if key in self.files:
                reader.os.close(self.files.pop(key).descriptor)
            after = reader.os.fstat(descriptor)
            self.files[key] = reader._File(reader.os.dup(descriptor), parent.descriptor, name, reader._file_identity(after))
            self.confirm()
            reader.fsx.fsync_dir(parent.descriptor)
        finally:
            if temporary is not None:
                with reader.contextlib.suppress(OSError):
                    named = reader.fsx.lstat_at(parent.descriptor, temporary)
                    opened = reader.os.fstat(descriptor)
                    if reader.stat.S_ISREG(named.st_mode) and (named.st_dev, named.st_ino) == (opened.st_dev, opened.st_ino):
                        reader.fsx.unlink_at(parent.descriptor, temporary)
            reader.os.close(descriptor)

    def remove_owned(self, parts: tuple[str, ...]) -> None:
        """Remove only the exact held protocol file, never a replacement."""
        parent = self.directory(parts[:-1])
        self._pin_file(parent, parts[-1], reader.MAX_MANIFEST_BYTES)
        self.confirm()
        reader.fsx.unlink_at(parent.descriptor, parts[-1])
        file = self.files.pop((parent.descriptor, parts[-1]))
        reader.os.close(file.descriptor)



def publish_snapshot(database: Path, source_id: str, payload: bytes, *, acquisition: dict[str, Any],
                     coverage: dict[str, Any], now: datetime | None = None, before_commit=None) -> dict[str, Any]:
    """Commit the authoritative pointer after its object; pre-commit failures keep the old pointer."""
    folder = reader._source_directory(database, source_id)
    current = reader._clock(now)
    if not isinstance(payload, bytes):
        raise reader.SecurityDataError('snapshot payload must be bytes')
    document = {'schema_version': 1, 'source_id': source_id, 'source_url': reader.SOURCE_URLS[source_id],
                'content_sha256': reader.hashlib.sha256(payload).hexdigest(), 'payload_size': len(payload),
                'acquisition': reader._acquisition(acquisition), 'coverage': reader._coverage(coverage)}
    evidence = reader._validate(document, payload, source_id, now=current, required_scope=None)
    serialized = (reader.json.dumps(document, sort_keys=True) + '\n').encode('utf-8')
    if len(serialized) > reader.MAX_MANIFEST_BYTES:
        raise reader.SecurityDataError('snapshot manifest is too large')
    source_parts = folder.relative_to(Path(database)).parts
    target = ('.snapshots', 'sha256', document['content_sha256'])
    pointer = (*source_parts, 'snapshot.json')
    pending = (*source_parts, '.publication-pending.json')
    try:
        with reader._snapshot_store(database, create=True) as store:
            store.lock_publication()
            # Bind both trees before creating an object or committing a pointer.
            store.directory(source_parts, create=True)
            store.directory(target[:-1], create=True)
            try:
                store.read(pending, reader.MAX_MANIFEST_BYTES)
            except FileNotFoundError:
                pass
            else:
                raise reader.SecurityDataError('snapshot commit_unknown; checked reconciliation is required')
            try:
                existing = store.read(target, len(payload))
            except FileNotFoundError:
                store.write(target, payload)
            else:
                if existing != payload:
                    raise reader.SecurityDataError('existing immutable snapshot object differs; repair the cache')
            staged = reader.json.dumps({'schema_version': 1, 'source_id': source_id,
                                 'next_manifest_sha256': reader.hashlib.sha256(serialized).hexdigest()}).encode('utf-8')
            store.write(pending, staged)
            try:
                def final_inputs():
                    reader._freshness(document['acquisition'], source_id, reader._clock(now))
                    if before_commit is not None:
                        before_commit()
                    reader._freshness(document['acquisition'], source_id, reader._clock(now))
                store.before_replace = final_inputs
                store.write(pointer, serialized)
            except BaseException as error:
                if store.last_replaced == pointer:
                    # The durable precommit marker keeps later consumers from
                    # accepting an indeterminate pointer switch.
                    if not isinstance(error, Exception):
                        raise
                    raise reader.SecurityDataError('snapshot commit_unknown; checked reconciliation is required') from error
                store.remove_owned(pending)
                raise
            finally:
                store.before_replace = None
            if source_id.startswith('osv:'):
                # Non-authoritative compatibility export, after pointer commit.
                # A safe I/O failure does not erase the committed snapshot.
                try:
                    store.write((*source_parts, 'all.zip'), payload)
                except OSError as exc:
                    store.confirm()
                    evidence['compatibility_export_warning'] = type(exc).__name__
            store.confirm()
            store.remove_owned(pending)
            # Pointer/object durability was already confirmed. If marker
            # removal is not durable, it can only reappear and refuse a read.
            try:
                directory = store.directory(source_parts)
                if hasattr(directory, 'descriptor'):
                    reader.fsx.fsync_dir(directory.descriptor)
                else:
                    store.native.flush(directory.handle)
            except (OSError, reader.SecurityDataError):
                evidence['publication_cleanup_warning'] = 'pending-marker durability unavailable'
            evidence['publication_outcome'] = 'committed'
    except OSError as exc:
        raise reader.SecurityDataError('snapshot publication failed before a confirmed commit') from exc
    return evidence


def copy_snapshot(source_database: Path, destination_database: Path, source_id: str, *,
                  now: datetime | None = None, required_scope: set[str] | None = None) -> dict[str, Any]:
    """Copy a valid snapshot without refreshing its original acquisition time."""
    payload, evidence = reader.read_snapshot(source_database, source_id, now=now, required_scope=required_scope)
    if source_id.startswith('osv:') or source_id == reader.OSV_QUERY_SOURCE:
        reader.confirm_snapshots(source_database, [evidence], now=now)
    return publish_snapshot(destination_database, source_id, payload, acquisition=evidence['acquisition'],
                            coverage=evidence['coverage'], now=now)

