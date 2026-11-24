"""Windows publication owner using the canonical held-handle reader and Native."""
from __future__ import annotations

from . import security_data_windows as reader

SecurityDataError = reader.SecurityDataError


class SnapshotStore(reader.SnapshotReader):
    def lock_publication(self):
        parent = self.directory(())
        try:
            try:
                handle = self.native.open(parent.handle, '.publication.lock', directory=False, create=True, exclusive=True)
            except FileExistsError:
                handle = self.native.open(parent.handle, '.publication.lock', directory=False, exclusive=True)
            try:
                self._metadata(handle, owned=True, directory=False, maximum=65536)
                self.confirm()
            except BaseException:
                self.native.close(handle)
                raise
            self.publication_lock = handle
        except OSError as error:
            raise reader.SecurityDataError('snapshot publication is busy or locking is unavailable') from error

    def remove_owned(self, parts):
        parent = self.directory(parts[:-1])
        held = self._file(parent, parts[-1], 65536)
        self.confirm()
        self.native.discard(held.handle)
        self.files.pop((parent.handle, parts[-1]))
        self.native.close(held.handle)
        self.expect_absent(parts)

    def write(self, parts, payload):
        parent = self.directory(parts[:-1], create=True)
        name = reader._component(parts[-1])
        try:
            previous = self._file(parent, name, 1024 * 1024 * 1024)
        except FileNotFoundError:
            previous = None
        temporary = f'.{name}.{reader.uuid.uuid4().hex}.partial'
        handle = self.native.open(parent.handle, temporary, directory=False, create=True, temporary=True)
        committed = False
        unresolved = False
        try:
            offset = 0
            while offset < len(payload):
                block = payload[offset:offset + 1024 * 1024]
                written = self.native.write(handle, block)
                if not 0 < written <= len(block):
                    raise reader.SecurityDataError('incomplete native snapshot write')
                offset += written
            self.native.flush(handle)
            before = self._metadata(handle, owned=True, directory=False, maximum=len(payload))
            actual = self._read(handle, len(payload))
            if (before.size != len(payload) or reader.hashlib.sha256(actual).digest() != reader.hashlib.sha256(payload).digest()
                    or self._metadata(handle, owned=True, directory=False).identity() != before.identity()):
                raise reader.SecurityDataError('snapshot native temporary changed before publication')
            probe = self.native.open(parent.handle, temporary, directory=False, inspect=True)
            try:
                if self._metadata(probe, owned=True, directory=False).identity() != before.identity():
                    raise reader.SecurityDataError('snapshot native temporary name was replaced')
            finally:
                self.native.close(probe)
            self.confirm()
            key = parent.handle, name
            if previous:
                # Ordinary native replacement refuses an open destination.
                # Release only our verified witness, retaining every parent
                # and unrelated reader. On failure _file() reopens the old name.
                self.native.close(self.files.pop(key).handle)
            if self.before_replace is not None:
                self.before_replace()
                self.confirm()
            try:
                self.native.rename(handle, parent.handle, name, replace=previous is not None)
            except reader.SecurityDataError as error:
                unresolved = bool(getattr(error, 'native_rename_unresolved', False))
                raise
            committed = True
            self.last_replaced = parts
            metadata = self._metadata(handle, owned=True, directory=False)
            self.files[key] = reader.Held(handle, parent.handle, name, metadata.identity(), True)
            handle = None  # held file now owns it
            self.confirm()
            self.native.flush(self.files[key].handle)
        finally:
            if handle is not None:
                if not committed and not unresolved:
                    try:
                        with reader.contextlib.suppress(OSError):
                            self.native.discard(handle)  # delete only the exact owned object
                    finally:
                        self.native.close(handle)
                else:
                    self.native.close(handle)
