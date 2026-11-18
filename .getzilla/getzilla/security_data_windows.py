"""Local NTFS snapshot I/O. No path/lstat fallback; native handles own every use.

Current user, SYSTEM and Administrators retain the same exclusive-writer trust
as UID/root on POSIX. TrustedInstaller is resolved locally for ancestry only.
Directory handles deny delete sharing; file handles deny write sharing.
"""
from __future__ import annotations

import ctypes as C
import contextlib
import hashlib
import itertools
import json
import os
import re
import uuid
from dataclasses import dataclass
from pathlib import PureWindowsPath

from .security_data import SecurityDataError

U32, U16, U8, HANDLE = C.c_uint32, C.c_uint16, C.c_ubyte, C.c_void_p
_READ = 0x120089  # FILE_GENERIC_READ (includes READ_CONTROL and SYNCHRONIZE)
_DIRECTORY = 0x1200A1  # list/traverse/read attributes/security/synchronize
_WRITE = 0x13019F  # FILE_GENERIC_READ|FILE_GENERIC_WRITE|DELETE
_DESTRUCTIVE = 0xD0150  # DELETE, WRITE_DAC/OWNER, DELETE_CHILD, WRITE_EA/ATTRIBUTES
_OWNED_WRITE = _DESTRUCTIVE | 0x6  # also add-file/add-subdirectory (write/append)
_ROOT_SELF = 0x10110  # DELETE, WRITE_EA/ATTRIBUTES on the proven volume root itself


class _Unicode(C.Structure):
    _fields_ = [('Length', U16), ('MaximumLength', U16), ('Buffer', HANDLE)]


class _Attributes(C.Structure):
    _fields_ = [('Length', U32), ('RootDirectory', HANDLE), ('ObjectName', C.POINTER(_Unicode)),
                ('Attributes', U32), ('SecurityDescriptor', HANDLE), ('SecurityQualityOfService', HANDLE)]


class _Status(C.Structure):
    _fields_ = [('Status', HANDLE), ('Information', C.c_size_t)]


class _FileId(C.Structure):
    _fields_ = [('Volume', C.c_uint64), ('Id', U8 * 16)]


class _Basic(C.Structure):
    _fields_ = [('Creation', C.c_int64), ('Access', C.c_int64), ('Write', C.c_int64),
                ('Change', C.c_int64), ('Attributes', U32)]


class _Standard(C.Structure):
    _fields_ = [('Allocation', C.c_int64), ('Size', C.c_int64), ('Links', U32),
                ('DeletePending', U8), ('Directory', U8)]


class _Rename(C.Structure):
    _fields_ = [('Replace', U8), ('Root', HANDLE), ('Length', U32), ('Name', U16 * 1)]


@dataclass(frozen=True)
class Metadata:
    file_id: tuple
    attributes: int
    directory: bool
    links: int
    size: int
    write: int
    change: int
    security: tuple

    def identity(self):
        stable = self.file_id, self.attributes, self.directory, self.security
        return stable if self.directory else (*stable, self.links, self.size, self.write, self.change)


def check_acl(owner, aces, trusted, *, owned, volume_root=False):
    """Conservative effective ACE policy; creation of siblings is not replacement."""
    if owner not in trusted:
        raise SecurityDataError('snapshot native owner is not trusted')
    if volume_root and owned:
        raise SecurityDataError('snapshot native volume-root role is invalid')
    for kind, flags, mask, sid in aces:
        if kind not in {0, 1}:
            raise SecurityDataError('snapshot DACL has an unsupported ACE type')
        if kind == 1 or flags & 0x8:  # deny or inherit-only: grants no current access
            continue
        expanded = mask
        if mask & 0x10000000:
            expanded |= 0x1F01FF
        if mask & 0x40000000:
            expanded |= 0x120116
        forbidden = _OWNED_WRITE if owned else _DESTRUCTIVE
        if volume_root:
            # Only the independently proven, held physical root can omit its
            # own deletion/metadata rights. Child removal and security changes
            # remain forbidden; generic write/all grants remain conservative.
            forbidden &= ~_ROOT_SELF
        # OWNER RIGHTS names this descriptor's already-checked owner, not the
        # CREATOR OWNER inheritance placeholder. Do not infer implicit rights.
        trustee = owner if sid == 'S-1-3-4' else sid
        if trustee not in trusted and (expanded & forbidden or volume_root and mask & 0x50000000):
            raise SecurityDataError('snapshot native DACL permits untrusted writes or path replacement')


def _diagnostic_sid(value):
    # SID text only, never an account name, path or raw descriptor. This is an
    # output filter, not a trust decision or an alternative security parser.
    return value if (type(value) is str and len(value) <= 192 and re.fullmatch(
        r'S-1-(?:[0-9]{1,15}|0x[0-9a-fA-F]{12})(?:-[0-9]{1,10}){0,15}', value)) else None


def _acl_diagnostic(native, security, *, owned, directory, ancestor_depth):
    def number(value, maximum):
        return value if type(value) is int and 0 <= value <= maximum else None

    def principals(values):
        if type(values) not in {set, frozenset, tuple, list}:
            return [], None
        selected = [_diagnostic_sid(value) for value in itertools.islice(values, 8)]
        valid = sorted(value for value in selected if value is not None)
        return valid, len(values) - len(valid)

    trusted, trusted_omitted = principals(native.trusted)
    ancestors, ancestors_omitted = principals(native.ancestors)
    aces = security[1]
    count = len(aces) if type(aces) in {tuple, list} else None
    entries = []
    for ace in itertools.islice(aces if count is not None else (), 32):
        kind, flags, mask, sid = ace if type(ace) in {tuple, list} and len(ace) == 4 else (None,) * 4
        entries.append({'kind': number(kind, 255), 'flags': number(flags, 255),
                        'mask': number(mask, 0xffffffff), 'sid': _diagnostic_sid(sid)})
    service = getattr(native, 'service_owner', None)
    lookup = ('unknown' if not hasattr(native, 'service_owner') else 'unavailable' if service is None
              else 'resolved' if _diagnostic_sid(service) is not None else 'invalid')
    return {'schema_version': 1,
            'role': ('owned-directory' if directory else 'owned-file') if owned else
                    'volume-root' if ancestor_depth == 0 else 'ancestor',
            'ancestor_depth': number(ancestor_depth, 128), 'owner_sid': _diagnostic_sid(security[0]),
            'aces': entries, 'ace_count': count, 'aces_omitted': count - len(entries) if count is not None else None,
            'dacl_protected': security[2] if len(security) > 2 and type(security[2]) is bool else None,
            'trusted_sids': trusted, 'trusted_sids_omitted': trusted_omitted,
            'ancestor_sids': ancestors, 'ancestor_sids_omitted': ancestors_omitted,
            'trustedinstaller_lookup': lookup}


def _component(name):
    if (not isinstance(name, str) or not name or len(name) > 255 or name in {'.', '..'}
            or re.search(r'[\\/:<>"|?*\x00-\x1f\ud800-\udfff]', name) or name[-1] in '. '
            or re.fullmatch(r'(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?', name)):
        raise SecurityDataError('snapshot name is not a physical Windows component')
    return name


class Native:
    """Small typed Win32/NT binding; instantiated only on Windows."""

    def __init__(self):
        if os.name != 'nt':
            raise SecurityDataError('native Windows snapshot handles unavailable')
        self.k = C.WinDLL('kernel32', use_last_error=True)
        self.a = C.WinDLL('advapi32', use_last_error=True)
        self.n = C.WinDLL('ntdll', use_last_error=True)
        for dll, name, args, result in (
            (self.k, 'CloseHandle', [HANDLE], C.c_int),
            (self.k, 'GetCurrentProcess', [], HANDLE),
            (self.k, 'LocalFree', [HANDLE], HANDLE),
            (self.k, 'GetDriveTypeW', [C.c_wchar_p], U32),
            (self.k, 'QueryDosDeviceW', [C.c_wchar_p, C.c_wchar_p, U32], U32),
            (self.k, 'GetFileType', [HANDLE], U32),
            (self.k, 'GetVolumeInformationByHandleW', [HANDLE, HANDLE, U32, HANDLE, HANDLE, C.POINTER(U32), C.c_wchar_p, U32], C.c_int),
            (self.k, 'GetFileInformationByHandleEx', [HANDLE, C.c_int, HANDLE, U32], C.c_int),
            (self.k, 'ReadFile', [HANDLE, HANDLE, U32, C.POINTER(U32), HANDLE], C.c_int),
            (self.k, 'WriteFile', [HANDLE, HANDLE, U32, C.POINTER(U32), HANDLE], C.c_int),
            (self.k, 'SetFilePointerEx', [HANDLE, C.c_int64, HANDLE, U32], C.c_int),
            (self.k, 'FlushFileBuffers', [HANDLE], C.c_int),
            (self.k, 'SetFileInformationByHandle', [HANDLE, C.c_int, HANDLE, U32], C.c_int),
            (self.a, 'OpenProcessToken', [HANDLE, U32, C.POINTER(HANDLE)], C.c_int),
            (self.a, 'GetTokenInformation', [HANDLE, C.c_int, HANDLE, U32, C.POINTER(U32)], C.c_int),
            (self.a, 'ConvertSidToStringSidW', [HANDLE, C.POINTER(HANDLE)], C.c_int),
            (self.a, 'LookupAccountNameW', [C.c_wchar_p, C.c_wchar_p, HANDLE, C.POINTER(U32), C.c_wchar_p, C.POINTER(U32), C.POINTER(U32)], C.c_int),
            (self.a, 'ConvertStringSecurityDescriptorToSecurityDescriptorW', [C.c_wchar_p, U32, C.POINTER(HANDLE), HANDLE], C.c_int),
            (self.a, 'GetSecurityInfo', [HANDLE, C.c_int, U32, C.POINTER(HANDLE), HANDLE, C.POINTER(HANDLE), HANDLE, C.POINTER(HANDLE)], U32),
            (self.a, 'GetSecurityDescriptorControl', [HANDLE, C.POINTER(U16), C.POINTER(U32)], C.c_int),
            (self.a, 'GetAce', [HANDLE, U32, C.POINTER(HANDLE)], C.c_int),
            (self.n, 'NtCreateFile', [C.POINTER(HANDLE), U32, C.POINTER(_Attributes), C.POINTER(_Status), HANDLE, U32, U32, U32, U32, HANDLE, U32], C.c_int32),
            (self.n, 'RtlNtStatusToDosError', [C.c_int32], U32),
        ):
            fn = getattr(dll, name)
            fn.argtypes, fn.restype = args, result
        token, needed = HANDLE(), U32()
        self._ok(self.a.OpenProcessToken(self.k.GetCurrentProcess(), 8, C.byref(token)))
        try:
            self.a.GetTokenInformation(token, 1, None, 0, C.byref(needed))
            if not 0 < needed.value <= 65536:
                raise SecurityDataError('snapshot current-user token is unavailable')
            buffer = C.create_string_buffer(needed.value)
            self._ok(self.a.GetTokenInformation(token, 1, buffer, needed, C.byref(needed)))
            self.user = self._sid(HANDLE.from_buffer(buffer).value)
        finally:
            self.close(token)
        self.trusted = {self.user, 'S-1-5-18', 'S-1-5-32-544'}
        self.ancestors = set(self.trusted)
        service = self._lookup_service()
        self.service_owner = service
        if service:
            self.ancestors.add(service)
        self.sd = HANDLE()
        sddl = f'O:{self.user}D:P(A;OICI;FA;;;{self.user})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
        self._ok(self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, C.byref(self.sd), None))

    @staticmethod
    def _ok(result):
        if not result:
            raise C.WinError(C.get_last_error())

    def close(self, handle):
        self.k.CloseHandle(handle)

    def shutdown(self):
        if self.sd:
            self.k.LocalFree(self.sd)
            self.sd = None

    def _sid(self, pointer):
        out = HANDLE()
        self._ok(self.a.ConvertSidToStringSidW(pointer, C.byref(out)))
        try:
            return C.wstring_at(out)
        finally:
            self.k.LocalFree(out)

    def _lookup_service(self):
        size, domain_size, use = U32(), U32(), U32()
        self.a.LookupAccountNameW(None, 'NT SERVICE\\TrustedInstaller', None, C.byref(size), None, C.byref(domain_size), C.byref(use))
        if not 0 < size.value <= 1024 or domain_size.value > 1024:
            return None
        sid, domain = C.create_string_buffer(size.value), C.create_unicode_buffer(max(1, domain_size.value))
        if not self.a.LookupAccountNameW(None, 'NT SERVICE\\TrustedInstaller', sid, C.byref(size), domain, C.byref(domain_size), C.byref(use)):
            return None
        if domain.value.casefold() != 'nt service':
            return None
        return self._sid(C.addressof(sid))

    def open(self, parent, name, *, directory, create=False, temporary=False, inspect=False):
        if parent is not None:
            _component(name)
        encoded = name.encode('utf-16-le')
        buffer = C.create_string_buffer(encoded + b'\0\0')
        text = _Unicode(len(encoded), len(encoded) + 2, C.addressof(buffer))
        attrs = _Attributes(C.sizeof(_Attributes), parent, C.pointer(text), 0x40,
                            self.sd if create else None, None)
        result, status = HANDLE(), _Status()
        access = _DIRECTORY if directory else (_WRITE if temporary else _READ)
        # No write/delete sharing on directories pins ancestry and reparse state.
        # Child creation uses the held parent, not a new writable directory handle.
        share = 1 if directory else (7 if inspect else 5)
        code = self.n.NtCreateFile(C.byref(result), access, C.byref(attrs), C.byref(status), None,
                                   0x10 if directory else 0x80, share, 2 if create else 1,
                                   0x200020 | (1 if directory else 0x40), None, 0)
        if code < 0:
            raise C.WinError(self.n.RtlNtStatusToDosError(code))
        return result.value

    def root(self, drive):
        if self.k.GetDriveTypeW(drive) != 3:
            raise SecurityDataError('snapshot Windows store requires a local fixed NTFS volume')
        device = C.create_unicode_buffer(32768)
        self._ok(self.k.QueryDosDeviceW(drive[:2], device, len(device)))
        if not re.fullmatch(r'\\Device\\HarddiskVolume[0-9]+', device.value):
            raise SecurityDataError('snapshot Windows store refuses redirected/substituted drive roots')
        handle = self.open(None, device.value + '\\', directory=True)
        try:
            name, flags = C.create_unicode_buffer(32), U32()
            self._ok(self.k.GetVolumeInformationByHandleW(handle, None, 0, None, None, C.byref(flags), name, 32))
            if name.value != 'NTFS' or not flags.value & 8:
                raise SecurityDataError('snapshot Windows store requires NTFS persistent ACLs')
            self.verify_root(handle)
            return handle
        except BaseException:
            self.close(handle)
            raise

    def verify_root(self, handle):
        # FILE_NAME_INFO is volume-relative. A larger/truncated/failed result
        # cannot prove root. Never infer this role from a drive letter or depth.
        name = C.create_string_buffer(8)
        self._ok(self.k.GetFileInformationByHandleEx(handle, 2, name, len(name)))
        if int.from_bytes(name.raw[:4], 'little') != 2 or name.raw[4:6] != b'\\\x00':
            raise SecurityDataError('snapshot native volume root proof failed')

    def security(self, handle):
        owner, acl, sd = HANDLE(), HANDLE(), HANDLE()
        error = self.a.GetSecurityInfo(handle, 1, 5, C.byref(owner), None, C.byref(acl), None, C.byref(sd))
        if error:
            raise C.WinError(error)
        try:
            if not owner.value or not acl.value:
                raise SecurityDataError('snapshot owner or DACL is unavailable/null')
            header = C.string_at(acl, 8)
            size, count = int.from_bytes(header[2:4], 'little'), int.from_bytes(header[4:6], 'little')
            if not 8 <= size <= 65535 or count > 4096:
                raise SecurityDataError('snapshot DACL exceeds its bound')
            aces = []
            for index in range(count):
                ace = HANDLE()
                self._ok(self.a.GetAce(acl, index, C.byref(ace)))
                data = C.string_at(ace, 4)
                length = int.from_bytes(data[2:4], 'little')
                if not acl.value + 8 <= ace.value <= acl.value + size - length or length < 16:
                    raise SecurityDataError('snapshot DACL ACE is malformed')
                if data[0] not in {0, 1}:
                    raise SecurityDataError('snapshot DACL has an unsupported ACE type')
                raw = C.string_at(ace, length)
                if raw[8] != 1 or 8 + 8 + raw[9] * 4 > length:
                    raise SecurityDataError('snapshot DACL SID is malformed')
                aces.append((raw[0], raw[1], int.from_bytes(raw[4:8], 'little'), self._sid(ace.value + 8)))
            control, revision = U16(), U32()
            self._ok(self.a.GetSecurityDescriptorControl(sd, C.byref(control), C.byref(revision)))
            return self._sid(owner), tuple(aces), bool(control.value & 0x1000)
        finally:
            self.k.LocalFree(sd)

    def metadata(self, handle):
        if self.k.GetFileType(handle) != 1:
            raise SecurityDataError('snapshot handle is not a disk object')
        identity, basic, standard = _FileId(), _Basic(), _Standard()
        for kind, value in ((18, identity), (0, basic), (1, standard)):
            self._ok(self.k.GetFileInformationByHandleEx(handle, kind, C.byref(value), C.sizeof(value)))
        if not any(identity.Id):
            raise SecurityDataError('snapshot native file ID is unavailable')
        if bool(basic.Attributes & 0x10) != bool(standard.Directory):
            raise SecurityDataError('snapshot native file type is inconsistent')
        if basic.Attributes & 0x400 or standard.DeletePending:
            raise SecurityDataError('snapshot handle is reparse or delete-pending')
        if not standard.Directory and standard.Links != 1:
            raise SecurityDataError('snapshot regular file is hardlinked')
        return Metadata((identity.Volume, bytes(identity.Id)), basic.Attributes, bool(standard.Directory),
                        standard.Links, standard.Size, basic.Write, basic.Change, self.security(handle))

    def seek(self, handle):
        self._ok(self.k.SetFilePointerEx(handle, 0, None, 0))

    def read(self, handle, size):
        buffer, count = C.create_string_buffer(size), U32()
        self._ok(self.k.ReadFile(handle, buffer, size, C.byref(count), None))
        return buffer.raw[:count.value]

    def write(self, handle, payload):
        count = U32()
        self._ok(self.k.WriteFile(handle, C.c_char_p(payload), len(payload), C.byref(count), None))
        return count.value

    def flush(self, handle):
        self._ok(self.k.FlushFileBuffers(handle))

    def rename(self, handle, parent, name, *, replace):
        _component(name)
        encoded = name.encode('utf-16-le')
        buffer = C.create_string_buffer(max(C.sizeof(_Rename), _Rename.Name.offset + len(encoded)))
        info = _Rename.from_buffer(buffer)
        info.Replace, info.Root, info.Length = bool(replace), parent, len(encoded)
        C.memmove(C.addressof(buffer) + _Rename.Name.offset, encoded, len(encoded))
        self._ok(self.k.SetFileInformationByHandle(handle, 3, buffer, len(buffer)))

    def discard(self, handle):
        delete = U8(1)
        self._ok(self.k.SetFileInformationByHandle(handle, 4, C.byref(delete), 1))


@dataclass(frozen=True)
class Held:
    handle: int
    parent: int | None
    name: str | None
    identity: tuple
    owned: bool


class SnapshotStore:
    """Same closed store API as POSIX, backed only by held native handles."""

    def __init__(self, database, *, create=False, _native=None):
        self.database, self.create = database, create
        self.native = _native
        self.directories, self.relative, self.files = [], {}, {}

    def __enter__(self):
        raw = os.fspath(self.database)
        if not isinstance(raw, str) or len(raw) > 4096 or '..' in PureWindowsPath(raw).parts:
            raise SecurityDataError('snapshot database needs a bounded physical Windows path')
        absolute = PureWindowsPath(os.path.abspath(raw)) if os.name == 'nt' else PureWindowsPath(raw)
        if (not re.fullmatch(r'[A-Za-z]:', absolute.drive) or not absolute.is_absolute()
                or not 2 <= len(absolute.parts) <= 128):
            raise SecurityDataError('snapshot Windows path requires a dedicated local drive directory')
        try:
            self.native = self.native or Native()
            root = self.native.root(absolute.anchor)
            self._hold(root, None, None, owned=False, directory=True)
            node = self.directories[0]
            for index, name in enumerate(absolute.parts[1:], start=1):
                node = self._directory(node, _component(name), create=self.create,
                                       owned=index == len(absolute.parts) - 1)
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
        if self.native:
            for held in [*self.files.values(), *reversed(self.directories)]:
                self.native.close(held.handle)
            self.files.clear()
            self.directories.clear()
            self.relative.clear()
            self.native.shutdown()
            self.native = None

    def _metadata(self, handle, *, owned, directory, maximum=None, ancestor_depth=None, volume_root=False):
        if volume_root:
            self.native.verify_root(handle)
        value = self.native.metadata(handle)
        if (value.directory != directory or value.attributes & 0x400
                or not directory and (value.links != 1 or value.size < 0)):
            raise SecurityDataError('snapshot native object type/reparse/hardlink is unsafe')
        trusted = self.native.trusted if owned else self.native.ancestors
        try:
            check_acl(*value.security[:2], trusted, owned=owned, volume_root=volume_root)
        except SecurityDataError as error:
            diagnostic = _acl_diagnostic(self.native, value.security, owned=owned,
                                         directory=directory, ancestor_depth=ancestor_depth)
            failure = SecurityDataError(str(error) + '; native_acl_diagnostic=' +
                                        json.dumps(diagnostic, sort_keys=True, separators=(',', ':')))
            failure.native_acl_diagnostic = diagnostic
            raise failure from error
        if maximum is not None and value.size > maximum:
            raise SecurityDataError('snapshot file exceeds the bounded read limit')
        return value

    def _hold(self, handle, parent, name, *, owned, directory, maximum=None):
        try:
            identity = self._metadata(handle, owned=owned, directory=directory, maximum=maximum,
                                      ancestor_depth=len(self.directories) if directory and not owned else None,
                                      volume_root=parent is None and directory and not owned).identity()
        except BaseException:
            self.native.close(handle)
            raise
        held = Held(handle, parent, name, identity, owned)
        if directory:
            self.directories.append(held)
        else:
            self.files[parent, name] = held
        return held

    def confirm(self):
        for depth, (directory, held) in enumerate([(True, node) for node in self.directories] + [(False, f) for f in self.files.values()]):
            ancestor_depth = depth if directory and not held.owned else None
            volume_root = directory and held.parent is None and not held.owned
            value = self._metadata(held.handle, owned=held.owned, directory=directory, ancestor_depth=ancestor_depth,
                                   volume_root=volume_root)
            if value.identity() != held.identity:
                raise SecurityDataError('snapshot held native identity or security changed')
            if held.parent is not None:
                named = self.native.open(held.parent, held.name, directory=directory, inspect=True)
                try:
                    current = self._metadata(named, owned=held.owned, directory=directory, ancestor_depth=ancestor_depth)
                    if current.identity() != held.identity:
                        raise SecurityDataError('snapshot native name was replaced while held')
                finally:
                    self.native.close(named)

    def _directory(self, parent, name, *, create, owned):
        self.confirm()
        try:
            handle = self.native.open(parent.handle, name, directory=True)
        except FileNotFoundError:
            if not create:
                raise
            try:
                handle = self.native.open(parent.handle, name, directory=True, create=True)
            except FileExistsError:
                handle = self.native.open(parent.handle, name, directory=True)
        node = self._hold(handle, parent.handle, name, owned=owned, directory=True)
        self.confirm()
        return node

    def directory(self, parts, *, create=False):
        if len(parts) > 8:
            raise SecurityDataError('snapshot directory exceeds the closed layout')
        for name in parts:
            _component(name)
        self.confirm()
        for size in range(1, len(parts) + 1):
            prefix = parts[:size]
            if prefix not in self.relative:
                self.relative[prefix] = self._directory(self.relative[prefix[:-1]], prefix[-1], create=create, owned=True)
        return self.relative[parts]

    def _file(self, parent, name, maximum):
        _component(name)
        self.confirm()
        key = parent.handle, name
        if key not in self.files:
            handle = self.native.open(parent.handle, name, directory=False)
            self._hold(handle, parent.handle, name, owned=True, directory=False, maximum=maximum)
        held = self.files[key]
        self._metadata(held.handle, owned=True, directory=False, maximum=maximum)
        return held

    def _read(self, handle, maximum):
        self.native.seek(handle)
        chunks, length = [], 0
        while length <= maximum:
            requested = min(1024 * 1024, maximum + 1 - length)
            chunk = self.native.read(handle, requested)
            if not isinstance(chunk, bytes) or len(chunk) > requested:
                raise SecurityDataError('invalid native bounded read result')
            if not chunk:
                return b''.join(chunks)
            chunks.append(chunk)
            length += len(chunk)
        raise SecurityDataError('snapshot file exceeds the bounded read limit')

    def read(self, parts, maximum):
        parent = self.directory(parts[:-1])
        held = self._file(parent, parts[-1], maximum)
        payload = self._read(held.handle, maximum)
        self.confirm()
        return payload

    def write(self, parts, payload):
        parent = self.directory(parts[:-1], create=True)
        name = _component(parts[-1])
        try:
            previous = self._file(parent, name, 1024 * 1024 * 1024)
        except FileNotFoundError:
            previous = None
        temporary = f'.{name}.{uuid.uuid4().hex}.partial'
        handle = self.native.open(parent.handle, temporary, directory=False, create=True, temporary=True)
        committed = False
        try:
            offset = 0
            while offset < len(payload):
                block = payload[offset:offset + 1024 * 1024]
                written = self.native.write(handle, block)
                if not 0 < written <= len(block):
                    raise SecurityDataError('incomplete native snapshot write')
                offset += written
            self.native.flush(handle)
            before = self._metadata(handle, owned=True, directory=False, maximum=len(payload))
            actual = self._read(handle, len(payload))
            if (before.size != len(payload) or hashlib.sha256(actual).digest() != hashlib.sha256(payload).digest()
                    or self._metadata(handle, owned=True, directory=False).identity() != before.identity()):
                raise SecurityDataError('snapshot native temporary changed before publication')
            probe = self.native.open(parent.handle, temporary, directory=False, inspect=True)
            try:
                if self._metadata(probe, owned=True, directory=False).identity() != before.identity():
                    raise SecurityDataError('snapshot native temporary name was replaced')
            finally:
                self.native.close(probe)
            self.confirm()
            self.native.rename(handle, parent.handle, name, replace=previous is not None)
            committed = True
            key = parent.handle, name
            if previous:
                self.native.close(self.files.pop(key).handle)
            metadata = self._metadata(handle, owned=True, directory=False)
            self.files[key] = Held(handle, parent.handle, name, metadata.identity(), True)
            handle = None  # held file now owns it
            self.confirm()
            self.native.flush(self.files[key].handle)
        finally:
            if handle is not None:
                if not committed:
                    try:
                        with contextlib.suppress(OSError):
                            self.native.discard(handle)  # delete only the exact owned object
                    finally:
                        self.native.close(handle)
                else:
                    self.native.close(handle)
