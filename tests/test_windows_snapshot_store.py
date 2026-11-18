"""Windows snapshot policy/model controls; native tests qualify only on Windows."""
from __future__ import annotations

import json
import os
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import security_data as SD
from getzilla import security_data_windows as W

NOW = datetime(2026, 11, 17, tzinfo=timezone.utc)


class DispatchTests(unittest.TestCase):
    def test_windows_read_uses_native_store_and_shared_validation(self):
        payload = b'{"vulnerabilities":[]}'
        import hashlib
        digest = hashlib.sha256(payload).hexdigest()
        manifest = {'schema_version': 1, 'source_id': 'kev', 'source_url': SD.SOURCE_URLS['kev'],
                    'content_sha256': digest, 'payload_size': len(payload),
                    'acquisition': {'last_verified_sync_utc': NOW.isoformat(), 'retrieval_kind': 'download'},
                    'coverage': {'scopes': ['CVE'], 'complete': True, 'record_count': 0, 'schema': 'kev-1'}}
        bodies = {('feeds', 'kev', 'snapshot.json'): json.dumps(manifest).encode(),
                  ('.snapshots', 'sha256', digest): payload}

        class NativeStore:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def read(self, parts, maximum):
                return bodies[parts]

        backend = SimpleNamespace(SnapshotStore=NativeStore)
        with mock.patch.object(SD, 'os', SimpleNamespace(name='nt')), \
                mock.patch.object(SD, 'DESCRIPTOR_IO_AVAILABLE', False), \
                mock.patch.dict(sys.modules, {'getzilla.security_data_windows': backend}):
            found, evidence = SD.read_snapshot(ROOT / '.getzilla/runtime/unused-native-fixture', 'kev', now=NOW)
            self.assertEqual(found, payload)
            self.assertEqual(evidence['acquisition']['last_verified_sync_utc'], NOW.isoformat())
            manifest['payload_size'] = 1
            bodies[('feeds', 'kev', 'snapshot.json')] = json.dumps(manifest).encode()
            with self.assertRaisesRegex(SD.SecurityDataError, 'size'):
                SD.read_snapshot(ROOT / '.getzilla/runtime/unused-native-fixture', 'kev', now=NOW)




class AclPolicyTests(unittest.TestCase):
    def test_proven_root_keeps_child_security_generic_owner_and_owned_guards(self):
        for mask in (0x40, 0x40000, 0x80000, 0x40000000, 0x10000000):
            with self.subTest(mask=mask), self.assertRaises(SD.SecurityDataError):
                W.check_acl('user', [(0, 0, mask, 'Everyone')], {'user'}, owned=False, volume_root=True)
        for mask in (0x10000, 0x10, 0x100):
            W.check_acl('user', [(0, 0, mask, 'Everyone')], {'user'}, owned=False, volume_root=True)
            with self.assertRaises(SD.SecurityDataError):
                W.check_acl('user', [(0, 0, mask, 'Everyone')], {'user'}, owned=False)
            with self.assertRaises(SD.SecurityDataError):
                W.check_acl('user', [(0, 0, mask, 'Everyone')], {'user'}, owned=True)
        with self.assertRaisesRegex(SD.SecurityDataError, 'owner'):
            W.check_acl('Everyone', [], {'user'}, owned=False, volume_root=True)
        with self.assertRaisesRegex(SD.SecurityDataError, 'ACE'):
            W.check_acl('user', [(9, 8, 0, 'user')], {'user'}, owned=False, volume_root=True)
        with self.assertRaisesRegex(SD.SecurityDataError, 'role'):
            W.check_acl('user', [], {'user'}, owned=True, volume_root=True)

    def test_root_api_requires_exact_actual_handle_name_and_closes_failures(self):
        import ctypes as C
        for name, success in ((b'\\\x00', True), (b'A\x00', True), (b'', True),
                              ('\\ordinary'.encode('utf-16le'), True), (b'\\\x00', False)):
            closed, queried = [], []

            def device(drive, buffer, length):
                buffer.value = r'\Device\HarddiskVolume4'
                return len(buffer.value) + 1

            def volume(handle, unused, size, serial, maximum, flags, filesystem, length):
                C.cast(flags, C.POINTER(W.U32))[0] = 8
                filesystem.value = 'NTFS'
                return 1

            def filename(handle, kind, buffer, length):
                queried.append((handle, kind))
                body = len(name).to_bytes(4, 'little') + name
                C.memmove(buffer, body, min(length, len(body)))
                return int(success)

            native = W.Native.__new__(W.Native)
            native.k = SimpleNamespace(GetDriveTypeW=lambda drive: 3, QueryDosDeviceW=device,
                                       GetVolumeInformationByHandleW=volume,
                                       GetFileInformationByHandleEx=filename)
            native.open = lambda parent, path, **kwargs: 17
            native.close = closed.append
            native._ok = lambda value: None if value else (_ for _ in ()).throw(OSError('query failed'))
            with self.subTest(name=name, success=success):
                if name == b'\\\x00' and success:
                    self.assertEqual(native.root('C:\\'), 17)
                    self.assertEqual(queried, [(17, 2)])
                    self.assertEqual(closed, [])
                else:
                    with self.assertRaises((SD.SecurityDataError, OSError)):
                        native.root('C:\\')
                    self.assertEqual(closed, [17])

    def test_substituted_drive_refuses_before_native_open(self):
        class Kernel:
            def GetDriveTypeW(self, drive):
                return 3

            def QueryDosDeviceW(self, drive, buffer, length):
                buffer.value = r'\??\C:\unheld\ancestor'
                return len(buffer.value) + 1

        native = W.Native.__new__(W.Native)
        native.k = Kernel()
        with self.assertRaisesRegex(SD.SecurityDataError, 'substituted'):
            native.root('X:\\')

    def test_sibling_creation_is_allowed_only_on_ancestors(self):
        aces = [(0, 0, 0x4, 'Everyone'), (0, 8, 0x1F01FF, 'CreatorOwner')]
        W.check_acl('TrustedInstaller', aces, {'user', 'TrustedInstaller'}, owned=False)
        with self.assertRaisesRegex(SD.SecurityDataError, 'untrusted'):
            W.check_acl('user', aces, {'user'}, owned=True)

    def test_destructive_ancestor_and_generic_owned_write_grants_refuse(self):
        for mask in (0x40, 0x10000, 0x40000, 0x80000, 0x100, 0x10):
            with self.subTest(mask=mask), self.assertRaises(SD.SecurityDataError):
                W.check_acl('user', [(0, 0, mask, 'Everyone')], {'user'}, owned=False)
        for mask in (0x40000000, 0x10000000, 2, 4):
            with self.subTest(mask=mask), self.assertRaises(SD.SecurityDataError):
                W.check_acl('user', [(0, 0, mask, 'Everyone')], {'user'}, owned=True)

    def test_trustedinstaller_is_ancestry_only_and_unknown_aces_refuse(self):
        with self.assertRaisesRegex(SD.SecurityDataError, 'owner'):
            W.check_acl('TrustedInstaller', [], {'user', 'SYSTEM', 'Admins'}, owned=True)
        with self.assertRaisesRegex(SD.SecurityDataError, 'ACE'):
            W.check_acl('user', [(9, 8, 0, 'user')], {'user'}, owned=True)


class MemoryNative:
    """Finite owned data model. It has no filesystem, process, registry or network I/O."""
    trusted = {'user', 'SYSTEM', 'Admins'}
    ancestors = trusted | {'TrustedInstaller'}

    def __init__(self):
        self.nodes, self.handles, self.next_node, self.next_handle = {}, {}, 0, 0
        self.root_id = self.node(True, security=('TrustedInstaller', ((0, 0, 4, 'Everyone'),)))
        self.fail_rename = False
        self.discarded = []

    def node(self, directory, *, security=None):
        self.next_node += 1
        self.nodes[self.next_node] = dict(directory=directory, children={}, body=b'', links=1,
                                        reparse=False, version=0,
                                        security=security or ('user', ((0, 0, 0x1F01FF, 'user'),)))
        return self.next_node

    def handle(self, node):
        self.next_handle += 1
        self.handles[self.next_handle] = [node, 0]
        return self.next_handle

    def root(self, drive):
        return self.handle(self.root_id)

    def verify_root(self, handle):
        if self.handles[handle][0] != self.root_id:
            raise SD.SecurityDataError('native volume root proof failed')

    def open(self, parent, name, *, directory, create=False, **kwargs):
        entry = self.nodes[self.handles[parent][0]]
        if create:
            if name in entry['children']:
                raise FileExistsError(name)
            entry['children'][name] = self.node(directory)
        if name not in entry['children']:
            raise FileNotFoundError(name)
        return self.handle(entry['children'][name])

    def metadata(self, handle):
        node_id = self.handles[handle][0]
        node = self.nodes[node_id]
        return W.Metadata((1, node_id.to_bytes(16, 'little')), 0x400 if node['reparse'] else 0,
                          node['directory'], node['links'], len(node['body']), node['version'],
                          node['version'], node['security'])

    def close(self, handle):
        del self.handles[handle]

    def shutdown(self):
        pass

    def seek(self, handle):
        self.handles[handle][1] = 0

    def read(self, handle, size):
        node, offset = self.handles[handle]
        result = self.nodes[node]['body'][offset:offset + size]
        self.handles[handle][1] += len(result)
        return result

    def write(self, handle, payload):
        node = self.nodes[self.handles[handle][0]]
        node['body'] += payload
        node['version'] += 1
        return len(payload)

    def flush(self, handle):
        pass

    def rename(self, handle, parent, name, *, replace):
        if self.fail_rename:
            raise OSError('owned failure before rename')
        entries = self.nodes[self.handles[parent][0]]['children']
        if not replace and name in entries:
            raise FileExistsError(name)
        identifier = self.handles[handle][0]
        old = next(key for key, value in entries.items() if value == identifier)
        del entries[old]
        entries[name] = identifier
        self.nodes[identifier]['version'] += 1

    def discard(self, handle):
        identifier = self.handles[handle][0]
        self.discarded.append(identifier)
        for node in self.nodes.values():
            for name in [name for name, value in node['children'].items() if value == identifier]:
                del node['children'][name]


class NativePublicationApiTests(unittest.TestCase):
    def native(self, setter):
        native = W.Native.__new__(W.Native)
        native.n = SimpleNamespace(NtSetInformationFile=setter, RtlNtStatusToDosError=lambda status: 5)
        native.k = SimpleNamespace(SetFileInformationByHandle=lambda *args: self.fail('rename must use native relative-handle API'))
        return native

    def test_relative_rename_uses_native_class_root_utf16_and_full_buffer(self):
        import ctypes as C
        found = []
        def setter(handle, iosb, buffer, size, kind):
            info = W._Rename.from_buffer(buffer)
            self.assertEqual((handle, kind, info.Root, info.Replace), (37, 10, 91, 1))
            encoded = 'pointer-😀.json'.encode('utf-16-le')
            self.assertEqual(info.Length, len(encoded))
            self.assertGreaterEqual(size, C.sizeof(W._Rename) + len(encoded))
            self.assertEqual(C.string_at(C.addressof(buffer) + W._Rename.Name.offset, info.Length), encoded)
            self.assertEqual(buffer.raw[W._Rename.Name.offset + info.Length:][:2], b'\0\0')
            found.append(True)
            return 0
        self.native(setter).rename(37, 91, 'pointer-😀.json', replace=True)
        self.assertEqual(found, [True])

    def test_invalid_components_refuse_before_any_rename_api(self):
        native = self.native(lambda *args: self.fail('invalid component reached API'))
        for name in ('../outside', r'child\outside', 'a:b', '', 'NUL'):
            with self.subTest(name=name), self.assertRaises(SD.SecurityDataError):
                native.rename(37, 91, name, replace=False)

    def test_native_error_status_is_signed_and_uses_return_not_iosb(self):
        import ctypes as C
        def setter(handle, iosb, buffer, size, kind):
            C.cast(iosb, C.POINTER(W._Status))[0].Status = 0
            return -1073741790
        native = self.native(setter)
        converted = []
        native.n.RtlNtStatusToDosError = lambda code: converted.append(code) or 5
        with mock.patch.object(C, 'WinError', side_effect=lambda code: OSError(code, 'native denied'), create=True):
            with self.assertRaisesRegex(OSError, 'native denied'):
                native.rename(37, 91, 'pointer', replace=False)
        self.assertEqual(converted, [-1073741790])

    def test_pending_waits_for_final_iosb_and_never_counts_pending_as_success(self):
        import ctypes as C
        for completion in (0, -1073741790, 0x103):
            events, pending = [], []
            def setter(handle, iosb, buffer, size, kind):
                pending.append(C.cast(iosb, C.POINTER(W._Status)))
                events.append('set')
                return 0x103
            native = self.native(setter)
            def wait(handle, duration):
                self.assertEqual((handle, duration), (37, 1000))
                pending[0][0].Status = completion
                events.append('wait')
                return 0
            native.k.WaitForSingleObject = wait
            native.k.CancelIoEx = lambda handle, overlapped: events.append('cancel') or 1
            with self.subTest(completion=completion), mock.patch.object(W, '_INCOMPLETE_RENAME', None, create=True), mock.patch.object(C, 'WinError', side_effect=lambda code: OSError(code, 'native denied'), create=True):
                if completion == 0:
                    native.rename(37, 91, 'pointer', replace=False)
                else:
                    with self.assertRaises((OSError, SD.SecurityDataError)):
                        native.rename(37, 91, 'pointer', replace=False)
            self.assertEqual(events, ['set', 'wait'] if completion != 0x103 else ['set', 'wait', 'cancel', 'wait'])

    def test_unresolved_request_is_bounded_retained_and_never_discarded_as_temp(self):
        import ctypes as C
        calls = []
        def setter(handle, iosb, buffer, size, kind):
            calls.append('set')
            return 0x103
        native = self.native(setter)
        native.k.WaitForSingleObject = lambda handle, duration: calls.append(('wait', duration)) or 258
        native.k.CancelIoEx = lambda handle, overlapped: calls.append(('cancel', handle, overlapped)) or 0
        with mock.patch.object(W, '_INCOMPLETE_RENAME', None, create=True):
            with self.assertRaisesRegex(SD.SecurityDataError, 'unresolved') as caught:
                native.rename(37, 91, 'pointer', replace=True)
            self.assertTrue(caught.exception.native_rename_unresolved)
            self.assertIsNotNone(W._INCOMPLETE_RENAME)
            self.assertEqual(calls, ['set', ('wait', 1000), ('cancel', 37, None), ('wait', 1000)])
            with self.assertRaisesRegex(SD.SecurityDataError, 'unresolved'):
                native.rename(38, 91, 'other', replace=True)
            self.assertEqual(calls.count('set'), 1)
            retained_status, retained_buffer = W._INCOMPLETE_RENAME
            self.assertEqual(retained_status.Status, 0x103)
            self.assertGreater(C.sizeof(retained_buffer), C.sizeof(W._Rename))
            # A late successful rename must not cause failure cleanup to delete
            # the now-published object through its formerly-temporary handle.
            model = MemoryNative()
            ordinary = model.rename
            def late(handle, parent, name, *, replace):
                ordinary(handle, parent, name, replace=replace)
                raise caught.exception
            with W.SnapshotStore('C:\\database', create=True, _native=model) as store:
                store.write(('pointer',), b'old')
                model.rename = late
                with self.assertRaisesRegex(SD.SecurityDataError, 'unresolved'):
                    store.write(('pointer',), b'new')
                self.assertEqual(model.discarded, [])
                self.assertEqual(store.read(('pointer',), 3), b'new')
            self.assertEqual(model.handles, {})

    def test_directory_share_allows_internal_add_but_keeps_data_delete_pin(self):
        import ctypes as C
        observed = []
        def create(output, access, attrs, status, allocation, attributes, share, disposition, options, ea, ea_size):
            observed.append((access, share, options))
            C.cast(output, C.POINTER(W.HANDLE))[0] = 73
            return 0
        native = self.native(None)
        native.sd = None
        native.n.NtCreateFile = create
        native.open(91, 'directory', directory=True)
        native.open(91, 'file', directory=False)
        native.open(91, 'temporary', directory=False, temporary=True)
        native.open(91, 'inspection', directory=False, inspect=True)
        self.assertEqual([share for _, share, _ in observed], [3, 5, 5, 7])
        self.assertEqual(observed[0][0], W._DIRECTORY)
        self.assertTrue(observed[0][0] & 1)  # LIST participates in share checks
        self.assertFalse(observed[0][1] & 4)  # no DELETE sharing
        self.assertTrue(all(access & 0x100000 and options & 0x20 for access, _, options in observed))

    def test_discard_marks_only_exact_held_object_with_boolean_abi(self):
        import ctypes as C
        calls = []
        native = self.native(None)
        def setter(handle, kind, buffer, size):
            calls.append((handle, kind, C.string_at(buffer, size)))
            return 1
        native.k.SetFileInformationByHandle = setter
        native.discard(37)
        self.assertEqual(calls, [(37, 4, b'\1')])

    def test_classic_replace_releases_only_own_old_witness_and_recovers_failure(self):
        native = MemoryNative()
        original_rename = native.rename
        def classic(handle, parent, name, *, replace):
            entries = native.nodes[native.handles[parent][0]]['children']
            target = entries.get(name)
            if target is not None and any(node == target for node, offset in native.handles.values()):
                raise PermissionError('destination still open')
            return original_rename(handle, parent, name, replace=replace)
        native.rename = classic
        with W.SnapshotStore('C:\\database', create=True, _native=native) as store:
            store.write(('pointer',), b'old')
            store.write(('pointer',), b'new')
            self.assertEqual(store.read(('pointer',), 3), b'new')
            reader = native.open(store.relative[()].handle, 'pointer', directory=False)
            try:
                with self.assertRaisesRegex(PermissionError, 'still open'):
                    store.write(('pointer',), b'bad')
                self.assertEqual(store.read(('pointer',), 3), b'new')
                self.assertTrue(native.discarded)
            finally:
                native.close(reader)
            native.fail_rename = True
            with self.assertRaisesRegex(OSError, 'before rename'):
                store.write(('pointer',), b'bad')
            self.assertEqual(store.read(('pointer',), 3), b'new')
        self.assertEqual(native.handles, {})


class OwnerRightsPolicyTests(unittest.TestCase):
    USER = 'S-1-5-21-1-2-3-500'
    SYSTEM = 'S-1-5-18'
    ADMINS = 'S-1-5-32-544'
    OWNER_RIGHTS = 'S-1-3-4'
    TRUSTED = {USER, SYSTEM, ADMINS}

    def test_exact_1079_owner_rights_acl_is_bound_to_already_trusted_owner(self):
        aces = tuple((0, 3, 2032127, sid) for sid in (self.SYSTEM, self.ADMINS, self.OWNER_RIGHTS))
        trusted = self.TRUSTED.copy()
        W.check_acl(self.USER, aces, trusted, owned=False)
        W.check_acl(self.USER, aces, trusted, owned=True)
        self.assertEqual(trusted, self.TRUSTED)
        self.assertNotIn(self.OWNER_RIGHTS, trusted)

    def test_unknown_networkservice_and_owner_rights_owners_refuse_first(self):
        for owner in ('S-1-5-20', 'S-1-5-21-1-2-3-9999', self.OWNER_RIGHTS):
            for aces in ((), ((0, 3, 2032127, self.OWNER_RIGHTS),), ((0, 0, 0, self.OWNER_RIGHTS),)):
                with self.subTest(owner=owner, aces=aces), self.assertRaisesRegex(SD.SecurityDataError, 'owner'):
                    W.check_acl(owner, aces, self.TRUSTED, owned=False)

    def test_creator_owner_and_other_principals_keep_existing_destructive_refusals(self):
        for principal in ('S-1-3-0', 'S-1-3-1', 'S-1-1-0', 'S-1-5-20'):
            for owned in (False, True):
                masks = (0x40, 0x40000, 0x80000, 0x10000, 0x100, 0x10, 0x40000000, 0x10000000)
                for mask in masks + ((2, 4) if owned else ()):
                    aces = ((0, 3, 2032127, self.OWNER_RIGHTS), (0, 0, mask, principal))
                    with self.subTest(principal=principal, owned=owned, mask=mask), self.assertRaisesRegex(SD.SecurityDataError, 'DACL'):
                        W.check_acl(self.USER, aces, self.TRUSTED, owned=owned)

    def test_owner_rights_deny_inheritance_or_empty_grants_do_not_invent_access(self):
        for kind, flags, mask in ((1, 0, 2032127), (0, 8, 2032127), (0, 0, 0)):
            W.check_acl(self.USER, ((kind, flags, mask, self.OWNER_RIGHTS),), self.TRUSTED, owned=False)
            with self.assertRaisesRegex(SD.SecurityDataError, 'DACL'):
                W.check_acl(self.USER, ((kind, flags, mask, self.OWNER_RIGHTS),
                                       (0, 0, 0x40000, 'S-1-1-0')), self.TRUSTED, owned=False)
        with self.assertRaisesRegex(SD.SecurityDataError, 'ACE'):
            W.check_acl(self.USER, ((9, 8, 0, self.OWNER_RIGHTS),), self.TRUSTED, owned=False)

    def test_changed_trusted_descriptor_owner_still_refuses_held_publication(self):
        native = MemoryNative()
        native.trusted = self.TRUSTED.copy()
        native.ancestors = self.TRUSTED.copy()
        security = (self.USER, ((0, 3, 2032127, self.OWNER_RIGHTS),), True)
        native.nodes[native.root_id]['security'] = security
        original_node = native.node
        native.node = lambda directory, **kwargs: original_node(directory, security=security)
        with W.SnapshotStore('C:\\database', create=True, _native=native) as store:
            store.write(('snapshot.json',), b'owned')
            node = native.nodes[native.handles[store.relative[()].handle][0]]
            node['security'] = (self.SYSTEM, security[1], True)
            try:
                with self.assertRaisesRegex(SD.SecurityDataError, 'identity or security changed'):
                    store.write(('not-published.json',), b'never')
                self.assertNotIn('not-published.json', node['children'])
            finally:
                node['security'] = security
        self.assertEqual(native.handles, {})


class AclDiagnosticTests(unittest.TestCase):
    USER = 'S-1-5-21-1-2-3-1001'
    OTHER = 'S-1-5-21-1-2-3-9999'
    SERVICE = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'

    def native(self):
        native = MemoryNative()
        native.trusted = {self.USER, 'S-1-5-18', 'S-1-5-32-544'}
        native.ancestors = native.trusted | {self.SERVICE}
        native.service_owner = self.SERVICE
        return native

    def refusal(self, native, security):
        native.nodes[native.root_id]['security'] = security
        with self.assertRaises(SD.SecurityDataError) as caught:
            W.SnapshotStore('C:\\database', create=True, _native=native).__enter__()
        self.assertEqual(native.handles, {})
        diagnostic = caught.exception.native_acl_diagnostic
        self.assertEqual(json.loads(str(caught.exception).split('; native_acl_diagnostic=', 1)[1]), diagnostic)
        return caught.exception, diagnostic

    def test_owner_refusal_reports_exact_bounded_root_facts_without_changing_trust(self):
        native = self.native()
        trusted, ancestors = native.trusted.copy(), native.ancestors.copy()
        aces = ((0, 0, 0x1F01FF, self.USER), (0, 8, 0x40000000, 'S-1-1-0'))
        error, found = self.refusal(native, (self.OTHER, aces, True))
        self.assertTrue(str(error).startswith('snapshot native owner is not trusted;'))
        self.assertEqual(found['schema_version'], 1)
        self.assertEqual((found['role'], found['ancestor_depth']), ('volume-root', 0))
        self.assertEqual(found['owner_sid'], self.OTHER)
        self.assertEqual(found['aces'], [{'kind': k, 'flags': f, 'mask': m, 'sid': s} for k, f, m, s in aces])
        self.assertEqual((found['ace_count'], found['aces_omitted'], found['dacl_protected']), (2, 0, True))
        self.assertEqual(found['trusted_sids'], sorted(trusted))
        self.assertEqual(found['ancestor_sids'], sorted(ancestors))
        self.assertEqual(found['trustedinstaller_lookup'], 'resolved')
        self.assertEqual((native.trusted, native.ancestors), (trusted, ancestors))

    def test_dacl_refusal_keeps_original_reason_and_service_unavailable_fact(self):
        native = self.native()
        native.service_owner = None
        error, found = self.refusal(native, (self.USER, ((0, 0, 0x40, self.OTHER),), False))
        self.assertTrue(str(error).startswith('snapshot native DACL permits untrusted writes or path replacement;'))
        self.assertEqual(found['trustedinstaller_lookup'], 'unavailable')
        self.assertFalse(found['dacl_protected'])

    def test_untrusted_diagnostic_fields_cannot_escape_shape_or_output_bound(self):
        native = self.native()
        untrusted_text = 'username=fixture; HOME=C:\\private\\tree\n' + 'x' * 100000
        native.trusted = {untrusted_text}
        native.ancestors = {untrusted_text}
        native.service_owner = untrusted_text
        aces = [(999, -1, 2**80, untrusted_text)] * 4096
        error, found = self.refusal(native, (untrusted_text, aces, 'raw descriptor'))
        self.assertIsNone(found['owner_sid'])
        self.assertIsNone(found['dacl_protected'])
        self.assertEqual((found['ace_count'], len(found['aces']), found['aces_omitted']), (4096, 32, 4064))
        self.assertEqual(found['aces'][0], {'kind': None, 'flags': None, 'mask': None, 'sid': None})
        self.assertNotIn('private', str(error))
        self.assertNotIn('username', str(error))
        self.assertLess(len(str(error).encode()), 16384)

    def test_ancestor_refusal_records_depth_and_releases_root_handle(self):
        native = self.native()
        native.nodes[native.root_id]['security'] = (self.USER, (), True)
        parent = native.node(True, security=(self.OTHER, (), False))
        native.nodes[native.root_id]['children']['parent'] = parent
        with self.assertRaises(SD.SecurityDataError) as caught:
            W.SnapshotStore('C:\\parent\\database', create=True, _native=native).__enter__()
        self.assertEqual(native.handles, {})
        self.assertEqual(caught.exception.native_acl_diagnostic['role'], 'ancestor')
        self.assertEqual(caught.exception.native_acl_diagnostic['ancestor_depth'], 1)

    def test_maximum_valid_sid_diagnostic_and_principal_collections_are_bounded(self):
        native = self.native()
        sid = 'S-1-281474976710655' + '-4294967295' * 15
        native.trusted = {sid + str(i) for i in range(100)}
        native.ancestors = {sid + str(i) for i in range(100)}
        error, found = self.refusal(native, (sid, [(255, 255, 0xffffffff, sid)] * 4096, True))
        self.assertEqual(len(found['aces']), 32)
        self.assertEqual(found['aces_omitted'], 4064)
        self.assertEqual(found['trusted_sids_omitted'], 100)
        self.assertLess(len(str(error).encode()), 16384)

    def test_native_security_api_port_preserves_owner_aces_protection_and_free_order(self):
        # The Windows ABI port supplies only typed API outputs in owned memory.
        # Native.security itself parses the real ACL/ACE layouts and SID offsets.
        import ctypes as C
        sid = b'\x01\x01' + (5).to_bytes(6, 'big') + (18).to_bytes(4, 'little')
        owner = C.create_string_buffer(sid)
        ace = b'\x00\x10' + (20).to_bytes(2, 'little') + (0x120089).to_bytes(4, 'little') + sid
        acl = C.create_string_buffer(b'\x02\x00' + (28).to_bytes(2, 'little') + b'\x01\x00\x00\x00' + ace)
        descriptor = C.create_string_buffer(8)
        freed = []

        def security(handle, kind, flags, owner_out, group, acl_out, sacl, sd_out):
            self.assertEqual((handle, kind, flags), (17, 1, 5))
            for output, value in ((owner_out, owner), (acl_out, acl), (sd_out, descriptor)):
                C.cast(output, C.POINTER(W.HANDLE))[0] = C.addressof(value)
            return 0

        def get_ace(pointer, index, output):
            self.assertEqual((pointer.value, index), (C.addressof(acl), 0))
            C.cast(output, C.POINTER(W.HANDLE))[0] = C.addressof(acl) + 8
            return 1

        def control(pointer, output, revision):
            C.cast(output, C.POINTER(W.U16))[0] = 0x1000
            C.cast(revision, C.POINTER(W.U32))[0] = 1
            return 1

        def convert(pointer):
            self.assertEqual(freed, [])
            address = pointer.value if isinstance(pointer, W.HANDLE) else pointer
            self.assertEqual(C.string_at(address, len(sid)), sid)
            return 'S-1-5-18'

        native = W.Native.__new__(W.Native)
        native.a = SimpleNamespace(GetSecurityInfo=security, GetAce=get_ace,
                                   GetSecurityDescriptorControl=control)
        native.k = SimpleNamespace(LocalFree=lambda pointer: freed.append(pointer.value))
        native._sid = convert
        self.assertEqual(native.security(17), ('S-1-5-18', ((0, 0x10, 0x120089, 'S-1-5-18'),), True))
        self.assertEqual(freed, [C.addressof(descriptor)])


class StoreModelTests(unittest.TestCase):
    def test_exact_b2_networkservice_owner_refuses_and_supported_owner_model_roundtrips(self):
        aces = ((0, 3, 2032127, 'S-1-5-32-544'), (0, 3, 2032127, 'S-1-5-18'),
                (0, 11, 268435456, 'S-1-3-0'), (0, 3, 1179817, 'S-1-5-32-545'),
                (0, 2, 4, 'S-1-5-32-545'), (0, 10, 2, 'S-1-5-32-545'),
                (0, 0, 1179817, 'S-1-1-0'))
        for owner in ('S-1-5-20', 'S-1-5-18'):
            native = MemoryNative()
            native.trusted = {'S-1-5-18', 'S-1-5-32-544', 'S-1-5-21-1-2-3-500'}
            native.ancestors = native.trusted.copy()
            native.nodes[native.root_id]['security'] = (owner, aces, False)
            if owner == 'S-1-5-20':
                with self.assertRaisesRegex(SD.SecurityDataError, 'owner is not trusted'):
                    W.SnapshotStore('C:\\database', create=True, _native=native).__enter__()
                self.assertEqual(native.nodes[native.root_id]['children'], {})
            else:
                original_node = native.node
                native.node = lambda directory, **kwargs: original_node(directory, security=(owner, (), True))
                with W.SnapshotStore('C:\\database', create=True, _native=native) as store:
                    store.write(('snapshot.json',), b'owned')
                    self.assertEqual(store.read(('snapshot.json',), 5), b'owned')
            self.assertNotIn('S-1-5-20', native.trusted)
            self.assertEqual(native.handles, {})

    def test_ancestor_depth_zero_is_not_volume_root_proof(self):
        native = MemoryNative()
        ordinary = native.node(True, security=('user', ((0, 0, 0x10000, 'Everyone'),)))
        handle = native.handle(ordinary)
        store = W.SnapshotStore('C:\\database', _native=native)
        try:
            with self.assertRaisesRegex(SD.SecurityDataError, 'untrusted'):
                store._metadata(handle, owned=False, directory=True, ancestor_depth=0)
        finally:
            native.close(handle)

    def test_unproven_or_changed_root_fails_before_publication(self):
        for change in ('nonroot', 'name', 'reparse', 'identity'):
            native = MemoryNative()
            verified = native.verify_root
            calls = []
            def proof(handle):
                calls.append(handle)
                if change == 'nonroot' or change == 'name' and len(calls) > 1:
                    raise SD.SecurityDataError('native volume root proof failed')
                return verified(handle)
            native.verify_root = proof
            if change == 'nonroot':
                with self.assertRaisesRegex(SD.SecurityDataError, 'root proof'):
                    W.SnapshotStore('C:\\database', create=True, _native=native).__enter__()
            else:
                store = W.SnapshotStore('C:\\database', create=True, _native=native)
                if change == 'name':
                    with self.assertRaisesRegex(SD.SecurityDataError, 'root proof'):
                        store.__enter__()
                else:
                    with store:
                        root = native.nodes[native.root_id]
                        if change == 'reparse':
                            root['reparse'] = True
                        else:
                            from dataclasses import replace
                            original_metadata = native.metadata
                            native.metadata = lambda handle: replace(original_metadata(handle),
                                file_id=(1, b'changed-root-id!')) if native.handles[handle][0] == native.root_id else original_metadata(handle)
                        with self.assertRaises(SD.SecurityDataError):
                            store.write(('snapshot.json',), b'never published')
                        self.assertFalse(store.files)
                        root['reparse'] = False
                        root['security'] = ('TrustedInstaller', ((0, 0, 4, 'Everyone'),))
                        if change == 'identity':
                            native.metadata = original_metadata
            self.assertEqual(native.handles, {})

    def test_observed_7dda_volume_root_acl_allows_store_without_trusting_authusers(self):
        native = MemoryNative()
        native.trusted = {'S-1-5-18', 'S-1-5-32-544', 'S-1-5-21-1-2-3-500'}
        native.ancestors = native.trusted.copy()
        aces = ((0, 0, 2032127, 'S-1-5-32-544'), (0, 11, 268435456, 'S-1-5-32-544'),
                (0, 0, 2032127, 'S-1-5-18'), (0, 11, 268435456, 'S-1-5-18'),
                (0, 0, 1245631, 'S-1-5-11'), (0, 11, 3758161920, 'S-1-5-11'),
                (0, 0, 1179817, 'S-1-5-32-545'), (0, 11, 2684354560, 'S-1-5-32-545'))
        native.nodes[native.root_id]['security'] = ('S-1-5-18', aces, False)
        original_node = native.node

        def owned_node(directory, **kwargs):
            return original_node(directory, security=('S-1-5-18', (), True))

        native.node = owned_node
        with W.SnapshotStore('C:\\database', create=True, _native=native) as store:
            store.write(('snapshot.json',), b'owned')
            self.assertEqual(store.read(('snapshot.json',), 5), b'owned')
        self.assertNotIn('S-1-5-11', native.trusted)
        self.assertNotIn('S-1-5-32-545', native.trusted)
        with self.assertRaisesRegex(SD.SecurityDataError, 'untrusted'):
            W.check_acl('S-1-5-18', aces, native.ancestors, owned=False)
        self.assertEqual(native.handles, {})

    def test_held_model_roundtrip_update_and_bounded_read(self):
        native = MemoryNative()
        with W.SnapshotStore('C:\\database', create=True, _native=native) as store:
            store.write(('feeds', 'kev', 'snapshot.json'), b'first')
            self.assertEqual(store.read(('feeds', 'kev', 'snapshot.json'), 5), b'first')
            with self.assertRaisesRegex(SD.SecurityDataError, 'bounded'):
                store.read(('feeds', 'kev', 'snapshot.json'), 4)
            store.write(('feeds', 'kev', 'snapshot.json'), b'next')
            self.assertEqual(store.read(('feeds', 'kev', 'snapshot.json'), 4), b'next')
        self.assertEqual(native.handles, {})

    def test_failed_atomic_pointer_commit_keeps_old_bytes_and_cleans_exact_temp(self):
        native = MemoryNative()
        with W.SnapshotStore('C:\\database', create=True, _native=native) as store:
            store.write(('snapshot.json',), b'old')
            native.fail_rename = True
            with self.assertRaisesRegex(OSError, 'before rename'):
                store.write(('snapshot.json',), b'new')
            self.assertEqual(store.read(('snapshot.json',), 3), b'old')
            self.assertEqual(len(native.discarded), 1)
            names = native.nodes[native.handles[store.relative[()].handle][0]]['children']
            self.assertEqual(set(names), {'snapshot.json'})
        self.assertEqual(native.handles, {})

    def test_reparse_hardlink_and_changed_name_identity_refuse(self):
        for mode in ('reparse', 'hardlink', 'identity'):
            native = MemoryNative()
            with self.subTest(mode=mode):
                store = W.SnapshotStore('C:\\database', create=True, _native=native).__enter__()
                try:
                    store.write(('snapshot.json',), b'owned')
                    parent = native.nodes[native.handles[store.relative[()].handle][0]]
                    identifier = parent['children']['snapshot.json']
                    if mode == 'reparse':
                        native.nodes[identifier]['reparse'] = True
                    elif mode == 'hardlink':
                        native.nodes[identifier]['links'] = 2
                    else:
                        parent['children']['snapshot.json'] = native.node(False)
                    with self.assertRaises(SD.SecurityDataError):
                        store.read(('snapshot.json',), 5)
                finally:
                    store.close()
                self.assertEqual(native.handles, {})

    def test_unsafe_owned_dacl_refuses_before_file_creation(self):
        native = MemoryNative()
        with W.SnapshotStore('C:\\database', create=True, _native=native) as store:
            node = native.nodes[native.handles[store.relative[()].handle][0]]
            node['security'] = ('user', ((0, 0, 2, 'Everyone'),))
            with self.assertRaisesRegex(SD.SecurityDataError, 'untrusted'):
                store.write(('snapshot.json',), b'never written')
            self.assertEqual(node['children'], {})
            node['security'] = ('user', ((0, 0, 0x1F01FF, 'user'),))

    def test_missing_target_appearance_cannot_be_replaced(self):
        native = MemoryNative()
        with W.SnapshotStore('C:\\database', create=True, _native=native) as store:
            rename = native.rename

            def appearance(handle, parent, name, *, replace):
                entries = native.nodes[native.handles[parent][0]]['children']
                appeared = native.node(False)
                native.nodes[appeared]['body'] = b'unrelated'
                entries[name] = appeared
                return rename(handle, parent, name, replace=replace)

            native.rename = appearance
            with self.assertRaises(FileExistsError):
                store.write(('snapshot.json',), b'new')
            self.assertEqual(store.read(('snapshot.json',), 9), b'unrelated')
        self.assertEqual(native.handles, {})


def _known_profile_parent(*, _shell=None, _ole=None):
    """The real application-default profile, independent of checkout/temp env."""
    import ctypes as C
    import re
    import uuid
    from pathlib import PureWindowsPath

    class Guid(C.Structure):
        _fields_ = [('data1', W.U32), ('data2', W.U16), ('data3', W.U16), ('data4', W.U8 * 8)]

    shell = _shell if _shell is not None else C.WinDLL('shell32', use_last_error=True)
    ole = _ole if _ole is not None else C.WinDLL('ole32', use_last_error=True)
    query = shell.SHGetKnownFolderPath
    query.argtypes, query.restype = [C.POINTER(Guid), W.U32, W.HANDLE, C.POINTER(W.HANDLE)], C.c_int32
    ole.CoTaskMemFree.argtypes, ole.CoTaskMemFree.restype = [W.HANDLE], None
    identifier = Guid.from_buffer_copy(uuid.UUID('5e6c858f-0e22-4760-9afe-ea3317b67173').bytes_le)
    result = W.HANDLE()
    try:
        if query(C.byref(identifier), 0, None, C.byref(result)) != 0 or not result.value:
            raise OSError('native user-profile Known Folder is unavailable')
        raw = C.wstring_at(result)
        profile = PureWindowsPath(raw)
        if (not raw or len(raw) > 4096 or re.search(r'[\x00-\x1f\ud800-\udfff]', raw)
                or not re.fullmatch(r'[A-Za-z]:', profile.drive) or not profile.is_absolute()
                or len(profile.parts) < 2 or '..' in profile.parts):
            raise OSError('native user-profile Known Folder is not a supported physical path')
        for part in profile.parts[1:]:
            W._component(part)
        return raw
    finally:
        if result.value:
            ole.CoTaskMemFree(result)


def _native_fixture_directory():
    import tempfile
    profile = _known_profile_parent()
    # Match updater.home_dir()'s user-profile ancestry. An unsafe real profile
    # is a failure, never a reason to skip, repair its ACL or try another drive.
    with W.SnapshotStore(Path(profile), create=False):
        pass
    return tempfile.TemporaryDirectory(prefix='getzilla-snapshot-native-', dir=profile)


class KnownFolderFixtureTests(unittest.TestCase):
    def api(self, value, status=0):
        import ctypes as C
        import uuid
        buffer = C.create_unicode_buffer(value) if value is not None else None
        freed = []
        def query(identifier, flags, token, output):
            self.assertEqual(C.string_at(identifier, 16), uuid.UUID('5e6c858f-0e22-4760-9afe-ea3317b67173').bytes_le)
            self.assertEqual(flags, 0)
            self.assertIsNone(token)
            if buffer is not None:
                C.cast(output, C.POINTER(W.HANDLE))[0] = C.addressof(buffer)
            return status
        shell = SimpleNamespace(SHGetKnownFolderPath=query)
        ole = SimpleNamespace(CoTaskMemFree=lambda pointer: freed.append(pointer.value))
        return shell, ole, freed

    def test_known_profile_api_uses_real_current_user_identifier_and_frees_result(self):
        import ctypes as C
        shell, ole, freed = self.api(r'C:\Users\native-fixture')
        with mock.patch.dict(os.environ, {'USERPROFILE': r'D:\untrusted', 'LOCALAPPDATA': r'D:\untrusted'}):
            self.assertEqual(_known_profile_parent(_shell=shell, _ole=ole), r'C:\Users\native-fixture')
        self.assertEqual(len(freed), 1)
        self.assertIs(shell.SHGetKnownFolderPath.restype, C.c_int32)

    def test_known_profile_api_failure_and_unsafe_names_refuse_without_fallback(self):
        for value, status in ((None, 0), (r'C:\Users\unused', -2147467259),
                              ('C:\\', 0), (r'\\server\profile', 0), ('relative', 0),
                              (r'C:\Users\..\escape', 0), ('C:\\bad\nname', 0),
                              (r'\\?\C:\Users\profile', 0), ('C:\\'+'x'*4096, 0)):
            with self.subTest(status=status, length=len(value or '')):
                shell, ole, freed = self.api(value, status)
                with self.assertRaises(OSError):
                    _known_profile_parent(_shell=shell, _ole=ole)
                self.assertEqual(len(freed), int(value is not None))

    def test_native_fixture_preflights_unchanged_store_before_temporary_creation(self):
        import tempfile
        events = []
        class Guard:
            def __init__(self, parent, *, create):
                self.test_parent, self.create = parent, create
            def __enter__(self):
                events.append(('guard', str(self.test_parent), self.create))
            def __exit__(self, *args):
                events.append('confirmed')
        def temporary(**kwargs):
            events.append(('temporary', kwargs))
            return 'owned-fixture'
        with mock.patch.object(sys.modules[__name__], '_known_profile_parent', return_value=r'C:\Users\fixture'), \
             mock.patch.object(W, 'SnapshotStore', Guard), mock.patch.object(tempfile, 'TemporaryDirectory', side_effect=temporary):
            self.assertEqual(_native_fixture_directory(), 'owned-fixture')
        self.assertEqual(events[:2], [('guard', r'C:\Users\fixture', False), 'confirmed'])
        self.assertEqual(events[2][1]['dir'], r'C:\Users\fixture')

    def test_unsafe_actual_profile_ancestry_refuses_before_any_temporary_creation(self):
        import tempfile
        class Unsafe:
            def __init__(self, *args, **kwargs):
                pass
            def __enter__(self):
                raise SD.SecurityDataError('snapshot native owner is not trusted')
            def __exit__(self, *args):
                pass
        with mock.patch.object(sys.modules[__name__], '_known_profile_parent', return_value=r'C:\Users\fixture'), \
             mock.patch.object(W, 'SnapshotStore', Unsafe), mock.patch.object(tempfile, 'TemporaryDirectory') as temporary:
            with self.assertRaisesRegex(SD.SecurityDataError, 'owner is not trusted'):
                _native_fixture_directory()
            temporary.assert_not_called()


@unittest.skipUnless(os.name == 'nt', 'native Windows NTFS handle/ACL execution required')
class NativeWindowsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = _native_fixture_directory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.database = self.root / 'database'

    def publish(self, database=None, payload=b'{"vulnerabilities":[]}'):
        return SD.publish_snapshot(database or self.database, 'kev', payload,
                                   acquisition={'last_verified_sync_utc': NOW.isoformat(), 'retrieval_kind': 'download'},
                                   coverage={'scopes': ['CVE'], 'complete': True, 'record_count': 0, 'schema': 'kev-1'}, now=NOW)

    def set_fixture_acl(self, path, extra=''):
        # Only a private test-owned directory; never an ancestor outside this fixture.
        import ctypes as C
        native = W.Native()
        descriptor = C.c_void_p()
        try:
            sddl = f'O:{native.user}D:P(A;OICI;FA;;;{native.user})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA){extra}'
            native._ok(native.a.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, C.byref(descriptor), None))
            setter = native.a.SetFileSecurityW
            setter.argtypes, setter.restype = [C.c_wchar_p, W.U32, C.c_void_p], C.c_int
            native._ok(setter(str(path), 0x80000004, descriptor))
        finally:
            if descriptor:
                native.k.LocalFree(descriptor)
            native.shutdown()

    def test_native_primitive_relative_handle_rename_new(self):
        # No publish()/SnapshotStore.write prerequisite: qualify the API itself.
        with W.SnapshotStore(self.database, create=True) as store:
            native, parent = store.native, store.relative[()].handle
            handle = native.open(parent, 'rename.partial', directory=False, create=True, temporary=True)
            try:
                self.assertEqual(native.write(handle, b'owned'), 5)
                native.flush(handle)
                before = native.metadata(handle).file_id
                native.rename(handle, parent, 'renamed', replace=False)
                self.assertEqual(native.metadata(handle).file_id, before)
                native.seek(handle)
                self.assertEqual(native.read(handle, 10), b'owned')
                self.assertFalse((self.database / 'rename.partial').exists())
            finally:
                native.close(handle)
            self.assertEqual((self.database / 'renamed').read_bytes(), b'owned')

    def test_native_primitive_replace_refuses_held_target_then_replaces_closed_target(self):
        with W.SnapshotStore(self.database, create=True) as store:
            native, parent = store.native, store.relative[()].handle
            old = native.open(parent, 'pointer', directory=False, create=True, temporary=True)
            try:
                self.assertEqual(native.write(old, b'old'), 3)
                native.flush(old)
            finally:
                native.close(old)
            reader = native.open(parent, 'pointer', directory=False)
            candidate = native.open(parent, 'replace.partial', directory=False, create=True, temporary=True)
            try:
                self.assertEqual(native.write(candidate, b'new'), 3)
                native.flush(candidate)
                with self.assertRaises(OSError):
                    native.rename(candidate, parent, 'pointer', replace=True)
                native.seek(reader)
                self.assertEqual(native.read(reader, 3), b'old')
                self.assertEqual((self.database / 'pointer').read_bytes(), b'old')
                native.close(reader)
                reader = None
                native.rename(candidate, parent, 'pointer', replace=True)
                native.seek(candidate)
                self.assertEqual(native.read(candidate, 3), b'new')
                self.assertFalse((self.database / 'replace.partial').exists())
            finally:
                if reader is not None:
                    native.close(reader)
                native.close(candidate)
            self.assertEqual((self.database / 'pointer').read_bytes(), b'new')

    def test_native_primitive_discard_removes_only_exact_temporary(self):
        with W.SnapshotStore(self.database, create=True) as store:
            native, parent = store.native, store.relative[()].handle
            keep = native.open(parent, 'keep', directory=False, create=True, temporary=True)
            doomed = None
            try:
                self.assertEqual(native.write(keep, b'keep'), 4)
                native.flush(keep)
                doomed = native.open(parent, 'discard.partial', directory=False, create=True, temporary=True)
                native.discard(doomed)
                native.close(doomed)
                doomed = None
                self.assertFalse((self.database / 'discard.partial').exists())
                native.seek(keep)
                self.assertEqual(native.read(keep, 4), b'keep')
            finally:
                if doomed is not None:
                    native.close(doomed)
                native.close(keep)
            self.assertEqual((self.database / 'keep').read_bytes(), b'keep')

    def test_native_primitive_readonly_target_refuses_replacement(self):
        import stat
        with W.SnapshotStore(self.database, create=True) as store:
            native, parent = store.native, store.relative[()].handle
            path = self.database / 'readonly'
            old = native.open(parent, 'readonly', directory=False, create=True, temporary=True)
            try:
                self.assertEqual(native.write(old, b'old'), 3)
                native.flush(old)
            finally:
                native.close(old)
            path.chmod(stat.S_IREAD)
            candidate = None
            try:
                candidate = native.open(parent, 'readonly.partial', directory=False, create=True, temporary=True)
                self.assertEqual(native.write(candidate, b'new'), 3)
                native.flush(candidate)
                with self.assertRaises(OSError):
                    native.rename(candidate, parent, 'readonly', replace=True)
                self.assertEqual(path.read_bytes(), b'old')
                native.discard(candidate)
            finally:
                if candidate is not None:
                    native.close(candidate)
                path.chmod(stat.S_IREAD | stat.S_IWRITE)
            self.assertFalse((self.database / 'readonly.partial').exists())

    def test_native_public_roundtrip_copy_and_old_acquisition(self):
        self.publish()
        with W.SnapshotStore(self.database) as store:
            self.assertTrue(store.native.metadata(store.relative[()].handle).security[2])
            store.read(('feeds', 'kev', 'snapshot.json'), SD.MAX_MANIFEST_BYTES)
            self.assertTrue(all(store.native.metadata(f.handle).security[2] for f in store.files.values()))
        payload, evidence = SD.read_snapshot(self.database, 'kev', now=NOW)
        self.assertEqual(payload, b'{"vulnerabilities":[]}')
        self.assertEqual(evidence['acquisition']['last_verified_sync_utc'], NOW.isoformat())
        target = self.root / 'copy'
        copied = SD.copy_snapshot(self.database, target, 'kev', now=NOW)
        self.assertEqual(copied['acquisition'], evidence['acquisition'])
        self.assertEqual(SD.read_snapshot(target, 'kev', now=NOW)[0], payload)

    def test_native_existing_private_inherited_database_can_refresh(self):
        self.database.mkdir()  # the normal cache from an older installer
        self.publish()
        self.assertEqual(SD.read_snapshot(self.database, 'kev', now=NOW)[0], b'{"vulnerabilities":[]}')

    def test_native_osv_snapshot_and_compatibility_export(self):
        import io
        import zipfile
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as stream:
            stream.writestr('OSV-owned.json', json.dumps({'id': 'OSV-owned', 'affected': [{
                'package': {'ecosystem': 'PyPI', 'name': 'owned'}, 'versions': ['1.0.0']}]}))
        payload = archive.getvalue()
        SD.publish_snapshot(self.database, 'osv:PyPI', payload,
                            acquisition={'last_verified_sync_utc': NOW.isoformat(), 'retrieval_kind': 'download'},
                            coverage=SD.osv_coverage(payload, 'PyPI'), now=NOW)
        self.assertEqual(SD.read_snapshot(self.database, 'osv:PyPI', now=NOW)[0], payload)
        self.assertEqual((self.database / 'PyPI/all.zip').read_bytes(), payload)

    def test_native_ancestor_sibling_create_acl_and_service_owner_resolution(self):
        parent = self.root / 'normal-parent'
        parent.mkdir()
        self.set_fixture_acl(parent, '(A;;0x4;;;WD)')
        database = parent / 'database'
        self.publish(database)
        self.assertEqual(SD.read_snapshot(database, 'kev', now=NOW)[0], b'{"vulnerabilities":[]}')
        native = W.Native()
        try:
            service = native._lookup_service()
            if service is not None:
                self.assertIn(service, native.ancestors)
                self.assertNotIn(service, native.trusted)
        finally:
            native.shutdown()

    def test_native_held_database_cannot_be_renamed(self):
        self.publish()
        with W.SnapshotStore(self.database):
            with self.assertRaises(PermissionError):
                self.database.rename(self.root / 'replaced')
        self.assertTrue((self.database / 'feeds/kev/snapshot.json').exists())

    def test_native_untrusted_store_write_acl_refuses(self):
        self.publish()
        self.set_fixture_acl(self.database, '(A;;FW;;;WD)')
        try:
            with self.assertRaisesRegex(SD.SecurityDataError, 'untrusted'):
                SD.read_snapshot(self.database, 'kev', now=NOW)
        finally:
            self.set_fixture_acl(self.database)

    def test_native_hardlink_refusal_keeps_other_link_bytes(self):
        self.publish()
        pointer = self.database / 'feeds/kev/snapshot.json'
        alias = self.root / 'alias'
        os.link(pointer, alias)
        before = alias.read_bytes()
        try:
            with self.assertRaisesRegex(SD.SecurityDataError, 'hardlink'):
                SD.read_snapshot(self.database, 'kev', now=NOW)
            self.assertEqual(alias.read_bytes(), before)
        finally:
            alias.unlink()

    def test_native_junction_never_reads_or_writes_outside(self):
        import _winapi
        if not hasattr(_winapi, 'CreateJunction'):
            self.skipTest('CPython native junction fixture helper unavailable')
        outside = self.root / 'outside'
        outside.mkdir()
        (outside / 'marker').write_bytes(b'unchanged')
        self.database.mkdir()
        _winapi.CreateJunction(str(outside), str(self.database / 'feeds'))
        try:
            with self.assertRaises(SD.SecurityDataError):
                self.publish()
            self.assertEqual((outside / 'marker').read_bytes(), b'unchanged')
            self.assertEqual(sorted(p.name for p in outside.iterdir()), ['marker'])
        finally:
            os.rmdir(self.database / 'feeds')

    def test_native_pointer_failure_preserves_old_pointer_and_cleans_temporary(self):
        self.publish()
        pointer = self.database / 'feeds/kev/snapshot.json'
        before = pointer.read_bytes()
        rename = W.Native.rename

        def fail_pointer(native, handle, parent, name, *, replace):
            if name == 'snapshot.json':
                raise OSError('before atomic pointer commit')
            return rename(native, handle, parent, name, replace=replace)

        with mock.patch.object(W.Native, 'rename', new=fail_pointer), \
                self.assertRaises(SD.SecurityDataError):
            self.publish(payload=b'{"vulnerabilities":[{}]}')
        self.assertEqual(pointer.read_bytes(), before)
        self.assertFalse(list(self.database.rglob('*.partial')))


if __name__ == '__main__':
    unittest.main()
