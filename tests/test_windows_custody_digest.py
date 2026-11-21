"""Memory-native custody checks do not qualify a Windows host."""
import hashlib
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'.getzilla'))
from getzilla import security_data as data
from getzilla.security_data_windows import Metadata

class CustodyDigestTests(unittest.TestCase):
    def native(self, file_id=b'\x01'*16):
        security=('S-1-5-18',((0,0,0x1F01FF,'S-1-5-18'),),True)
        parent=Metadata((123,file_id),0x10,True,1,0,0,0,security).identity()
        child=Metadata((123,b'\x02'*16),0,False,1,12,1,2,security).identity()
        return SimpleNamespace(directories=[SimpleNamespace(handle=1,identity=parent)],files={2:SimpleNamespace(name='snapshot.json',parent=1,identity=child)})
    def test_native_ids_have_stable_bounded_canonical_digest(self):
        self.assertEqual(data._custody_identity(self.native().directories[0].identity)[0],
                         ['ntfs-file-id/v1',123,'01'*16])
        first=data._custody_digest(self.native())
        self.assertRegex(first,r'^[a-f0-9]{64}$')
        self.assertEqual(first,data._custody_digest(self.native()))
        self.assertNotEqual(first,data._custody_digest(self.native(b'\x03'*16)))
        store=self.native()
        store.files[2].identity=Metadata((123,b'\x04'*16),0,False,1,12,1,2,store.files[2].identity[3]).identity()
        self.assertNotEqual(first,data._custody_digest(store))
    def test_posix_digest_bytes_remain_unchanged(self):
        directory=(1,2,0o40700,1000,1000)
        file=(*directory,1,12,1234,5678)
        store=SimpleNamespace(directories=[SimpleNamespace(descriptor=1,identity=directory)],files={2:SimpleNamespace(name='snapshot.json',parent=1,identity=file)})
        previous={'directories':[list(directory)],'files':[('snapshot.json',list(directory),list(file))]}
        self.assertEqual(data._custody_digest(store),hashlib.sha256(json.dumps(previous,sort_keys=True).encode()).hexdigest())
    def test_unknown_shapes_and_unbounded_or_misplaced_bytes_fail_closed(self):
        for file_id in (b'',b'x'*15,b'x'*17,bytearray(b'x'*16),'x'*16,b'\x00'*16):
            with self.subTest(file_id=type(file_id).__name__),self.assertRaises(data.SecurityDataError):
                data._custody_digest(self.native(file_id))
        for bad in (object(),(1,b'x'*16),((1,b'x'*16),0,True,('owner',((0,0,0,b'secret'),))),((1,b'x'*16),0,True,('owner',(),object()))):
            store=self.native()
            store.directories[0].identity=bad
            with self.subTest(shape=type(bad).__name__),self.assertRaises(data.SecurityDataError):
                data._custody_digest(store)

    def test_memory_native_held_ids_and_source_tamper_still_refuse(self):
        from dataclasses import replace
        from unittest.mock import patch
        from getzilla import security_data_windows as windows
        from tests.test_windows_snapshot_store import MemoryNative
        native=MemoryNative()
        with windows.SnapshotStore('C:\\custody430',create=True,_native=native) as store:
            store.write(('snapshot.json',),b'public fixture')
            held=next(iter(store.files.values()))
            identity=held.identity
            self.assertEqual(data._custody_digest(store),data._custody_digest(store))
            self.assertIs(held.identity,identity)
            self.assertIs(type(held.identity[0][1]),bytes)
            original=native.metadata
            def changed(handle):
                metadata=original(handle)
                if handle==held.handle:
                    return replace(metadata,file_id=(1,b'\x99'*16))
                return metadata
            with patch.object(native,'metadata',side_effect=changed):
                with self.assertRaisesRegex(data.SecurityDataError,'identity or security changed'):
                    store.confirm()
            node=native.nodes[native.handles[held.handle][0]]
            body,version=node['body'],node['version']
            try:
                node['body']=b'tampered source'
                node['version']+=1
                with self.assertRaisesRegex(data.SecurityDataError,'identity or security changed'):
                    store.confirm()
            finally:
                node['body'],node['version']=body,version
        self.assertEqual(native.handles,{})
