"""Experimental reader controls. No production behavior is under test."""
import hashlib,pathlib,tempfile,unittest
from trusted_read import read_hit
class ReaderControls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=pathlib.Path(__file__).resolve().parent);self.root=pathlib.Path(self.tmp.name)
        self.data=b'def sample():\n    return 1\n';(self.root/'ok.py').write_bytes(self.data)
        self.hit={'tenant':'t1','repository':'r1','path':'ok.py','file_sha256':hashlib.sha256(self.data).hexdigest(),'start':1,'end':2,'sha256':hashlib.sha256(self.data).hexdigest()}
    def tearDown(self):self.tmp.cleanup()
    def read(self,hit=None):return read_hit(self.root,hit or self.hit,'t1','r1',{'ok.py'})
    def test_valid(self):self.assertEqual(self.read(),self.data)
    def test_stale(self):
        (self.root/'ok.py').write_bytes(b'changed');self.assertRaises(ValueError,self.read)
    def test_deleted(self):
        (self.root/'ok.py').unlink();self.assertRaises(ValueError,self.read)
    def test_rename(self):
        (self.root/'ok.py').rename(self.root/'new.py');self.assertRaises(ValueError,self.read)
    def test_range(self):self.assertRaises(ValueError,self.read,{**self.hit,'end':300})
    def test_chunk_digest(self):self.assertRaises(ValueError,self.read,{**self.hit,'sha256':'0'*64})
    def test_tenant(self):self.assertRaises(ValueError,self.read,{**self.hit,'tenant':'t2'})
    def test_repository(self):self.assertRaises(ValueError,self.read,{**self.hit,'repository':'r2'})
    def test_path_filter(self):self.assertRaises(ValueError,self.read,{**self.hit,'path':'excluded.py'})
    def test_traversal(self):self.assertRaises(ValueError,self.read,{**self.hit,'path':'../ok.py'})
    def test_symlink(self):
        (self.root/'link.py').symlink_to('ok.py')
        self.assertRaises(ValueError,read_hit,self.root,{**self.hit,'path':'link.py'},'t1','r1',{'link.py'})
    def test_nonregular_directory(self):
        (self.root/'ok.py').unlink();(self.root/'ok.py').mkdir()
        self.assertRaises(ValueError,self.read)
if __name__=='__main__':unittest.main()
