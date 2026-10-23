import hashlib,json,pathlib,unittest
R=pathlib.Path(__file__).resolve().parent
class Inputs(unittest.TestCase):
    def test_frozen_source(self):
        manifest=json.loads((R/'artifacts/source-manifest.json').read_text())
        self.assertEqual(len(manifest),60)
        for name,digest in manifest.items():
            self.assertEqual(hashlib.sha256((R/'original'/name).read_bytes()).hexdigest(),digest,name)
        self.assertEqual(len(list((R/'original/src').rglob('*.py'))),8)
        self.assertEqual(len(list((R/'original/tests').rglob('*.py'))),6)
    def test_no_git_or_links(self):
        self.assertFalse(any(p.is_symlink() or p.name=='.git' for p in (R/'original').rglob('*')))
if __name__=='__main__': unittest.main()
