"""NEW pure data contract; no source/provider/scanner execution credit."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / '.getzilla'))
from getzilla import public_security_context as module
ACTIVE = False

def guard(event, args):
    if ACTIVE and (event == 'open' or event.startswith(('os.', 'socket.', 'subprocess.', 'ctypes.', 'shutil.'))):
        raise AssertionError('owned pure fixture denies outside/native/network I/O')
sys.addaudithook(guard)

class PublicExecutionContext(unittest.TestCase):
    def setUp(self):
        self.source = dict(head_sha='a'*40, tree_sha='b'*40, checker_sha='c'*40,
                           checker_tree_sha='d'*40, candidate_clean=True, checker_clean=True, same_project=True)
        self.context = dict(kind='getzilla-public-execution-v1', repository='owner/project', repository_id=1,
            pr_number=2, base_sha='e'*40, head_sha='a'*40, tree_sha='b'*40, checker_sha='c'*40,
            checker_tree_sha='d'*40, runner_repository='owner/runner', runner_repository_id=3,
            runner_sha='f'*40, runner_tree_sha='1'*40, workflow_id=4, workflow_blob_sha='2'*40,
            run_id=5, run_attempt=6)
    def guarded(self, operation):
        global ACTIVE
        ACTIVE = True
        try:
            return operation()
        finally:
            ACTIVE = False
    def test_actual_runner_head_stays_distinct_from_candidate(self):
        value=self.guarded(lambda: module.validate_context(self.context,self.source))
        self.assertEqual(value['head_sha'],'f'*40)
        self.assertNotEqual(value['head_sha'],self.source['head_sha'])
    def test_foreign_source_cannot_bind(self):
        self.context['head_sha']='0'*40
        with self.assertRaises(ValueError):
            self.guarded(lambda: module.validate_context(self.context,self.source))
    def test_context_is_scoped_and_callers_cannot_mutate_authority(self):
        def fixture():
            with module.bind_context(self.context,self.source):
                value=module.current_context()
                value['run_attempt']=9
                self.assertEqual(module.current_context()['run_attempt'],6)
            self.assertIsNone(module.current_context())
        self.guarded(fixture)
    def test_projection_preserves_original_catalog_identity(self):
        self.assertTrue(callable(getattr(module,'selection_document',None)))
        self.assertTrue(callable(getattr(module,'project_catalog',None)))
        inventory={'images':[dict(manifest='compose.yml',line=2,source_sha256='3'*64,
            source_reference='example:tag',reference='example@sha256:'+'4'*64,platform='linux/amd64')]}
        catalog={'schema_version':1,'inventory_sha256':'5'*64,'records':[]}
        def fixture():
            declaration=module.selection_document(inventory,self.source,
                module.validate_context(self.context,self.source),'2026-11-17T00:00:00+00:00')
            self.assertEqual(declaration['uses'][0]['path'],'compose.yml')
            projected=module.project_catalog(catalog,'6'*64)
            self.assertEqual(projected['source_catalog_sha256'],module.digest(catalog))
            self.assertEqual(projected['inventory_sha256'],'6'*64)
            self.assertEqual(catalog['inventory_sha256'],'5'*64)
            self.assertEqual(projected['records'],catalog['records'])
        self.guarded(fixture)

if __name__=='__main__':
    unittest.main()
