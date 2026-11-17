"""NEW pure AST/data control; never execute the existing Ops test body."""
import ast
from pathlib import Path
import sys
import unittest
ROOT = Path(__file__).resolve().parents[2]
OPS = ast.parse((ROOT / 'trust-ci/tests/test_ops.py').read_bytes())
FUNCTION = next(node for node in ast.walk(OPS) if isinstance(node, ast.FunctionDef)
                and node.name == 'test_repository_workflows_are_hardened')
WORKFLOWS = {path.name: path.read_text(encoding='utf-8')
             for path in (ROOT / '.github/workflows').iterdir()}
NAMES = ('getzilla-public-producer.yml', 'getzilla.yml', 'windows-full-suite.yml')
ACTIVE = False


def guard(event, args):
    if ACTIVE and (event == 'open' or event.startswith(('os.', 'socket.', 'subprocess.', 'ctypes.', 'shutil.'))):
        raise AssertionError('new pure fixture denies filesystem/native/network')
sys.addaudithook(guard)


def guarded(function):
    def invoke(self):
        global ACTIVE
        ACTIVE = True
        try:
            return function(self)
        finally:
            ACTIVE = False
    return invoke


class PublicWorkflowContract(unittest.TestCase):
    @guarded
    def test_inventory_and_hardening_cover_exact_three_shipped_workflows(self):
        calls = [node for node in ast.walk(FUNCTION) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute) and node.func.attr == 'assertEqual']
        inventory = ast.literal_eval(calls[0].args[1])
        loops = [node for node in ast.walk(FUNCTION) if isinstance(node, ast.For)]
        hardened = ast.literal_eval(loops[0].iter)
        self.assertEqual(tuple(sorted(WORKFLOWS)), NAMES)
        self.assertEqual(tuple(inventory), NAMES)
        self.assertEqual(tuple(hardened), NAMES)
    @guarded
    def test_old_permissions_secret_trigger_and_dispatch_restrictions_remain(self):
        calls = [node for node in ast.walk(FUNCTION) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute)]
        assertions = [(node.func.attr, node.args[0].value) for node in calls
                      if node.args and isinstance(node.args[0], ast.Constant)]
        for assertion in [('assertIn', 'permissions:\n  contents: read'), ('assertNotIn', 'secrets.'),
                          ('assertNotIn', 'pull_request_target'), ('assertNotIn', 'workflow_dispatch')]:
            self.assertIn(assertion, assertions)
        self.assertNotIn('workflow_dispatch', WORKFLOWS['getzilla.yml'])
        for source in WORKFLOWS.values():
            self.assertIn('permissions:\n  contents: read', source)
            self.assertNotIn('secrets.', source)
            self.assertNotIn('pull_request_target', source)
        producer = WORKFLOWS['getzilla-public-producer.yml']
        self.assertIn('  workflow_dispatch:', producer)
        self.assertIn('  repository_dispatch:', producer)
        self.assertNotIn('contents: write', producer)
        self.assertNotIn('actions: write', producer)


if __name__ == '__main__':
    unittest.main()
