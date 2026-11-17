"""NEW retained-failure joins: static contracts and an owned pure refusal."""
import ast
import json
from pathlib import Path
import sys
import unittest

W = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(W / '.getzilla'))
from getzilla import queue_provenance
ACTIVE = False


def audit(event, args):
    if ACTIVE and (event == 'open' or event.startswith(('os.', 'socket.', 'subprocess.', 'shutil.'))):
        raise AssertionError('new pure fixture denies I/O/process/network')


sys.addaudithook(audit)


class GateJoins(unittest.TestCase):
    def guarded(self, function):
        global ACTIVE
        ACTIVE = True
        try:
            return function()
        finally:
            ACTIVE = False

    def test_cli_preserves_existing_named_inventory_boundary(self):
        raw = (W / '.getzilla/getzilla/security_cli.py').read_bytes()
        def check():
            tree = ast.parse(raw)
            aliases = [alias.asname or alias.name for node in tree.body if isinstance(node, ast.ImportFrom)
                       and node.module == 'security_inventory' for alias in node.names]
            self.assertIn('collect_inventory', aliases, 'retained preflight callers need the existing named seam')
        self.guarded(check)

    def test_only_opted_in_empty_fixture_omits_ci_image_inputs_before_copy(self):
        raw = (W / 'tests/_support.py').read_bytes()
        def check():
            tree = ast.parse(raw)
            copy = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'project_copy')
            guards = [node for node in ast.walk(copy) if isinstance(node, ast.If)
                      and 'verification_fixture' in ast.unparse(node.test)
                      and "PROJECT / '.getzilla/config'" in ast.unparse(node.test)]
            self.assertEqual(len(guards), 1)
            literals = {node.value for child in guards[0].body for node in ast.walk(child)
                        if isinstance(node, ast.Constant) and isinstance(node.value, str)}
            self.assertIn('ci-images.json', literals, 'empty fixture still inherits real build image inputs')
            self.assertEqual(literals, {'ci-images.json', 'python-quality-requirements.txt', 'python-test-requirements.txt'})
        self.guarded(check)

    def test_existing_bound_helper_preserves_closed_refusal_without_analyzer(self):
        self.assertTrue(hasattr(queue_provenance, 'queue_refusal_text'), 'pure bounded serializer still inflates architecture analyzer module')
        detail = dict(version=1, kind='queue-analysis-refusal', side='head', category='depth', limit=8, observed=9,
                      site='active', witness_scope='ordered-module-request-frames', active=['owned.first'], cached=[],
                      active_omitted=0, cached_omitted=0, cached_witness_unavailable=False)
        class OwnedRefusal(Exception):
            code = 'limit'
        error = OwnedRefusal('owned limit refusal')
        error._queue_refusal_capture = queue_provenance.QueueRefusalCapture(error, str(error), json.dumps(detail))
        error.queue_refusal = {'PRIVATE-OWNED-CANARY': object()}
        text = self.guarded(lambda: queue_provenance.queue_refusal_text(error))
        self.assertIn('; ', text, 'genuine closed provenance must survive')
        self.assertEqual(json.loads(text.split('; ', 1)[1]), detail)
        self.assertLessEqual(len(text.encode()), 2048)
        self.assertNotIn('PRIVATE-OWNED-CANARY', text)
        error._queue_refusal_capture = None
        self.assertEqual(self.guarded(lambda: queue_provenance.queue_refusal_text(error)), str(error))


if __name__ == '__main__':
    unittest.main(verbosity=2)
