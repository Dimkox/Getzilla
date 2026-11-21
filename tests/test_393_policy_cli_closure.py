"""NEW static closure control: no engine, loader or producer execution."""
import ast
from pathlib import Path
import sys
import unittest

ACTIVE = False


def audit(event, args):
    if ACTIVE and (event == 'open' or event.startswith(('os.', 'socket.', 'subprocess.', 'shutil.'))):
        raise AssertionError('AST-only fixture denies I/O/process/network')


sys.addaudithook(audit)


class PolicyCliClosure(unittest.TestCase):
    def test_actual_loader_loop_hashes_security_cli_source(self):
        # Named static source read before the no-I/O AST boundary; never import
        # or execute policy_binding/current_required_plan/the implementation.
        raw = (Path(__file__).resolve().parents[1] / '.getzilla/getzilla/verification_plan.py').read_bytes()
        global ACTIVE
        ACTIVE = True
        try:
            tree = ast.parse(raw)
            function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'policy_binding')
            loops = [node for node in function.body if isinstance(node, ast.For) and isinstance(node.iter, ast.Tuple)]
            self.assertEqual(len(loops), 1)
            loop = loops[0]
            names = ast.literal_eval(loop.iter)
            self.assertEqual(names.count('security_cli.py'), 1, 'shared CLI policy helper must be in actual implementation closure')
            self.assertEqual(len(names), len(set(names)))
            self.assertIsInstance(loop.target, ast.Name)
            target = loop.target.id
            assignments = [node for node in loop.body if isinstance(node, ast.Assign)]
            imports = [node for node in assignments if isinstance(node.value, ast.Call)
                       and isinstance(node.value.func, ast.Attribute) and node.value.func.attr == 'import_module']
            self.assertEqual(len(imports), 1)
            self.assertIn(target, {node.id for node in ast.walk(imports[0].value) if isinstance(node, ast.Name)})
            module = imports[0].targets[0].id
            stores = [node for node in assignments if isinstance(node.targets[0], ast.Subscript)
                      and isinstance(node.targets[0].value, ast.Name) and node.targets[0].value.id == 'implementation']
            self.assertEqual(len(stores), 1)
            store = stores[0]
            self.assertIsInstance(store.targets[0].slice, ast.Name)
            self.assertEqual(store.targets[0].slice.id, target)
            source_calls = [node for node in ast.walk(store.value) if isinstance(node, ast.Call)
                            and isinstance(node.func, ast.Name) and node.func.id == '_module_source']
            self.assertEqual(len(source_calls), 1)
            self.assertEqual(ast.dump(source_calls[0].args[0]), ast.dump(ast.Name(id=module, ctx=ast.Load())))
            self.assertTrue(any(isinstance(node, ast.Attribute) and node.attr == 'sha256' for node in ast.walk(store.value)))
        finally:
            ACTIVE = False


if __name__ == '__main__':
    unittest.main(verbosity=2)
