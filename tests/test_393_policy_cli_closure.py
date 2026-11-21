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
        engine = Path(__file__).resolve().parents[1] / '.getzilla/getzilla'
        plan = (engine / 'verification_plan.py').read_bytes()
        provider = (engine / 'verification_policy_source.py').read_bytes()
        global ACTIVE
        ACTIVE = True
        try:
            plan_function = next(node for node in ast.parse(plan).body
                                 if isinstance(node, ast.FunctionDef) and node.name == 'policy_binding')
            self.assertIn('implementation = implementation_source_binding()', ast.unparse(plan_function))
            function = next(node for node in ast.parse(provider).body
                            if isinstance(node, ast.FunctionDef) and node.name == 'implementation_source_binding')
            loops = [node for node in function.body if isinstance(node, ast.For) and isinstance(node.target, ast.Name)
                     and isinstance(node.iter, ast.Tuple) and all(isinstance(item, ast.Constant)
                     and isinstance(item.value, str) for item in node.iter.elts)]
            names = [item.value for loop in loops for item in loop.iter.elts]
            self.assertEqual(names.count('security_cli.py'), 1)
            self.assertEqual(len(names), len(set(names)))
            loop = next(loop for loop in loops if 'security_cli.py' in ast.literal_eval(loop.iter))
            self.assertIsInstance(loop.target, ast.Name)
            target = loop.target.id
            assignments = [node for node in loop.body if isinstance(node, ast.Assign)]
            imports = [node for node in assignments if isinstance(node.value, ast.Call)
                       and isinstance(node.value.func, ast.Attribute) and node.value.func.attr == 'import_module']
            self.assertEqual(len(imports), 1)
            derived = {node.targets[0].id for node in assignments if isinstance(node.targets[0], ast.Name)
                       and any(isinstance(value, ast.Name) and value.id == target for value in ast.walk(node.value))}
            self.assertTrue(derived & {node.id for node in ast.walk(imports[0].value) if isinstance(node, ast.Name)})
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
