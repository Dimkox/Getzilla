"""G04: bounded call resolution; uncertainty is explicit, candidates are never proven calls."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from tests.code_graph_support import calls_by_expression, generation  # noqa: E402

LIB = {'lib.py': 'def helper():\n    pass\n'}


class PythonCallTests(unittest.TestCase):
    def test_direct_local_and_imported_calls_resolve(self) -> None:
        gen = generation({**LIB, 'main.py': 'from lib import helper\nimport lib\n'
                                            'def local():\n    pass\n'
                                            'def run():\n    local()\n    helper()\n    lib.helper()\n'
                                            '    def nested():\n        pass\n    nested()\n'})
        calls = calls_by_expression(gen, '::run')
        self.assertEqual(calls['local'].targets, ('sym:main.py::local',))
        self.assertEqual(calls['helper'].targets, ('sym:lib.py::helper',))
        self.assertEqual(calls['lib.helper'].targets, ('sym:lib.py::helper',))
        self.assertEqual(calls['nested'].targets, ('sym:main.py::run.nested',))
        self.assertTrue(all(edge.resolution == 'exact' for edge in calls.values()))

    def test_recursion_has_finite_edge_set(self) -> None:
        gen = generation({'r.py': 'def f(n):\n    return f(n - 1) + f(n - 2)\n'})
        self.assertEqual({(e.caller, e.targets, e.resolution) for e in gen.calls},
                         {('sym:r.py::f', ('sym:r.py::f',), 'exact')})
        self.assertEqual(len(gen.calls), 1)

    def test_rebinding_invalidates_exact_resolution(self) -> None:
        gen = generation({'m.py': 'def f():\n    pass\nf = other\ndef g():\n    f()\n',
                          'n.py': 'def h():\n    pass\ndef h():\n    pass\nh()\n'})
        f_call = calls_by_expression(gen, '::g')['f']
        self.assertEqual((f_call.resolution, f_call.reason, f_call.targets), ('candidate', 'REBOUND_NAME', ('sym:m.py::f',)))
        self.assertEqual(calls_by_expression(gen, 'file:n.py')['h'].resolution, 'candidate')

    def test_monkey_patching_is_candidate(self) -> None:
        gen = generation({**LIB, 'patch.py': 'import lib\nlib.helper = None\n',
                          'main.py': 'from lib import helper\nhelper()\n'})
        edge = calls_by_expression(gen, 'file:main.py')['helper']
        self.assertEqual((edge.resolution, edge.reason), ('candidate', 'MONKEY_PATCHED'))

    def test_dynamic_attribute_call_unresolved(self) -> None:
        gen = generation({'m.py': 'class A:\n    def go(self):\n        self.step()\n    def step(self):\n        pass\n'
                                  'def run(obj, fns):\n    obj.go()\n    fns[0]()\n    (lambda: 1)()\n'})
        step = calls_by_expression(gen, '::A.go')['self.step']
        self.assertEqual((step.resolution, step.reason, step.targets), ('unresolved', 'ATTRIBUTE_DISPATCH', ()))
        run = [edge for edge in gen.calls if edge.caller == 'sym:m.py::run']
        self.assertEqual({edge.resolution for edge in run}, {'unresolved'})
        self.assertIn('DYNAMIC_CALLEE', {edge.reason for edge in run})

    def test_reflection_gap_visible(self) -> None:
        gen = generation({'m.py': 'def f():\n    pass\ngetattr(mod, "f")()\neval("f()")\n'})
        reasons = {edge.expression: edge.reason for edge in gen.calls}
        self.assertEqual(reasons['getattr(...)'], 'REFLECTION')
        self.assertEqual(reasons['eval'], 'REFLECTION')
        self.assertGreaterEqual(gen.coverage.dynamic_gaps, 2)
        self.assertGreaterEqual(gen.coverage.unresolved_calls, 2)

    def test_candidate_not_treated_as_proven_call(self) -> None:
        gen = generation({'m.py': 'def f():\n    pass\nif flag:\n    def f():\n        pass\nf()\n'})
        edge = calls_by_expression(gen, 'file:m.py')['f']
        self.assertEqual(edge.resolution, 'candidate')
        self.assertNotEqual(edge.resolution, 'exact')
        self.assertTrue(edge.reason)

    def test_builtins_and_external_are_not_local(self) -> None:
        gen = generation({'m.py': 'import json\nprint(len([]))\njson.dumps({})\n'})
        calls = calls_by_expression(gen)
        self.assertEqual((calls['print'].resolution, calls['print'].targets), ('external', ()))
        self.assertEqual(calls['json.dumps'].resolution, 'external')


if __name__ == '__main__':
    unittest.main()
