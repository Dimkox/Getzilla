"""G07: conservative impact; every gap widens scope and security checks are always required."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.code_graph.impact import calculate_impact  # noqa: E402
from getzilla.code_graph.models import GraphConfig  # noqa: E402
from tests.code_graph_support import generation  # noqa: E402

CHAIN = {
    'a.py': 'def fa():\n    pass\n',
    'b.py': 'from a import fa\ndef fb():\n    fa()\n',
    'c.py': 'import b\ndef fc():\n    b.fb()\n',
    'd.py': 'def alone():\n    pass\n',
}


class ImpactTests(unittest.TestCase):
    def test_reverse_dependencies_included(self) -> None:
        current = generation(CHAIN)
        report = calculate_impact(current, current, ['a.py'])
        self.assertEqual(report.affected_files, ('a.py', 'b.py', 'c.py'))
        self.assertTrue(report.complete)
        self.assertEqual(report.fallback_scope, 'none')
        self.assertIn('DEPENDS_ON:sym:a.py::fa', report.reasons['sym:b.py::fb'])
        symbol = calculate_impact(current, current, ['sym:a.py::fa'])
        self.assertIn('sym:c.py::fc', symbol.affected_symbols)

    def test_deleted_target_uses_old_edges(self) -> None:
        previous = generation(CHAIN)
        files = dict(CHAIN)
        del files['a.py']
        current = generation(files)
        report = calculate_impact(previous, current)
        self.assertEqual(report.changed, ('file:a.py',))
        self.assertIn('b.py', report.affected_files)
        self.assertIn('c.py', report.affected_files)

    def test_cycle_terminates(self) -> None:
        current = generation({'x.py': 'import y\ndef fx():\n    y.fy()\n', 'y.py': 'import x\ndef fy():\n    x.fx()\n'})
        report = calculate_impact(current, current, ['x.py'])
        self.assertEqual(report.affected_files, ('x.py', 'y.py'))

    def test_unknown_call_widens_scope(self) -> None:
        files = {**CHAIN, 'e.py': 'def run(handler):\n    handler.fa()\n', 'f.py': 'def g(obj):\n    obj.other()\n',
                 'r.py': 'def go(mod):\n    getattr(mod, "x")()\n'}
        current = generation(files)
        report = calculate_impact(current, current, ['a.py'])
        self.assertIn('e.py', report.affected_files)
        self.assertIn('r.py', report.affected_files)
        self.assertNotIn('f.py', report.affected_files)
        self.assertTrue(any(reason.startswith('UNRESOLVED_CALL_MAY_REACH_CHANGE') for reason in report.reasons['file:e.py']))

    def test_limit_hit_is_incomplete_not_clean(self) -> None:
        current = generation(CHAIN, GraphConfig(max_impact_nodes=2))
        report = calculate_impact(current, current, ['a.py'])
        self.assertFalse(report.complete)
        self.assertIn('TRAVERSAL_LIMIT_REACHED', report.gaps)
        self.assertEqual(report.fallback_scope, 'configured_project')
        self.assertIn('full_test_suite', report.required_checks)

    def test_uncovered_language_prevents_narrow_global_claim(self) -> None:
        current = generation({**CHAIN, 'web/app.js': 'fa()\n'})
        report = calculate_impact(current, current, ['d.py'])
        self.assertFalse(report.complete)
        self.assertEqual(report.fallback_scope, 'configured_project')
        self.assertIn('UNSUPPORTED_LANGUAGE:web/app.js:javascript', report.gaps)
        unknown = calculate_impact(generation(CHAIN), generation(CHAIN), ['config/settings.toml'])
        self.assertEqual(unknown.fallback_scope, 'configured_project')

    def test_security_checks_never_omitted(self) -> None:
        current = generation(CHAIN)
        for changed in (['d.py'], [], ['a.py']):
            with self.subTest(changed=changed):
                self.assertIn('security_checks', calculate_impact(current, current, changed).required_checks)
        self.assertIn('NO_CHANGE_DETECTED', calculate_impact(current, current, []).gaps)

    def test_isolated_change_is_narrow_with_evidence(self) -> None:
        current = generation(CHAIN)
        report = calculate_impact(current, current, ['d.py'])
        self.assertEqual(report.affected_files, ('d.py',))
        self.assertTrue(report.complete)


if __name__ == '__main__':
    unittest.main()
