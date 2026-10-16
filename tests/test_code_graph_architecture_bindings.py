"""G08: code files bind to declared architecture nodes; bindings are evidence, the model is only read."""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.architecture import load_architecture  # noqa: E402
from getzilla.code_graph.architecture_bindings import architecture_impact, bind_architecture  # noqa: E402
from getzilla.code_graph.impact import calculate_impact  # noqa: E402
from getzilla.code_graph.models import GraphError  # noqa: E402
from tests.code_graph_support import generation  # noqa: E402

MODEL = {
    'system': {'architecture_id': 'ARCH-T', 'nodes': [
        {'id': 'NODE-API', 'type': 'service', 'trust_domain': 'TD-A', 'repository_paths': ['svc/api.py', 'svc']},
        {'id': 'NODE-CORE', 'type': 'library', 'trust_domain': 'TD-B', 'repository_paths': ['core']},
        {'id': 'NODE-X', 'type': 'library', 'trust_domain': 'TD-B', 'repository_paths': ['shared']},
        {'id': 'NODE-Y', 'type': 'worker', 'trust_domain': 'TD-C', 'repository_paths': ['shared']},
    ]},
    'rules': {'architecture_id': 'ARCH-T',
              'path_boundaries': [{'id': 'FIT-CORE-PATH', 'source_prefixes': ['core']}],
              'network_policies': [{'id': 'FIT-SERVICE-NET', 'node_types': ['service']}],
              'forbidden_edges': [{'id': 'FIT-TD-C', 'from_trust_domains': ['TD-C']}]},
}
FILES = {'core/__init__.py': '', 'core/calc.py': 'def add():\n    pass\n',
         'svc/__init__.py': '', 'svc/api.py': 'from core.calc import add\ndef handle():\n    add()\n',
         'svc/other.py': '', 'shared/util.py': '', 'loose.py': ''}


class ArchitectureBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.graph = generation(FILES)
        self.bindings = bind_architecture(self.graph, MODEL)

    def test_declared_path_maps_to_component(self) -> None:
        self.assertEqual(self.bindings.node_of('core/calc.py'), 'NODE-CORE')
        self.assertEqual(self.bindings.node_of('svc/api.py'), 'NODE-API')
        self.assertEqual(self.bindings.node_of('svc/other.py'), 'NODE-API')
        self.assertIsNone(self.bindings.node_of('loose.py'))

    def test_ambiguous_binding_stays_unknown(self) -> None:
        self.assertIsNone(self.bindings.node_of('shared/util.py'))
        self.assertEqual(self.bindings.ambiguous['shared/util.py'], ('NODE-X', 'NODE-Y'))

    def test_changed_symbol_reports_component_and_rule(self) -> None:
        impact = calculate_impact(self.graph, self.graph, ['sym:core/calc.py::add'])
        report = architecture_impact(impact, self.bindings, MODEL)
        self.assertEqual(report.components, ('NODE-API', 'NODE-CORE'))
        self.assertIn('FIT-CORE-PATH', report.rules)
        self.assertIn('FIT-SERVICE-NET', report.rules)
        self.assertNotIn('FIT-TD-C', report.rules)

    def test_architecture_policy_not_mutated(self) -> None:
        before = copy.deepcopy(MODEL)
        architecture_impact(calculate_impact(self.graph, self.graph, ['core/calc.py']), self.bindings, MODEL)
        self.assertEqual(MODEL, before)
        snapshot = load_architecture(ROOT)
        files = {path: '' for path in ('scripts/getzilla_cli.py', '.getzilla/getzilla/architecture.py')}
        real = bind_architecture(generation(files), snapshot)
        self.assertEqual(real.architecture_id, snapshot.system['architecture_id'])
        self.assertEqual(load_architecture(ROOT).system, snapshot.system)

    def test_architecture_source_change_invalidates_bindings(self) -> None:
        changed = copy.deepcopy(MODEL)
        changed['system']['nodes'][1]['repository_paths'] = ['core', 'loose.py']
        impact = calculate_impact(self.graph, self.graph, ['core/calc.py'])
        with self.assertRaises(GraphError) as caught:
            architecture_impact(impact, self.bindings, changed)
        self.assertEqual(caught.exception.reason_code, 'ARCHITECTURE_SOURCE_CHANGED')
        self.assertNotEqual(bind_architecture(self.graph, changed).architecture_digest, self.bindings.architecture_digest)


if __name__ == '__main__':
    unittest.main()
