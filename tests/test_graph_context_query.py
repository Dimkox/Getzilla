"""Bounded graph queries use the existing generation, without source or model IO."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla.code_graph.builder import build_generation
from getzilla.code_graph.models import GraphConfig, make_graph_input


class GraphContextQueryTests(unittest.TestCase):
    def graph(self):
        return build_generation(make_graph_input({'source_kind': 'folder', 'source_digest': 'a' * 64}, {
            'a.py': b'from b import helper\ndef entry():\n    return helper()\n',
            'b.py': b'def helper():\n    return 1\n',
            'dynamic.py': b'def unknown(fn):\n    return fn()\n',
            'other.ts': b'export const x = 1;\n',
        }, GraphConfig()))

    def test_symbol_expands_callers_callees_and_imports_with_visible_coverage(self):
        from getzilla.code_graph.context import query_graph
        graph = self.graph()
        result = query_graph(graph, 'entry', depth=1, max_nodes=8)
        self.assertIn('sym:a.py::entry', result['node_ids'])
        self.assertIn('sym:b.py::helper', result['node_ids'])
        self.assertIn('file:b.py', result['node_ids'])
        self.assertEqual(result['generation_id'], graph.generation_id)
        self.assertIn('unsupported_language', result['coverage'])
        self.assertEqual(result['qualification'], 'source_selection_only')
        reverse = query_graph(graph, 'helper', depth=1, max_nodes=8)
        self.assertIn('sym:a.py::entry', reverse['node_ids'])

    def test_path_exact_and_zero_depth_are_bounded(self):
        from getzilla.code_graph.context import query_graph
        result = query_graph(self.graph(), 'a.py', depth=0, max_nodes=1)
        self.assertEqual(len(result['node_ids']), 1)
        self.assertTrue(result['truncated'])
        self.assertEqual(result['reason'], 'node_budget_exceeded')

    def test_invalid_query_bounds_rejected(self):
        from getzilla.code_graph.context import query_graph
        for options in ({'depth': 4}, {'max_nodes': 0}, {'depth': True}):
            with self.assertRaises(ValueError):
                query_graph(self.graph(), 'entry', **options)
        with self.assertRaises(ValueError):
            query_graph(self.graph(), 'x' * 4097)

    def test_no_match_and_ambiguous_symbol_are_explicit(self):
        from getzilla.code_graph.context import query_graph
        graph = self.graph()
        self.assertEqual(query_graph(graph, 'missing_name')['reason'], 'no_graph_match')
        graph = build_generation(make_graph_input({'source_kind': 'folder', 'source_digest': 'a' * 64}, {
            'a.py': b'def same():\n    pass\n', 'b.py': b'def same():\n    pass\n'}, GraphConfig()))
        self.assertEqual(query_graph(graph, 'same')['reason'], 'ambiguous_symbol')
