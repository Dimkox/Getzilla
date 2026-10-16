"""G01: graph identity is bound to source, scope, config and extractor; exports carry no source text."""
from __future__ import annotations

import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.code_graph.builder import build_generation  # noqa: E402
from getzilla.code_graph.models import (  # noqa: E402
    GraphConfig, GraphError, GraphGeneration, ImportEdge, make_graph_input,
)
from getzilla.project_ingestion import IngestionBaseline  # noqa: E402
from getzilla.source_models import GitIdentity  # noqa: E402
from tests.code_graph_support import FOLDER, generation, graph_input, scope  # noqa: E402

FILES = {'a.py': 'def f():\n    return "literal-value-xyz"\n', 'b.py': 'def f():\n    pass\n'}


def git_baseline(working_set: str | None) -> IngestionBaseline:
    return IngestionBaseline('local_git', '/repo', 'dirty' if working_set else 'clean',
                             GitIdentity('sha1', 'a' * 40, 'b' * 40), 'complete', working_set, ('a' * 40,), ())


class GraphModelTests(unittest.TestCase):
    def test_dirty_scope_changes_graph_identity(self) -> None:
        clean = make_graph_input(git_baseline(None), scope(FILES), GraphConfig())
        dirty = make_graph_input(git_baseline('c' * 64), scope(FILES), GraphConfig())
        self.assertNotEqual(clean.identity, dirty.identity)
        edited = make_graph_input(git_baseline(None), scope({**FILES, 'b.py': 'x = 1\n'}), GraphConfig())
        self.assertNotEqual(clean.identity, edited.identity)
        self.assertEqual(clean.to_dict()['source']['commit_oid'], 'a' * 40)

    def test_extractor_or_config_change_invalidates_generation(self) -> None:
        base = generation(FILES)
        for config in (GraphConfig(extractor='getzilla-python-ast-v2'), GraphConfig(package_roots=('src',)),
                       GraphConfig(namespace_packages=True)):
            with self.subTest(config=config):
                other = build_generation(graph_input(FILES, config))
                self.assertNotEqual(other.input_identity, base.input_identity)
                self.assertNotEqual(other.generation_id, base.generation_id)

    def test_unknown_language_reported_in_coverage(self) -> None:
        coverage = generation({**FILES, 'web/app.js': 'x()\n', 'notes.txt': 'n\n'}, omitted={'big.bin': 'POLICY'}).coverage
        self.assertEqual(coverage.unsupported_language, (('web/app.js', 'javascript'),))
        self.assertEqual(coverage.unknown_language, ('notes.txt',))
        self.assertEqual(coverage.omitted, (('big.bin', 'POLICY'),))
        self.assertFalse(coverage.complete)
        self.assertEqual(coverage.to_dict()['claim'], 'python_files_only')

    def test_same_symbol_name_in_other_file_distinct(self) -> None:
        ids = {symbol.id for symbol in generation(FILES).symbols}
        self.assertEqual(ids, {'sym:a.py::f', 'sym:b.py::f'})

    def test_foreign_generation_edge_rejected(self) -> None:
        base = generation(FILES)
        foreign = ImportEdge('a.py', 'other', 'elsewhere.py', 'internal', None, 1)
        with self.assertRaises(GraphError) as caught:
            GraphGeneration(base.input_identity, base.graph_input, base.files, base.symbols, (foreign,), base.calls,
                            base.coverage)
        self.assertEqual(caught.exception.reason_code, 'FOREIGN_GENERATION_EDGE')
        with self.assertRaises(GraphError):
            replace(base, symbols=base.symbols[:0], calls=generation({'a.py': 'def g():\n    pass\ng()\n'}).calls)

    def test_source_contents_not_part_of_public_export(self) -> None:
        text = json.dumps(generation(FILES).export())
        self.assertNotIn('literal-value-xyz', text)
        self.assertNotIn('return', text)
        gi = graph_input(FILES)
        self.assertNotIn('contents', gi.to_dict())

    def test_scope_paths_must_be_normalized(self) -> None:
        for bad in ('../x.py', '/abs.py', 'a\\b.py', './a.py'):
            with self.subTest(path=bad), self.assertRaises(GraphError):
                make_graph_input(FOLDER, {bad: b''}, GraphConfig())

    def test_over_limit_file_is_omitted_not_parsed(self) -> None:
        gi = graph_input({'a.py': 'x = 1\n' * 100}, GraphConfig(max_file_bytes=10))
        self.assertEqual(gi.omitted, (('a.py', 'FILE_OVER_GRAPH_LIMIT'),))


if __name__ == '__main__':
    unittest.main()
