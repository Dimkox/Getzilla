"""G02: static Python symbol extraction; nothing is executed, literals are never exported."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.code_graph.builder import build_generation  # noqa: E402
from getzilla.code_graph.models import GraphConfig, make_graph_input  # noqa: E402
from getzilla.code_graph.python_parser import parse_python  # noqa: E402
from tests.code_graph_support import FOLDER, fixture_scope  # noqa: E402

CONFIG = GraphConfig()


def symbols(source: str) -> dict[str, object]:
    parsed = parse_python('m.py', source.encode('utf-8'), CONFIG)
    return {symbol.qualname: symbol for symbol in parsed.symbols}


class PythonSymbolTests(unittest.TestCase):
    def test_nested_and_async_symbols_have_qualified_names(self) -> None:
        found = symbols('class A:\n    async def run(self):\n        def inner():\n            pass\n'
                        'async def top():\n    pass\n')
        self.assertEqual({name: s.kind for name, s in found.items()},
                         {'A': 'class', 'A.run': 'async_function', 'A.run.inner': 'function', 'top': 'async_function'})

    def test_same_names_in_distinct_scopes_distinct(self) -> None:
        found = symbols('class A:\n    def go(self):\n        pass\nclass B:\n    def go(self):\n        pass\n'
                        'def go():\n    pass\n')
        self.assertTrue({'A.go', 'B.go', 'go'} <= set(found))
        self.assertEqual(len({s.id for s in found.values()}), len(found))

    def test_source_spans_correct(self) -> None:
        found = symbols('\n\nclass A:\n    def m(self):\n        return 1\n')
        self.assertEqual(found['A'].span.to_list(), [3, 0, 5, 16])
        self.assertEqual(found['A.m'].span.to_list(), [4, 4, 5, 16])

    def test_import_side_effect_not_executed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / 'executed'
            source = f'import os\nopen({str(marker)!r}, "w").write("x")\nraise SystemExit(3)\n'
            parsed = parse_python('evil.py', source.encode('utf-8'), CONFIG)
            self.assertEqual(parsed.status, 'complete')
            self.assertFalse(marker.exists())
            self.assertNotIn('evil', sys.modules)

    def test_syntax_or_encoding_error_is_incomplete(self) -> None:
        broken = parse_python('b.py', b'def f(:\n', CONFIG)
        self.assertEqual((broken.status, broken.reason, broken.symbols), ('incomplete', 'SYNTAX_ERROR', ()))
        bad_encoding = parse_python('e.py', b'# -*- coding: utf-8 -*-\nx = "\xff\xfe"\n', CONFIG)
        self.assertEqual((bad_encoding.status, bad_encoding.reason), ('incomplete', 'ENCODING_ERROR'))
        unknown_codec = parse_python('u.py', b'# coding: no-such-codec\nx = 1\n', CONFIG)
        self.assertEqual(unknown_codec.status, 'incomplete')
        latin = parse_python('l.py', '# coding: latin-1\ndef caf\u00e9():\n    pass\n'.encode('latin-1'), CONFIG)
        self.assertEqual(latin.status, 'complete')

    def test_sensitive_literal_not_exported(self) -> None:
        generation = build_generation(make_graph_input(FOLDER, fixture_scope(), CONFIG))
        text = json.dumps(generation.export())
        self.assertNotIn('fixture-literal-must-not-be-exported', text)
        self.assertNotIn('not analysed', text)

    def test_fixture_corpus_inventory_is_deterministic(self) -> None:
        first = build_generation(make_graph_input(FOLDER, fixture_scope(), CONFIG))
        second = build_generation(make_graph_input(FOLDER, fixture_scope(), CONFIG))
        self.assertEqual(first.export(), second.export())
        self.assertEqual(sorted(s.id for s in first.symbols), [
            'sym:shop/models.py::Order', 'sym:shop/models.py::Order.Line', 'sym:shop/models.py::Order.Line.total',
            'sym:shop/models.py::Order.total', 'sym:shop/models.py::sum_items',
            'sym:shop/service.py::checkout', 'sym:shop/service.py::checkout.audit'])
        self.assertEqual(first.coverage.incomplete, (('shop/broken.py', 'SYNTAX_ERROR'),))
        self.assertFalse(first.coverage.complete)


if __name__ == '__main__':
    unittest.main()
