import importlib
import ast
from pathlib import Path
import unittest

from getzilla.retrieval.contracts import sha
from getzilla.retrieval.study_windows import StudyWindow


class ByteCounter:
    identity = 'a' * 64

    def count(self, text):
        return len(text.encode())


def window(start, text, function='x.py:1:f'):
    return StudyWindow('small', 'x.py', 'f', function, start,
                       start + len(text.splitlines()) - 1, 'b' * 64,
                       sha(text.encode()), text, 5, False, 'c' * 64)


class StudyContextTests(unittest.TestCase):
    def owner(self):
        try:
            return importlib.import_module('getzilla.retrieval.study_context')
        except ModuleNotFoundError:
            self.fail('complete historical context owner missing')

    def test_citation_bytes_and_overlap_line_dedup_are_exact(self):
        a, b = window(1, 'one\ntwo\n'), window(2, 'two\nthree\n')
        result = self.owner().pack_context([a.id, b.id], {a.id: a, b.id: b}, ByteCounter(), 2048)
        expected = (f'[small x.py:1-2 sha256={"b" * 64} source-lines=1,2]\n'
                    'one\ntwo\n\n---\n'
                    f'[small x.py:2-3 sha256={"b" * 64} source-lines=3]\n'
                    'three\n\n---\n')
        self.assertEqual(result.text, expected)
        self.assertEqual(result.tokens, len(expected.encode()))
        self.assertEqual(result.functions, ('x.py:1:f', 'x.py:1:f'))

        tree = ast.parse((Path(__file__).resolve().parents[1]
                          / 'engineering/benchmarks/issue162/benchmark.py').read_text())
        definitions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                       and node.name in {'dedup', 'evaluate'}]
        namespace = {}
        exec(compile(ast.Module(body=definitions, type_ignores=[]),
                     '<published-context-definitions>', 'exec'), namespace)
        original = [{'repository': row.corpus, 'path': row.path, 'start': row.start,
                     'end': row.end, 'file_sha256': row.file_sha256, 'text': row.text,
                     'function_id': row.function_id} for row in (a, b)]
        class HistoricalCodec:
            def encode(self, text):
                self.last = text
                return list(text.encode())
        codec = HistoricalCodec()
        old = namespace['evaluate']({'qrels': [{'id': a.function_id, 'path': a.path}]},
                                    [(0, 1.), (1, .5)], original, codec, 2048)
        self.assertEqual(result.text, codec.last)
        self.assertEqual(result.tokens, old['budget_2048_tokens'])

    def test_budget_counts_whole_serialization_and_does_not_drop_citations(self):
        a = window(1, 'x' * 2040 + '\n')
        result = self.owner().pack_context([a.id], {a.id: a}, ByteCounter(), 2048)
        self.assertEqual(result.text, '')
        self.assertEqual(result.tokens, 0)
        self.assertEqual(result.skipped_positions, (1,))

    def test_unknown_or_denied_original_slots_are_visible_and_not_refilled(self):
        a = window(1, 'one\n')
        result = self.owner().pack_context(['outside', a.id], {a.id: a}, ByteCounter(), 2048)
        self.assertEqual(result.unavailable_positions, (1,))
        self.assertEqual(result.included_positions, (2,))
        with self.assertRaises(ValueError):
            self.owner().pack_context(['outside'] * 100 + [a.id], {a.id: a}, ByteCounter(), 2048)

    def test_mutated_window_and_unregistered_budget_refuse(self):
        a = window(1, 'one\n')
        object.__setattr__(a, 'text', 'changed\n')
        with self.assertRaisesRegex(ValueError, 'invalid_context_window'):
            self.owner().pack_context([a.id], {a.id: a}, ByteCounter(), 2048)
        with self.assertRaises(ValueError):
            self.owner().pack_context([], {}, ByteCounter(), 4096)
