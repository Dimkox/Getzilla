"""Inert source-window controls, never a real tokenizer or data seal."""
import hashlib
import importlib
import ast
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))


def function(raw, *, start=1, end=None, symbol='choose', overload=False):
    lines = raw.splitlines(keepends=True)
    end = len(lines) if end is None else end
    return {'id': f'x.py:{start}:{symbol}', 'path': 'x.py', 'symbol': symbol,
            'start': start, 'end': end, 'file_sha256': hashlib.sha256(raw).hexdigest(),
            'sha256': hashlib.sha256(b''.join(lines[start - 1:end])).hexdigest(),
            'overload_stub': overload}


class InertLineCounter:
    identity = 'a' * 64

    def count(self, text):
        return 2 + 80 * len(text.splitlines())


class StudyWindowTests(unittest.TestCase):
    def builder(self):
        try:
            return importlib.import_module('getzilla.retrieval.study_windows').windows_for_file
        except ImportError:
            self.fail('fixed study window computation is missing')

    def test_original_greedy_windows_keep_two_lines_and_historical_ids(self):
        raw = b'def choose():\n    x=1\n    y=2\n    z=3\n    w=4\n    return x\n'
        windows = self.builder()('small', 'x.py', raw, [function(raw)], InertLineCounter())
        self.assertEqual([(row.start, row.end) for row in windows], [(1, 3), (2, 4), (3, 5), (4, 6)])
        self.assertEqual(windows[1].id, 'x.py:1:choose@2-4')
        self.assertEqual(windows[1].text, '    x=1\n    y=2\n    z=3\n')
        self.assertEqual(windows[1].sha256, hashlib.sha256(b'    x=1\n    y=2\n    z=3\n').hexdigest())

    def test_protocol_ellipsis_is_retained_and_only_marked_overload_is_excluded(self):
        raw = b'def choose(): ...\ndef overloaded(): ...\n'
        records = [function(raw, end=1), function(raw, start=2, symbol='overloaded', overload=True)]
        windows = self.builder()('small', 'x.py', raw, records, InertLineCounter())
        self.assertEqual([row.function_id for row in windows], ['x.py:1:choose'])
        self.assertEqual(windows[0].text, 'def choose(): ...\n')

    def test_long_line_keeps_bytes_and_reports_encoder_truncation(self):
        raw = b'def choose(): ' + b'x' * 300 + b'\n'
        class Counter(InertLineCounter):
            def count(self, text):
                return len(text)
        windows = self.builder()('small', 'x.py', raw, [function(raw)], Counter())
        self.assertEqual(windows[0].text.encode(), raw)
        self.assertTrue(windows[0].encoder_truncated)

    def test_published_counter_and_windows_parity_at_token_boundaries(self):
        # Execute only these two original pure definitions on tiny fake bytes.
        # No benchmark import, model, tokenizer package or retained corpus read.
        tree = ast.parse((ROOT / 'engineering/benchmarks/issue162/benchmark.py').read_text())
        encoder = next(node for node in tree.body if isinstance(node, ast.ClassDef)
                       and node.name == 'Encoder')
        count = next(node for node in encoder.body if isinstance(node, ast.FunctionDef)
                     and node.name == 'count')
        chunks = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                      and node.name == 'chunks_for')
        for length in (252, 253, 254, 255, 256, 257, 300):
            with self.subTest(source_tokens=length):
                raw = b'x' * length
                record = function(raw)
                class TinyPath:
                    def __truediv__(self, unused):
                        return self

                    def read_text(self):
                        return '[]'

                    def read_bytes(self):
                        return raw

                namespace = {'sha': lambda data: hashlib.sha256(data).hexdigest(),
                             'R': TinyPath(), 'json': SimpleNamespace(loads=lambda text: [record]),
                             'pathlib': SimpleNamespace(Path=lambda path: TinyPath())}
                exec(compile(ast.Module(body=[count, chunks], type_ignores=[]),
                             '<published-pure-study-definitions>', 'exec'), namespace)
                # Fake specials are explicit: source count +2. The historical
                # count method includes encode().ids, rather than subtracting2.
                counter = SimpleNamespace(identity='a' * 64, tokenizer=SimpleNamespace(
                    encode=lambda text: SimpleNamespace(ids=list(range(len(text) + 2)))))
                counter.count = lambda text: namespace['count'](counter, text)
                old = namespace['chunks_for']('small', counter)
                actual = self.builder()('small', 'x.py', raw, [record], counter)
                self.assertEqual([(row.id, row.text, row.encoder_tokens, row.encoder_truncated)
                                  for row in actual],
                                 [(row['id'], row['text'], row['encoder_tokens'],
                                   row['encoder_truncated']) for row in old])
                self.assertEqual(actual[0].encoder_tokens, length + 2)
                self.assertEqual(actual[0].encoder_truncated, length + 2 > 256)

    def test_changed_source_or_manifest_span_refuses_before_emitting_windows(self):
        raw = b'def choose():\n    return 1\n'
        record = function(raw)
        for changed in (raw.replace(b'1', b'2'), raw + b'\n'):
            with self.assertRaises(ValueError):
                self.builder()('small', 'x.py', changed, [record], InertLineCounter())

    def test_a_counter_cannot_remove_the_existing_source_deadline(self):
        from getzilla.retrieval.budget import Budget
        current = [0.0]
        budget = Budget(clock=lambda: current[0])
        class Counter(InertLineCounter):
            def count(self, text):
                current[0] = 3.0
                return 2
        raw = b'def choose(): ...\n'
        with self.assertRaisesRegex(ValueError, 'deadline_exceeded'):
            self.builder()('small', 'x.py', raw, [function(raw)], Counter(), budget=budget)
