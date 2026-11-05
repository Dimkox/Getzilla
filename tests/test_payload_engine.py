"""One public-fixture byte engine in Core and standalone Factory layouts."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ROOT / '.getzilla/getzilla/_payload_engine.py'
MIRROR = ROOT / 'factory/src/getzilla_factory/_payload_engine.py'


def load_engine(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PayloadEngineTests(unittest.TestCase):
    def test_native_bound_uses_counted_replacement_without_full_regex_sub(self):
        engine = load_engine(CANONICAL, 'public_payload_engine_redaction_bound')
        from unittest.mock import patch
        original = engine._BEARER
        class CountedOnly:
            def finditer(self, value):
                return original.finditer(value)
            def sub(self, *args):
                raise AssertionError('unbounded intermediate replacement')
        with patch.object(engine, '_BEARER', CountedOnly()):
            with self.assertRaises(engine.PayloadError) as caught:
                engine.redact('Bearer a', 8, bound_intermediate=True)
        self.assertEqual(caught.exception.code, 'output_too_large')

    def test_legacy_default_keeps_original_final_size_redaction_semantics(self):
        engine = load_engine(CANONICAL, 'public_payload_engine_legacy_bound')
        text = 'Bearer a password=abcdefghijkl'
        self.assertEqual(engine.redact(text, len(text)), '[REDACTED] [REDACTED]')
        with self.assertRaises(engine.PayloadError):
            engine.redact(text, len(text), bound_intermediate=True)

    def test_record_budget_refuses_before_visiting_over_budget_container(self):
        engine = load_engine(CANONICAL, 'public_payload_engine_budget')
        visited = []
        class Observed(dict):
            def items(self):
                visited.append('traversed')
                return super().items()
        with self.assertRaises(engine.PayloadError) as caught:
            engine.check_shape(Observed({'a': 1, 'b': 2, 'c': 3}), max_depth=32, max_records=2)
        self.assertEqual(caught.exception.code, 'record_limit')
        self.assertEqual(visited, [], 'aggregate budget must precede child traversal')

    def test_encoded_size_counts_unicode_escapes_and_rejects_before_dump(self):
        engine = load_engine(CANONICAL, 'public_payload_engine_encoding')
        from unittest.mock import patch
        expected = b'{"a":"\\n\\t\\\"\\\\", "b":false}'.replace(b', ', b',')
        value = {'a': '\n\t"\\', 'b': False}
        self.assertEqual(engine.encode_json(value, max_bytes=len(expected)), expected)
        with patch.object(engine.json, 'dumps', side_effect=AssertionError('encoded before bound')):
            with self.assertRaises(engine.PayloadError) as caught:
                engine.encode_json({'a': 'many-public-characters'}, max_bytes=4)
        self.assertEqual(caught.exception.code, 'output_too_large')

    def test_both_layouts_run_identical_public_secret_and_json_semantics(self):
        self.assertTrue(CANONICAL.is_file(), 'canonical payload engine is missing')
        self.assertTrue(MIRROR.is_file(), 'generated standalone Factory engine is missing')
        self.assertEqual(CANONICAL.read_bytes(), MIRROR.read_bytes())
        for index, path in enumerate((CANONICAL, MIRROR)):
            with self.subTest(layout=path.name, index=index):
                engine = load_engine(path, f'public_payload_engine_{index}')
                self.assertEqual(engine.redact('contact note; password=public-fixture', 100),
                                 'contact note; [REDACTED]')
                self.assertEqual(engine.strict_json('{"public":[1,true,null]}'),
                                 {'public': [1, True, None]})
                with self.assertRaises(engine.PayloadError) as caught:
                    engine.strict_json('{"a":1,"a":2}')
                self.assertEqual(caught.exception.code, 'duplicate_json_key')

    def test_standalone_factory_engine_needs_no_core_or_database_import(self):
        self.assertTrue(MIRROR.is_file(), 'generated standalone Factory engine is missing')
        # -I ignores inherited Python paths. Execute the one exact source
        # file; no Core, Factory package __init__, credentials or network exists.
        result = subprocess.run(
            [sys.executable, '-I', str(MIRROR)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8'))
        self.assertEqual(result.stdout, b'')


if __name__ == '__main__':
    unittest.main()
