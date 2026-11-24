"""Port orchestration tests. Test doubles establish no native authority qualification."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from tests.test_retrieval_engine import document, snapshot


class RetrievalPortTests(unittest.TestCase):
    def test_missing_native_authority_never_reads_files_or_falls_back(self):
        from getzilla.retrieval.ports import RetrievalService
        with self.assertRaisesRegex(ValueError, '^authority_unavailable$'):
            RetrievalService().query(object(), 'choose_key')

    def test_service_rechecks_before_encoder_and_preparation_returns_only_owned_reference(self):
        from getzilla.retrieval.extract import build_generation
        from getzilla.retrieval.ports import RetrievalService
        source = snapshot(document())
        generation = build_generation(source)
        calls = []

        class AlgorithmPort:
            def current(self, request, budget):
                calls.append('current')
                return source, generation

            def recheck(self, request, source, budget):
                calls.append('recheck')

            def prepare(self, request, source, packed, budget):
                calls.append('prepare')
                self.packed = packed
                return 'native_prepared_reference'

        port = AlgorithmPort()
        result = RetrievalService(port=port, token_counter=lambda text: len(text.encode())).query(object(), 'choose_key')
        self.assertEqual(result.prepared_ref, 'native_prepared_reference')
        self.assertEqual(calls, ['current', 'recheck', 'recheck', 'prepare'])
        self.assertEqual(result.qualification, 'native_adapter_required')
        self.assertFalse(hasattr(result, 'text'))
        self.assertIn('choose_key', port.packed.text)

    def test_revoked_current_port_cannot_prepare_old_generation(self):
        from getzilla.retrieval.extract import build_generation
        from getzilla.retrieval.ports import RetrievalService
        source = snapshot(document())
        generation = build_generation(source)

        class RevokedPort:
            prepared = False
            def current(self, request, budget):
                return source, generation
            def recheck(self, request, source, budget):
                raise ValueError('source_unavailable')
            def prepare(self, *args):
                self.prepared = True

        port = RevokedPort()
        with self.assertRaisesRegex(ValueError, '^source_unavailable$'):
            RetrievalService(port=port, token_counter=len).query(object(), 'choose_key')
        self.assertFalse(port.prepared)

    def test_unqualified_adapter_exception_is_fixed_and_never_echoes_payload(self):
        from getzilla.retrieval.ports import RetrievalService
        class BadPort:
            def current(self, *args):
                raise ValueError('PRIVATE_ERROR_SENTINEL')
        with self.assertRaisesRegex(ValueError, '^adapter_unavailable$'):
            RetrievalService(port=BadPort(), token_counter=len).query(object(), 'choose_key')

    def test_policy_only_change_cannot_reuse_current_cached_generation(self):
        from getzilla.retrieval.extract import build_generation
        from getzilla.retrieval.ports import RetrievalService
        old = snapshot(document())
        generation = build_generation(old)
        changed = snapshot(document(revision='redaction-2'))
        class StalePort:
            prepared = False
            def current(self, *args):
                return changed, generation
            def recheck(self, *args):
                pass
            def prepare(self, *args):
                self.prepared = True
        port = StalePort()
        with self.assertRaisesRegex(ValueError, '^current_index_unavailable$'):
            RetrievalService(port=port, token_counter=len).query(object(), 'choose_key')
        self.assertFalse(port.prepared)

    def test_boolean_permission_assertion_cannot_replace_native_recheck_contract(self):
        from getzilla.retrieval.extract import build_generation
        from getzilla.retrieval.ports import RetrievalService
        source = snapshot(document())
        generation = build_generation(source)
        class BooleanPort:
            def current(self, *args):
                return source, generation
            def recheck(self, *args):
                return True
            def prepare(self, *args):
                return 'MUST_NOT_PREPARE'
        with self.assertRaisesRegex(ValueError, '^adapter_unavailable$'):
            RetrievalService(port=BooleanPort(), token_counter=len).query(object(), 'choose_key')


if __name__ == '__main__':
    unittest.main()
