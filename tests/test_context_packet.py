"""Pure packet tests use provenance fixtures, never caller-granted authority."""
from dataclasses import replace
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from tests.test_retrieval_engine import document, snapshot
from getzilla.retrieval.extract import build_generation
from getzilla.retrieval.ranking import RankedHit


class ContextPacketTests(unittest.TestCase):
    def test_packet_preserves_mandatory_scope_and_marks_estimates_unknown_usage(self):
        from getzilla.retrieval.packet import prepare_packet
        source = snapshot(document())
        packet = prepare_packet(source, build_generation(source), 'choose_key',
                                mandatory='Original task\nOutstanding obligation\nEvidence gaps: OPEN\n')
        self.assertTrue(packet['text'].startswith('Original task\nOutstanding obligation\nEvidence gaps: OPEN\n'))
        self.assertIn('choose_key', packet['text'])
        self.assertEqual(packet['token_accounting']['kind'], 'utf8_bytes_upper_bound_estimate')
        self.assertIsNone(packet['token_accounting']['actual_input_tokens'])
        self.assertIsNone(packet['token_accounting']['billed_tokens'])
        self.assertEqual(packet['source_identity'], source.source_identity)
        self.assertEqual(packet['qualification'], 'unadmitted_source_packet')
        self.assertTrue(packet['citations'])
        self.assertTrue(packet['ranking_components'])
        self.assertGreater(packet['ranking_components'][0]['scores']['exact_symbol'],0)
        self.assertIn('bm25',packet['ranking_components'][0]['scores'])
        self.assertLessEqual(len(packet['text'].encode()), 8192)

    def test_mandatory_overflow_never_discards_original_task(self):
        from getzilla.retrieval.packet import prepare_packet
        source = snapshot(document())
        with self.assertRaisesRegex(ValueError, 'mandatory_budget_exceeded'):
            prepare_packet(source, build_generation(source), 'choose_key', mandatory='x' * 8193)

    def test_stale_source_or_fragment_hash_never_leaks_text(self):
        from getzilla.retrieval.packet import prepare_packet
        source = snapshot(document())
        generation = build_generation(source)
        changed = snapshot(document(text='def changed():\n    pass\n'))
        with self.assertRaisesRegex(ValueError, 'current_index_unavailable'):
            prepare_packet(changed, generation, 'choose_key')
        changed_chunk = replace(generation.chunks[0], chunk_sha256='f' * 64)
        with self.assertRaisesRegex(ValueError, 'stale_citation'):
            prepare_packet(source, replace(generation, chunks=(changed_chunk,)), 'choose_key',
                           graph_hits=(RankedHit(changed_chunk, 1, 1),))

    def test_graph_selection_does_not_authorize_path_outside_snapshot(self):
        from getzilla.retrieval.packet import prepare_packet
        source = snapshot(document())
        generation = build_generation(source)
        chunk = replace(generation.chunks[0], path='../outside.py')
        with self.assertRaisesRegex(ValueError, 'stale_citation'):
            prepare_packet(source, generation, 'choose_key', graph_hits=(RankedHit(chunk, 1, 1),))

    def test_exact_counter_identity_must_be_explicit_and_budget_includes_headers(self):
        from getzilla.retrieval.packet import prepare_packet
        source = snapshot(document())
        with self.assertRaisesRegex(ValueError, 'tokenizer_identity_required'):
            prepare_packet(source, build_generation(source), 'choose_key', token_counter=len)
        packet = prepare_packet(source, build_generation(source), 'choose_key', token_counter=len,
                                tokenizer_identity='fixture-v1', token_budget=2048)
        self.assertEqual(packet['token_accounting']['kind'], 'supplied_tokenizer_count')
        self.assertLessEqual(packet['token_accounting']['count'], 2048)
