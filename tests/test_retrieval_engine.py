"""Algorithm/provenance tests only; these fixtures do not authenticate a native user."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))


def document(path='a.py', text='def choose_key():\n    return newest_secret\n', resource='r1',
             project='project', transformed=None, revision='redaction-1'):
    from getzilla.retrieval.contracts import SourceDocument, SourceKey
    raw = text.encode()
    return SourceDocument(SourceKey('tenant', project, 'local', 'site', resource), path, 'source-1',
        raw, raw if transformed is None else transformed.encode(), 'a' * 64, revision)


def snapshot(*documents, git=False):
    from getzilla.retrieval.contracts import SourceSnapshot
    return SourceSnapshot.create('tenant', 'project', 'repository', tuple(documents),
        base_sha='1' * 40 if git else None, head_sha='2' * 40 if git else None)


class RetrievalEngineTests(unittest.TestCase):
    def build(self, source, **kwargs):
        from getzilla.retrieval.extract import build_generation
        return build_generation(source, **kwargs)

    def search(self, generation, query, **kwargs):
        from getzilla.retrieval.engine import search
        return search(generation, query, **kwargs)

    def test_symbol_bm25_and_rrf_have_independent_ranks_and_honest_dense_absence(self):
        g = self.build(snapshot(document(), document('b.py', 'def verify_signature():\n    return signature\n', 'r2')))
        result = self.search(g, 'choose_key newest_secret')
        self.assertEqual(result.rankings['exact_symbol'][0].chunk.symbol, 'choose_key')
        self.assertEqual(result.rankings['bm25'][0].chunk.symbol, 'choose_key')
        self.assertEqual(result.rankings['rrf'][0].score, 2 / 61)
        self.assertEqual(result.component_status['semantic'], 'unavailable')
        self.assertEqual(result.status, 'degraded')
        self.assertEqual(result.answerability, 'unknown')
        self.assertIsNone(result.billed_tokens)

    def test_ast_keeps_implementation_range_and_nested_functions_excludes_overloads(self):
        text = ('from typing import overload\n@overload\ndef f(x: int): ...\n'
                'def f(x):\n    def nested():\n        return x\n    return nested()\n')
        g = self.build(snapshot(document(text=text)))
        self.assertEqual([(c.symbol, c.start, c.end) for c in g.chunks], [('f', 4, 7), ('f.nested', 5, 6)])
        self.assertEqual(g.overload_stubs, 1)
        self.assertEqual(g.candidate_kind, 'non_overload_ast_functions')

    def test_citations_verify_original_and_transformed_bytes_without_fake_gitless_commit(self):
        from getzilla.retrieval.engine import verify_citation
        source = snapshot(document())
        g = self.build(source)
        citation = verify_citation(source, g.chunks[0])
        self.assertEqual(citation['source_snapshot']['kind'], 'gitless')
        self.assertNotIn('head_sha', citation['source_snapshot'])
        self.assertEqual(citation['chunk_sha256'], hashlib.sha256(source.documents[0].original).hexdigest())
        changed = snapshot(document(text='def choose_key():\n    return other_key\n'))
        with self.assertRaisesRegex(ValueError, '^stale_citation$'):
            verify_citation(changed, g.chunks[0])

    def test_identical_git_and_gitless_bytes_have_identical_order_not_identical_source_claim(self):
        d = document()
        a, b = self.build(snapshot(d)), self.build(snapshot(d, git=True))
        self.assertNotEqual(a.identity, b.identity)
        self.assertEqual([h.chunk.id for h in self.search(a, 'choose_key').rankings['rrf']],
                         [h.chunk.id for h in self.search(b, 'choose_key').rankings['rrf']])

    def test_same_resource_id_in_other_partition_cannot_join_a_cohort(self):
        with self.assertRaisesRegex(ValueError, '^partition_mismatch$'):
            snapshot(document(), document('b.py', project='other', resource='r1'))

    def test_transform_policy_and_exact_representation_bind_generation_and_citation(self):
        from getzilla.retrieval.engine import verify_citation
        raw = document()
        changed = replace(raw, representation=b'def choose_key():\n    return REDACTED\n', transform_revision='redaction-2')
        first, second = self.build(snapshot(raw)), self.build(snapshot(changed))
        self.assertEqual(first.source_snapshot, second.source_snapshot)
        self.assertNotEqual(first.identity, second.identity)
        with self.assertRaisesRegex(ValueError, '^stale_citation$'):
            verify_citation(snapshot(changed), first.chunks[0])
        policy_only = self.build(snapshot(replace(raw, transform_revision='redaction-2')))
        self.assertNotEqual(first.identity, policy_only.identity)

    def test_no_answer_and_bad_source_are_explicit_not_semantic_success(self):
        g = self.build(snapshot(document(), document('broken.py', 'def broken(:\n', 'r2')))
        result = self.search(g, 'zzzz_unrelated')
        self.assertEqual(result.rankings['rrf'], ())
        self.assertEqual(result.answerability, 'unknown')
        self.assertEqual(g.gaps, ('python_parse_unavailable',))

    def test_packed_context_counts_mandatory_citations_and_separators(self):
        from getzilla.retrieval.engine import pack_context
        source = snapshot(document())
        g = self.build(source)
        hits = self.search(g, 'choose_key').rankings['rrf']
        result = pack_context(source, hits, lambda value: len(value.encode()), 2048, mandatory='RULE\n')
        self.assertTrue(result.text.startswith('RULE\n'))
        self.assertIn('a.py:1-2', result.text)
        self.assertEqual(result.proxy_tokens, len(result.text.encode()))
        self.assertEqual(len(result.dependencies), 1)
        with self.assertRaisesRegex(ValueError, '^mandatory_budget_exceeded$'):
            pack_context(source, hits, len, 2048, mandatory='x' * 2049)
        with self.assertRaisesRegex(ValueError, '^invalid_context_budget$'):
            pack_context(source, hits, len, 999)

    def test_one_absolute_deadline_and_whole_work_budget_never_reset_per_stage(self):
        from getzilla.retrieval.budget import Budget
        clock = [10.0]
        budget = Budget(clock=lambda: clock[0])
        g = self.build(snapshot(document()), budget=budget)
        clock[0] = 12.0
        with self.assertRaisesRegex(ValueError, '^deadline_exceeded$'):
            self.search(g, 'choose_key', budget=budget)
        budget = Budget()
        budget.charge('authorization_calls', 32)
        with self.assertRaisesRegex(ValueError, '^authorization_calls_exceeded$'):
            budget.charge('authorization_calls', 1)

    def test_hard_profile_rejects_unbounded_source_and_query_before_ranking(self):
        with self.assertRaisesRegex(ValueError, '^source_file_exceeded$'):
            document(text='x' * (1_048_576 + 1))
        g = self.build(snapshot(document()))
        with self.assertRaisesRegex(ValueError, '^query_bytes_exceeded$'):
            self.search(g, 'x' * 4097)
        with self.assertRaisesRegex(ValueError, '^query_terms_exceeded$'):
            self.search(g, ' '.join('word' + str(i) for i in range(65)))

    def test_invalid_snapshot_document_is_fixed_diagnostic(self):
        from getzilla.retrieval.contracts import SourceSnapshot
        with self.assertRaisesRegex(ValueError, '^invalid_source_document$'):
            SourceSnapshot.create('tenant', 'project', 'repo', (object(),))
    def test_generation_source_identity_cannot_be_mutated_after_build(self):
        g = self.build(snapshot(document()))
        with self.assertRaises(TypeError):
            g.source_snapshot['kind'] = 'caller_claim'

    def test_explicit_counter_reuses_fixed_254_token_two_line_overlap_windows(self):
        text = 'def f():\n' + ''.join('    value = "' + 'word ' * 70 + '"\n' for _ in range(6))
        class AlgorithmCounter:
            identity = 'b' * 64
            def count(self, value):
                return len(value.split())
        g = self.build(snapshot(document(text=text)), window_counter=AlgorithmCounter())
        by_start = sorted(g.chunks, key=lambda c: c.start)
        self.assertEqual((by_start[0].start, by_start[0].end), (1, 4))
        self.assertEqual(by_start[1].start, by_start[0].end - 1)
        self.assertEqual(by_start[-1].end, 7)
        self.assertTrue(all(c.encoder_tokens <= 254 and c.encoder_truncated is False for c in g.chunks))
        self.assertIn('b' * 64, g.window_profile)

    def test_long_single_line_records_encoder_truncation_without_discarding_source_bytes(self):
        class AlgorithmCounter:
            identity = 'b' * 64
            def count(self, value):
                return len(value.split())
        text = 'def f():\n    return "' + 'word ' * 300 + '"\n'
        source = snapshot(document(text=text))
        g = self.build(source, window_counter=AlgorithmCounter())
        self.assertTrue(any(c.encoder_truncated for c in g.chunks))
        self.assertIn('word ' * 300, ''.join(c.text for c in g.chunks))

    def test_ranking_and_citation_work_share_aggregate_source_byte_limit(self):
        from getzilla.retrieval.budget import Budget
        g = self.build(snapshot(document()))
        b = Budget()
        b.charge('query_source_bytes', 8 * 1024 * 1024)
        with self.assertRaisesRegex(ValueError, '^query_source_bytes_exceeded$'):
            self.search(g, 'choose_key', budget=b)

    def test_token_counter_error_never_echoes_private_payload(self):
        from getzilla.retrieval.engine import pack_context
        source = snapshot(document())
        def broken(value):
            raise RuntimeError('PRIVATE_TOKENIZER_SENTINEL')
        with self.assertRaisesRegex(ValueError, '^tokenizer_unavailable$'):
            pack_context(source, (), broken, 2048)

    def test_index_chunk_storage_budget_is_aggregate_across_the_generation(self):
        from getzilla.retrieval.budget import Budget
        b = Budget()
        b.charge('index_bytes', 32 * 1024 * 1024)
        with self.assertRaisesRegex(ValueError, '^index_bytes_exceeded$'):
            self.build(snapshot(document()), budget=b)

    def test_unicode_literals_keep_physical_citation_lines_and_following_declaration(self):
        from getzilla.retrieval.engine import pack_context, verify_citation
        from getzilla.retrieval.ranking import RankedHit
        for separator in ('\u2028', '\u2029', '\u0085', '\v', '\f', '\x1c'):
            for newline in ('\n', '\r\n', '\r'):
                with self.subTest(separator=ascii(separator), newline=ascii(newline)):
                    text = newline.join(('def hello():', f'    return "hello{separator}world"',
                        'def next_item():', '    return 2', ''))
                    source = snapshot(document(path='hello.py', text=text))
                    generation = self.build(source)
                    chunks = sorted(generation.chunks, key=lambda chunk: chunk.start)
                    self.assertEqual([(c.symbol, c.start, c.end) for c in chunks],
                        [('hello', 1, 2), ('next_item', 3, 4)])
                    for chunk in chunks:
                        verify_citation(source, chunk)
                    hits = tuple(RankedHit(c, 1.0, i) for i, c in enumerate(chunks, 1))
                    packed = pack_context(source, hits, len, 2048)
                    headers = [line for line in packed.text.split('\n') if line.startswith('[')]
                    self.assertEqual(len(headers), 2)
                    self.assertIn('source-lines=1,2]', headers[0])
                    self.assertIn('source-lines=3,4]', headers[1])
                    self.assertIn('def next_item():', packed.text)
                    self.assertIn(f'hello{separator}world', packed.text)
                    self.assertIn(newline.join(('def hello():', f'    return "hello{separator}world"', '')),
                        packed.text)


if __name__ == '__main__':
    unittest.main()
