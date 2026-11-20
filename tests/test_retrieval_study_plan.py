import importlib
import unittest


class StudyPlanTests(unittest.TestCase):
    def owner(self):
        try:
            return importlib.import_module('getzilla.retrieval.study_plan')
        except ModuleNotFoundError:
            self.fail('fixed study orchestration plan owner missing')

    def test_compiled_plan_contains_all_six_arms_and_ten_observations(self):
        owner = self.owner()
        self.assertEqual(owner.ARMS, ('exact_symbol', 'bm25', 'dense_minilm', 'dense_bge_m3',
                                    'rrf_minilm', 'rrf_bge_m3'))
        rows = owner.query_schedule(({'query_id': 'q1'}, {'query_id': 'q2'}))
        self.assertEqual(len(rows), 40)
        self.assertEqual(rows[:2], (('minilm', 0, 'q1'), ('minilm', 0, 'q2')))
        self.assertEqual(rows[-1], ('bge_m3', 9, 'q2'))

    def test_mapping_preserves_original_overloads_and_protocol_rows(self):
        owner = self.owner()
        original = [{'id': 'x.py:1:f', 'path': 'x.py', 'start': 1, 'end': 1,
                     'symbol': 'f', 'sha256': 'a' * 64, 'file_sha256': 'b' * 64,
                     'overload_stub': False},
                    {'id': 'x.py:2:f', 'path': 'x.py', 'start': 2, 'end': 2,
                     'symbol': 'f', 'sha256': 'c' * 64, 'file_sha256': 'b' * 64,
                     'overload_stub': True}]
        universe = {'universes': [{'corpus': 'small', 'functions': [
            {'historical_id': 'x.py:1:f', 'function_id': 'd' * 64}]}]}
        grouped, mapping = owner.original_function_mapping(universe, (('small', tuple(original)),))
        self.assertEqual(len(grouped['small', 'x.py']), 2)
        self.assertFalse(grouped['small', 'x.py'][0]['overload_stub'])
        self.assertEqual(mapping['small', 'x.py:1:f'], 'd' * 64)

    def test_cut_document_mapping_requires_exact_catalog_commit_path_and_bytes(self):
        from getzilla.native_access import SourceDependency, SourceDocument
        from getzilla.retrieval.contracts import sha
        owner = self.owner()
        raw = b'inert public bytes'
        catalog = (('small', 'x.py', 'a' * 40, len(raw), sha(raw)),)
        dependency = SourceDependency(('os-test', 'repo', 'public-research', 'a' * 40,
            sha(b'small/x.py')), 'sha256:' + sha(raw), sha(raw), sha(raw), 'exact-public-original-v1')
        doc = SourceDocument(dependency, raw)
        self.assertEqual(owner.map_source_documents(catalog, (doc,)), (('small', 'x.py', raw),))
        with self.assertRaises(ValueError):
            owner.map_source_documents(catalog, (SourceDocument(dependency, b'changed'),))

    def test_unknown_original_function_stays_unjudged_in_rank_projection(self):
        owner = self.owner()
        self.assertEqual(owner.project_function_positions(['missing@1-1', 'x@1-2'],
            {'x@1-2': {'function_id': 'x'}}, {'x': 'stable'}),
            ('unjudged-window:missing@1-1', 'stable'))
