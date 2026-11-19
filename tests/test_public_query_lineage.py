"""Tiny consistency controls, without issuing public review authority."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla.retrieval.public_query_lineage import query_revision
from getzilla.retrieval.public_review_inputs import ScientificBudget
from getzilla.retrieval.contracts import sha


class QueryLineageTests(unittest.TestCase):
    def fixture(self):
        old = {'queries': [
            {'query_id': 'q-en', 'task_id': 'task', 'language': 'en', 'text': 'Locate alpha in module.'},
            {'query_id': 'q-mix', 'task_id': 'task', 'language': 'mixed', 'text': 'Locate alpha in module. найти'}]}
        new = deepcopy(old)
        new['queries'][1]['text'] = 'Найдите alpha in module и проверьте signature.'
        report = {'clusters': [{'variants': [{'query_id': 'q-mix', 'language': 'mixed',
            'mixed_language_factor': 'suffix_only_or_weak'}]}]}
        return old, new, report

    def validate(self, old, new, report):
        def raw(value):
            return json.dumps(value, ensure_ascii=False).encode()
        return query_revision(old, new, raw(old), raw(new), report,
            {'task': {'stratum': 'exact', 'corpus': 'small'}}, expected_sha256=sha(raw(new)),
            expected_changes=1, budget=ScientificBudget())

    def test_exact_rejected_mixed_revision_retains_identifiers_and_inverse_bytes(self):
        result = self.validate(*self.fixture())
        self.assertEqual(result['q-mix']['code_identifiers'], ['alpha', 'module'])
        self.assertEqual(result['q-mix']['pointer'], '/queries/1/text')

    def test_english_identifier_metadata_and_unflagged_changes_refuse(self):
        for mutation in ('english', 'identifier', 'metadata', 'unflagged'):
            with self.subTest(mutation=mutation):
                old, new, report = self.fixture()
                if mutation == 'english':
                    new['queries'][0]['text'] = 'Locate beta in module.'
                elif mutation == 'identifier':
                    new['queries'][1]['text'] = 'Найдите beta in module.'
                elif mutation == 'metadata':
                    new['queries'][1]['task_id'] = 'other'
                else:
                    report['clusters'][0]['variants'][0]['mixed_language_factor'] = 'natural_identifier_mixed'
                with self.assertRaises(ValueError):
                    self.validate(old, new, report)

    def test_source_equivalence_requires_original_reviewer_and_unchanged_meaning(self):
        from getzilla.retrieval.public_query_lineage import source_equivalence
        from tests.test_public_review_inputs import scenario
        original = scenario()[3][0]
        changed = self.validate(*self.fixture())
        known = changed['q-mix']
        report = {'schema_version': 1, 'kind': 'independent_source_query_equivalence_v1',
            'reviewer': original['reviewer'], 'original_annotation_sha256': 'a' * 64,
            'original_query_sha256': 'b' * 64, 'revised_query_sha256': 'c' * 64,
            'corpus': original['corpus'], 'source_commit': 'd' * 40, 'manifest_sha256': 'e' * 64,
            'universe_digest': original['universe_digest'], 'slice_start': original['slice_start'],
            'slice_end': original['slice_end'], 'function_ids': original['function_ids'],
            'observed_provenance': {}, 'limitations': ['Tiny factual consistency fixture.'],
            'touched_variants': [{key: known[key] for key in ('task_id', 'query_id', 'old_text_sha256',
                'new_text_sha256', 'base_en_query_id', 'base_en_text_sha256', 'code_identifiers')}]}
        report['touched_variants'][0].update(inspected_meaning='Same literal function lookup.',
            base_en_intent='preserved', label_impact='unchanged', rationale='Original source slice inspected.')
        def check(value):
            return source_equivalence(value, original, 'a' * 64, changed,
                corpus_manifest=('d' * 40, 'e' * 64), old_query_sha256='b' * 64,
                new_query_sha256='c' * 64, budget=ScientificBudget())
        self.assertEqual(len(check(report)), 2)
        for mutation in ('unknown', 'reviewer', 'identifier', 'missing'):
            altered = deepcopy(report)
            if mutation == 'unknown':
                altered['touched_variants'][0]['label_impact'] = 'unknown'
            elif mutation == 'reviewer':
                altered['reviewer']['native_session_id'] = 'other'
            elif mutation == 'identifier':
                altered['touched_variants'][0]['code_identifiers'] = ['beta']
            else:
                altered['touched_variants'] = []
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                check(altered)
