"""Explicit tiny scientific fixtures; no production review or native authority."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla.retrieval.contracts import sha
from getzilla.retrieval.evaluation_inputs import AuditProfile
from tests.test_retrieval_evaluation_inputs import fixture

PROFILE = AuditProfile((('small', 2), ('large', 2)), 1)
NAMES = ('function-universes.json', 'partition.json', 'queries.json', 'full-qrels.json')


def scenario():
    old = fixture()
    for query in old[2]['queries']:
        symbol = 'gamma_missing' if query['task_id'].endswith('no_answer') else 'alpha'
        query['text'] = {'en': 'Find the implementation of ' + symbol + '.',
            'ru': 'Найдите реализацию ' + symbol + '.',
            'mixed': 'Find ' + symbol + ' и объясните return value.'}[query['language']]
    final = deepcopy(old)
    for table in final[3]['tables']:
        for row in table['rows']:
            row['judgments'] = [2, 2] if row['task_id'].endswith('no_answer') else [1, 2]
    hashes = {name: sha(json.dumps(body, sort_keys=True).encode()) for name, body in zip(NAMES, old[:4])}
    reports = []
    for reviewer in ('first', 'second'):
        wave = []
        for universe, table in zip(final[0]['universes'], final[3]['tables']):
            evidence = []
            for row in table['rows']:
                for index, decision in enumerate(row['judgments']):
                    function = universe['functions'][index]
                    evidence.append({'task_id': row['task_id'], 'decision': decision,
                        'function_indices': [index], 'rationale': 'Owned synthetic source fixture decision.',
                        'locators': [{key: function[key] for key in ('path', 'start', 'end', 'file_sha256', 'declaration_sha256')}]})
            wave.append({'schema_version': 1, 'kind': 'independent_partial_qrels_v1',
                'reviewer': {'agent_task': reviewer, 'role': 'data_reviewer', 'native_session_id': reviewer, 'native_generation': None},
                'corpus': universe['corpus'], 'slice_start': 0, 'slice_end': 2,
                'function_ids': table['function_ids'], 'input_hashes': hashes,
                'universe_digest': universe['universe_digest'],
                'tasks': [{'task_id': row['task_id'], 'judgments': list(row['judgments']), 'issues': []} for row in table['rows']],
                'source_evidence': evidence, 'limitations': ['Separate tiny fixture.']})
        reports.append(wave)
    clusters = []
    for task in final[1]['tasks']:
        variants = [q for q in final[2]['queries'] if q['task_id'] == task['task_id']]
        no_answer = task['stratum'] == 'no_answer'
        clusters.append({'task_id': task['task_id'], 'cluster_id': task['cluster_id'], 'corpus': task['corpus'],
            'split': task['split'], 'declared_stratum': task['stratum'], 'partition_grouping': 'supported',
            'stratum_fit': 'supported', 'novelty': 'development_reference' if task['split'] == 'development' else 'distinct_intent_supported',
            'source_answerability': 'confirmed_no_answer' if no_answer else 'direct_support_observed',
            'nearest_task_ids': [], 'source_locators': [] if no_answer else [{key: next(
                universe for universe in final[0]['universes'] if universe['corpus'] == task['corpus'])['functions'][0][key]
                for key in ('path', 'start', 'end', 'file_sha256', 'declaration_sha256')}], 'rationale': 'Separate reviewed synthetic fixture.',
            'variants': [{'query_id': q['query_id'], 'language': q['language'], 'text_sha256': sha(q['text'].encode()),
                'semantic_equivalence': 'supported', 'mixed_language_factor': 'natural_identifier_mixed' if q['language'] == 'mixed' else 'not_applicable',
                'rationale': 'Fixture equivalence.', 'proposed_text': None} for q in variants]})
    query = {'schema_version': 1, 'kind': 'independent_query_review_v1', 'reviewer': {
        'agent_task': 'query', 'role': 'data_reviewer', 'native_session_id': 'query', 'native_generation': None},
        'input_hashes': hashes, 'clusters': clusters, 'limitations': ['Separate tiny fixture.']}
    return final, hashes, reports[0], reports[1], query


class PublicReviewInputTests(unittest.TestCase):
    def validate(self, value):
        from getzilla.retrieval.public_review_inputs import validate_reviewed_inputs
        final, hashes, first, second, query = value
        return validate_reviewed_inputs(final, hashes, first, second, query,
            author=('author', 'author'), dispositions=[], no_answer_resolutions=[], profile=PROFILE)

    def test_complete_source_review_facts_do_not_mint_authority(self):
        result = self.validate(scenario())
        self.assertEqual(result['cells'], 40)
        self.assertFalse(result['ranking_permitted'])

    def test_missing_second_unjudged_order_crossdataset_and_self_review_fail(self):
        for change in ('second', 'zero', 'order', 'hash', 'self', 'evidence', 'variant', 'disagreement'):
            value = scenario()
            if change == 'second':
                value[3].pop()
            if change == 'zero':
                value[0][3]['tables'][0]['rows'][0]['judgments'][0] = 0
            if change == 'order':
                value[2][0]['function_ids'] = list(reversed(value[2][0]['function_ids']))
            if change == 'hash':
                value[2][0]['input_hashes'] = {**value[1], 'queries.json': 'a' * 64}
            if change == 'self':
                value[3][0]['reviewer'] = value[2][0]['reviewer']
            if change == 'evidence':
                value[3][0]['source_evidence'].pop()
            if change == 'variant':
                value[4]['clusters'][0]['variants'].pop()
            if change == 'disagreement':
                value[2][0]['tasks'][0]['judgments'][0] = 2
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate(value)

    def test_actual_cell_and_noanswer_dispositions_are_required_and_bound(self):
        from getzilla.retrieval.public_review_inputs import validate_reviewed_inputs
        from getzilla.retrieval.contracts import digest
        final, hashes, first, second, query = scenario()
        row = first[0]['tasks'][0]
        row['judgments'][0] = 0
        first[0]['source_evidence'][0]['decision'] = 0
        disposition = {'corpus': 'small', 'task_id': row['task_id'],
            'function_id': final[0]['universes'][0]['functions'][0]['function_id'],
            'first': 0, 'second': 1, 'final': 1, 'initial_report_digest': digest(first[0]),
            'second_report_digest': digest(second[0]), 'reason': 'Fixture coordinator resolves actual source-backed difference.'}
        cluster = next(c for c in query['clusters'] if c['declared_stratum'] == 'no_answer')
        cluster['stratum_fit'] = 'ambiguous'
        cluster['source_answerability'] = 'declared_no_answer_not_exhaustively_certified'
        resolution = {'task_id': cluster['task_id'], 'query_report_digest': digest(query),
            'decision': 'confirmed-no-answer-from-complete-source-reviews',
            'reason': 'All fixed-universe cells have complete distinct source review and are nonrelevant.'}
        arguments = dict(author=('author', 'author'), dispositions=[disposition],
                         no_answer_resolutions=[resolution], profile=PROFILE)
        result = validate_reviewed_inputs(final, hashes, first, second, query, **arguments)
        self.assertEqual(result['cells'], 40)
        for field, bad in [('dispositions', []), ('no_answer_resolutions', [])]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_reviewed_inputs(final, hashes, first, second, query, **{**arguments, field: bad})

    def test_unresolved_mixed_factor_and_wrong_language_factor_refuse(self):
        for language, factor in [('mixed', 'UNRESOLVED_INVALID_MIX'), ('mixed', 'not_applicable'),
                                 ('mixed', 'suffix_only_or_weak'), ('en', 'natural_identifier_mixed')]:
            value = scenario()
            for cluster in value[4]['clusters']:
                for variant in cluster['variants']:
                    if variant['language'] == language:
                        variant['mixed_language_factor'] = factor
            with self.subTest(language=language, factor=factor), self.assertRaises(ValueError):
                self.validate(value)

    def test_scientific_cpu_work_checks_original_deadline_mid_loop(self):
        from unittest.mock import patch
        from getzilla.retrieval.public_review_inputs import ScientificBudget, validate_reviewed_inputs
        value = scenario()
        with patch('getzilla.retrieval.public_review_inputs.time.monotonic', side_effect=[1] * 12 + [100] * 100) as clock:
            budget = ScientificBudget(31)
            with self.assertRaisesRegex(ValueError, 'public_review_deadline'):
                validate_reviewed_inputs(value[0], value[1], value[2], value[3], value[4],
                    author=('author', 'author'), dispositions=[], no_answer_resolutions=[], profile=PROFILE, budget=budget)
            self.assertGreater(clock.call_count, 12)


if __name__ == '__main__':
    unittest.main()
