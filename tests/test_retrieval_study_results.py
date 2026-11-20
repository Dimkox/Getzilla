import importlib
import unittest
from unittest.mock import patch


class StudyResultTests(unittest.TestCase):
    def test_class_language_corpus_table_keeps_missing_pair_denominator(self):
        owner = self.owner()
        tasks = [{'task_id': 't', 'corpus': 'small', 'stratum': 'exact', 'split': 'holdout'}]
        dataset = ({}, {'tasks': tasks}, {'queries': [
            {'query_id': 'q0', 'task_id': 't', 'language': 'ru'},
            {'query_id': 'q1', 'task_id': 't', 'language': 'ru'}]},
            {'tables': [{'rows': [{'judgments': [0, 1, 2]}]}]})
        values = {name: [1, 1] for name in ('recall_at_5_ratio', 'mrr_at_10_ratio',
                  'context_recall_2048_ratio', 'context_recall_8192_ratio')}
        report = owner.quality_tables(dataset, {('minilm', 'q0'): {'bm25': values}})
        row = next(value for value in report['groups'] if value['arm'] == 'bm25')
        self.assertEqual((row['corpus'], row['language'], row['class']), ('small', 'ru', 'exact'))
        self.assertEqual(row['metrics']['recall_at_5_ratio'],
                         {'denominator': 2, 'observed': 1, 'mean': None, 'mean_ratio': None})
        self.assertEqual(row['status'], 'INCONCLUSIVE')
        self.assertEqual(report['label_coverage'], {'0': 1, '1': 1, '2': 1})

    def test_registered_runtime_summary_uses_all_samples_and_linear_percentiles(self):
        owner = self.owner()
        summary = owner.measurement_summary([
            {'model': 'minilm', 'corpus': 'small', 'phase': 'query_encoding',
             'wall_seconds': value, 'cpu_seconds': value / 2, 'peak_rss_bytes': 4096}
            for value in (1., 2., 3., 4.)])
        row = summary['groups'][0]
        self.assertEqual(row['samples'], 4)
        self.assertEqual(row['wall_seconds']['p50'], 2.5)
        self.assertAlmostEqual(row['wall_seconds']['p95'], 3.85)
        self.assertEqual(summary['peak_native_child_rss_bytes'], 4096)
        self.assertEqual(summary['updates']['status'], 'not_performed')
        with self.assertRaises(ValueError):
            owner.measurement_summary([{'model': 'minilm', 'corpus': 'small', 'phase': 'query_encoding',
                'wall_seconds': float('nan'), 'cpu_seconds': 0., 'peak_rss_bytes': 1}])

    def test_measurement_schema_count_and_unknown_counters_cannot_be_upgraded(self):
        owner = self.owner()
        row = {'model': 'minilm', 'corpus': 'small', 'phase': 'index',
               'wall_seconds': .1, 'cpu_seconds': None, 'peak_rss_bytes': None}
        report = owner.measurement_summary([row])
        self.assertIsNone(report['groups'][0]['cpu_seconds'])
        self.assertIsNone(report['peak_native_child_rss_bytes'])
        self.assertIsNone(report['whole_container_peak_ram_bytes'])
        for changed in (row | {'approved': True}, row | {'cpu_seconds': True},
                        row | {'phase': 'unregistered'}, row | {'peak_rss_bytes': -1}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                owner.measurement_summary([changed])
        with self.assertRaises(ValueError):
            owner.measurement_summary([row] * 81921)

    def test_observation_serialization_expiry_cannot_accept_an_overtime_query(self):
        owner = self.owner()
        accumulator = owner.Observations(('q',))
        clock, original = [0.], owner.json.dumps
        def serialize(*args, **kwargs):
            raw = original(*args, **kwargs)
            clock[0] = 2.
            return raw
        with patch.object(owner.time, 'monotonic', side_effect=lambda: clock[0]), \
                patch.object(owner.json, 'dumps', side_effect=serialize):
            with self.assertRaisesRegex(ValueError, 'study_query_deadline'):
                accumulator.add('minilm', 0, 'q', {}, seconds=.1,
                                absolute_deadline=2., query_started=0.)
        self.assertEqual(accumulator.coverage()['observed'], 0)

    def owner(self):
        try:
            return importlib.import_module('getzilla.retrieval.study_results')
        except ModuleNotFoundError:
            self.fail('exact fixed-study result reducer missing')

    def test_exact_five_percent_boundary_does_not_depend_on_float_rounding(self):
        owner = self.owner()
        tasks = tuple(f't{i}' for i in range(16))
        baseline = dict.fromkeys(tasks, (1, 1))
        candidate = dict.fromkeys(tasks, (19, 20))
        result = owner.paired_ratios(tasks, baseline, candidate)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['mean_delta_ratio'], [-1, 20])
        self.assertEqual(result['paired_task_deltas'], dict.fromkeys(tasks, [-1, 20]))
        candidate['t0'] = (18, 20)
        self.assertEqual(owner.paired_ratios(tasks, baseline, candidate)['status'], 'FAIL')

    def test_missing_pair_retains_fixed_sixteen_denominator(self):
        owner = self.owner()
        tasks = tuple(f't{i}' for i in range(16))
        result = owner.paired_ratios(tasks, dict.fromkeys(tasks, (1, 1)), {})
        self.assertEqual(result['status'], 'INCONCLUSIVE')
        self.assertEqual(result['denominator'], 16)
        self.assertEqual(len(result['missing_tasks']), 16)

    def test_immutable_query_observation_key_never_selects_best_pass(self):
        owner = self.owner()
        accumulator = owner.Observations(('q',))
        accumulator.add('minilm', 0, 'q', {'rankings': {'dense_minilm': [('w', .1)]}}, seconds=.2)
        accumulator.add('minilm', 1, 'q', {'rankings': {'dense_minilm': [('v', .9)]}}, seconds=.1)
        self.assertEqual(accumulator.first('minilm', 'q')['result']['rankings']['dense_minilm'][0][0], 'w')
        self.assertEqual(accumulator.nondeterministic(), (('minilm', 'q'),))
        with self.assertRaises(ValueError):
            accumulator.add('minilm', 0, 'q', {}, seconds=.01)
        self.assertEqual(accumulator.coverage()['expected'], 20)
        self.assertEqual(accumulator.coverage()['observed'], 2)

    def test_result_alias_and_returned_copy_cannot_rewrite_first_observation(self):
        owner = self.owner()
        accumulator = owner.Observations(('q',))
        result = {'rankings': {'dense_minilm': [['original', .1]]}}
        accumulator.add('minilm', 0, 'q', result, seconds=.2)
        result['rankings']['dense_minilm'][0][0] = 'rewritten'
        observed = accumulator.first('minilm', 'q')
        self.assertEqual(observed['result']['rankings']['dense_minilm'][0][0], 'original')
        observed['result']['rankings']['dense_minilm'][0][0] = 'other'
        self.assertEqual(accumulator.first('minilm', 'q')['result']['rankings']['dense_minilm'][0][0], 'original')
