import importlib
import unittest


class StudyResultTests(unittest.TestCase):
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
