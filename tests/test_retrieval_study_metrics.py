"""Tiny fixed-study metrics controls; no retained corpus or model execution."""
import importlib
import unittest


class StudyMetricsTests(unittest.TestCase):
    def owner(self):
        try:
            return importlib.import_module('getzilla.retrieval.study_metrics')
        except ModuleNotFoundError:
            self.fail('fixed-position study metrics owner is missing')

    def test_unknown_positions_are_not_dropped_or_refilled(self):
        result = self.owner().ranking_metrics(
            ['outside', 'a', 'a', 'outside2', 'b', 'c'], {'a': 2, 'b': 2, 'c': 1})
        self.assertEqual(result['recall_at_5'], 0)
        self.assertEqual(result['mrr_at_10'], 1 / 6)
        self.assertEqual(result['unjudged_positions_at_10'], [1, 4])
        self.assertEqual(result['judgment_status'], 'partial')

    def test_duplicate_relevant_windows_credit_one_function(self):
        result = self.owner().ranking_metrics(['a', 'a', 'b'], {'a': 1, 'b': 1, 'c': 1})
        self.assertEqual(result['recall_at_5'], 2 / 3)
        self.assertEqual(result['mrr_at_10'], 1)

    def test_unjudged_is_never_a_negative_and_no_answer_is_separate(self):
        result = self.owner().ranking_metrics(['a'], {'a': 0, 'b': 2})
        self.assertIsNone(result['recall_at_5'])
        self.assertIsNone(result['mrr_at_10'])
        self.assertEqual(result['positive_functions'], 0)
        self.assertEqual(result['judgment_status'], 'partial')

    def test_holdout_missing_pair_does_not_shrink_sixteen_task_denominator(self):
        owner = self.owner()
        ids = tuple(f't{i}' for i in range(16))
        a = dict.fromkeys(ids, 1.0)
        b = dict.fromkeys(ids[:-1], 1.0)
        result = owner.paired_holdout(ids, a, b)
        self.assertEqual(result['status'], 'INCONCLUSIVE')
        self.assertEqual(result['denominator'], 16)
        self.assertEqual(result['missing_tasks'], ['t15'])
        self.assertIsNone(result['mean_delta'])

    def test_holdout_threshold_and_complete_negative_delta(self):
        owner = self.owner()
        ids = tuple(f't{i}' for i in range(16))
        result = owner.paired_holdout(ids, dict.fromkeys(ids, 1.0), dict.fromkeys(ids, .9))
        self.assertEqual(result['status'], 'FAIL')
        self.assertAlmostEqual(result['mean_delta'], -.1)
        self.assertEqual(result['denominator'], 16)

    def test_malformed_or_nonfinite_metrics_fail_closed(self):
        owner = self.owner()
        for labels in ({'x': True}, {'x': 3}):
            with self.subTest(labels=labels), self.assertRaises(ValueError):
                owner.ranking_metrics(['x'], labels)
        with self.assertRaises(ValueError):
            owner.paired_holdout(tuple(str(i) for i in range(16)), {}, {'0': float('nan')})
