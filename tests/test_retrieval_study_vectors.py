import importlib
import math
import unittest


class StudyVectorTests(unittest.TestCase):
    def owner(self):
        try:
            return importlib.import_module('getzilla.retrieval.study_vectors')
        except ModuleNotFoundError:
            self.fail('fixed numerical study owner is missing')

    def test_mean_includes_active_special_tokens_and_excludes_padding(self):
        owner = self.owner()
        states = [[1.0] * 384, [3.0] * 384, [900.0] * 384]
        vector = owner.pool_hidden('minilm', states, [1, 1, 0])
        self.assertAlmostEqual(vector[0], 1 / math.sqrt(384))
        self.assertEqual(len(vector), 384)

    def test_cls_only_for_bge(self):
        owner = self.owner()
        first = [1.0, 0.0] + [0.0] * 1022
        other = [0.0, 1.0] + [0.0] * 1022
        self.assertEqual(owner.pool_hidden('bge_m3', [first, other], [1, 1]), tuple(first))

    def test_raw_rank3_contract_cannot_accept_already_pooled_or_nonfinite(self):
        owner = self.owner()
        for states, mask in (([1.0] * 384, [1]), ([[float('nan')] * 384], [1]),
                             ([[1.0] * 383], [1]), ([[1.0] * 384], [0]),
                             ([[1.0] * 384], [True])):
            with self.subTest(mask=mask), self.assertRaises(ValueError):
                owner.pool_hidden('minilm', states, mask)

    def test_dense_negative_scores_remain_and_ties_use_original_ids(self):
        scores = self.owner().dense_ranks((1.0, 0.0), {'z': (-1.0, 0.0),
                                                    'a': (0.0, 1.0), 'b': (0.0, -1.0)})
        self.assertEqual(scores, (('a', 0.0), ('b', 0.0), ('z', -1.0)))

    def test_three_arm_rrf_uses_positions_and_fixed_sixty(self):
        scores = self.owner().rrf_ranks((('x', 'y'), ('y',), ('z', 'x')))
        self.assertEqual(scores[0][0], 'x')
        self.assertAlmostEqual(dict(scores)['x'], 1 / 61 + 1 / 62)
        self.assertAlmostEqual(dict(scores)['z'], 1 / 61)

    def test_empty_unknown_or_repeated_arm_rows_do_not_mutate_protocol(self):
        owner = self.owner()
        with self.assertRaises(ValueError):
            owner.rrf_ranks((('x', 'x'), (), ()))
        with self.assertRaises(ValueError):
            owner.rrf_ranks(((), ()))
