"""Closed original-body accounting; these factual seams issue no witness."""
import unittest
from unittest.mock import Mock
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".getzilla"))
from getzilla.retrieval import public_review_witness as witness


class SupplementBudgetTests(unittest.TestCase):
    def test_original_b_is_hash_read_in_the_same_group_not_a_producer_reference(self):
        capture = Mock()
        original = {'path': '.getzilla/runtime/b-original.json',
            'sha256': '5971c88d285172e345a07418dd269ae63760c4e147efe01f3a3c7cd13846981c',
            'bytes': 6967743}
        group = {'original': original, 'supplement': {'path': 'manifest'}, 'delivery_identity': {}}
        witness._capture_original(capture, group)
        capture.read.assert_called_once_with(original['path'], limit=8 * 1048576,
                                              expected=original, keep=False)
        capture.producer_reference.assert_not_called()

    def test_unknown_original_cannot_use_either_factual_port(self):
        capture = Mock()
        with self.assertRaises(ValueError):
            witness._capture_original(capture, {'original': {'path': '.getzilla/runtime/unknown',
                'sha256': 'a' * 64, 'bytes': 6967743}, 'supplement': {}, 'delivery_identity': {}})
        capture.read.assert_not_called()
        capture.producer_reference.assert_not_called()

    def test_exact_a_keeps_separate_owner_fingerprint_requirement(self):
        capture = Mock()
        group = {'original': {'path': '.getzilla/runtime/a-original.json',
            'sha256': 'b1e1245b7d56570388cda4497d769cca0b8225361f8b80f27af9bf43a264e063',
            'bytes': 12774653}, 'supplement': {'path': 'manifest'}, 'delivery_identity': {'agent_task': 'producer'}}
        witness._capture_original(capture, group)
        capture.producer_reference.assert_called_once_with(group['original'], group['delivery_identity'], group['supplement'])
        capture.read.assert_not_called()
