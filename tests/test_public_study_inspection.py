"""Unavailable native/result ports never turn JSON into PhaseB authority."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla.retrieval import public_study_inspection as owner
from getzilla.retrieval.public_review_witness import OperatorWitnessedPublicReviewedInputs


class PublicStudyInspectionTests(unittest.TestCase):
    def test_json_and_unissued_objects_cannot_be_consumed_as_b(self):
        for value in ({'status': 'pass'}, object(), object.__new__(owner.OperatorWitnessedPublicInspection)):
            for phase_a in ({'approved': True}, object.__new__(OperatorWitnessedPublicReviewedInputs)):
                with self.subTest(value=type(value).__name__), self.assertRaises(ValueError):
                    owner.consume_public_inspection(value, phase_a)
        with self.assertRaises(TypeError):
            owner.OperatorWitnessedPublicInspection()

    def test_source_report_and_declared_native_ids_cannot_issue_b(self):
        with self.assertRaises(ValueError):
            owner.witness_public_inspection(Path('/nonexistent-untrusted-root'), 'report.json',
                {'reviewed': True}, {'native_session_id': 'declared'}, {'execution_status': 'succeeded'})

    def test_declared_failure_is_not_an_observed_owned_attempt(self):
        with self.assertRaises(ValueError):
            owner.record_public_inspection_outcome(Path('/nonexistent-untrusted-root'),
                {'operation': 'inspect_public_artifacts'}, {'execution_status': 'failed'})

    def test_positive_inspection_cannot_survive_original_deadline(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        observed = SimpleNamespace(execution_status='succeeded', cleanup_status='confirmed',
            native_execution_observation='native-completed', image_id='sha256:' + 'a' * 64,
            resource_readback_digest='b' * 64, original_deadline=100.0)
        with patch.object(owner.time, 'monotonic', return_value=99.0):
            owner._completed(observed)
        for current in (100.0, 101.0):
            with self.subTest(current=current), patch.object(owner.time, 'monotonic', return_value=current):
                with self.assertRaisesRegex(ValueError, 'public_inspection_original_deadline'):
                    owner._completed(observed)
        for invalid in (None, True, '100', float('inf'), float('nan')):
            observed.original_deadline = invalid
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                owner._completed(observed)

    def test_declared_deadline_cannot_replace_genuine_b_owner(self):
        with self.assertRaises(ValueError):
            owner.public_inspection_deadline({'original_deadline': 10**20}, {'approved': True})
