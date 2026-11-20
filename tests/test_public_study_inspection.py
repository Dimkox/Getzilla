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
