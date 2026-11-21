"""Delivery cut precision must never make a later append visible earlier."""
import unittest

from tests import test_sprint_report as fixtures
from getzilla.metrics_journal import digest
from getzilla.sprint_report import summarize_sprint


class DeliveryClockTests(unittest.TestCase):
    def row(self):
        return fixtures.observation('selected', window_start=fixtures.START,
                                    at='2026-10-23T23:59:59Z', captured_at='2026-10-23T23:59:59Z')

    def proof(self, row, at='2026-10-24T00:00:00.900000Z'):
        return {'proof_version': 2, 'clock_domain': 'native_local_utc',
                'row_digest': digest(row), 'delivered_by': at}

    def report(self, row, proof, cut):
        return summarize_sprint([row], start=fixtures.START, as_of=cut,
            source_manifest={'delivery_proofs': {row['event_id']: proof}})

    def test_legacy_floored_seconds_proof_is_unqualified(self):
        row = self.row()
        old = {'row_digest': digest(row), 'delivered_by': '2026-10-24T00:00:00Z'}
        report = self.report(row, old, '2026-10-24T00:00:00Z')
        self.assertEqual(report['tasks'], [])
        self.assertIsNone(report['counts']['observed_selected'])

    def test_fraction_second_proof_does_not_cross_the_earlier_cut(self):
        row = self.row()
        before = self.report(row, self.proof(row), '2026-10-24T00:00:00Z')
        after = self.report(row, self.proof(row), '2026-10-24T00:00:01Z')
        self.assertEqual(before['tasks'], [])
        self.assertEqual(len(after['tasks']), 1)

    def test_closed_proof_parser_refuses_missing_precision_timezone_and_version(self):
        from getzilla.trace_contracts import validate_delivery
        row = self.row()
        validate_delivery(self.proof(row), row)
        for value in ('2026-10-24T00:00:00Z', '2026-10-24T00:00:00.9Z',
                      '2026-10-24T00:00:00.900000+00:00', '2026-10-24T00:00:00.900000'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_delivery(self.proof(row, value), row)
        for bad in ({**self.proof(row), 'proof_version': 1},
                    {**self.proof(row), 'clock_domain': 'external'},
                    {**self.proof(row), 'extra': 'arbitrary'},
                    self.proof(row, '2026-10-22T00:00:00.999999Z')):
            with self.subTest(proof=bad), self.assertRaises(ValueError):
                validate_delivery(bad, row)


if __name__ == '__main__':
    unittest.main()
