"""Synthetic supplied cohorts exercise timing and target matching, not native authority."""
import unittest
from datetime import datetime, timedelta, timezone

from tests._support import PROJECT
import sys
sys.path.insert(0,str(PROJECT/'.getzilla'))
from getzilla import sprint_forecast
from getzilla.sprint_report import TARGET


def origins(counts, *, remaining=3, horizon=86400):
    first = datetime(2025,1,1,tzinfo=timezone.utc)
    result = []
    for index,count in enumerate(counts):
        start = first+timedelta(days=14*index)
        end = start+timedelta(seconds=horizon)
        result.append({'start':start.isoformat(),'end':end.isoformat(),'count':count,
                       'coverage':'complete','target':TARGET,'cohort':'prospective_original_roster_v1',
                       'remaining':remaining,'available_by':end.isoformat()})
    return result


class MatchedForecastTests(unittest.TestCase):
    def forecast(self,rows,**kwargs):
        return sprint_forecast.forecast_matched_origins(
            rows,origin='2026-01-01T00:00:00Z',horizon_seconds=86400,remaining=3,
            cohort='prospective_original_roster_v1',**kwargs)

    def test_real_empty_history_remains_null(self):
        result = self.forecast([])
        self.assertEqual(result['eligible_windows'],0)
        self.assertIsNone(result['additional_completions'])

    def test_matched_residual_horizon_and_remaining_are_required_without_display_cap(self):
        rows = origins([0,1,2,3]*4)
        result = self.forecast(rows)
        self.assertEqual(result['additional_completions'],{'lower':0,'median':1,'upper':3})
        self.assertEqual(result['calibration']['origins'],8)
        self.assertEqual(result['raw_counts'],result['additional_completions'])
        full_horizon = origins([0]*16,horizon=14*86400)
        self.assertIsNone(self.forecast(full_horizon)['additional_completions'])
        different_remaining = origins([0]*16,remaining=4)
        self.assertIsNone(self.forecast(different_remaining)['additional_completions'])

    def test_training_proof_must_be_available_before_each_historical_origin(self):
        rows = origins([0]*16)
        for row in rows:
            row['available_by'] = '2025-12-30T00:00:00Z'
        result = self.forecast(rows)
        self.assertEqual(result['eligible_windows'],16)
        self.assertEqual(result['calibration']['origins'],0)
        self.assertIsNone(result['additional_completions'])

    def test_future_proof_censored_and_zero_windows(self):
        rows = origins([0]*16)
        self.assertEqual(self.forecast(rows)['additional_completions'],{'lower':0,'median':0,'upper':0})
        rows[0]['available_by'] = '2027-01-01T00:00:00Z'
        result = self.forecast(rows)
        self.assertEqual(result['eligible_windows'],15)
        self.assertIsNone(result['additional_completions'])

    def test_inconsistent_unbounded_and_overlapping_outcomes_are_excluded(self):
        for field,value in [('remaining',True),('count',4),('available_by','2024-01-01T00:00:00Z'),
                            ('target','first_green'),('coverage','censored')]:
            with self.subTest(field=field):
                rows = origins([0]*16)
                rows[0][field] = value
                self.assertEqual(self.forecast(rows)['eligible_windows'],15)
        rows = origins([0]*16)
        rows[1] = dict(rows[0])
        self.assertEqual(self.forecast(rows)['eligible_windows'],15)


if __name__ == '__main__':
    unittest.main()
