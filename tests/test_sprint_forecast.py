"""Forecast counts use covered original-scope outcomes, never model confidence."""
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'.getzilla'))
try:
    from getzilla import sprint_forecast
except ImportError:
    sprint_forecast = None


def windows(counts):
    origin = datetime(2025, 1, 1, tzinfo=timezone.utc)
    return [{'start': (origin+timedelta(days=14*i)).isoformat(),
             'end': (origin+timedelta(days=14*(i+1))).isoformat(),
             'count': count, 'coverage': 'complete', 'cohort': 'fixture-policy-v1',
             'target': 'qualified_original_scope_task_completion_count_v1'}
            for i, count in enumerate(counts)]


class ForecastTests(unittest.TestCase):
    def forecast(self, values, **kwargs):
        self.assertIsNotNone(sprint_forecast, 'empirical forecast method is missing')
        return sprint_forecast.forecast_counts(values, origin='2026-01-01T00:00:00Z',
                                               horizon_days=14, remaining=3,
                                               cohort='fixture-policy-v1', **kwargs)

    def test_real_unavailable_history_is_null_with_zero_eligible_windows(self):
        result = self.forecast([])
        self.assertEqual(result['eligible_windows'], 0)
        self.assertIsNone(result['additional_completions'])
        self.assertEqual(result['status'], 'insufficient_history')

    def test_rolling_backtest_and_raw_forecast_do_not_become_display_cap(self):
        result = self.forecast(windows([0, 1, 1, 2, 2, 3, 4, 6]*2))
        self.assertEqual(result['raw_counts'], {'lower': 0, 'median': 2, 'upper': 6})
        self.assertEqual(result['additional_completions'], {'lower': 0, 'median': 2, 'upper': 3})
        self.assertEqual(result['calibration']['origins'], 8)
        self.assertNotIn('probability', result)

    def test_future_and_censored_windows_do_not_supply_training(self):
        values = windows([0]*16)
        values[0]['coverage'] = 'censored'
        values[-1]['end'] = '2027-01-01T00:00:00Z'
        result = self.forecast(values)
        self.assertEqual(result['eligible_windows'], 14)
        self.assertEqual(result['calibration']['origins'], 6)
        self.assertIsNone(result['additional_completions'])

    def test_wrong_target_policy_and_overlapping_windows_are_excluded(self):
        values = windows([0]*16)
        values[0]['target'] = 'first_green'
        values[1]['cohort'] = 'other-policy'
        values[3]['start'] = values[2]['start']
        result = self.forecast(values)
        self.assertLess(result['eligible_windows'], 16)
        self.assertIsNone(result['additional_completions'])

    def test_fully_observed_zero_windows_are_not_discarded(self):
        result = self.forecast(windows([0]*16))
        self.assertEqual(result['raw_counts'], {'lower': 0, 'median': 0, 'upper': 0})
        self.assertEqual(result['calibration']['interval_hits'], 8)


if __name__ == '__main__':
    unittest.main()
