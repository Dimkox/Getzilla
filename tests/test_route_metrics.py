"""O01: per-route overhead and caught-defect counters answer whether the ritual pays for itself."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.route_metrics import METRICS, load, profile_of, record, record_verify, summarize  # noqa: E402
from getzilla.state import set_active_route  # noqa: E402

T0 = datetime(2026, 10, 18, 9, 0, tzinfo=timezone.utc)


def event(minutes: float, name: str, route_id: str, **fields) -> dict:
    return {'at': (T0 + timedelta(minutes=minutes)).strftime('%Y-%m-%dT%H:%M:%SZ'), 'event': name, 'route_id': route_id, **fields}


class SummaryTests(unittest.TestCase):
    def test_one_route_counts_runs_reviews_and_caught_defects(self) -> None:
        summary = summarize([
            event(0, 'route', 'r1', intent='feature'),
            event(1, 'verify', 'r1', status='fail', blocking=2, profile='standard', effective_risk='medium'),
            event(5, 'verify', 'r1', status='pass', blocking=0, profile='standard', effective_risk='medium'),
            event(5, 'receipt', 'r1', kind='verification', status='pass'),
            event(7, 'receipt', 'r1', kind='code_review', status='fail'),
            event(9, 'receipt', 'r1', kind='code_review', status='pass'),
        ])
        route = summary['routes'][0]
        self.assertEqual((route['minutes_to_pass'], route['verify_runs'], route['verify_blocking'], route['reviews'],
                          route['review_blocking'], route['caught_before_merge']), (5.0, 2, 2, 2, 1, 3))
        self.assertEqual((route['profile'], route['effective_risk']), ('standard', 'medium'))

    def test_profiles_aggregate_across_routes(self) -> None:
        summary = summarize([
            event(0, 'route', 'a'), event(2, 'verify', 'a', status='pass', profile='trivial'),
            event(0, 'route', 'b'), event(30, 'verify', 'b', status='fail', blocking=3, profile='full'),
            event(60, 'verify', 'b', status='pass', profile='full'),
            event(0, 'route', 'c'), event(40, 'verify', 'c', status='pass', profile='full'),
        ])
        self.assertEqual(summary['profiles']['trivial'], {'routes': 1, 'verify_runs': 1, 'reviews': 0, 'caught_before_merge': 0,
                                                          'median_minutes_to_pass': 2.0, 'verify_runs_per_route': 1.0})
        full = summary['profiles']['full']
        self.assertEqual((full['routes'], full['median_minutes_to_pass'], full['verify_runs_per_route'], full['caught_before_merge']),
                         (2, 50.0, 1.5, 3))

    def test_profile_comes_from_the_trivial_waiver_or_the_effective_risk(self) -> None:
        self.assertEqual(profile_of({'profile_reason': 'TRIVIAL_PROVEN_BY_DIFF'}), 'trivial')
        self.assertEqual(profile_of({'diff_risk': {'effective_risk': 'high'}}), 'full')
        self.assertEqual(profile_of({'diff_risk': {'effective_risk': 'low'}}), 'standard')


class RecordingTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        (self.root / '.getzilla').mkdir()

    def lines(self) -> list[dict]:
        return [json.loads(line) for line in (self.root / METRICS).read_text(encoding='utf-8').splitlines()]

    def test_events_never_carry_prompts_paths_or_output(self) -> None:
        record(self.root, 'verify', 'r1', status='fail', blocking=1, prompt='add payments to /etc/passwd',
               stdout='secret output', profile='/home/user/project', mode='pr')
        item = self.lines()[0]
        self.assertEqual(set(item), {'at', 'event', 'route_id', 'status', 'blocking', 'profile', 'mode'})
        self.assertIsNone(item['profile'])
        self.assertNotIn('add payments', json.dumps(item))

    def test_a_new_route_and_a_verification_run_are_recorded(self) -> None:
        set_active_route(self.root, {'route_id': 'r9', 'intent': 'bugfix', 'risk_level': 'medium', 'quality_profiles': ['base']})
        set_active_route(self.root, {'route_id': 'r9', 'intent': 'bugfix', 'risk_level': 'medium', 'quality_profiles': ['base']})
        record_verify(self.root, {'route_id': 'r9', 'mode': 'pr', 'status': 'fail', 'diff_risk': {'effective_risk': 'medium'},
                                  'checks': [{'name': 'ruff', 'status': 'fail'}, {'name': 'bandit', 'status': 'pass'}]})
        events = self.lines()
        self.assertEqual([item['event'] for item in events], ['route', 'verify'], 'a route is recorded once')
        self.assertEqual((events[1]['blocking'], events[1]['profile']), (1, 'standard'))

    def test_metrics_failure_never_breaks_the_work(self) -> None:
        (self.root / '.getzilla' / 'runtime').write_text('not a directory', encoding='utf-8')
        record(self.root, 'verify', 'r1', status='pass')  # must not raise
        self.assertEqual(load(self.root), [])

    def test_report_cli_prints_profiles_and_hook_counters(self) -> None:
        runtime = self.root / '.getzilla' / 'runtime'
        runtime.mkdir()
        now = datetime.now(timezone.utc)
        stamps = [(now - timedelta(minutes=minutes)).strftime('%Y-%m-%dT%H:%M:%SZ') for minutes in (30, 20, 10)]
        (self.root / METRICS).write_text('\n'.join(json.dumps(item) for item in [
            {'at': stamps[0], 'event': 'route', 'route_id': 'r1'},
            {'at': stamps[1], 'event': 'verify', 'route_id': 'r1', 'status': 'fail', 'blocking': 2, 'profile': 'standard'},
            {'at': stamps[2], 'event': 'verify', 'route_id': 'r1', 'status': 'pass', 'profile': 'standard'},
        ]) + '\n', encoding='utf-8')
        (runtime / 'path-hints.json').write_text(json.dumps({'refused': 4, 'hinted': 9}), encoding='utf-8')
        (runtime / 'parallel-guard.json').write_text(json.dumps({'chain': 2, 'loop': 1, 'since': 'x'}), encoding='utf-8')
        cli = [sys.executable, str(ROOT / 'scripts' / 'getzilla_report.py')]
        text = subprocess.run([*cli, '--since', '1d'], cwd=self.root, capture_output=True, text=True, check=True).stdout
        self.assertIn('1 route(s)', text)
        self.assertIn('standard', text)
        self.assertIn('4 refused, 9 hinted', text)
        self.assertIn('chain 2, loop 1', text)
        data = json.loads(subprocess.run([*cli, '--json', '--since', 'all'], cwd=self.root, capture_output=True,
                                         text=True, check=True).stdout)
        self.assertEqual(data['profiles']['standard']['caught_before_merge'], 2)
        self.assertEqual(data['routes'][0]['minutes_to_pass'], 20.0)


if __name__ == '__main__':
    unittest.main()
