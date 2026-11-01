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
from tests._support import activate_owned_route

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
                          route['review_blocking'], route['failed_check_or_review_outcomes']), (5.0, 2, 2, 2, 1, 3))
        self.assertEqual((route['profile'], route['effective_risk']), ('standard', 'medium'))

    def test_profiles_aggregate_across_routes(self) -> None:
        summary = summarize([
            event(0, 'route', 'a'), event(2, 'verify', 'a', status='pass', profile='trivial'),
            event(0, 'route', 'b'), event(30, 'verify', 'b', status='fail', blocking=3, profile='full'),
            event(60, 'verify', 'b', status='pass', profile='full'),
            event(0, 'route', 'c'), event(40, 'verify', 'c', status='pass', profile='full'),
        ])
        self.assertEqual(summary['profiles']['trivial'], {'routes': 1, 'verify_runs': 1, 'reviews': 0, 'failed_check_or_review_outcomes': 0,
                                                          'median_minutes_to_pass': 2.0, 'verify_runs_per_route': 1.0})
        full = summary['profiles']['full']
        self.assertEqual((full['routes'], full['median_minutes_to_pass'], full['verify_runs_per_route'], full['failed_check_or_review_outcomes']),
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
        self.assertEqual(set(item), {'schema_version', 'event_id', 'at', 'event', 'route_id', 'session_id', 'head', 'base', 'tree', 'status', 'blocking', 'profile', 'mode'})
        self.assertIsNone(item['profile'])
        self.assertNotIn('add payments', json.dumps(item))

    def test_a_new_route_and_a_verification_run_are_recorded(self) -> None:
        activate_owned_route(self.root, {'route_id': 'r9', 'intent': 'bugfix', 'risk': 'medium', 'quality_profiles': ['base']})
        activate_owned_route(self.root, {'route_id': 'r9', 'intent': 'bugfix', 'risk': 'medium', 'quality_profiles': ['base']})
        record_verify(self.root, {'route_id': 'r9', 'mode': 'pr', 'status': 'fail', 'diff_risk': {'effective_risk': 'medium'},
                                  'checks': [{'name': 'ruff', 'status': 'fail'}, {'name': 'bandit', 'status': 'pass'}]})
        events = self.lines()
        self.assertEqual([item['event'] for item in events], ['route', 'verify'], 'a route is recorded once')
        self.assertEqual((events[1]['blocking'], events[1]['profile']), (1, 'standard'))

    def test_metrics_failure_never_breaks_the_work(self) -> None:
        (self.root / '.getzilla' / 'runtime').write_text('not a directory', encoding='utf-8')
        record(self.root, 'verify', 'r1', status='pass')  # must not raise
        self.assertEqual(load(self.root), [])

    def test_malformed_rows_and_conflicting_replays_are_disclosed(self):
        record(self.root, 'verify', 'r1', event_id='run-1', status='pass', blocking=0)
        path = self.root / METRICS
        original = path.read_text()
        path.write_text(original + original + '{truncated\n' + original.replace('"pass"', '"fail"'))
        result = summarize(load(self.root))
        self.assertFalse(result['coverage']['complete'])
        self.assertTrue(any('conflicting' in item for item in result['coverage']['gaps']))
        self.assertTrue(any('malformed' in item for item in result['coverage']['gaps']))
        self.assertEqual(result['routes'][0]['verify_runs'], 1)

    def test_nonfinite_and_invalid_timestamp_are_incomplete_not_crashes(self):
        path = self.root / METRICS
        path.parent.mkdir(parents=True)
        path.write_text('{"at":"not-a-time","event":"verify","route_id":"r1"}\n'
                        '{"at":"2026-10-18T09:00:00Z","event":"verify","route_id":"r1","blocking":NaN}\n')
        result = summarize(load(self.root))
        self.assertFalse(result['coverage']['complete'])
        self.assertEqual(result['routes'], [])

    def test_wrong_field_types_and_bounded_rows_are_rejected(self):
        from getzilla.metrics_journal import MAX_ROW
        path = self.root / METRICS
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(event(0, 'verify', 'r1', blocking='not-a-number')) + '\n' + 'x' * MAX_ROW + '\n')
        result = summarize(load(self.root))
        self.assertEqual(result['routes'], [])
        self.assertFalse(result['coverage']['complete'])

    def test_offline_source_observations_distinguish_zero_missing_and_binary_inventory(self):
        from getzilla.metrics_journal import import_observations
        from tests.branch_support import git
        git(self.root, 'init', '-q', '-b', 'work')
        (self.root / '.gitignore').write_text('.getzilla/runtime/\n')
        (self.root / 'app.py').write_text('value = 1\n')
        git(self.root, 'add', '.')
        git(self.root, 'commit', '-qm', 'base')
        base = git(self.root, 'rev-parse', 'HEAD')
        (self.root / 'app.py').write_text('value = 2\n')
        git(self.root, 'add', '.')
        git(self.root, 'commit', '-qm', 'change')
        head = git(self.root, 'rev-parse', 'HEAD')
        identity = {'session_id': 's1', 'head': head, 'base': base, 'tree': git(self.root, 'rev-parse', 'HEAD^{tree}')}
        record(self.root, 'grant', 'r1', event_id='grant:1', source_identity=identity)
        facts = []
        for name, extra in [('merge', {}), ('cost', {'amount': 0, 'currency': 'USD'}), ('ci', {'seconds': 60})]:
            facts.append({**event(20, name, 'r1', **extra), **identity, 'schema_version': 2, 'event_id': name + ':1',
                          'source': 'github', 'source_ref': 'run123'})
        path = self.root / '.getzilla/runtime/import.json'
        path.write_text(json.dumps(facts))
        self.assertEqual(import_observations(self.root, '.getzilla/runtime/import.json')['imported'], 3)
        import_observations(self.root, '.getzilla/runtime/import.json')
        result = summarize(load(self.root), self.root)
        route = result['routes'][0]
        self.assertEqual(route['approval_count_per_commit'], 1)
        self.assertEqual(route['cost_per_changed_line'], 0)
        self.assertEqual(route['observed_cost'], 0)
        self.assertEqual(route['ci_minutes'], 1)
        self.assertIsNone(route['unique_defects_before_merge'])
        self.assertEqual(result['sessions'][0]['session_id'], 's1')
        self.assertEqual(route['gaps'], ['confirmed before-merge findings not observed'])
        finding = {**event(10, 'finding', 'r1', finding_id='f1', confirmed=True), **identity, 'schema_version': 2,
                   'event_id': 'finding:1', 'source': 'github', 'source_ref': 'run123'}
        path.write_text(json.dumps([finding]))
        import_observations(self.root, '.getzilla/runtime/import.json')
        result = summarize(load(self.root), self.root)
        self.assertEqual((result['routes'][0]['gaps'], result['routes'][0]['unique_defects_before_merge']), ([], 1))
        self.assertEqual(result['route_observations'], {'complete': True, 'routes_with_gaps': 0, 'routes': 1})
        (self.root / 'binary').write_bytes(b'\0value')
        git(self.root, 'add', '.')
        git(self.root, 'commit', '-qm', 'binary')
        facts[0].update(head=git(self.root, 'rev-parse', 'HEAD'), event_id='merge:2')
        path.write_text(json.dumps([facts[0]]))
        import_observations(self.root, '.getzilla/runtime/import.json')
        route = summarize(load(self.root), self.root)['routes'][0]
        self.assertIsNone(route['approval_count_per_commit'])
        self.assertIsNone(route['cost_per_changed_line'])

    def test_failed_grant_publication_does_not_record_materialization(self):
        from unittest.mock import patch
        from getzilla.state import add_approval
        from tests.branch_support import git
        git(self.root, 'init', '-q', '-b', 'work')
        (self.root / 'file.py').write_text('value = 1\n')
        git(self.root, 'add', '.')
        git(self.root, 'commit', '-qm', 'base')
        git(self.root, 'remote', 'add', 'origin', 'https://github.com/example/metrics-fixture.git')
        with patch('getzilla.state.dump_json', side_effect=OSError('disk unavailable')):
            with self.assertRaises(OSError):
                add_approval(self.root, 'protected-path', 'owner', actions=['protected-path-write'], resources=['file.py'])
        self.assertFalse(any(item.get('event') == 'grant' for item in load(self.root)))

    def test_unsafe_metrics_path_never_mutates_external_file(self):
        outside = self.root / 'outside'
        outside.write_text('unchanged')
        path = self.root / METRICS
        path.parent.mkdir(parents=True)
        try:
            path.symlink_to(outside)
        except OSError:
            self.skipTest('symlinks unavailable')
        record(self.root, 'verify', 'r1', status='pass')
        self.assertEqual(outside.read_text(), 'unchanged')
        self.assertFalse(summarize(load(self.root))['coverage']['complete'])

    def test_measured_lane_is_distinct_from_provisional_route(self):
        record(self.root, 'route', 'r1', risk='low')
        record_verify(self.root, {'route_id': 'r1', 'status': 'pass', 'created_at': 'run1', 'light_diff': {'admitted': True, 'code_lines': 2}})
        result = summarize(load(self.root))['routes'][0]
        self.assertEqual((result['fast_lane_admitted'], result['fast_lane_known']), (1, 1))
        self.assertIsNone(result['approval_count_per_commit'])
        self.assertIsNone(result['cost_per_changed_line'])
        self.assertIsNone(result['unique_defects_before_merge'])

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
        (runtime / 'path-hints.json').write_text(json.dumps({'refused': 4, 'hinted': 9, 'named': 7, 'edit_unread_refused': 2}), encoding='utf-8')
        (runtime / 'parallel-guard.json').write_text(json.dumps({'chain': 2, 'loop': 1, 'since': 'x'}), encoding='utf-8')
        cli = [sys.executable, str(ROOT / 'scripts' / 'getzilla_report.py')]
        text = subprocess.run([*cli, '--since', '1d'], cwd=self.root, capture_output=True, text=True, check=True).stdout
        self.assertIn('1 route(s)', text)
        self.assertIn('standard', text)
        self.assertIn('4 refused, 9 hinted', text)
        self.assertIn('the files they name: 7; patches refused because the file was not read first: 2', text)
        self.assertIn('chain 2, loop 1', text)
        data = json.loads(subprocess.run([*cli, '--json', '--since', 'all'], cwd=self.root, capture_output=True,
                                         text=True, check=True).stdout)
        self.assertEqual(data['profiles']['standard']['failed_check_or_review_outcomes'], 2)
        self.assertEqual(data['routes'][0]['minutes_to_pass'], 20.0)
        # Journal coverage and route observations are separate: the route never observed merge or cost.
        self.assertNotIn('cost not observed', data['coverage']['gaps'])
        self.assertEqual(data['route_observations'], {'complete': False, 'routes_with_gaps': 1, 'routes': 1})
        self.assertIsNone(data['routes'][0]['observed_cost'])
        self.assertIn('Route observation gaps (1 of 1 routes; unknown is not zero):', text)
        self.assertIn('r1: exact commit inventory unavailable; merge not observed', text)
        self.assertIn('cost not observed', text)

    def test_report_cli_bounds_the_route_gap_list(self) -> None:
        stamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        (self.root / '.getzilla' / 'runtime').mkdir()
        (self.root / METRICS).write_text('\n'.join(json.dumps({'at': stamp, 'event': 'route', 'route_id': f'r{index}'})
                                                   for index in range(12)) + '\n', encoding='utf-8')
        text = subprocess.run([sys.executable, str(ROOT / 'scripts' / 'getzilla_report.py'), '--since', '1d'], cwd=self.root,
                              capture_output=True, text=True, check=True).stdout
        self.assertIn('(12 of 12 routes', text)
        self.assertEqual(sum(line.startswith('  r') for line in text.splitlines()), 10)
        self.assertIn('2 more; use --json for all.', text)

    def test_report_cli_never_prints_terminal_control_characters_from_the_journal(self) -> None:
        stamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        (self.root / '.getzilla' / 'runtime').mkdir()
        hostile = 'r1\x1b]0;owned\x07‮'
        (self.root / METRICS).write_text('\n'.join(json.dumps(item) for item in [
            {'at': stamp, 'event': 'route', 'route_id': hostile},
            {'at': stamp, 'event': 'verify', 'route_id': hostile, 'status': 'pass', 'profile': 'std\x1b[2J'},
        ]) + '\n', encoding='utf-8')
        text = subprocess.run([sys.executable, str(ROOT / 'scripts' / 'getzilla_report.py'), '--since', '1d'],
                              cwd=self.root, capture_output=True, text=True, check=True).stdout
        self.assertNotIn('\x1b', text)
        self.assertNotIn('\x07', text)
        self.assertNotIn('‮', text)
        self.assertIn('r1?]0;owned??:', text)


if __name__ == '__main__':
    unittest.main()
