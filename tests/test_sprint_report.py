"""Native evidence, scope and missing history must not become invented progress."""
from __future__ import annotations

import unittest
import sys
import json
import subprocess
import tempfile
import hashlib
import importlib.util
import contextlib
import io
import os
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))

try:
    from getzilla import sprint_report
except ImportError:
    sprint_report = None


START = '2026-10-22T00:00:00Z'
CUTOFF = '2026-11-05T00:00:00Z'


def observation(kind, task='task:'+'a'*32, day=23, **payload):
    return {'schema_version': 3, 'event': 'task', 'kind': kind,
            'event_id': hashlib.sha256(f'{task}:{kind}:{day}'.encode()).hexdigest(), 'at': f'2026-10-{day:02}T00:00:00Z',
            'captured_at': f'2026-10-{day:02}T00:00:00Z', 'logical_task_id': task,
            'route_id': 'abcdef123456', 'session_id': '00000000-0000-4000-8000-000000000001',
            'authority_epoch': 0, 'state_revision': day, 'context_revision': 0,
            'repository_digest': 'a'*64, 'workspace_digest': 'b'*64,
            'scope_digest': 'c'*64, 'spec_digest': None, 'evidence_digest': None,
            'head': 'd'*40, 'tree': 'e'*40, 'base': 'f'*40,
            'producer_version': 1, **payload}


class SprintReportTests(unittest.TestCase):
    def test_classic_cli_uses_unknown_census_on_unqualified_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / '.getzilla/runtime'
            runtime.mkdir(parents=True, mode=0o755)
            (root / '.getzilla').chmod(0o755)
            journal = runtime / 'metrics.jsonl'
            journal.write_text(json.dumps({'event': 'route', 'at': START, 'route_id': 'PRIVATE_SENTINEL'})+'\n')
            journal.chmod(0o600)
            script = Path(__file__).resolve().parents[1] / 'scripts/getzilla_report.py'
            result = subprocess.run([sys.executable, str(script), '--since', 'all', '--json'],
                                    cwd=root, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertIsNone(report['routes'])
            self.assertIsNone(report['route_observations']['routes'])
            self.assertNotIn('PRIVATE_SENTINEL', result.stdout)

    def report(self, events):
        self.assertIsNotNone(sprint_report, 'sprint report consumer is missing')
        return sprint_report.summarize_sprint(events, start=START, as_of=CUTOFF)

    def test_legacy_observations_do_not_select_or_complete_tasks(self):
        result = self.report([{'event': 'route', 'at': START, 'route_id': 'legacy'},
                              {'event': 'verify', 'at': START, 'status': 'pass', 'route_id': 'legacy'}])
        self.assertIsNone(result['counts']['selected'])
        self.assertIsNone(result['counts']['qualified_completed'])
        self.assertEqual(result['legacy_observations'], 2)
        self.assertEqual(result['forecast']['status'], 'insufficient_history')

    def test_removal_and_handoff_do_not_erase_selected_denominator(self):
        selected = observation('selected', window_start=START)
        removed = observation('removed', day=24)
        result = self.report([selected, selected, removed])
        self.assertEqual(result['counts']['observed_selected'], 1)
        self.assertEqual(result['counts']['observed_removed'], 1)
        self.assertIsNone(result['counts']['selected'])  # no complete enrollment inventory
        self.assertEqual(len(result['tasks']), 1)

    def test_green_session_end_and_unproven_merge_are_not_qualified_completion(self):
        result = self.report([observation('selected', window_start=START),
                              {'event': 'verify', 'at': START, 'status': 'pass'},
                              {'event': 'session_end', 'at': START},
                              {'event': 'merge', 'at': START, 'source': 'github'}])
        self.assertEqual(result['counts']['observed_qualified_completed'], 0)
        self.assertIsNone(result['counts']['accepted_merged'])
        self.assertIsNone(result['human_interventions'])

    def test_changed_scope_completion_does_not_count_original_scope(self):
        result = self.report([observation('selected', window_start=START),
                              observation('task_completed', day=24, scope_digest='0'*64,
                                          evidence_digest='1'*64)])
        self.assertEqual(result['counts']['observed_qualified_completed'], 0)
        self.assertIn('scope_changed', result['tasks'][0]['at_risk'])

    def test_late_observation_is_not_known_at_earlier_cutoff(self):
        result = self.report([observation('selected', window_start=START,
                                         captured_at='2026-11-06T00:00:00Z')])
        self.assertEqual(result['counts']['observed_selected'], 0)
        self.assertIn('late_observations', result['coverage']['gaps'])

    def test_conflicting_replay_censors_qualified_facts(self):
        row = observation('selected', window_start=START)
        result = self.report([row, {**row, 'scope_digest': '0'*64}])
        self.assertFalse(result['coverage']['complete'])
        self.assertIn('conflicting_replay', result['coverage']['gaps'])

    def test_unknown_payload_field_cannot_become_a_selected_task(self):
        result = self.report([observation('selected', window_start=START, prompt='private-sentinel')])
        self.assertEqual(result['counts']['observed_selected'], 0)
        self.assertNotIn('private-sentinel', json.dumps(result))

    def test_naive_or_reversed_window_refuses(self):
        self.assertIsNotNone(sprint_report, 'sprint report consumer is missing')
        for start, cutoff in [('2026-10-22', CUTOFF), (CUTOFF, START)]:
            with self.assertRaises(ValueError):
                sprint_report.summarize_sprint([], start=start, as_of=cutoff)

    def test_existing_cli_reports_unknowns_without_writing_or_echoing_legacy_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / '.getzilla/runtime'
            runtime.mkdir(parents=True, mode=0o700)
            (root/'.getzilla').chmod(0o755)
            journal = runtime/'metrics.jsonl'
            raw = json.dumps({'event': 'route', 'at': START, 'route_id': 'private-sentinel'})+'\n'
            journal.write_text(raw)
            journal.chmod(0o600)
            script = Path(__file__).resolve().parents[1]/'scripts/getzilla_report.py'
            result = subprocess.run([sys.executable, str(script), '--sprint-start', START,
                                     '--as-of', CUTOFF, '--json'], cwd=root, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads(result.stdout)
            self.assertIsNone(summary['counts']['selected'])
            self.assertEqual(summary['legacy_observations'], 1)
            self.assertNotIn('private-sentinel', result.stdout)
            self.assertEqual(journal.read_text(), raw)

    def test_trace_mode_uses_same_private_read_boundary_and_has_no_synthetic_stages(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'.getzilla/runtime').mkdir(parents=True, mode=0o700)
            (root/'.getzilla').chmod(0o755)
            journal = root/'.getzilla/runtime/metrics.jsonl'
            journal.write_text('')
            journal.chmod(0o600)
            script = Path(__file__).resolve().parents[1]/'scripts/getzilla_report.py'
            result = subprocess.run([sys.executable, str(script), '--trace-operation', 'fixture-op',
                                     '--as-of', CUTOFF, '--json'], cwd=root, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads(result.stdout)
            self.assertIsNone(summary['binding'])
            self.assertEqual(summary['outcome'], 'unknown')
            self.assertTrue(all(value == 'unsupported' for value in summary['stages'].values()))
            self.assertEqual(journal.read_text(), '')

    def test_cli_revocation_during_projection_censors_counts_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root/'.getzilla/runtime'
            runtime.mkdir(parents=True, mode=0o700)
            (root/'.getzilla').chmod(0o755)
            journal = runtime/'metrics.jsonl'
            journal.write_text(json.dumps({'event': 'route', 'at': START})+'\n')
            journal.chmod(0o600)
            script = Path(__file__).resolve().parents[1]/'scripts/getzilla_report.py'
            definition = importlib.util.spec_from_file_location('report_revocation_fixture', script)
            module = importlib.util.module_from_spec(definition)
            definition.loader.exec_module(module)
            original = sprint_report.summarize_sprint
            def revoke(*args, **kwargs):
                value = original(*args, **kwargs)
                runtime.chmod(0o755)
                return value
            prior = Path.cwd()
            output = io.StringIO()
            try:
                os.chdir(root)
                with patch('getzilla.sprint_report.summarize_sprint', side_effect=revoke), contextlib.redirect_stdout(output):
                    self.assertEqual(module.main(['--sprint-start', START, '--as-of', CUTOFF, '--json']), 0)
            finally:
                os.chdir(prior)
            result = json.loads(output.getvalue())
            self.assertIsNone(result['legacy_observations'])
            self.assertIn('disclosure_revalidation_failed', result['coverage']['gaps'])


if __name__ == '__main__':
    unittest.main()
