"""Pure reconstruction cannot establish ACL, completeness, or backend delivery."""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from tests.test_trace_contracts import observation

CUTOFF = '2026-11-05T00:10:00Z'


def stage(kind, event_id, span_id='s1', **fields):
    row = observation('span', kind, event_id=event_id * 64, operation_id='native_op-1',
        span_id=span_id, parent_span_id=None, attempt_id='attempt1', stage='lexical',
        outcome=None, elapsed_ns=None)
    row.update(fields)
    return row


class TraceReportTests(unittest.TestCase):
    def reconstruct(self, rows, operation_id='native_op-1', cutoff=CUTOFF):
        from getzilla.trace_report import reconstruct
        return reconstruct(rows, operation_id, cutoff)

    def test_operation_duration_never_sums_parallel_stages_and_unknown_stays_null(self):
        rows = [observation(), observation(kind='operation_finished', event_id='1' * 64,
            state_revision=3, outcome='succeeded', elapsed_ns=10),
            stage('stage_started', '2'), stage('stage_finished', '3', outcome='empty', elapsed_ns=8),
            stage('stage_started', '4', 's2'),
            stage('stage_finished', '5', 's2', outcome='succeeded', elapsed_ns=8)]
        result = self.reconstruct(rows)
        self.assertEqual(result['elapsed_ns'], 10)
        self.assertEqual(result['outcome'], 'succeeded')
        self.assertEqual(len(result['spans']), 2)
        self.assertIsNone(result['spans'][0]['ttft_ns'])
        self.assertIsNone(result['resource_usage'])
        self.assertEqual(result['authority'], 'observations_only')
        self.assertFalse(result['coverage']['complete'])
        self.assertEqual(result['stages']['semantic'], 'unsupported')

    def test_replay_is_idempotent_and_conflicts_are_censored(self):
        original = observation()
        result = self.reconstruct([original, copy.deepcopy(original)])
        self.assertEqual(result['observations'], 1)
        conflict = observation(head='1' * 40)
        conflicted = self.reconstruct([original, conflict])
        self.assertIn('conflicting_replay', conflicted['coverage']['gaps'])
        self.assertIsNone(conflicted['binding'])

    def test_conflicting_replay_under_other_operation_cannot_preserve_target_edge(self):
        result = self.reconstruct([observation(), observation(operation_id='other_op')])
        self.assertIn('conflicting_replay', result['coverage']['gaps'])
        self.assertIsNone(result['binding'])

    def test_delayed_delivery_and_future_events_do_not_change_frozen_report(self):
        original = self.reconstruct([observation()])
        late = observation(kind='operation_finished', event_id='1' * 64,
            outcome='succeeded', elapsed_ns=10, captured_at='2026-11-05T00:11:00Z')
        future = observation(event_id='2' * 64, at='2026-11-06T00:00:00Z',
            captured_at='2026-11-06T00:00:00Z')
        self.assertEqual(original, self.reconstruct([observation(), late, future]))
        result = self.reconstruct([observation(), late], cutoff='2026-11-05T00:12:00Z')
        self.assertEqual(result['outcome'], 'succeeded')

    def test_mismatched_project_task_source_and_context_never_join(self):
        for field, value in [('logical_task_id', 'task:' + '2' * 32), ('route_id', '2' * 12),
                ('repository_digest', '2' * 64), ('workspace_digest', '2' * 64),
                ('head', '2' * 40), ('authority_epoch', 2), ('context_revision', 2)]:
            with self.subTest(field=field):
                end = observation(kind='operation_finished', event_id='1' * 64,
                    outcome='succeeded', elapsed_ns=1, **{field: value})
                result = self.reconstruct([observation(), end])
                self.assertEqual(result['outcome'], 'unknown')
                self.assertIn('binding_mismatch', result['coverage']['gaps'])

    def test_terminal_without_start_and_missing_span_are_partial(self):
        result = self.reconstruct([observation(kind='operation_finished',
            outcome='timeout', elapsed_ns=3),
            stage('stage_finished', '2', outcome='timeout', elapsed_ns=3)])
        self.assertIn('operation_start_missing', result['coverage']['gaps'])
        self.assertIn('span_start_missing', result['coverage']['gaps'])
        self.assertFalse(result['coverage']['complete'])
        self.assertEqual(result['outcome'], 'unknown')

    def test_no_operation_binding_cannot_join_or_disclose_orphan_stage_metadata(self):
        rows = [stage('stage_started', '1'),
            stage('stage_finished', '2', outcome='succeeded', elapsed_ns=3)]
        result = self.reconstruct(rows)
        self.assertIsNone(result['binding'])
        self.assertEqual(result['spans'], [])
        self.assertEqual(result['stages']['lexical'], 'unsupported')

    def test_stage_identity_conflict_cannot_become_success(self):
        rows = [observation(), stage('stage_started', '1'),
            stage('stage_finished', '2', stage='semantic', outcome='succeeded', elapsed_ns=3)]
        result = self.reconstruct(rows)
        self.assertEqual(result['spans'][0]['outcome'], 'unknown')
        self.assertIn('span_identity_conflict', result['coverage']['gaps'])

    def test_retry_attempts_are_separate_and_explicit_not_run_is_preserved(self):
        rows = [observation(), stage('stage_started', '1'),
            stage('stage_finished', '2', outcome='timeout', elapsed_ns=8),
            stage('stage_started', '3', attempt_id='attempt2'),
            stage('stage_finished', '4', attempt_id='attempt2', outcome='not_run', elapsed_ns=None)]
        result = self.reconstruct(rows)
        self.assertEqual({r['attempt_id'] for r in result['spans']}, {'attempt1', 'attempt2'})
        self.assertEqual({r['outcome'] for r in result['spans']}, {'timeout', 'not_run'})

    def test_raw_errors_never_echo_and_legacy_is_aggregate_only(self):
        legacy = {'event': 'route', 'route_id': 'PRIVATE_LEGACY', 'at': '2026-11-05T00:00:00Z'}
        bad = observation(error='PRIVATE_SENTINEL')
        result = self.reconstruct([legacy, bad])
        raw = json.dumps(result)
        self.assertNotIn('PRIVATE_', raw)
        self.assertEqual(result['legacy_observations'], 1)
        self.assertIn('invalid_observation', result['coverage']['gaps'])

    def test_deterministic_read_only_projection_and_bounded_inputs(self):
        rows = [observation(), stage('stage_started', '1')]
        before = copy.deepcopy(rows)
        self.assertEqual(self.reconstruct(rows), self.reconstruct(list(reversed(rows))))
        self.assertEqual(rows, before)
        result = self.reconstruct([observation()] * 4097)
        self.assertIn('record_limit', result['coverage']['gaps'])
        for value in ('bad/path', ''):
            with self.assertRaisesRegex(ValueError, '^invalid_operation_id$'):
                self.reconstruct([], operation_id=value)
        with self.assertRaisesRegex(ValueError, '^invalid_cutoff$'):
            self.reconstruct([], cutoff='not a date')

    def test_evidence_and_policy_are_reported_as_observed_not_approval(self):
        rows = [observation(), observation('evidence', 'evidence_linked',
            event_id='1' * 64, operation_id='native_op-1', evidence_kind='ci', reference_digest='1' * 64),
            observation('policy', 'policy_observed', event_id='2' * 64, operation_id='native_op-1',
                decision='allow', policy_digest='1' * 64, reason_code='policy_allowed')]
        result = self.reconstruct(rows)
        self.assertEqual(result['evidence'][0]['qualification'], 'observed_unverified')
        self.assertEqual(result['policies'][0]['decision'], 'allow')
        self.assertIsNone(result['export_delivery'])


if __name__ == '__main__':
    unittest.main()
