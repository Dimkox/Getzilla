"""Closed observations are data, never a source of task/access authority."""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))


def observation(event='operation', kind='operation_started', **extra):
    row = dict(schema_version=3, event_id='e' * 64,
        at='2026-11-05T00:00:00Z', captured_at='2026-11-05T00:00:00Z',
        event=event, kind=kind, logical_task_id='task:' + 'a' * 32,
        route_id='b' * 12, session_id='01a1a6ba-10e8-7bc1-81b1-684978be3580',
        authority_epoch=1, state_revision=2, context_revision=1,
        repository_digest='c' * 64, workspace_digest='d' * 64,
        scope_digest='f' * 64, spec_digest=None, evidence_digest=None,
        head='a' * 40, base='b' * 40, tree='c' * 40, producer_version=1)
    if event == 'operation':
        row.update(operation_id='native_op-1', outcome=None, elapsed_ns=None, attempt_id=None)
    row.update(extra)
    return row


class TraceContractTests(unittest.TestCase):
    def validate(self, row):
        from getzilla.trace_contracts import validate_v3
        return validate_v3(row)

    def rejected(self, row):
        with self.assertRaisesRegex(ValueError, '^invalid_observation$'):
            self.validate(row)

    def test_valid_native_envelopes_and_selected_window(self):
        self.assertIsNone(self.validate(observation()))
        self.validate(observation('task', 'selected', window_start='2026-11-05T00:00:00Z'))
        self.validate(observation('task', 'task_completed', evidence_digest='1' * 64))
        self.validate(observation('operation', 'operation_finished', outcome='cancelled', elapsed_ns=0))

    def test_unknown_fields_never_accept_raw_payload_or_caller_authority(self):
        for name in ('argv', 'prompt', 'error', 'provider', 'uid', 'role', 'access_context'):
            with self.subTest(name=name):
                self.rejected(observation(**{name: 'PRIVATE_SENTINEL'}))

    def test_closed_identity_types_and_finite_bounded_numbers(self):
        for field, value in [('logical_task_id', 'task:other'), ('route_id', 'private/path'),
                ('session_id', 'caller'), ('authority_epoch', True), ('context_revision', -1),
                ('state_revision', 10**18 + 1), ('head', 'main'), ('spec_digest', 'bad'),
                ('producer_version', True), ('schema_version', True), ('elapsed_ns', float('nan')),
                ('operation_id', ''), ('operation_id', 'x' * 65), ('attempt_id', 'bad/path')]:
            with self.subTest(field=field, value=value):
                self.rejected(observation(**{field: value}))

    def test_timestamp_requires_real_utc_and_observation_not_before_event(self):
        for value in ('2026-02-30T00:00:00Z', '2026-11-05T00:00:00+00:00',
                '2026-11-05', 'private timestamp'):
            self.rejected(observation(at=value))
        self.rejected(observation(captured_at='2026-11-04T23:59:59Z'))

    def test_event_specific_fields_and_terminal_semantics(self):
        self.rejected(observation('task', 'task_completed', operation_id='op'))
        self.rejected(observation('task', 'selected'))
        self.rejected(observation('task', 'task_completed', window_start='2026-11-05T00:00:00Z'))
        self.rejected(observation(kind='operation_finished'))
        self.rejected(observation(outcome='succeeded'))

    def test_safe_stage_data_accepts_unknown_metrics_as_null_and_rejects_text(self):
        row = observation('span', 'stage_finished', operation_id='op', span_id='span-1',
            parent_span_id=None, attempt_id='attempt1', stage='semantic', outcome='unsupported',
            elapsed_ns=None, ttft_ns=None, provider_digest=None, candidate_count=None,
            timing_source='unavailable')
        self.validate(row)
        for field, value in [('stage', 'raw_stage'), ('candidate_count', True),
                ('usage_input_tokens', -1), ('provider_digest', 'private_provider'),
                ('timing_source', 'provider_private_name')]:
            bad = copy.deepcopy(row)
            bad[field] = value
            self.rejected(bad)

    def test_policy_and_evidence_have_closed_non_authoritative_shapes(self):
        self.validate(observation('policy', 'policy_observed', operation_id='op',
            decision='deny', policy_digest='1' * 64, reason_code='policy_denied'))
        self.validate(observation('evidence', 'evidence_linked', operation_id='op',
            evidence_kind='ci', reference_digest='1' * 64))
        self.rejected(observation('policy', 'policy_observed', operation_id='op',
            decision='owner_approved', policy_digest='1' * 64, reason_code='private error'))


if __name__ == '__main__':
    unittest.main()
