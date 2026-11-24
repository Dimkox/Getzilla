"""Actual native retrieval observations, not authored span fixtures."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from concurrent.futures import CancelledError
from asyncio import CancelledError as AsyncCancelledError
from itertools import count
from unittest.mock import patch

from tests import test_native_context as context_fixtures

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import state, sprint_lifecycle
from getzilla.router import build_route
from getzilla.observation_privacy import load_local, revalidate_local
from getzilla.retrieval.native_local import deliver_local_context
from getzilla.trace_report import reconstruct
from getzilla.retrieval import native_local, observation
from getzilla.retrieval.budget import RetrievalError
from getzilla.retrieval.policy_inputs import current_policy_digest
from getzilla.optional_modules import manage_modules
from getzilla.trace_storage import native_root

SESSION = '00000000-0000-4000-8000-000000000052'


class RetrievalTraceTests(unittest.TestCase):
    def setUp(self):
        fixture = context_fixtures.NativeContextTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.root = fixture.root
        (self.root / '.gitignore').write_text('.getzilla/runtime/\n.getzilla/index/\n')
        for arguments in (('init', '-q'), ('config', 'user.name', 'Test'),
                          ('config', 'user.email', 'test@example.invalid'), ('add', '.'),
                          ('-c', 'maintenance.auto=false', '-c', 'gc.auto=0', 'commit', '-qm', 'fixture')):
            subprocess.run(['git', *arguments], cwd=self.root, check=True, capture_output=True)
        state.bind_session(SESSION)
        self.route = build_route(self.root, 'Find the answer without exposing query text.', SESSION).to_dict()
        state.set_active_route(self.root, self.route)

    def query(self, query='answer'):
        with redirect_stdout(io.StringIO()) as output:
            result = deliver_local_context(self.root, query)
        return result, json.loads(output.getvalue())

    def enroll(self):
        self.route = sprint_lifecycle.enroll_trace(self.root, expected_epoch=0, expected_revision=0)

    def test_actual_query_reconstructs_native_stages_without_a_paid_claim(self):
        self.enroll()
        result, packet = self.query()
        operation = result.get('trace_operation_id')
        self.assertIsInstance(operation, str, 'actual retrieval must publish its own observed read operation')
        source = load_local(self.root)
        report = reconstruct(source['events'], operation, '2099-01-01T00:00:00Z')
        self.assertEqual(report['outcome'], 'succeeded')
        self.assertFalse(report['claim_observed'])
        self.assertEqual(report['binding']['route_id'], self.route['route_id'])
        self.assertEqual(report['stages']['cache_lookup'], 'cache_miss')
        self.assertEqual(report['stages']['lexical'], 'succeeded')
        self.assertEqual(report['stages']['structural'], 'succeeded')
        self.assertEqual(report['stages']['fusion'], 'succeeded')
        self.assertEqual(report['stages']['context_assembly'], 'succeeded')
        self.assertEqual(report['stages']['semantic'], 'unsupported')
        self.assertIsNone(report['resource_usage'])
        self.assertTrue(all(span['elapsed_ns'] >= 0 for span in report['spans']))
        self.assertTrue(all(span.get('usage_input_tokens') is None for span in report['spans']))
        journal = (self.root / '.getzilla/runtime/metrics.jsonl').read_text()
        self.assertNotIn('def answer', journal)
        self.assertNotIn('Find the answer', journal)
        self.assertNotIn('return 42', journal)
        self.assertIn('def answer', packet['text'])

    def test_disabled_capture_performs_no_diagnostic_or_publication_io(self):
        journal = self.root / '.getzilla/runtime/metrics.jsonl'
        original = journal.read_bytes() if journal.exists() else None
        with patch.object(observation, 'publish', side_effect=AssertionError('publication')):
            result, packet = self.query()
        self.assertNotIn('trace_operation_id', result)
        self.assertNotIn('trace_operation_id', packet)
        self.assertEqual(journal.read_bytes() if journal.exists() else None, original)

    def test_capture_failure_is_visible_without_changing_original_read(self):
        self.enroll()
        with patch.object(observation, '_Capture', side_effect=AssertionError('PRIVATE_DIAGNOSTIC_ERROR')):
            result, packet = self.query()
        self.assertEqual(result['status'], 'issued')
        self.assertEqual(packet['trace_observation_status'], 'capture_unavailable')
        self.assertNotIn('trace_operation_id', packet)
        self.assertIn('def answer', packet['text'])

    def test_repeated_query_has_distinct_attempt_and_real_cache_hit(self):
        self.enroll()
        # Exercise two real journal deliveries without making cache semantics
        # depend on the scheduler meeting the production 50 ms delivery window.
        with patch.object(sprint_lifecycle, 'DELIVERY_SECONDS', 1.0):
            first, _ = self.query()
            second, second_packet = self.query()
        self.assertNotEqual(first['trace_operation_id'], second['trace_operation_id'])
        rows = load_local(self.root)['events']
        report = reconstruct(rows, second['trace_operation_id'], '2099-01-01T00:00:00Z')
        # Name the second read's real path when the cache stage is absent.
        observed = {'status': second.get('status'), 'reason': second.get('reason'),
                    'packet_status': second_packet.get('status'),
                    'trace_status': second_packet.get('trace_observation_status'),
                    'outcome': report.get('outcome'), 'stages': report.get('stages')}
        self.assertTrue(second['trace_observation_delivered'], observed)
        self.assertEqual(report['stages']['cache_lookup'], 'cache_hit', observed)
        self.assertEqual(len({row['attempt_id'] for row in rows if row.get('event') == 'operation'}), 2)
        self.assertFalse(state.get_active_route(self.root).get('task_budget'))

    def test_empty_query_retains_unsupported_inference_and_unknown_usage(self):
        self.enroll()
        result, packet = self.query('NoSuchSymbol_AnUnmatchedLiteral')
        report = reconstruct(load_local(self.root)['events'], result['trace_operation_id'], '2099-01-01T00:00:00Z')
        self.assertEqual(report['stages']['lexical'], 'empty')
        self.assertEqual(report['stages']['context_assembly'], 'empty')
        self.assertEqual(report['stages']['inference'], 'unsupported')
        self.assertEqual(packet['status'], 'no_fitting_fragments')
        self.assertIsNone(report['export_delivery'])

    def test_monotonic_stage_intervals_are_not_summed_as_operation_wall_time(self):
        self.enroll()
        ticks = count(0, 10)
        with patch.object(observation.time, 'monotonic_ns', side_effect=lambda: next(ticks)):
            result, _ = self.query()
        report = reconstruct(load_local(self.root)['events'], result['trace_operation_id'], '2099-01-01T00:00:00Z')
        self.assertEqual({span['elapsed_ns'] for span in report['spans']}, {10})
        self.assertGreater(report['elapsed_ns'], sum(span['elapsed_ns'] for span in report['spans']))
        self.assertTrue(all(span['timing_source'] == 'monotonic' for span in report['spans']))

    def test_failure_timeout_and_cancellation_keep_truthful_native_outcome(self):
        self.enroll()
        from getzilla.native_access import NativeAccessError
        for error, expected_error, outcome in (
                (RetrievalError('deadline_exceeded'), RetrievalError, 'timeout'),
                (CancelledError(), NativeAccessError, 'cancelled'),
                (AsyncCancelledError(), AsyncCancelledError, 'cancelled'),
                (ValueError('PRIVATE_ERROR'), NativeAccessError, 'failed')):
            with self.subTest(outcome=outcome), patch.object(native_local, 'prepare_graph_packet', side_effect=error):
                with self.assertRaises(expected_error):
                    self.query()
                rows = state.get_active_route(self.root)['observation_publication']['events']
                terminal = [row for row in rows if row.get('kind') == 'operation_finished'][-1]
                self.assertEqual(terminal['outcome'], outcome)
                self.assertNotIn('PRIVATE_ERROR', (self.root / '.getzilla/runtime/metrics.jsonl').read_text())

    def test_new_route_during_capture_does_not_retag_original_rows(self):
        self.enroll()
        old_route = state.get_active_route(self.root)
        original = native_local.prepare_graph_packet
        def change(*args, **kwargs):
            packet = original(*args, **kwargs)
            replacement = build_route(self.root, 'A different current task.', SESSION).to_dict()
            state.set_active_route(self.root, replacement)
            return packet
        with patch.object(native_local, 'prepare_graph_packet', side_effect=change):
            with self.assertRaises(ValueError):
                self.query()
        self.assertEqual(state.canonical_route(self.root, old_route['route_id'])['observation_publication']['events'], [])
        self.assertNotEqual(state.get_active_route(self.root)['route_id'], old_route['route_id'])

    def test_journal_failure_does_not_change_success_or_repeat_read(self):
        self.enroll()
        with patch.object(observation, 'publish', side_effect=RuntimeError('PRIVATE_STORAGE_ERROR')):
            result, packet = self.query()
        self.assertEqual(result['status'], 'issued')
        self.assertFalse(result['trace_observation_delivered'])
        self.assertIn('def answer', packet['text'])

    def test_actual_report_cli_reads_source_bound_retrieval_operation(self):
        self.enroll()
        result, packet = self.query()
        self.assertEqual(packet['trace_operation_id'], result['trace_operation_id'])
        completed = subprocess.run([sys.executable, str(ROOT / 'scripts/getzilla_report.py'),
            '--trace-operation', result['trace_operation_id'], '--as-of', '2099-01-01T00:00:00Z', '--json'],
            cwd=self.root, env={**os.environ, 'GETZILLA_SESSION_ID': SESSION}, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(report['outcome'], 'succeeded')
        self.assertEqual(report['stages']['lexical'], 'succeeded')
        self.assertFalse(report['claim_observed'])

    def test_real_expired_query_budget_is_recorded_as_timeout_without_synthetic_stages(self):
        self.enroll()
        from getzilla.retrieval.budget import Budget
        with patch.object(native_local, 'Budget', side_effect=lambda: Budget(seconds=0.000001)):
            with self.assertRaises(ValueError):
                self.query()
        rows = load_local(self.root)['events']
        terminal = [row for row in rows if row.get('kind') == 'operation_finished'][-1]
        self.assertEqual(terminal['outcome'], 'timeout')
        self.assertFalse(any(row.get('event') == 'span' for row in rows))

    def test_policy_revocation_before_response_also_refuses_observation_disclosure(self):
        self.enroll()
        original = native_local.prepare_graph_packet
        def revoke(*args, **kwargs):
            packet = original(*args, **kwargs)
            (self.root / '.getzilla/config/policy.json').write_text(json.dumps(
                {'schema_version': 2, 'secret_read_paths': ['a.py']}))
            return packet
        with patch.object(native_local, 'prepare_graph_packet', side_effect=revoke):
            with self.assertRaises(ValueError):
                self.query()
        self.assertEqual(state.get_active_route(self.root)['observation_publication']['events'], [])

    def test_foreign_session_and_project_do_not_create_trace_or_source_delivery(self):
        self.enroll()
        state.bind_session('00000000-0000-4000-8000-000000000099')
        with self.assertRaises(ValueError):
            self.query()
        state.bind_session(SESSION)
        with self.assertRaises(ValueError):
            deliver_local_context(self.root.parent, 'answer')
        self.assertEqual(state.get_active_route(self.root)['observation_publication']['events'], [])

    def test_source_inventory_change_after_delivery_refuses_later_trace_publication(self):
        self.enroll()
        original = native_local._write_stdout
        def emit_then_change(value):
            original(value)
            (self.root / 'new_source.py').write_text('def another():\n    return 7\n')
        with patch.object(native_local, '_write_stdout', side_effect=emit_then_change):
            result, packet = self.query()
        self.assertEqual(result['status'], 'issued')
        self.assertIn('def answer', packet['text'])
        self.assertFalse(result['trace_observation_delivered'])
        self.assertEqual(state.get_active_route(self.root)['observation_publication']['events'], [])

    def test_current_policy_revocation_hides_already_stored_source_metadata(self):
        self.enroll()
        result, _ = self.query()
        operation = result['trace_operation_id']
        captured = load_local(self.root)
        self.assertTrue(any(row.get('operation_id') == operation for row in captured['events']))
        (self.root / '.getzilla/config/policy.json').write_text(json.dumps(
            {'schema_version': 2, 'secret_read_paths': ['a.py']}))
        current = load_local(self.root)
        self.assertFalse(any(row.get('operation_id') == operation for row in current['events']))
        self.assertFalse(revalidate_local(self.root, captured))
        self.assertIsNone(current['input_digest'])
        self.assertFalse(any(identity in current['delivery_proofs'] for identity in (
            row['event_id'] for row in captured['events'] if row.get('operation_id') == operation)))
        report = reconstruct(current['events'], operation, '2099-01-01T00:00:00Z')
        self.assertIsNone(report['binding'])
        self.assertFalse(report['spans'])

    def test_changed_managed_inputs_and_missing_or_unsafe_policy_hide_whole_operation(self):
        self.enroll()
        result, _ = self.query()
        policy = self.root / '.getzilla/config/policy.json'
        manifest = self.root / '.getzilla/managed-components.json'
        policy_raw, manifest_raw = policy.read_bytes(), manifest.read_bytes()
        alternate = self.root / 'same-policy.json'
        alternate.write_bytes(policy_raw)
        actions = (
            lambda: policy.write_bytes(b'{malformed'),
            lambda: policy.unlink(),
            lambda: policy.chmod(0),
            lambda: (policy.unlink(), policy.symlink_to(alternate)),
            lambda: manifest.write_bytes(manifest_raw + b'\n'),
            lambda: (self.root / '.getzilla/config/model-continuation.json').write_bytes(b'{}'),
        )
        for index, change in enumerate(actions):
            with self.subTest(case=index):
                change()
                hidden = load_local(self.root)
                self.assertFalse(any(row.get('operation_id') == result['trace_operation_id'] for row in hidden['events']))
                self.assertIsNone(hidden['input_digest'])
                self.assertIn('retrieval_access_unavailable', hidden['gaps'])
            if policy.is_symlink():
                policy.unlink()
            elif policy.exists():
                policy.chmod(0o644)
            policy.write_bytes(policy_raw)
            policy.chmod(0o644)
            manifest.write_bytes(manifest_raw)
            (self.root / '.getzilla/config/model-continuation.json').unlink(missing_ok=True)
        restored = load_local(self.root)
        self.assertTrue(any(row.get('operation_id') == result['trace_operation_id'] for row in restored['events']),
                        'this local profile checks current exact bytes, not a monotonic enterprise revocation history')

    def test_all_six_hook_profiles_bind_their_own_exact_module_inputs(self):
        harnesses = ('grok', 'claude', 'codex', 'copilot', 'gemini', 'qwen')
        manifest_path = self.root / '.getzilla/managed-components.json'
        manifest = json.loads(manifest_path.read_bytes())
        manifest['agents'] = list(harnesses)
        manifest_path.write_text(json.dumps(manifest))
        for harness in harnesses[1:]:
            module = 'context-hook-' + harness
            manage_modules(self.root, 'install', {module: '0.1.0'}, source=ROOT)
            manage_modules(self.root, 'enable', {module: None}, source=ROOT,
                           grants=['context.hook.' + harness])
        profiles = ('native-local-stdout', *('native-hook-' + name for name in harnesses))
        with native_root(self.root) as anchor:
            original = {profile: current_policy_digest(anchor, profile) for profile in profiles}
        self.assertEqual(len(set(original.values())), 7)
        manifest = json.loads(manifest_path.read_bytes())
        for harness in harnesses:
            selected = 'native-hook-' + harness
            path = self.root / manifest['components']['module:context-hook-' + harness]['files'][0]
            raw = path.read_bytes()
            path.write_bytes(raw + b'\n')
            with native_root(self.root) as anchor:
                changed = {profile: current_policy_digest(anchor, profile) for profile in profiles}
            self.assertNotEqual(changed[selected], original[selected])
            self.assertEqual({key: value for key, value in changed.items() if key != selected},
                             {key: value for key, value in original.items() if key != selected})
            path.write_bytes(raw)

    def test_unproved_changed_profile_is_rejected_before_current_policy_selection(self):
        self.enroll()
        result, _ = self.query()
        journal = self.root / '.getzilla/runtime/metrics.jsonl'
        rows = [json.loads(line) for line in journal.read_bytes().splitlines()]
        for row in rows:
            if row.get('operation_id') == result['trace_operation_id'] and row.get('event') == 'policy':
                row['read_profile'] = 'native-hook-grok'
        journal.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        with patch('getzilla.retrieval.policy_inputs.current_policy_digest', side_effect=AssertionError('unproved selector')):
            hidden = load_local(self.root)
        self.assertFalse(any(row.get('operation_id') == result['trace_operation_id'] for row in hidden['events']))
        self.assertIsNone(hidden['input_digest'])

    def test_conflicting_native_policy_observations_suppress_the_entire_operation(self):
        self.enroll()
        finish = observation._Capture.finish
        def contradictory(captured, outcome):
            finish(captured, outcome)
            captured._row('policy', 'policy_observed', decision='allow', reason_code='policy_allowed',
                          read_profile=captured.profile, policy_digest='f' * 64)
        with patch.object(observation._Capture, 'finish', contradictory):
            result, _ = self.query()
        hidden = load_local(self.root)
        self.assertFalse(any(row.get('operation_id') == result['trace_operation_id'] for row in hidden['events']))
        self.assertIsNone(hidden['input_digest'])


class RetrievalProfileSyntaxTests(unittest.TestCase):
    def test_profile_is_closed_data_on_policy_observations_only(self):
        from tests.test_trace_contracts import observation as fixture
        from getzilla.trace_contracts import validate_v3
        valid = fixture('policy', 'policy_observed', operation_id='native_op-1', decision='allow',
                        policy_digest='a' * 64, reason_code='policy_allowed', read_profile='native-local-stdout')
        validate_v3(valid)
        for row in ({**valid, 'read_profile': 'caller-invented'},
                    fixture(read_profile='native-local-stdout')):
            with self.assertRaisesRegex(ValueError, '^invalid_observation$'):
                validate_v3(row)
