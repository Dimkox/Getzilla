"""Exercise native canonical transitions; imported JSON cannot finish a task."""
import os
import json
import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'.getzilla'))
from getzilla import state
from getzilla.router import build_route
from tests._support import project_copy
try:
    from getzilla import sprint_lifecycle
except ImportError:
    sprint_lifecycle = None

SESSION = '00000000-0000-4000-8000-000000000001'


class ProducerTests(unittest.TestCase):
    def setUp(self):
        saved = os.open('.', os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, saved)
        self.addCleanup(os.fchdir, saved)

    def route(self, root):
        os.chdir(root)
        root.chmod(0o755)
        (root/'.getzilla').chmod(0o755)
        state.bind_session(SESSION)
        route = build_route(root, 'Fix a typo in README documentation.', SESSION).to_dict()
        state.set_active_route(root, route)
        return state.get_active_route(root)

    def select(self, root, route, *, flush=True):
        self.assertIsNotNone(sprint_lifecycle, 'native selection producer is missing')
        start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).strftime('%Y-%m-%dT%H:%M:%SZ')
        current = sprint_lifecycle.select_sprint(root, start, expected_epoch=route['authority_epoch'],
                                                 expected_revision=route['state_revision'])
        if flush:
            sprint_lifecycle.deliver(root, current['route_id'])
        return state.canonical_route(root, current['route_id'])

    def test_library_transition_keeps_pending_rows_without_journal_io(self):
        with project_copy(git=True, minimal_runtime=True) as root:
            route = self.route(root)
            with patch('getzilla.sprint_lifecycle.append_batch') as append:
                current = self.select(root, route, flush=False)
            append.assert_not_called()
            self.assertEqual(current['observation_publication']['delivery'], {})
            self.assertEqual(len(current['observation_publication']['events']), 1)

    def test_delivery_never_takes_journal_lock_inside_task_transition(self):
        from getzilla import fsx
        with project_copy(git=True, minimal_runtime=True) as root:
            route = self.route(root)
            current = self.select(root, route, flush=False)
            journal = (root / '.getzilla/runtime/metrics.jsonl').stat()
            real_lock = fsx.lock_file
            journal_calls = []
            def checked(descriptor, *args, **kwargs):
                info = os.fstat(descriptor)
                if (info.st_dev, info.st_ino) == (journal.st_dev, journal.st_ino):
                    journal_calls.append(True)
                    self.assertEqual(state._TRANSITIONS.get(), ())
                    self.assertFalse(kwargs.get('blocking', True))
                return real_lock(descriptor, *args, **kwargs)
            with patch('getzilla.fsx.lock_file', side_effect=checked):
                self.assertTrue(sprint_lifecycle.deliver(root, current['route_id']))
            self.assertEqual(journal_calls, [True])

    def test_native_selection_replay_reuses_exact_committed_event(self):
        with project_copy(git=True, minimal_runtime=True) as root:
            route = self.route(root)
            current = self.select(root, route)
            pending = current['observation_publication']['events']
            replay = self.select(root, route)
            self.assertEqual(replay['observation_publication']['events'], pending)
            self.assertEqual(current['logical_task_id'], route['logical_task_id'])
            self.assertEqual(pending[0]['context_revision'], route['context']['revision'])
            self.assertNotIn('Fix a typo', str(pending))
            proof = state.canonical_route(root, route['route_id'])['observation_publication']['delivery']
            self.assertIn(pending[0]['event_id'], proof)
            from getzilla.trace_contracts import delivery_utc, utc
            self.assertGreaterEqual(delivery_utc(proof[pending[0]['event_id']]['delivered_by']), utc(pending[0]['captured_at']))

    def test_failed_native_finish_does_not_emit_completion(self):
        from getzilla.continuity import finish_task
        with project_copy(git=True, minimal_runtime=True) as root:
            route = self.route(root)
            current = self.select(root, route)
            with self.assertRaises(ValueError):
                finish_task(root)
            records = state.canonical_route(root, current['route_id'])['observation_publication']['events']
            self.assertNotIn('task_completed', [row['kind'] for row in records])

    def test_append_failure_preserves_native_selection_for_reconciliation(self):
        with project_copy(git=True, minimal_runtime=True) as root:
            route = self.route(root)
            self.assertIsNotNone(sprint_lifecycle, 'native selection producer is missing')
            with patch('getzilla.sprint_lifecycle.append_batch', return_value=None):
                current = self.select(root, route)
            self.assertIn('sprint', state.canonical_route(root, route['route_id']))
            self.assertEqual(current['observation_publication']['coverage'], 'censored')

    def test_delayed_delivery_after_pointer_change_uses_original_task_binding(self):
        with project_copy(git=True, minimal_runtime=True) as root:
            route = self.route(root)
            first = self.select(root, route)
            captured = first['observation_publication']['events'][0]
            (root/'.getzilla/runtime/active-route.json').unlink()
            self.assertEqual(sprint_lifecycle.deliver(root, first['route_id']), True)
            from getzilla.observation_privacy import load_local
            rows = [row for row in load_local(root)['events'] if row.get('schema_version') == 3]
            self.assertEqual(rows[0]['logical_task_id'], captured['logical_task_id'])
            self.assertEqual(rows[0]['head'], captured['head'])

    def test_lost_delivery_ack_does_not_retry_native_work_or_claim_delivery(self):
        with project_copy(git=True, minimal_runtime=True) as root:
            route = self.route(root)
            self.assertIsNotNone(sprint_lifecycle)
            with patch('getzilla.sprint_lifecycle.ack_delivery', side_effect=OSError('private-sentinel')):
                current = self.select(root, route)
            self.assertEqual(current['observation_publication']['delivery'], {})
            captured = current['observation_publication']['events'][0]
            from getzilla.observation_privacy import load_local
            from getzilla.sprint_report import summarize_sprint
            source = load_local(root)
            result = summarize_sprint(source['events'], start=current['sprint']['window_start'],
                as_of=(datetime.now(timezone.utc)+timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
                source_manifest=source)
            self.assertIsNone(result['counts']['observed_selected'])
            self.assertIn('native_delivery_proof_missing', result['coverage']['gaps'])
            self.assertTrue(sprint_lifecycle.deliver(root, route['route_id']))
            restored = state.canonical_route(root, route['route_id'])
            self.assertEqual(restored['observation_publication']['events'][0], captured)
            self.assertEqual(len(restored['observation_publication']['delivery']), 1)

    def test_backward_delivery_clock_stays_censored(self):
        with project_copy(git=True, minimal_runtime=True) as root:
            route = self.route(root)
            self.assertIsNotNone(sprint_lifecycle)
            with patch('getzilla.sprint_lifecycle.append_batch', return_value=None):
                current = self.select(root, route)
            with patch('getzilla.sprint_lifecycle._native_clock', return_value='2000-01-01T00:00:00.000000Z'):
                self.assertFalse(sprint_lifecycle.deliver(root, route['route_id']))
            self.assertEqual(state.canonical_route(root, route['route_id'])['observation_publication']['delivery'], {})

    def test_telemetry_privacy_failure_does_not_block_native_task_state(self):
        with project_copy(git=True, minimal_runtime=True) as root:
            route = self.route(root)
            current = self.select(root, route)
            (root/'.getzilla/runtime').chmod(0o755)
            updated = state.update_route(root, status='working')
            self.assertEqual(updated['status'], 'working')
            self.assertEqual(updated['observation_publication']['events'], current['observation_publication']['events'])
            from getzilla.observation_privacy import load_local
            self.assertEqual(load_local(root)['access'], 'metadata_only')

    def test_existing_native_route_cli_selects_only_explicit_current_owner_task(self):
        with project_copy(git=True, minimal_runtime=True) as root:
            route = self.route(root)
            start = datetime.now(timezone.utc).strftime('%Y-%m-%dT00:00:00Z')
            script = Path(__file__).resolve().parents[1]/'scripts/getzilla_route.py'
            result = subprocess.run([sys.executable, str(script), '--sprint-select', start,
                '--expected-epoch', str(route['authority_epoch']), '--expected-revision', str(route['state_revision']),
                '--session', SESSION, '--json'], cwd=root, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            reported = json.loads(result.stdout)
            self.assertEqual(reported['sprint']['window_start'], start)
            actual = state.canonical_route(root, route['route_id'])
            self.assertEqual(reported, actual)
            self.assertTrue(reported['observation_publication']['delivery'])

    def test_missing_journal_selection_does_not_turn_membership_into_zero(self):
        from getzilla.observation_privacy import load_local
        from getzilla.sprint_report import summarize_sprint
        with project_copy(git=True, minimal_runtime=True) as root:
            route = self.route(root)
            current = self.select(root, route)
            (root/'.getzilla/runtime/metrics.jsonl').write_text('')
            source = load_local(root)
            result = summarize_sprint(source['events'], start=current['sprint']['window_start'],
                as_of=(datetime.now(timezone.utc)+timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
                source_manifest=source)
            self.assertIsNone(result['counts']['observed_selected'])
            self.assertIn('native_journal_gap', result['coverage']['gaps'])

    def test_late_a_delivery_never_changes_the_selected_b_task(self):
        from getzilla.continuity import submit
        from getzilla import task_budget
        with project_copy(git=True, minimal_runtime=True) as root:
            route_a = self.route(root)
            limits = {'calls': 3, 'failures': 2, 'repeat_failures': 2, 'deadline_epoch': 2000000000,
                      'tokens': None, 'cpu_ms': None, 'cost_micros': None, 'elapsed_ms': 10000}
            task_budget.initialize(root, limits, 0, route_a['state_revision'], task_id=route_a['logical_task_id'])
            route_a = state.get_active_route(root)
            task_budget.reserve(root, 'reserved', 'a'*64, {'tokens': None, 'cpu_ms': None, 'cost_micros': None, 'elapsed_ms': 100},
                                0, route_a['state_revision'], task_id=route_a['logical_task_id'])
            route_a = state.get_active_route(root)
            with patch('getzilla.sprint_lifecycle.append_batch', return_value=None):
                selected = self.select(root, route_a)
            route_b = submit(root, 'Fix another README typo.', SESSION, new_task=True)
            before_b = (root/'.getzilla/runtime/routes'/f"{route_b['route_id']}.json").read_bytes()
            active_before = (root/'.getzilla/runtime/active-route.json').read_bytes()
            pointer_before = (root/'.getzilla/runtime/sessions'/f'{SESSION}.json').read_bytes()
            self.assertTrue(sprint_lifecycle.deliver(root, route_a['route_id']))
            self.assertEqual(state.get_active_route(root)['route_id'], route_b['route_id'])
            self.assertEqual((root/'.getzilla/runtime/routes'/f"{route_b['route_id']}.json").read_bytes(), before_b)
            self.assertEqual((root/'.getzilla/runtime/active-route.json').read_bytes(), active_before)
            self.assertEqual((root/'.getzilla/runtime/sessions'/f'{SESSION}.json').read_bytes(), pointer_before)
            updated_a = state.canonical_route(root, route_a['route_id'])
            self.assertEqual(updated_a['task_budget'], selected['task_budget'])
            self.assertEqual(updated_a['observation_publication']['events'], selected['observation_publication']['events'])
            proof = updated_a['observation_publication']['delivery']
            self.assertTrue(sprint_lifecycle.deliver(root, route_a['route_id']))
            self.assertEqual(state.canonical_route(root, route_a['route_id'])['observation_publication']['delivery'], proof)

    def test_observation_only_cas_cannot_mutate_authority_or_accept_stale_epoch(self):
        import copy
        with project_copy(git=True, minimal_runtime=True) as root:
            current = self.select(root, self.route(root))
            changed = copy.deepcopy(current)
            changed.update(status='completed', state_revision=current['state_revision']+1)
            with self.assertRaises(ValueError):
                state._commit_route(root, changed, expected=current, observation_only=True)
            stale = copy.deepcopy(current)
            stale['authority_epoch'] += 1
            self.assertFalse(sprint_lifecycle.ack_delivery(root, stale, []))
            state.bind_session('00000000-0000-4000-8000-000000000002')
            self.assertFalse(sprint_lifecycle.deliver(root, current['route_id']))
            self.assertEqual(state.canonical_route(root, current['route_id']), current)

    def test_conflicting_duplicate_censors_even_the_row_with_a_valid_proof(self):
        from getzilla.observation_privacy import load_local
        with project_copy(git=True, minimal_runtime=True) as root:
            current = self.select(root, self.route(root))
            original = current['observation_publication']['events'][0]
            conflict = {**original, 'scope_digest': '0'*64}
            with (root / '.getzilla/runtime/metrics.jsonl').open('a') as output:
                output.write(json.dumps(conflict) + '\n')
            source = load_local(root)
            self.assertIn('conflicting_replay', source['gaps'])
            self.assertNotIn(original['event_id'], source['delivery_proofs'])
            self.assertFalse(any(row.get('event_id') == original['event_id'] for row in source['events']))


if __name__ == '__main__':
    unittest.main()
