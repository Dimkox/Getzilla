"""The injected backend counts actual calls; observations never dispatch it."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import subprocess
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from getzilla import execution as execution, execution_store as store, state
from getzilla.agent_lifecycle import start_agent
from getzilla.router import build_route


class FakeClock:
    def __init__(self):
        self.seconds = 100.0
        self.now = datetime(2026, 11, 4, tzinfo=timezone.utc)
        self.sleeps = []

    def monotonic(self):
        return self.seconds

    def utcnow(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.seconds += seconds
        self.now += timedelta(seconds=seconds)


class CountingBackend:
    kind = 'contract-test'
    external_mutations = False

    def __init__(self, complete=True):
        self.calls = 0
        self.cancels = 0
        self.complete = complete
        self.admissions = []
        self.lock = threading.Lock()

    def dispatch(self, root, admission, request):
        persisted = store.load_registry(root)['records'][admission.execution_id]
        assert persisted['backend']['claim'] == 'committed'
        with self.lock:
            self.calls += 1
            self.admissions.append(admission)
        return {'execution_status': 'succeeded', 'terminal_reason': 'exit_zero'} if self.complete else None

    def cancel(self, root, admission):
        self.cancels += 1
        return True


def owned_route(root, session='owner', task='Fix a README typo.'):
    state.bind_session(session)
    route = build_route(root, task, session).to_dict()
    state.set_active_route(root, route)
    return state.get_active_route(root)


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.env = patch.dict(os.environ, {'GETZILLA_SESSION_ID': 'owner'})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.addCleanup(state.bind_session, None)
        self.route = owned_route(self.root)
        self.caller = execution.trusted_caller(self.root)
        self.request = execution.SubmitRequest(intent_key='intent-1', arguments={'command': 'credential=private'},
                                               hard_timeout_seconds=60, label='contract-test')

    def submit(self, backend=None, request=None):
        return execution.submit(self.root, self.caller, request or self.request,
                                backend=backend if backend is not None else CountingBackend())

    def test_fast_completion_and_ten_replays_have_one_dispatch_and_fixed_owner_deadline(self):
        backend = CountingBackend()
        first = self.submit(backend)
        self.assertEqual(first['execution_status'], 'succeeded')
        self.assertFalse(first['evidence_authority'])
        for _ in range(10):
            self.assertEqual(self.submit(backend), first)
            self.assertEqual(execution.get(self.root, self.caller, first['execution_id']), first)
        self.assertEqual(backend.calls, 1)
        self.assertEqual(first['owner']['route_id'], self.route['route_id'])
        raw = (self.root / store.REGISTRY_PATH).read_text()
        self.assertNotIn('credential=private', raw)
        self.assertNotIn('intent-1', raw)
        self.assertNotIn('environment', raw)

    def test_simultaneous_submit_publishes_one_attempt_and_dispatch(self):
        backend = CountingBackend()
        with ThreadPoolExecutor(max_workers=4) as pool:
            views = list(pool.map(lambda _: self.submit(backend), range(12)))
        self.assertEqual(backend.calls, 1)
        self.assertEqual(len({view['execution_id'] for view in views}), 1)
        self.assertEqual(len(store.load_registry(self.root)['records']), 1)

    def test_same_intent_conflicts_on_arguments_backend_deadline_and_operation_binding(self):
        self.submit()
        for request in (replace(self.request, arguments={'command': 'different'}),
                        replace(self.request, hard_timeout_seconds=61),
                        replace(self.request, operation_id='separate-operation'),
                        replace(self.request, mcp_request_id='request-2')):
            with self.subTest(request=request), self.assertRaises(execution.ExecutionError) as caught:
                self.submit(request=request)
            self.assertEqual(caught.exception.code, 'intent_conflict')
        other = CountingBackend()
        other.kind = 'other-contract'
        with self.assertRaises(execution.ExecutionError):
            self.submit(other)
        self.assertEqual(other.calls, 0)

    def test_unsupported_production_operations_and_external_backends_create_no_attempt(self):
        with self.assertRaises(execution.ExecutionError) as caught:
            execution.submit(self.root, self.caller, self.request)
        self.assertEqual(caught.exception.code, 'unsupported_backend')
        backend = CountingBackend()
        backend.external_mutations = True
        with self.assertRaises(execution.ExecutionError) as caught:
            self.submit(backend)
        self.assertEqual(caught.exception.code, 'external_backend_unqualified')
        self.assertEqual(backend.calls, 0)
        self.assertFalse((self.root / store.REGISTRY_PATH).exists())
        with self.assertRaises(execution.ExecutionError) as caught:
            execution.cancel(self.root, self.caller, 'a' * 32)
        self.assertEqual(caught.exception.code, 'unsupported_backend')

    def test_old_owner_reads_and_requests_real_backend_cancel_after_active_route_switch(self):
        backend = CountingBackend(complete=False)
        view = self.submit(backend)
        new_route = owned_route(self.root, task='Fix a different README typo.')
        self.assertNotEqual(new_route['route_id'], view['owner']['route_id'])
        self.assertEqual(execution.get(self.root, self.caller, view['execution_id'])['owner'], view['owner'])
        cancelled = execution.cancel(self.root, self.caller, view['execution_id'], backend=backend)
        self.assertEqual(cancelled['execution_status'], 'cancel_requested')
        self.assertEqual(cancelled['cleanup_status'], 'pending')
        self.assertEqual(backend.cancels, 1)
        self.assertEqual(state.get_active_route(self.root)['route_id'], new_route['route_id'])
        self.assertNotEqual(cancelled['execution_status'], 'cancelled')

    def test_foreign_workspace_session_and_handoff_epoch_cannot_disclose_old_work(self):
        view = self.submit()
        with tempfile.TemporaryDirectory() as other:
            owned_route(Path(other))
            foreign = execution.trusted_caller(Path(other))
            with self.assertRaises(execution.ExecutionError):
                execution.get(self.root, foreign, view['execution_id'])
        state.bind_session('intruder')
        with self.assertRaises(execution.ExecutionError):
            execution.get(self.root, self.caller, view['execution_id'])
        state.bind_session('owner')
        route = state.canonical_route(self.root, self.route['route_id'])
        route['authority_epoch'] += 1
        state.durable_json(self.root, self.root / '.getzilla/runtime/routes' / (route['route_id'] + '.json'), route)
        with self.assertRaises(execution.ExecutionError):
            execution.get(self.root, self.caller, view['execution_id'])

    def test_worker_context_is_derived_and_old_generation_is_fenced(self):
        worker = start_agent(self.root, 'worker-one', 'general_implementer')
        caller = execution.trusted_caller(self.root, agent_id='worker-one')
        backend = CountingBackend(complete=False)
        view = execution.submit(self.root, caller, self.request, backend=backend)
        self.assertEqual(view['owner']['agent_generation'], worker['generation'])
        ledger = state.get_agent_state(self.root)
        ledger['active']['worker-one']['generation'] = 'new-generation'
        state.durable_json(self.root, state.agent_state_path(self.root), ledger)
        admission = backend.admissions[0]
        with self.assertRaises(execution.ExecutionError):
            execution.record_event(self.root, admission.token, view['execution_id'], view['revision'],
                                   admission.execution_generation, 'late-worker', {'execution_status': 'succeeded'})
        for callback in (lambda: execution.get(self.root, caller, view['execution_id']),
                         lambda: execution.cancel(self.root, caller, view['execution_id'], backend=CountingBackend())):
            with self.assertRaises(execution.ExecutionError):
                callback()

    def test_callback_revision_generation_terminal_and_event_replay_are_fenced(self):
        backend = CountingBackend(complete=False)
        view = self.submit(backend)
        admission = backend.admissions[0]
        event = {'execution_status': 'failed', 'terminal_reason': 'exit_nonzero'}
        complete = execution.record_event(self.root, admission.token, view['execution_id'], view['revision'],
                                          admission.execution_generation, 'event-1', event)
        replay = execution.record_event(self.root, admission.token, view['execution_id'], view['revision'],
                                        admission.execution_generation, 'event-1', event)
        self.assertEqual(complete, replay)
        for revision, generation, event_id, changed in (
            (complete['revision'], admission.execution_generation, 'event-1', {'execution_status': 'succeeded'}),
            (complete['revision'], '0' * 32, 'event-2', event),
            (view['revision'], admission.execution_generation, 'event-2', event),
            (complete['revision'], admission.execution_generation, 'event-2', {'execution_status': 'succeeded'}),
        ):
            with self.subTest(event=event_id, revision=revision), self.assertRaises(execution.ExecutionError):
                execution.record_event(self.root, admission.token, view['execution_id'], revision, generation, event_id, changed)
        self.assertEqual(execution.get(self.root, self.caller, view['execution_id']), complete)
        self.assertEqual(backend.calls, 1)

    def test_storage_failure_before_dispatch_has_zero_calls_and_after_dispatch_is_unknown(self):
        backend = CountingBackend()
        with patch.object(store.state, 'durable_bytes', side_effect=OSError('injected intent write failure')):
            with self.assertRaises(store.RegistryError):
                self.submit(backend)
        self.assertEqual(backend.calls, 0)
        real = store.state.durable_bytes
        writes = 0
        def fail_receipt(root, path, raw):
            nonlocal writes
            if path.name == 'registry.json':
                writes += 1
                if writes > 1:
                    raise OSError('injected receipt failure')
            return real(root, path, raw)
        with patch.object(store.state, 'durable_bytes', side_effect=fail_receipt):
            result = self.submit(backend)
        self.assertEqual(backend.calls, 1)
        self.assertEqual(result['observation_status'], 'persistence_unknown')
        self.assertEqual(result['operation_outcome'], 'unknown')
        self.assertFalse(result['evidence_authority'])
        self.assertNotEqual(result['execution_status'], 'succeeded')


    def test_wait_validates_cap_uses_monotonic_and_never_restarts_or_extends_deadline(self):
        clock = FakeClock()
        backend = CountingBackend(complete=False)
        view = execution.submit(self.root, self.caller, self.request, backend=backend, clock=clock)
        deadline = view['deadline'].copy()
        for timeout in (0, -1, float('nan'), float('inf'), 30.01, True, '1'):
            with self.subTest(timeout=timeout), self.assertRaises(execution.ExecutionError):
                execution.wait(self.root, self.caller, view['execution_id'], timeout, clock=clock)
        clock.now -= timedelta(days=365)
        for _ in range(10):
            observed = execution.wait(self.root, self.caller, view['execution_id'], .02, clock=clock)
            self.assertEqual(observed['wait_status'], 'wait_expired')
            self.assertEqual(observed['execution']['execution_status'], 'running')
            self.assertEqual(observed['execution']['deadline'], deadline)
        self.assertEqual(backend.calls, 1)
        self.assertAlmostEqual(clock.monotonic(), 100.2, places=9)
        self.assertTrue(all(0 < duration <= .02 for duration in clock.sleeps))
        clock.seconds = 161
        elapsed = execution.get(self.root, self.caller, view['execution_id'])
        self.assertTrue(elapsed['deadline_elapsed'])
        self.assertEqual(elapsed['execution_status'], 'running')
        self.assertEqual(elapsed['cleanup_status'], 'not_required')
        self.assertEqual(elapsed['deadline'], deadline)

    def test_ready_wait_has_one_terminal_result_and_late_deadline_callback_is_fenced(self):
        clock = FakeClock()
        backend = CountingBackend()
        view = execution.submit(self.root, self.caller, self.request, backend=backend, clock=clock)
        for _ in range(10):
            ready = execution.wait(self.root, self.caller, view['execution_id'], 30, clock=clock)
            self.assertEqual(ready['wait_status'], 'ready')
            self.assertEqual(ready['execution']['execution_id'], view['execution_id'])
        self.assertEqual(clock.sleeps, [])
        self.assertEqual(backend.calls, 1)
        running = CountingBackend(complete=False)
        request = replace(self.request, intent_key='second')
        current = execution.submit(self.root, self.caller, request, backend=running, clock=clock)
        admission = running.admissions[0]
        clock.seconds += 60
        with self.assertRaises(execution.ExecutionError):
            execution.record_event(self.root, admission.token, current['execution_id'], current['revision'],
                                   admission.execution_generation, 'too-late', {'execution_status': 'succeeded'})
        self.assertEqual(execution.get(self.root, self.caller, current['execution_id'])['execution_status'], 'running')

    def test_restore_without_live_continuity_orphans_without_relaunch_or_clock_budget(self):
        clock = FakeClock()
        backend = CountingBackend(complete=False)
        request = replace(self.request, operation_id='stable-operation')
        view = execution.submit(self.root, self.caller, request, backend=backend, clock=clock)
        restarted = FakeClock()
        restarted.now -= timedelta(days=30)
        with patch.dict(execution._LIVE, {}, clear=True):
            report = execution.restore(self.root, clock=restarted)
        self.assertEqual(report['orphaned'], 1)
        restored = execution.get(self.root, self.caller, view['execution_id'])
        self.assertEqual(restored['execution_status'], 'orphaned')
        self.assertEqual(restored['cleanup_status'], 'unconfirmed')
        self.assertEqual(restored['operation_outcome'], 'unknown')
        self.assertEqual(restored['terminal_reason'], 'recovery_uncertain')
        self.assertEqual(restored['deadline'], view['deadline'])
        self.assertEqual(backend.calls, 1)
        replay = execution.submit(self.root, self.caller, request, backend=backend, clock=restarted)
        self.assertEqual(replay['execution_id'], view['execution_id'])
        self.assertEqual(backend.calls, 1)

    def test_restore_compacts_expired_output_but_keeps_bounded_acl_tombstone_and_dedup(self):
        clock = FakeClock()
        backend = CountingBackend()
        view = execution.submit(self.root, self.caller, self.request, backend=backend, clock=clock)
        clock.now += timedelta(days=2)
        report = execution.restore(self.root, clock=clock)
        self.assertEqual(report['expired'], 1)
        expired = execution.get(self.root, self.caller, view['execution_id'])
        self.assertEqual(expired['observation_status'], 'expired')
        self.assertEqual(expired['owner'], view['owner'])
        self.assertEqual(expired['execution_status'], 'succeeded')
        self.assertEqual(self.submit(backend)['execution_id'], view['execution_id'])
        self.assertEqual(backend.calls, 1)
        self.assertEqual(len(store.load_registry(self.root)['intents']), 1)
        with self.assertRaises(execution.ExecutionError) as caught:
            execution.get(self.root, self.caller, '0' * 32)
        self.assertEqual(caught.exception.code, 'execution_not_found')

    def test_completion_preserves_original_source_and_real_git_identity_on_changed_bytes(self):
        source = self.root / 'source.txt'
        source.write_text('before')
        subprocess.run(['git', 'init', '-q', '-b', 'main', str(self.root)], check=True)
        for args in (['config', 'user.email', 'execution@example.test'], ['config', 'user.name', 'Execution fixture'],
                     ['add', 'source.txt'], ['commit', '-qm', 'before attempt']):
            subprocess.run(['git', *args], cwd=self.root, check=True)
        head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=self.root, text=True).strip()
        class ChangingBackend(CountingBackend):
            def dispatch(inner, root, admission, request):
                super().dispatch(root, admission, request)
                source.write_text('after')
                return {'execution_status': 'succeeded', 'terminal_reason': 'exit_zero'}
        result = self.submit(ChangingBackend())
        self.assertEqual(result['execution_status'], 'succeeded')
        self.assertTrue(result['source_changed'])
        self.assertEqual(result['source']['git_head'], head)
        self.assertNotEqual(result['source']['fingerprint'], result['source_final']['fingerprint'])
        self.assertFalse(result['evidence_authority'])
        self.assertEqual((self.root / '.getzilla/runtime/receipts').exists(), False)
        self.assertEqual(execution.get(self.root, self.caller, result['execution_id'])['source'], result['source'])

    def test_nested_non_git_workspace_never_inherits_parent_sha_and_secret_files_are_not_read(self):
        subprocess.run(['git', 'init', '-q', '-b', 'main', str(self.root)], check=True)
        child = self.root / 'nested'
        child.mkdir()
        owned_route(child)
        caller = execution.trusted_caller(child)
        view = execution.submit(child, caller, self.request, backend=CountingBackend())
        self.assertIsNone(view['source']['git_head'])
        self.assertEqual(len(view['source']['fingerprint']), 64)
        (child / '.env').write_text('PRIVATE=must not be read')
        real_read = execution.read_package_file
        def guarded_read(root, relative, **kwargs):
            self.assertNotEqual(relative, '.env')
            return real_read(root, relative, **kwargs)
        with patch.object(execution, 'read_package_file', side_effect=guarded_read):
            with self.assertRaises(execution.ExecutionError) as caught:
                execution.submit(child, caller, replace(self.request, intent_key='secret-root'), backend=CountingBackend())
        self.assertEqual(caught.exception.code, 'source_inventory_unavailable')
