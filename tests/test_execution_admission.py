"""Collected b2 advisory regressions using real fixture authority and storage."""
from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from getzilla import continuity, execution, execution_store as store, state
from tests.test_execution import CountingBackend, FakeClock, owned_route


class BoundaryClock(FakeClock):
    def __init__(self, hook):
        super().__init__()
        self.reads = 0
        self.hook = hook

    def monotonic(self):
        self.reads += 1
        if self.reads == 2:
            self.hook()
        return super().monotonic()


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        env = patch.dict(os.environ, {'GETZILLA_SESSION_ID': 'owner'})
        env.start()
        self.addCleanup(env.stop)
        self.addCleanup(state.bind_session, None)
        self.route = owned_route(self.root)
        self.caller = execution.trusted_caller(self.root)
        self.request = execution.SubmitRequest('intent', {'nested': {'values': ['original-private-value']}}, 60)

    def handoff(self):
        route = state.canonical_route(self.root, self.route['route_id'])
        continuity.submit(self.root, '', 'new-owner', continue_route=route['route_id'],
                          expected_epoch=route['authority_epoch'], expected_revision=route['state_revision'],
                          request_id='real-fixture-handoff')
        state.bind_session('owner')

    def test_digest_and_dispatch_share_one_owned_argument_snapshot(self):
        class Capture(CountingBackend):
            def dispatch(inner, root, admission, request):
                inner.seen = copy.deepcopy(request.arguments)
                return super().dispatch(root, admission, request)
        backend = Capture()
        original = copy.deepcopy(self.request.arguments)
        clock = BoundaryClock(lambda: self.request.arguments['nested']['values'].append('changed-after-intent'))
        result = execution.submit(self.root, self.caller, self.request, backend=backend, clock=clock)
        self.assertEqual(backend.seen, original)
        self.assertEqual(backend.calls, 1)
        expected = execution._digest({'arguments': original, 'backend': backend.kind, 'timeout': 60,
                                      'label': 'tool', 'operation_id': None, 'remote_task_id': None})
        self.assertEqual(result['input']['request_digest'], expected)
        self.assertNotIn('original-private-value', (self.root / store.REGISTRY_PATH).read_text())
        self.assertNotIn('changed-after-intent', (self.root / store.REGISTRY_PATH).read_text())

    def test_real_handoff_before_dispatch_makes_zero_adapter_and_work_calls(self):
        class CountEntry(CountingBackend):
            adapter_calls = 0
            def dispatch(inner, root, admission, request):
                inner.adapter_calls += 1
                return super().dispatch(root, admission, request)
        backend = CountEntry(complete=False)
        with self.assertRaises(execution.ExecutionError):
            execution.submit(self.root, self.caller, self.request, backend=backend, clock=BoundaryClock(self.handoff))
        self.assertEqual(backend.adapter_calls, 0)
        self.assertEqual(backend.calls, 0)
        self.assertEqual(state.canonical_route(self.root, self.route['route_id'])['authority_epoch'], 1)

    def test_real_handoff_inside_adapter_before_consumption_makes_zero_work_calls(self):
        class RevokeBeforeWork(CountingBackend):
            adapter_calls = 0
            def dispatch(inner, root, admission, request):
                inner.adapter_calls += 1
                self.handoff()
                return super().dispatch(root, admission, request)
        backend = RevokeBeforeWork(complete=False)
        try:
            execution.submit(self.root, self.caller, self.request, backend=backend)
        except execution.ExecutionError:
            pass
        self.assertEqual(backend.adapter_calls, 1)
        self.assertEqual(backend.calls, 0)

    def test_unqualified_legacy_adapter_is_refused_without_publication(self):
        class Legacy:
            kind = 'legacy'
            external_mutations = False
            calls = 0
            def dispatch(inner, *args):
                inner.calls += 1
        backend = Legacy()
        with self.assertRaises(execution.ExecutionError) as caught:
            execution.submit(self.root, self.caller, self.request, backend=backend)
        self.assertEqual(caught.exception.code, 'unsupported_admission_fence')
        self.assertEqual(backend.calls, 0)
        self.assertEqual(store.load_registry(self.root)['records'], {})

    def test_concurrent_cancel_reserves_once_without_holding_global_lock_over_adapter(self):
        entered, release = threading.Event(), threading.Event()
        class Blocking(CountingBackend):
            cancel_entries = 0
            def cancel(inner, root, admission):
                inner.cancel_entries += 1
                entered.set()
                self.assertTrue(release.wait(3))
                return super().cancel(root, admission)
        backend = Blocking(complete=False)
        view = execution.submit(self.root, self.caller, self.request, backend=backend)
        def cancel():
            try:
                return execution.cancel(self.root, self.caller, view['execution_id'], backend=backend)
            except (execution.ExecutionError, store.RegistryError) as error:
                return {'error': error.code}
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(cancel)
            self.assertTrue(entered.wait(2))
            second = pool.submit(cancel)
            returned_before_release = True
            try:
                second_result = second.result(timeout=.5)
            except FutureTimeout:
                returned_before_release = False
            finally:
                release.set()
            first_result = first.result(timeout=2)
            second_result = second.result(timeout=2)
        self.assertEqual(backend.cancel_entries, 1)
        self.assertEqual(backend.cancels, 1)
        self.assertTrue(returned_before_release)
        self.assertEqual(first_result['execution_status'], 'cancel_requested')
        self.assertNotEqual(second_result.get('execution_status'), 'cancelled')
        repeated = execution.cancel(self.root, self.caller, view['execution_id'], backend=backend)
        self.assertEqual(repeated['execution_status'], 'cancel_requested')
        self.assertEqual(backend.cancels, 1)

    def test_lost_cancel_response_is_unknown_and_never_resent(self):
        class LostResponse(CountingBackend):
            def cancel(inner, root, admission):
                super().cancel(root, admission)
                raise OSError('response lost')
        backend = LostResponse(complete=False)
        view = execution.submit(self.root, self.caller, self.request, backend=backend)
        result = execution.cancel(self.root, self.caller, view['execution_id'], backend=backend)
        self.assertEqual(result['cancel_claim']['state'], 'unknown')
        self.assertNotEqual(result['execution_status'], 'cancelled')
        execution.cancel(self.root, self.caller, view['execution_id'], backend=backend)
        self.assertEqual(backend.cancels, 1)

    def test_cancel_storage_failure_before_reservation_has_zero_adapter_calls(self):
        backend = CountingBackend(complete=False)
        view = execution.submit(self.root, self.caller, self.request, backend=backend)
        with patch.object(store.state, 'durable_bytes', side_effect=OSError('cancel intent save failed')):
            with self.assertRaises(store.RegistryError):
                execution.cancel(self.root, self.caller, view['execution_id'], backend=backend)
        self.assertEqual(backend.cancels, 0)

    def test_late_success_before_cancel_consumption_wins_without_cancel_effect(self):
        entered, release = threading.Event(), threading.Event()
        class Blocking(CountingBackend):
            def cancel(inner, root, admission):
                entered.set()
                self.assertTrue(release.wait(3))
                return super().cancel(root, admission)
        backend = Blocking(complete=False)
        view = execution.submit(self.root, self.caller, self.request, backend=backend)
        admission = backend.admissions[0]
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(execution.cancel, self.root, self.caller, view['execution_id'], backend=backend)
            self.assertTrue(entered.wait(2))
            current = store.load_registry(self.root)['records'][view['execution_id']]
            completed = execution.record_event(self.root, admission.token, view['execution_id'], current['revision'],
                                                admission.execution_generation, 'late-success',
                                                {'execution_status': 'succeeded', 'terminal_reason': 'exit_zero'})
            terminal = store.load_registry(self.root)['records'][view['execution_id']]
            release.set()
            try:
                response = pending.result(timeout=2)
            except execution.ExecutionError:
                response = execution.get(self.root, self.caller, view['execution_id'])
        self.assertEqual(backend.cancels, 0)
        self.assertEqual(response['execution_status'], 'succeeded')
        self.assertEqual(store.load_registry(self.root)['records'][view['execution_id']], terminal)
        self.assertFalse(completed['evidence_authority'])

    def test_success_after_accepted_cancel_keeps_the_backend_terminal_result(self):
        backend = CountingBackend(complete=False)
        view = execution.submit(self.root, self.caller, self.request, backend=backend)
        accepted = execution.cancel(self.root, self.caller, view['execution_id'], backend=backend)
        admission = backend.admissions[0]
        result = execution.record_event(self.root, admission.token, view['execution_id'], accepted['revision'],
                                        admission.execution_generation, 'finished-before-stop',
                                        {'execution_status': 'succeeded', 'terminal_reason': 'exit_zero'})
        self.assertEqual(result['execution_status'], 'succeeded')
        self.assertEqual(backend.cancels, 1)
        self.assertNotEqual(result['execution_status'], 'cancelled')


    def test_handoff_after_consumption_is_not_a_physical_fencing_guarantee(self):
        class InFlight(CountingBackend):
            def dispatch(inner, root, admission, request):
                admission.consume(root, request)
                self.handoff()
                inner.calls += 1
                return None
        backend = InFlight(complete=False)
        result = execution.submit(self.root, self.caller, self.request, backend=backend)
        self.assertEqual(backend.calls, 1)
        self.assertEqual(result['dispatch_claim'], 'consumed')
        self.assertFalse(result['evidence_authority'])
        self.assertEqual(state.canonical_route(self.root, self.route['route_id'])['authority_epoch'], 1)
        # Counted cooperative work was admitted before revocation. No physical process/external fence is qualified.

    def test_consumed_dispatch_token_cannot_be_used_twice(self):
        class Capture(CountingBackend):
            def dispatch(inner, root, admission, request):
                inner.request = request
                return super().dispatch(root, admission, request)
        backend = Capture(complete=False)
        execution.submit(self.root, self.caller, self.request, backend=backend)
        with self.assertRaises(execution.ExecutionError):
            backend.admissions[0].consume(self.root, backend.request)
        payload = backend.request.arguments
        payload['nested']['values'].append('adapter-owned-mutation')
        self.assertEqual(backend.request.arguments, {'nested': {'values': ['original-private-value']}})
        self.assertEqual(backend.calls, 1)

    def test_marker_without_actual_consumption_cannot_report_success(self):
        class MissingConsumption(CountingBackend):
            def dispatch(inner, root, admission, request):
                return {'execution_status': 'succeeded'}
        backend = MissingConsumption()
        with self.assertRaises(execution.ExecutionError) as caught:
            execution.submit(self.root, self.caller, self.request, backend=backend)
        self.assertEqual(caught.exception.code, 'unsupported_admission_fence')
        self.assertEqual(backend.calls, 0)
        record = next(iter(store.load_registry(self.root)['records'].values()))
        self.assertEqual(record['execution_status'], 'running')
        self.assertEqual(record['dispatch_claim'], 'pending')

    def test_deadline_reached_inside_adapter_before_consumption_has_zero_work(self):
        clock = FakeClock()
        class Expired(CountingBackend):
            def dispatch(inner, root, admission, request):
                clock.seconds += 61
                return super().dispatch(root, admission, request)
        backend = Expired(complete=False)
        result = execution.submit(self.root, self.caller, self.request, backend=backend, clock=clock)
        self.assertEqual(backend.calls, 0)
        self.assertFalse(result['evidence_authority'])
        self.assertNotEqual(result['execution_status'], 'succeeded')

    def test_cancel_reservation_acknowledgment_failure_never_reissues_adapter_call(self):
        backend = CountingBackend(complete=False)
        view = execution.submit(self.root, self.caller, self.request, backend=backend)
        real = store.state.durable_bytes
        def fail_ack(root, path, raw):
            result = real(root, path, raw)
            if path.name == 'registry.json':
                raise OSError('reservation saved but acknowledgment uncertain')
            return result
        with patch.object(store.state, 'durable_bytes', side_effect=fail_ack):
            with self.assertRaises(store.RegistryError):
                execution.cancel(self.root, self.caller, view['execution_id'], backend=backend)
        result = execution.cancel(self.root, self.caller, view['execution_id'], backend=backend)
        self.assertEqual(backend.cancels, 0)
        self.assertEqual(result['cancel_claim']['state'], 'reserved')
        self.assertNotEqual(result['execution_status'], 'cancel_requested')

    def test_cancel_receipt_failure_after_accepted_effect_remains_unknown(self):
        backend = CountingBackend(complete=False)
        view = execution.submit(self.root, self.caller, self.request, backend=backend)
        real = store.state.durable_bytes
        def fail_receipt(root, path, raw):
            import json
            if path.name == 'registry.json' and any(item['execution_status'] == 'cancel_requested'
                    for item in json.loads(raw)['records'].values()):
                raise OSError('accepted cancellation receipt was not saved')
            return real(root, path, raw)
        with patch.object(store.state, 'durable_bytes', side_effect=fail_receipt):
            result = execution.cancel(self.root, self.caller, view['execution_id'], backend=backend)
        self.assertEqual(backend.cancels, 1)
        self.assertEqual(result['cancel_claim']['state'], 'unknown')
        self.assertEqual(result['cleanup_status'], 'unconfirmed')
        self.assertEqual(result['operation_outcome'], 'unknown')
        execution.cancel(self.root, self.caller, view['execution_id'], backend=backend)
        self.assertEqual(backend.cancels, 1)

    def test_cancel_marker_without_consumption_is_refused(self):
        class MissingCancelConsumption(CountingBackend):
            def cancel(inner, root, admission):
                return True
        backend = MissingCancelConsumption(complete=False)
        view = execution.submit(self.root, self.caller, self.request, backend=backend)
        with self.assertRaises(execution.ExecutionError) as caught:
            execution.cancel(self.root, self.caller, view['execution_id'], backend=backend)
        self.assertEqual(caught.exception.code, 'unsupported_admission_fence')
        record = store.load_registry(self.root)['records'][view['execution_id']]
        self.assertEqual(record['execution_status'], 'running')
        self.assertEqual(record['cancel_claim']['state'], 'reserved')

    def test_owner_is_checked_after_clock_read_inside_dispatch_admission(self):
        class Clock(FakeClock):
            reads = 0
            def monotonic(inner):
                inner.reads += 1
                if inner.reads == 3:
                    self.handoff()
                return super().monotonic()
        class Entries(CountingBackend):
            entries = 0
            def dispatch(inner, *args):
                inner.entries += 1
                return super().dispatch(*args)
        backend = Entries(complete=False)
        with self.assertRaises(execution.ExecutionError):
            execution.submit(self.root, self.caller, self.request, backend=backend, clock=Clock())
        self.assertEqual(backend.entries, 0)
        self.assertEqual(backend.calls, 0)
