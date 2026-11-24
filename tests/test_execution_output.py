"""Bounded historical restore and explicit ACL-checked output reads."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from getzilla import execution, execution_output as output, execution_store as store, state
from tests.execution_contract_support import CountingBackend, FakeClock, owned_route


class OutputTests(unittest.TestCase):
    def test_historical_oversized_multibyte_controls_and_many_jobs_stay_bounded(self):
        for value in ({'stdout': '€' * 300000, 'stderr': '\0' * 200000},
                      {'jobs': [{'stdout': 'job\n' + '€' * 10000} for _ in range(500)]}):
            with self.subTest(kind=list(value)):
                result = output.normalize_output(value)
                self.assertLessEqual(len(result['preview'].encode()), 4096)
                self.assertLessEqual(len(json.dumps(result, ensure_ascii=False).encode()), 32768)
                self.assertTrue(result['truncated'])
                self.assertFalse(result['complete_output'])
                self.assertFalse(result['evidence_authority'])
                self.assertNotIn('\ufffd', result['preview'])
                self.assertFalse(result['counters_known'])
                self.assertIsNone(result['observed_bytes'])

    def test_valid_counters_and_closed_invalid_outputs_are_distinct(self):
        value = {'stdout': 'ok', 'stderr': '', 'observed_bytes': 2, 'retained_bytes': 2, 'dropped_bytes': 0}
        result = output.normalize_output(value)
        self.assertTrue(result['complete_output'])
        self.assertTrue(result['counters_known'])
        self.assertEqual(result['observed_bytes'], 2)
        contradictory = dict(result, observed_bytes=99, retained_bytes=99)
        self.assertEqual(output.normalize_output(contradictory)['status'], 'invalid')
        for field, invalid in (('observed_bytes', True), ('retained_bytes', -1), ('dropped_bytes', float('nan')),
                               ('retained_bytes', '2'), ('observed_bytes', 99)):
            altered = dict(value, **{field: invalid})
            with self.subTest(field=field, invalid=invalid):
                refused = output.normalize_output(altered)
                self.assertEqual(refused['status'], 'invalid')
                self.assertFalse(refused['complete_output'])
                self.assertFalse(refused['counters_known'])
        for malformed in ({'schema_version': 99}, {'stdout': b'\xff'}, {'stdout': '\ud800'}, {'arbitrary': 'secret'}):
            self.assertEqual(output.normalize_output(malformed)['status'], 'invalid')

    def test_credential_suppression_matches_shared_parallel_preview_policy(self):
        from getzilla.parallel import _preview
        raw = b'password=synthetic-sensitive\n'
        self.assertEqual(_preview(raw), output.credential_preview(raw))
        result = output.normalize_output({'stdout': raw.decode()})
        self.assertIn('preview withheld', result['preview'])
        self.assertNotIn('synthetic-sensitive', json.dumps(result))

    def test_get_wait_and_explicit_restore_normalize_old_raw_output_without_reopening_log_strings(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            with patch.dict(os.environ, {'GETZILLA_SESSION_ID': 'owner'}):
                owned_route(root)
                caller = execution.trusted_caller(root)
                clock = FakeClock()
                view = execution.submit(root, caller, execution.SubmitRequest('one', {}, 60),
                                        backend=CountingBackend(), clock=clock)
                raw = store.load_registry(root)
                raw['records'][view['execution_id']]['output'] = {'stdout': '€' * 300000,
                                                                 'stderr': '\0' * 100000,
                                                                 'log': '/must/not/open'}
                path = root / store.REGISTRY_PATH
                path.write_text(json.dumps(raw))
                before = path.read_bytes()
                observed = execution.get(root, caller, view['execution_id'])
                waited = execution.wait(root, caller, view['execution_id'], .1, clock=clock)['execution']
                for result in (observed, waited):
                    self.assertLessEqual(len(json.dumps(result, ensure_ascii=False).encode()), 32768)
                    self.assertLessEqual(len(result['output']['preview'].encode()), 4096)
                    self.assertFalse(result['output']['complete_output'])
                    self.assertNotIn('/must/not/open', json.dumps(result))
                self.assertEqual(path.read_bytes(), before)
                report = execution.restore(root, clock=clock)
                self.assertEqual(report['normalized_outputs'], 1)
                self.assertLess(path.stat().st_size, 32768)
                self.assertEqual(execution.get(root, caller, view['execution_id'])['output'], observed['output'])

    def test_read_output_checks_acl_identity_limits_and_never_follows_historical_host_paths(self):
        with tempfile.TemporaryDirectory() as name, patch.dict(os.environ, {'GETZILLA_SESSION_ID': 'owner'}):
            root = Path(name)
            owned_route(root)
            caller = execution.trusted_caller(root)
            request = execution.SubmitRequest('artifact', {}, 60)
            backend = CountingBackend(complete=False)
            view = execution.submit(root, caller, request, backend=backend)
            log = root / '.getzilla/runtime/par/fixture/001.log'
            log.parent.mkdir(parents=True)
            log.write_bytes(b'actual-output\n')
            reference = output.capture_artifact(root, log.relative_to(root).as_posix())
            admission = backend.admissions[0]
            execution.record_event(root, admission.token, view['execution_id'], view['revision'],
                                   admission.execution_generation, 'output',
                                   {'execution_status': 'succeeded', 'output': {'preview': 'retained preview',
                                    'artifact': reference}})
            read = output.read_output(root, caller, view['execution_id'])
            self.assertTrue(read['artifact_available'])
            self.assertEqual(read['preview'], 'actual-output\n')
            for size in (0, -1, True, 4097, float('nan')):
                with self.subTest(size=size), self.assertRaises(execution.ExecutionError):
                    output.read_output(root, caller, view['execution_id'], max_bytes=size)
            state.bind_session('foreign')
            with self.assertRaises(execution.ExecutionError):
                output.read_output(root, caller, view['execution_id'])
            state.bind_session('owner')
            original = log.read_bytes()
            moved = log.with_name('prior.log')
            log.rename(moved)
            log.write_bytes(original)
            self.assertFalse(output.read_output(root, caller, view['execution_id'])['artifact_available'])
            log.unlink()
            self.assertFalse(output.read_output(root, caller, view['execution_id'])['artifact_available'])
            with self.assertRaises(execution.ExecutionError):
                output.capture_artifact(root, '/etc/passwd')
            with self.assertRaises(execution.ExecutionError):
                output.capture_artifact(root, '.getzilla/runtime/par/fixture/../001.log')

    def test_historical_job_counter_sum_keeps_exact_boundary_and_refuses_overflow(self):
        maximum = 2**63 - 1
        def job(count):
            return {'stdout': 'public', 'observed_bytes': count,
                    'retained_bytes': count, 'dropped_bytes': 0}
        boundary = output.normalize_output({'jobs': [job(maximum - 1), job(1)]})
        self.assertEqual(boundary['status'], 'available')
        self.assertEqual(boundary['observed_bytes'], maximum)
        self.assertTrue(boundary['counters_known'])
        self.assertFalse(boundary['complete_output'])
        overflow = output.normalize_output({'jobs': [job(maximum), job(1)]})
        self.assertEqual(overflow['status'], 'invalid')
        self.assertFalse(overflow['counters_known'])
        self.assertIsNone(overflow['observed_bytes'])
        self.assertEqual(overflow['preview'], '')

    def test_get_wait_output_and_restore_refuse_historical_counter_sum_overflow(self):
        with tempfile.TemporaryDirectory() as name, patch.dict(os.environ, {'GETZILLA_SESSION_ID': 'owner'}):
            root = Path(name)
            owned_route(root)
            caller = execution.trusted_caller(root)
            clock = FakeClock()
            view = execution.submit(root, caller, execution.SubmitRequest('counter-restore', {}, 60),
                                    backend=CountingBackend(), clock=clock)
            registry = store.load_registry(root)
            registry['records'][view['execution_id']]['output'] = {'jobs': [
                {'stdout': 'public', 'observed_bytes': count,
                 'retained_bytes': count, 'dropped_bytes': 0}
                for count in (2**63 - 1, 1)]}
            path = root / store.REGISTRY_PATH
            path.write_text(json.dumps(registry))
            before = path.read_bytes()
            for observed in (execution.get(root, caller, view['execution_id'])['output'],
                             execution.wait(root, caller, view['execution_id'], .1, clock=clock)['execution']['output'],
                             output.read_output(root, caller, view['execution_id'])):
                self.assertEqual(observed['status'], 'invalid')
                self.assertFalse(observed['counters_known'])
                self.assertFalse(observed['complete_output'])
                self.assertFalse(observed['evidence_authority'])
            self.assertEqual(path.read_bytes(), before)
            report = execution.restore(root, clock=clock)
            self.assertEqual(report['normalized_outputs'], 1)
            self.assertEqual(execution.get(root, caller, view['execution_id'])['output']['status'], 'invalid')
            self.assertEqual(execution.restore(root, clock=clock)['normalized_outputs'], 0)

    def tearDown(self):
        state.bind_session(None)


    def test_restore_normalizes_live_historical_output_without_touching_its_deadline(self):
        with tempfile.TemporaryDirectory() as name, patch.dict(os.environ, {'GETZILLA_SESSION_ID': 'owner'}):
            root = Path(name)
            owned_route(root)
            caller = execution.trusted_caller(root)
            clock = FakeClock()
            view = execution.submit(root, caller, execution.SubmitRequest('live-output', {}, 60),
                                    backend=CountingBackend(complete=False), clock=clock)
            registry = store.load_registry(root)
            registry['records'][view['execution_id']]['output'] = {'stdout': 'x' * 200000}
            (root / store.REGISTRY_PATH).write_text(json.dumps(registry))
            report = execution.restore(root, clock=clock)
            self.assertEqual(report['normalized_outputs'], 1)
            self.assertEqual(report['orphaned'], 0)
            self.assertLess((root / store.REGISTRY_PATH).stat().st_size, 32768)
            current = execution.get(root, caller, view['execution_id'])
            self.assertEqual(current['deadline'], view['deadline'])
            self.assertEqual(current['execution_status'], 'running')

    def test_requested_partial_output_marks_view_loss_without_rewriting_capture_counters(self):
        for text, cap in (('hello', 1), ('a€b', 2), ('password=synthetic-sensitive', 1)):
            with self.subTest(text=text, cap=cap), tempfile.TemporaryDirectory() as name, \
                 patch.dict(os.environ, {'GETZILLA_SESSION_ID': 'owner'}):
                root = Path(name)
                owned_route(root)
                caller = execution.trusted_caller(root)
                backend = CountingBackend(complete=False)
                view = execution.submit(root, caller, execution.SubmitRequest('small-view', {}, 60), backend=backend)
                admission = backend.admissions[0]
                size = len(text.encode())
                execution.record_event(root, admission.token, view['execution_id'], view['revision'],
                                       admission.execution_generation, 'output',
                                       {'execution_status': 'succeeded', 'output': {'stdout': text,
                                        'observed_bytes': size, 'retained_bytes': size, 'dropped_bytes': 0}})
                result = output.read_output(root, caller, view['execution_id'], max_bytes=cap)
                self.assertFalse(result['complete_output'])
                self.assertTrue(result['truncated'])
                self.assertTrue(result['preview_truncated'])
                self.assertEqual(result['observed_bytes'], size)
                self.assertEqual(result['retained_bytes'], size)
                self.assertEqual(result['dropped_bytes'], 0)
                self.assertLessEqual(len(result['preview'].encode()), cap)
                self.assertNotIn('\ufffd', result['preview'])
                self.assertNotIn('synthetic-sensitive', str(result))
