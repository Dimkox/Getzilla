"""Inert orchestration controls; no fixture can issue production authority."""
from contextlib import contextmanager
from types import SimpleNamespace
import time
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from getzilla.retrieval import study_driver as driver
from getzilla.retrieval.contracts import digest
from getzilla.retrieval.study_run_artifacts import RunArtifacts, serialized_payload


class StudyDriverTests(unittest.TestCase):
    def test_bootstrap_marker_and_summary_preflight_before_retaining_bytes(self):
        from getzilla.retrieval import study_supervisor as supervisor
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with RunArtifacts(root, byte_limit=4096) as output:
                held = SimpleNamespace(projection=SimpleNamespace(root=root,
                    operation='inspect_public_artifacts', operation_digest='a' * 64),
                    operation_ref=object(), execution_id='inert', reference=object(),
                    backend=SimpleNamespace(run_artifact_context=output), report_artifact=None,
                    readback_digest=None, pid_scope='docker-daemon', records=[],
                    _native_completed=False, _native_start_dispatched=False)
                with patch('getzilla.retrieval.public_study_storage.study_storage_observation',
                           return_value=SimpleNamespace(logical_bytes=12 * 1024**3 - 1)), \
                        patch('getzilla.retrieval.public_study_operation.admit_public_study_stage'), \
                        patch('getzilla.execution_output.capture_artifact') as capture:
                    with self.assertRaisesRegex(ValueError, 'study_storage_budget_exceeded'):
                        driver._bind_output(held, output)
                    self.assertIs(held.backend.run_artifact_context, output)
                    self.assertEqual(tuple(output._folder.iterdir()), ())
                    with self.assertRaisesRegex(ValueError, 'study_storage_budget_exceeded'):
                        supervisor._capture_inspection_observation(held, ())
                    self.assertEqual(tuple(output._folder.iterdir()), ())
                    capture.assert_not_called()

    def test_shared_storage_preflight_uses_the_exact_retained_utf8_bytes(self):
        payload = {'inert': 'я'}
        raw = serialized_payload(payload)
        owner = SimpleNamespace(current=Mock(), operation_ref=object(), execution_id='inert')
        for room in (len(raw) - 1, len(raw)):
            with self.subTest(room=room), tempfile.TemporaryDirectory() as temporary:
                with RunArtifacts(Path(temporary), byte_limit=4096) as output:
                    def observed(*args):
                        return SimpleNamespace(logical_bytes=12 * 1024**3 - room + output.used)
                    with patch('getzilla.retrieval.public_study_storage.study_storage_observation',
                               side_effect=observed), \
                            patch.object(driver, '_storage', wraps=driver._storage) as storage:
                        if room < len(raw):
                            with self.assertRaisesRegex(ValueError, 'study_storage_budget_exceeded'):
                                driver._persist(Mock(), owner, output, 'tiny.json', payload)
                            self.assertEqual(tuple(output._folder.iterdir()), ())
                        else:
                            item = driver._persist(Mock(), owner, output, 'tiny.json', payload)
                            self.assertEqual((Path(temporary) / item.path).read_bytes(), raw)
                        self.assertEqual(storage.call_args_list[0].kwargs, {'additional': len(raw)})

    def test_storage_scan_consuming_query_deadline_cannot_retain_a_frame(self):
        clock = [0.]
        owner, output = SimpleNamespace(current=Mock()), Mock()
        def storage(*args, **kwargs):
            clock[0] = 2.
        with patch.object(driver.time, 'monotonic', side_effect=lambda: clock[0]), \
                patch.object(driver, '_storage', side_effect=storage):
            with self.assertRaisesRegex(ValueError, 'study_query_deadline'):
                driver._persist(Mock(), owner, output, 'tiny.json', {}, absolute_deadline=2.)
        output.write_bytes.assert_not_called()

    def test_forged_operation_never_reaches_runtime(self):
        with patch('getzilla.retrieval.study_supervisor.owned_study_runtime') as runtime:
            with self.assertRaises(ValueError):
                driver.run_fixed_study({'allow_execution': True})
        runtime.assert_not_called()

    def test_rank_reproduces_witnessed_windows_and_actual_asset_observations(self):
        windows = [{'corpus': 'small', 'id': 'a'}]
        graph = {'graph_sha256': 'a' * 64, 'report_sha256': 'b' * 64}
        tokenizer = {'tokenizer_sha256': 'c' * 64}
        manifest = {'window_manifest': {'ordered_windows_digest': digest(windows)},
                    'models': {'minilm': {'graph_sha256': 'a' * 64,
                    'graph_inspection_digest': 'b' * 64, 'tokenizer_sha256': 'c' * 64}}}
        inputs = SimpleNamespace(inspection_manifest=manifest)
        driver._check_rank_reproduction(inputs, 'minilm', graph, tokenizer, windows)
        for changed in ('window', 'tokenizer', 'graph', 'inspection'):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                driver._check_rank_reproduction(inputs, 'minilm',
                    graph | ({'graph_sha256': 'd' * 64} if changed == 'graph' else
                             {'report_sha256': 'd' * 64} if changed == 'inspection' else {}),
                    tokenizer | ({'tokenizer_sha256': 'd' * 64} if changed == 'tokenizer' else {}),
                    windows + ([{'corpus': 'large', 'id': 'b'}] if changed == 'window' else []))

    def test_all_fixed_query_passes_and_six_fresh_process_steps_without_native(self):
        queries = tuple({'query_id': f'q{i}', 'task_id': f't{i // 3}', 'text': 'inert'}
                        for i in range(240))
        tasks = tuple({'task_id': f't{i}', 'corpus': 'small' if i < 40 else 'large'}
                      for i in range(80))
        inputs = SimpleNamespace(dataset=({}, {'tasks': tasks}, {'queries': queries}, {}))
        calls, advances, persisted = [], [], []
        score_count = [0]
        self.last_calls, self.last_advances = calls, advances
        owner = SimpleNamespace(deadline=time.monotonic() + 10000, operation_ref=object())
        def request(stage, payload, **kwargs):
            calls.append((stage, payload, kwargs))
            if getattr(self, 'fail_query', False) and payload['op'] == 'score':
                raise ValueError('controlled owned query failure')
            score_count[0] += payload['op'] == 'score'
            iteration = (score_count[0] - 1) // 240 % 10
            return {'rankings': {'exact_symbol': [], 'bm25': []}, 'packing': {}, 'iteration': iteration}
        owner._request = request
        def advance(reference):
            advances.append(reference)
            return SimpleNamespace(_owner=owner)
        owner.reference = object()
        owner.backend = SimpleNamespace(advance=advance)
        @contextmanager
        def cuts(*args):
            yield ('first-actual-cut', 'second-actual-cut'), {}
            if getattr(self, 'expire_on_release', False) and calls[-1][1]['op'] == 'score':
                self.test_clock = 3.
        def primary(dataset, observations, metrics):
            self.last_metrics = metrics
            return observations.coverage()
        with patch.object(driver, '_cuts', cuts), \
                patch.object(driver, '_storage'), \
                patch.object(driver, '_persist', side_effect=lambda *args, **kwargs: persisted.append(args[3])), \
                patch.object(driver, '_prepare', return_value=({}, {}, {})) as prepare, \
                patch.object(driver, '_windows', return_value=(
                    {'corpus': 'small', 'id': 's'}, {'corpus': 'large', 'id': 'l'})), \
                patch.object(driver, '_check_rank_reproduction'), \
                patch.object(driver, 'original_function_mapping', return_value=({}, {})), \
                patch.object(driver, '_judgments', return_value={row['task_id']: {} for row in tasks}), \
                patch.object(driver, '_query_metrics', side_effect=lambda result, *args: {'pass': result['iteration']}), \
                patch.object(driver, '_primary', side_effect=primary):
            result = driver._rank(Mock(), owner, inputs, (), (), {'minilm': {}, 'bge_m3': {}}, Mock())
        self.assertEqual(prepare.call_count, 6)
        self.assertEqual(len(advances), 5)
        self.assertTrue(result['complete'])
        self.assertEqual(result['observed'], 4800)
        self.assertEqual(len([row for row in calls if row[1]['op'] == 'score']), 4800)
        self.assertEqual(len([row for row in calls if row[1]['op'] == 'prepare-index']), 4)
        self.assertEqual(len(persisted), 4806)
        self.assertEqual(len(self.last_metrics), 480)
        self.assertTrue(all(value == {'pass': 0} for value in self.last_metrics.values()))
        scored = [row for row in calls if row[1]['op'] == 'score']
        self.assertEqual([row[1]['query_id'] for row in scored[:240]],
                         [row['query_id'] for row in queries])
        self.assertTrue(all(row[2]['source_cuts'] == ('first-actual-cut', 'second-actual-cut')
                            for row in scored))

    def test_owned_query_failure_stops_without_repeat_or_second_model(self):
        self.fail_query = True
        with self.assertRaisesRegex(ValueError, 'controlled owned query failure'):
            self.test_all_fixed_query_passes_and_six_fresh_process_steps_without_native()
        self.assertEqual(len([row for row in self.last_calls if row[1]['op'] == 'score']), 1)
        self.assertEqual(len(self.last_advances), 2)

    def test_cut_final_check_expiry_prevents_timing_acceptance(self):
        self.expire_on_release, self.test_clock = True, 0.
        with patch.object(driver.time, 'monotonic', side_effect=lambda: self.test_clock), \
                patch.object(driver.Observations, 'add') as accept:
            with self.assertRaisesRegex(ValueError, 'study_query_deadline'):
                self.test_all_fixed_query_passes_and_six_fresh_process_steps_without_native()
        accept.assert_not_called()


if __name__ == '__main__':
    unittest.main()
