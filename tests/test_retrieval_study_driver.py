"""Inert orchestration controls; no fixture can issue production authority."""
from contextlib import contextmanager
from types import SimpleNamespace
import time
import unittest
from unittest.mock import Mock, patch

from getzilla.retrieval import study_driver as driver
from getzilla.retrieval.contracts import digest


class StudyDriverTests(unittest.TestCase):
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
        owner = SimpleNamespace(deadline=time.monotonic() + 10000, operation_ref=object())
        def request(stage, payload, **kwargs):
            calls.append((stage, payload, kwargs))
            return {'rankings': {'exact_symbol': [], 'bm25': []}, 'packing': {}}
        owner._request = request
        def advance(reference):
            advances.append(reference)
            return SimpleNamespace(_owner=owner)
        owner.reference = object()
        owner.backend = SimpleNamespace(advance=advance)
        @contextmanager
        def cuts(*args):
            yield ('first-actual-cut', 'second-actual-cut'), {}
        def primary(dataset, observations, metrics):
            return observations.coverage()
        with patch.object(driver, '_cuts', cuts), \
                patch.object(driver, '_storage'), \
                patch.object(driver, '_persist', side_effect=lambda *args: persisted.append(args[3])), \
                patch.object(driver, '_prepare', return_value=({}, {}, {})) as prepare, \
                patch.object(driver, '_windows', return_value=(
                    {'corpus': 'small', 'id': 's'}, {'corpus': 'large', 'id': 'l'})), \
                patch.object(driver, '_check_rank_reproduction'), \
                patch.object(driver, 'original_function_mapping', return_value=({}, {})), \
                patch.object(driver, '_judgments', return_value={row['task_id']: {} for row in tasks}), \
                patch.object(driver, '_query_metrics', return_value={}), \
                patch.object(driver, '_primary', side_effect=primary):
            result = driver._rank(Mock(), owner, inputs, (), (), {'minilm': {}, 'bge_m3': {}}, Mock())
        self.assertEqual(prepare.call_count, 6)
        self.assertEqual(len(advances), 5)
        self.assertTrue(result['complete'])
        self.assertEqual(result['observed'], 4800)
        self.assertEqual(len([row for row in calls if row[1]['op'] == 'score']), 4800)
        self.assertEqual(len([row for row in calls if row[1]['op'] == 'prepare-index']), 4)
        self.assertEqual(len(persisted), 4806)
        scored = [row for row in calls if row[1]['op'] == 'score']
        self.assertEqual([row[1]['query_id'] for row in scored[:240]],
                         [row['query_id'] for row in queries])
        self.assertTrue(all(row[2]['source_cuts'] == ('first-actual-cut', 'second-actual-cut')
                            for row in scored))


if __name__ == '__main__':
    unittest.main()
