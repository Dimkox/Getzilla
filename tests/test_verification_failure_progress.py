"""Source-bound progress rendering and failure-prefix certainty."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import verification_progress_evidence as verification_module  # noqa: E402


class Low336FailureRenderTests(unittest.TestCase):
    def progress(self):
        import hashlib
        name = 'tests/test_public.py::Probe::test_one'
        return {'status': 'unavailable', 'selected_workers': 1, 'observed_workers': 0, 'omitted_workers': 1, 'slots': [],
                'failure_events': {'version': 1, 'status': 'observed', 'workers': [
                    {'worker': 0, 'sequence': 1, 'overflow': False, 'dropped': False, 'partial_tail': False,
                     'events': [{'ordinal': 1, 'phase': 'call', 'path': 'tests/test_public.py',
                                 'key': hashlib.sha256(name.encode()).hexdigest()}]}]}}

    def test_render_rederives_source_identity_and_preserves_unknown_partial_semantics(self):
        progress = self.progress()
        trusted = {'tests/test_public.py': (200, {'Probe::test_one'})}
        with patch.object(verification_module, '_trusted_progress_metadata', return_value=trusted) as metadata:
            result = verification_module._core_progress_details(Path('/public-inert-root'), progress)
        self.assertIn('failure_events', result)
        events = result['failure_events']
        self.assertEqual(events['events'][0]['identity'], 'tests/test_public.py::Probe::test_one')
        self.assertTrue(events['prefix_only'])
        self.assertEqual(metadata.call_count, 1)
        self.assertNotIn('failed_tests', events)
        self.assertNotIn('completed_tests', events)
        progress['failure_events']['workers'][0]['events'][0]['path'] = 'tests/UNTRACKED_CANARY.py'
        with patch.object(verification_module, '_trusted_progress_metadata', return_value={}):
            result = verification_module._core_progress_details(Path('/public-inert-root'), progress)
        self.assertIsNone(result['failure_events']['events'][0]['identity'])
        self.assertNotIn('UNTRACKED_CANARY', json.dumps(result))
        self.assertEqual(result['failure_events']['status'], 'partial')

    def test_closed_render_shape_and_shared_byte_bound_never_echo_values(self):
        import copy
        progress = self.progress()
        progress['failure_events']['workers'][0]['payload'] = 'PAYLOAD_CANARY'
        with patch.object(verification_module, '_trusted_progress_metadata', return_value={}):
            result = verification_module._core_progress_details(Path('/public-inert-root'), progress)
        self.assertIn('failure_events', result)
        self.assertNotIn('PAYLOAD_CANARY', json.dumps(result))
        self.assertEqual(result['failure_events']['status'], 'unavailable')
        progress = self.progress()
        progress['selected_workers'] = 64
        progress['failure_events']['workers'] = []
        nodes = set()
        for worker in range(64):
            item = copy.deepcopy(self.progress()['failure_events']['workers'][0])
            item['worker'] = worker
            item['sequence'] = 4
            item['events'] = []
            for ordinal in range(1, 5):
                node = 'Class' + str(worker) + '::test_' + str(ordinal) + '_' + 'x' * 110
                nodes.add(node)
                identity = 'tests/test_public.py::' + node
                item['events'].append({'ordinal': ordinal, 'phase': 'call', 'path': 'tests/test_public.py',
                    'key': hashlib.sha256(identity.encode()).hexdigest()})
            progress['failure_events']['workers'].append(item)
        with patch.object(verification_module, '_trusted_progress_metadata', return_value={'tests/test_public.py': (200, nodes)}):
            result = verification_module._core_progress_details(Path('/public-inert-root'), progress)
        self.assertLessEqual(len(json.dumps(result).encode()), 16000)
        self.assertLessEqual(len(json.dumps(result['failure_events']).encode()), 8192)
        self.assertTrue(result['failure_events']['render_truncated'])
        self.assertLess(len(result['failure_events']['events']), 256)

    def _actual_failure_prefix(self, *, workers=1, torn=False, facts=False):
        from types import SimpleNamespace
        from getzilla import pytest_progress
        temporary = tempfile.TemporaryDirectory(prefix='public-certainty-')
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name) / 'progress'
        directory.mkdir(mode=0o700)
        nodes = set()
        nonce = 'c' * 32
        for worker in range(workers):
            writer = pytest_progress._WorkerProgress(directory, nonce, worker)
            self.addCleanup(writer.pytest_unconfigure, None)
            if facts and worker == 0:
                writer.pytest_runtest_logreport(SimpleNamespace(failed=True, when='call', nodeid='/unmapped-public'))
            count = 4 if workers > 1 or torn or facts else 1
            for ordinal in range(count):
                node = 'C' + str(worker) + 'X' * 100 + '::test_' + str(ordinal) + '_' + 'y' * 100
                nodes.add(node)
                report = SimpleNamespace(failed=True, when='call', nodeid='tests/test_public.py::' + node)
                writer.pytest_runtest_logreport(report)
            if torn and worker == 0:
                original = os.write
                with patch.object(pytest_progress.os, 'write', side_effect=lambda fd, content: original(fd, content[:12])):
                    writer.pytest_runtest_logreport(report)
            elif facts and worker == 0:
                writer.pytest_runtest_logreport(report)
        return pytest_progress.read_progress(directory, nonce, workers), {'tests/test_public.py': (500, nodes)}

    def _render_failure_prefix(self, progress, trusted):
        with patch.object(verification_module, '_trusted_progress_metadata', return_value=trusted):
            result = verification_module._core_progress_details(Path('/public-inert-root'), progress)
        return result['failure_events']

    def test_actual_torn_overflow_fact_keeps_unproved_losses_unknown(self):
        progress, trusted = self._actual_failure_prefix(torn=True)
        row = progress['failure_events']['workers'][0]
        self.assertEqual(len(row['events']), 4)
        self.assertTrue(row['partial_tail'])
        public = self._render_failure_prefix(progress, trusted)
        self.assertEqual(public['status'], 'partial')
        self.assertEqual(len(public['events']), 4)
        self.assertTrue(public['partial_tail'])
        self.assertIsNone(public['overflow'])
        self.assertIsNone(public['dropped'])

    def test_actual_prefix_without_source_proof_keeps_all_negative_losses_unknown(self):
        progress, _trusted = self._actual_failure_prefix()
        public = self._render_failure_prefix(progress, {})
        self.assertEqual(public['status'], 'partial')
        self.assertIsNone(public['events'][0]['identity'])
        for name in ('overflow', 'dropped', 'partial_tail'):
            with self.subTest(flag=name):
                self.assertIsNone(public[name])

    def test_actual_source_bound_prefix_render_cap_invalidates_negative_losses(self):
        progress, trusted = self._actual_failure_prefix(workers=16)
        self.assertEqual(progress['failure_events']['status'], 'observed')
        public = self._render_failure_prefix(progress, trusted)
        self.assertTrue(public['render_truncated'])
        self.assertEqual(public['status'], 'partial')
        self.assertLessEqual(len(json.dumps(public).encode()), 8192)
        for name in ('overflow', 'dropped', 'partial_tail'):
            with self.subTest(flag=name):
                self.assertIsNone(public[name])

    def test_complete_negatives_and_proven_true_facts_remain_distinct(self):
        complete, trusted = self._actual_failure_prefix()
        public = self._render_failure_prefix(complete, trusted)
        self.assertEqual(public['status'], 'observed')
        for name in ('overflow', 'dropped', 'partial_tail'):
            self.assertIs(public[name], False)
        lossy, _trusted = self._actual_failure_prefix(facts=True)
        public = self._render_failure_prefix(lossy, {})
        self.assertIs(public['overflow'], True)
        self.assertIs(public['dropped'], True)
        self.assertIsNone(public['partial_tail'])
        self.assertEqual(public['status'], 'partial')
