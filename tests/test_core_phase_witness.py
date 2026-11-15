"""Pure phase protocol controls; no pytest workload or child process is launched."""
from __future__ import annotations

import ast
import copy
import inspect
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from getzilla import pytest_progress as progress

NONCE = 'a' * 32


class CorePhaseWitnessTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='phase-witness-pure-')
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        os.chmod(self.directory, 0o700)
        self.writers = []
        self.addCleanup(self.close_writers)

    def close_writers(self):
        for writer in self.writers:
            writer.pytest_unconfigure(None)

    def configure(self, worker='gw0', phases=True):
        options = {'getzilla_progress_dir': str(self.directory), 'getzilla_progress_nonce': NONCE,
                   'getzilla_progress_workers': '1'}
        if phases is not None:
            options['getzilla_progress_phases'] = phases
        manager = SimpleNamespace(register=lambda writer, name: self.writers.append(writer))
        config = SimpleNamespace(getoption=options.get, pluginmanager=manager)
        if worker is not None:
            config.workerinput = {'workerid': worker}
        progress.pytest_configure(config)
        return self.writers[-1] if worker is not None else None

    def test_legacy_default_has_only_slots_and_exact_progress_keys(self):
        self.configure(None, phases=None)
        writer = self.configure(phases=None)
        self.finish_collection(writer)
        self.assertEqual(list(self.directory.iterdir()), [])
        writer.pytest_runtest_logstart('tests/test_public.py::Case::test_one[PRIVATE]', None)
        self.assertEqual({p.name for p in self.directory.iterdir()}, {'worker-0.json'})
        report = progress.read_progress(self.directory, NONCE, 1)
        self.assertEqual(set(report), {'status', 'selected_workers', 'observed_workers',
                                      'omitted_workers', 'slots', 'failure_events'})
        self.assertEqual(report['observed_workers'], 1)
        self.assertNotIn('PRIVATE', (self.directory / 'worker-0.json').read_text())

    def test_phase_option_defaults_disabled_and_is_explicit_boolean(self):
        options = []
        group = SimpleNamespace(addoption=lambda *args, **kwargs: options.append((args, kwargs)))
        progress.pytest_addoption(SimpleNamespace(getgroup=lambda name: group))
        phase = [row for row in options if row[0] == ('--getzilla-progress-phases',)]
        self.assertEqual(phase, [(('--getzilla-progress-phases',),
                                 {'action': 'store_true', 'default': False})])
        writer = self.configure(phases=False)
        self.finish_collection(writer)
        self.assertEqual(list(self.directory.iterdir()), [])
        options = {'getzilla_progress_dir': str(self.directory),
                   'getzilla_progress_nonce': NONCE, 'getzilla_progress_workers': '1'}
        legacy = SimpleNamespace(getoption=options.__getitem__)
        progress.pytest_configure(legacy)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_native_progress_arguments_enable_phases_without_other_changes(self):
        from getzilla import python_test_runner
        builder = getattr(python_test_runner, '_progress_arguments', None)
        self.assertIsNotNone(builder)
        self.assertEqual(builder(self.directory, NONCE, 1), [
            '-p', 'getzilla.pytest_progress', '--getzilla-progress-dir', str(self.directory),
            '--getzilla-progress-nonce', NONCE, '--getzilla-progress-workers', '1',
            '--getzilla-progress-phases'])
        body = ast.parse(inspect.getsource(python_test_runner.run_core_tests))
        calls = [node for node in ast.walk(body) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == '_progress_arguments']
        self.assertEqual(len(calls), 1)
        self.assertEqual([node.id for node in calls[0].args],
                         ['progress_root', 'progress_nonce', 'workers'])

    def phases(self):
        return progress.read_progress(self.directory, NONCE, 1).get('phase_witness')

    def finish_collection(self, writer):
        callback = getattr(writer, 'pytest_collection_finish', None)
        self.assertIsNotNone(callback, 'configured progress has no collection phase callback')
        callback(None)

    def test_configure_collection_and_first_start_are_closed_monotonic_facts(self):
        with mock.patch.object(time, 'monotonic_ns', side_effect=[100, 160, 220]):
            writer = self.configure()
            self.finish_collection(writer)
            writer.pytest_runtest_logstart('tests/test_public.py::Case::test_one[PRIVATE-PARAM]', None)
            writer.pytest_runtest_logstart('tests/test_public.py::Case::test_two[OTHER]', None)
        phase = self.phases()
        self.assertIsNotNone(phase)
        self.assertEqual(phase['actors'], [{'worker': 0, 'elapsed_ns': {
            'configured': 0, 'collection_finished': 60, 'first_test_start': 120}}])
        content = (self.directory / 'worker-0.phases.jsonl').read_text()
        self.assertNotIn('PRIVATE', content)
        self.assertNotIn('test_public', content)
        self.assertNotIn(str(self.directory), content)

    def test_controller_configuration_and_empty_worker_collection_are_distinct(self):
        with mock.patch.object(time, 'monotonic_ns', side_effect=[10, 30, 50]):
            self.configure(None)
            worker = self.configure()
            self.finish_collection(worker)
        self.assertEqual(self.phases()['actors'], [
            {'worker': None, 'elapsed_ns': {'configured': 0, 'collection_finished': None, 'first_test_start': None}},
            {'worker': 0, 'elapsed_ns': {'configured': 0, 'collection_finished': 20, 'first_test_start': None}},
        ])

    def test_missing_and_stale_publication_stay_unknown(self):
        self.assertIsNone(self.phases())
        self.configure()
        self.assertNotIn('phase_witness', progress.read_progress(self.directory, 'b' * 32, 1))

    def test_backwards_clock_preserves_only_prior_reported_prefix(self):
        with mock.patch.object(time, 'monotonic_ns', side_effect=[100, 90]):
            worker = self.configure()
            self.finish_collection(worker)
        self.assertEqual(self.phases()['actors'][0]['elapsed_ns'], {
            'configured': 0, 'collection_finished': None, 'first_test_start': None})

    def test_torn_oversized_duplicate_and_unknown_fields_refuse(self):
        worker = self.configure()
        path = self.directory / 'worker-0.phases.jsonl'
        original = path.read_bytes()
        worker.pytest_unconfigure(None)
        self.writers.clear()
        for malformed in (original[:-1], b'x' * 1025, original + b'{}\n',
                          original.replace(b'"version":1', b'"version":1,"version":1'),
                          original.replace(b'"kind":', b'"private":"SECRET","kind":')):
            with self.subTest(size=len(malformed)):
                path.write_bytes(malformed)
                self.assertIsNone(self.phases())

    @unittest.skipUnless(os.name == 'posix', 'POSIX file mode contract')
    def test_link_fifo_multilink_and_group_readable_files_are_unknown(self):
        worker = self.configure()
        path = self.directory / 'worker-0.phases.jsonl'
        worker.pytest_unconfigure(None)
        self.writers.clear()
        original = path.read_bytes()
        os.chmod(path, 0o640)
        self.assertIsNone(self.phases())
        os.chmod(path, 0o600)
        alias = self.directory / 'alias'
        os.link(path, alias)
        self.assertIsNone(self.phases())
        alias.unlink()
        path.unlink()
        os.mkfifo(path, 0o600)
        self.assertIsNone(self.phases())
        path.unlink()
        alias.write_bytes(original)
        os.chmod(alias, 0o600)
        path.symlink_to(alias.name)
        self.assertIsNone(self.phases())

    def test_phase_failure_does_not_disable_existing_slot_protocol(self):
        (self.directory / 'worker-0.phases.jsonl').write_text('collision')
        worker = self.configure()
        worker.pytest_runtest_logstart('tests/test_public.py::Case::test_one', None)
        result = progress.read_progress(self.directory, NONCE, 1)
        self.assertEqual(result['slots'][0]['state'], 'active')
        self.assertIsNone(result.get('phase_witness'))
        self.assertEqual((self.directory / 'worker-0.phases.jsonl').read_text(), 'collision')

    def test_existing_result_transport_exports_only_revalidated_phase_facts(self):
        from getzilla.python_test_runner import CoreTestRun, ProcessResult
        from getzilla.verification import _core_progress_details
        self.configure()
        observed = progress.read_progress(self.directory, NONCE, 1)
        run = CoreTestRun(ProcessResult(['inert-public-fixture'], 0), None, 1, {}, {}, observed)
        exported = _core_progress_details(self.directory, run.progress)
        self.assertIn('phase_witness', exported)
        encoded = json.dumps(exported)
        self.assertNotIn(NONCE, encoded)
        self.assertNotIn(str(self.directory), encoded)
        self.assertLessEqual(len(encoded.encode()), 16000)
        self.assertEqual(run.tests.returncode, 0)

    def test_consumer_rejects_untrusted_types_order_duplicates_and_extra_data(self):
        from getzilla.verification import _core_progress_details
        valid = {'version': 1, 'actors': [{'worker': 0, 'elapsed_ns': {
            'configured': 0, 'collection_finished': 5, 'first_test_start': 8}}]}
        mutations = []
        for key, value in [('configured', True), ('collection_finished', -1), ('first_test_start', 4)]:
            changed = copy.deepcopy(valid)
            changed['actors'][0]['elapsed_ns'][key] = value
            mutations.append(changed)
        mutations += [{**valid, 'secret': 'PRIVATE'}, {'version': 1, 'actors': valid['actors'] * 2}]
        for document in mutations:
            with self.subTest(document=document):
                result = _core_progress_details(self.directory, {'selected_workers': 1, 'slots': [],
                    'phase_witness': document})
                self.assertNotEqual(result.get('phase_witness', {}).get('status'), 'reported')
                self.assertNotIn('PRIVATE', json.dumps(result))

    def test_replaced_phase_name_during_open_is_unknown(self):
        worker = self.configure()
        worker.pytest_unconfigure(None)
        self.writers.clear()
        path = self.directory / 'worker-0.phases.jsonl'
        content = path.read_bytes()
        original_open = progress.fsx.open_at
        def replace(handle, name, flags, *args):
            if name == path.name:
                path.rename(self.directory / 'retained-original')
                path.write_bytes(content)
                os.chmod(path, 0o600)
            return original_open(handle, name, flags, *args)
        with mock.patch.object(progress.fsx, 'open_at', side_effect=replace):
            self.assertIsNone(self.phases())

    def test_short_phase_append_never_qualifies_or_disables_slots(self):
        with mock.patch.object(progress.os, 'write', side_effect=lambda fd, content: len(content) - 1):
            worker = self.configure()
        worker.pytest_runtest_logstart('tests/test_public.py::Case::test_one', None)
        observed = progress.read_progress(self.directory, NONCE, 1)
        self.assertNotIn('phase_witness', observed)
        self.assertEqual(observed['slots'][0]['state'], 'active')

    def test_phase_export_preserves_old_facts_when_remaining_budget_is_small(self):
        from getzilla.verification import _core_progress_details
        legacy = {'version': 1, 'events': [{'identity': 'x' * 600} for _ in range(20)]}
        actors = [{'worker': worker, 'elapsed_ns': {
            'configured': 0, 'collection_finished': 1, 'first_test_start': 2}} for worker in range(64)]
        # Inject bounded existing rendered facts, not source/test execution.
        with mock.patch('getzilla.verification_progress_evidence._failure_progress_details', return_value=legacy):
            output = _core_progress_details(self.directory, {'selected_workers': 64, 'slots': [],
                'phase_witness': {'version': 1, 'actors': actors}})
        self.assertNotIn('phase_witness', output)
        self.assertEqual(output['failure_events']['events'], legacy['events'])
        self.assertLessEqual(len(json.dumps(output).encode()), 16000)


if __name__ == '__main__':
    unittest.main()
