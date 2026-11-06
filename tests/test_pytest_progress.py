"""Public generated fixtures for observation-only Core progress diagnostics."""
from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla import python_test_runner as runner, verification

NONCE = 'a' * 32


class ProgressTests(unittest.TestCase):
    def plugin(self):
        self.assertIsNotNone(importlib.util.find_spec('getzilla.pytest_progress'),
                             'Core progress plugin is not implemented')
        return importlib.import_module('getzilla.pytest_progress')

    def directory(self):
        temporary = tempfile.TemporaryDirectory(prefix='public-progress-')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        directory = root / 'progress'
        directory.mkdir(mode=0o700)
        return root, directory

    def writer(self, module, directory, worker='gw0', workers=2):
        registered = []
        options = {'getzilla_progress_dir': str(directory),
                   'getzilla_progress_nonce': NONCE,
                   'getzilla_progress_workers': str(workers)}
        config = SimpleNamespace(getoption=lambda name: options[name],
                                 workerinput={'workerid': worker},
                                 pluginmanager=SimpleNamespace(register=lambda value, name: registered.append(value)))
        module.pytest_configure(config)
        self.assertEqual(len(registered), 1)
        self.addCleanup(registered[0].pytest_unconfigure, None)
        return registered[0]

    def test_slots_strip_parameters_before_persistence_and_track_idle(self):
        module = self.plugin()
        _, directory = self.directory()
        writer = self.writer(module, directory)
        writer.pytest_runtest_logstart('tests/test_public.py::TestPublic::test_case[PARAM_CANARY]', None)
        raw = (directory / 'worker-0.json').read_text()
        self.assertNotIn('PARAM_CANARY', raw)
        self.assertNotIn('TestPublic', raw)
        active = module.read_progress(directory, NONCE, 2)
        self.assertEqual(active['slots'][0]['state'], 'active')
        self.assertEqual(active['slots'][0]['key'], hashlib.sha256(
            b'tests/test_public.py::TestPublic::test_case').hexdigest())
        writer.pytest_runtest_logfinish('tests/test_public.py::TestPublic::test_case[PARAM_CANARY]', None)
        idle = module.read_progress(directory, NONCE, 2)
        self.assertEqual(idle['slots'][0]['state'], 'idle')
        self.assertEqual(idle['slots'][0]['sequence'], 2)
        self.assertEqual({p.name for p in directory.iterdir()}, {'worker-0.json'})

    def test_unknown_node_spellings_never_persist_raw_values(self):
        module = self.plugin()
        _, directory = self.directory()
        writer = self.writer(module, directory)
        for node in ('/PRIVATE_CANARY/test.py::test_x', '../PRIVATE_CANARY.py::test_x',
                     'tests/./PRIVATE_CANARY.py::test_x', 'tests//PRIVATE_CANARY.py::test_x',
                     'tests/test_public.py::test_x\nPRIVATE_CANARY', 'tests/' + 'x' * 300 + '.py::test_x'):
            writer.pytest_runtest_logstart(node, None)
            raw = (directory / 'worker-0.json').read_text()
            self.assertNotIn('PRIVATE_CANARY', raw)
            slot = module.read_progress(directory, NONCE, 2)['slots'][0]
            self.assertIsNone(slot['path'])
            self.assertIsNone(slot['key'])

    def test_missing_corrupt_replayed_and_oversized_slots_are_unavailable(self):
        module = self.plugin()
        _, directory = self.directory()
        writer = self.writer(module, directory)
        self.assertEqual(module.read_progress(directory, NONCE, 2)['status'], 'unavailable')
        writer.pytest_runtest_logstart('tests/test_public.py::test_case', None)
        valid = (directory / 'worker-0.json').read_bytes()
        for content in (b'{', valid.replace(NONCE.encode(), b'b' * 32), valid + b' ' * (2049 - len(valid)),
                        b'[' * 1001 + b']' * 1001,
                        valid.replace(b'"sequence":1', b'"sequence":true')):
            (directory / 'worker-0.json').write_bytes(content)
            try:
                observation = module.read_progress(directory, NONCE, 2)
            except RecursionError:
                self.fail('bounded malformed JSON escaped the diagnostic refusal boundary')
            self.assertEqual(observation['status'], 'unavailable')
        (directory / 'worker-0.json').write_bytes(valid)
        self.assertEqual(module.read_progress(directory, NONCE, 2)['status'], 'partial')

    def test_slot_files_refuse_links_nonregulars_and_write_failure_invalidates_old_slot(self):
        module = self.plugin()
        root, directory = self.directory()
        writer = self.writer(module, directory)
        writer.pytest_runtest_logstart('tests/test_public.py::test_case', None)
        with patch.object(module.fsx, 'replace_at', side_effect=OSError('ERROR_CANARY')):
            writer.pytest_runtest_logfinish('tests/test_public.py::test_case', None)
        self.assertEqual(module.read_progress(directory, NONCE, 2)['status'], 'unavailable')
        self.assertNotIn('ERROR_CANARY', ''.join(p.read_text() for p in directory.iterdir()))
        target = root / 'foreign'
        target.write_text('FOREIGN_CANARY')
        slot = directory / 'worker-0.json'
        slot.symlink_to(target)
        self.assertEqual(module.read_progress(directory, NONCE, 2)['status'], 'unavailable')
        self.assertEqual(target.read_text(), 'FOREIGN_CANARY')
        slot.unlink()
        slot.mkdir()
        self.assertEqual(module.read_progress(directory, NONCE, 2)['status'], 'unavailable')
        slot.rmdir()
        os.link(target, slot)
        self.assertEqual(module.read_progress(directory, NONCE, 2)['status'], 'unavailable')
        slot.unlink()
        if hasattr(os, 'mkfifo'):
            os.mkfifo(slot)
            self.assertEqual(module.read_progress(directory, NONCE, 2)['status'], 'unavailable')

    def test_unsupported_worker_count_does_not_reduce_or_refuse_core_execution(self):
        self.plugin()
        root, _ = self.directory()
        (root / 'tests').mkdir()
        commands = []
        def execute(command, cwd, environment, **kwargs):
            commands.append(command)
            return runner.ProcessResult(command, 0)
        with patch.object(runner, 'select_engine', return_value=(65, 'pytest-xdist')), \
             patch.object(runner, '_tool_versions', return_value={}), \
             patch.object(runner, 'execute', side_effect=execute):
            result = runner.run_core_tests(root, 'fast', 65)
        self.assertEqual(result.workers, 65)
        self.assertEqual(commands[0][commands[0].index('-n') + 1], '65')
        self.assertNotIn('getzilla.pytest_progress', commands[0])
        self.assertEqual(result.progress['status'], 'not_supported')
        self.assertEqual(result.tests.returncode, 0)

    def test_mocked_timeout_keeps_exit_budget_coverage_and_single_invocation(self):
        root, _ = self.directory()
        (root / 'tests').mkdir()
        (root / '.coveragerc').write_text('[run]\nsource = app\n[report]\nfail_under = 100\n')
        calls = []
        directories = []
        def execute(command, cwd, environment, **kwargs):
            calls.append((command, kwargs))
            if '--getzilla-progress-dir' in command:
                progress = Path(command[command.index('--getzilla-progress-dir') + 1])
                directories.append(progress)
                self.assertEqual(progress.parent, Path(environment['TMPDIR']).parent)
                self.assertEqual(progress.parent, Path(environment['COVERAGE_FILE']).parent.parent)
                self.assertNotEqual(progress, Path(environment['TMPDIR']))
            return runner.ProcessResult(command, 124, seconds=900.272, terminal_state='timeout')
        with patch.object(runner, 'select_engine', return_value=(2, 'pytest-xdist')), \
             patch.object(runner, '_tool_versions', return_value={}), \
             patch.object(runner, 'execute', side_effect=execute):
            result = runner.run_core_tests(root, 'pr', 2)
        self.assertIsNotNone(getattr(result, 'progress', None), 'Core result lacks progress observations')
        self.assertEqual(result.tests.returncode, 124)
        self.assertEqual(result.tests.seconds, 900.272)
        self.assertEqual(result.tests.terminal_state, 'timeout')
        self.assertEqual(result.coverage.returncode, 1)
        self.assertEqual(len(calls), 1)
        self.assertEqual(runner.TIMEOUT, 900)
        self.assertEqual(result.progress['status'], 'unavailable')
        self.assertEqual(len(directories), 1)
        self.assertFalse(directories[0].parent.exists())

    def test_actual_two_workers_do_not_invent_idle_for_unused_worker(self):
        module = self.plugin()
        root, directory = self.directory()
        (root / 'tests').mkdir()
        (root / 'tests/test_public.py').write_text(
            'import pytest,time\n@pytest.mark.parametrize("value",[1,2],ids=["PARAM_CANARY_A","PARAM_CANARY_B"])\n'
            'def test_public(value):\n time.sleep(0.05)\n assert value in (1,2)\n')
        command = runner._pytest_command(2, 'loadfile') + [
            '-p', 'getzilla.pytest_progress', '--getzilla-progress-dir', str(directory),
            '--getzilla-progress-nonce', NONCE, '--getzilla-progress-workers', '2', 'tests']
        environment = runner._environment(root, root / '.coverage')
        environment['PYTHONPATH'] += os.pathsep + str(Path(__file__).resolve().parents[1] / '.getzilla')
        result = runner.execute(command, root, environment, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        report = module.read_progress(directory, NONCE, 2)
        # loadfile deliberately leaves one worker without an event. Unknown is
        # required there; do not invent idle for an unused worker.
        self.assertEqual(report['status'], 'partial')
        self.assertEqual(report['observed_workers'], 1)
        self.assertEqual(report['slots'][0]['state'], 'idle')
        self.assertNotIn('PARAM_CANARY', ''.join(p.read_text() for p in directory.iterdir()))

    def test_actual_two_workers_publish_distinct_fixed_slots(self):
        module = self.plugin()
        root, directory = self.directory()
        (root / 'tests').mkdir()
        for name in ('one', 'two'):
            (root / f'tests/test_{name}.py').write_text(
                'import time\ndef test_public():\n time.sleep(0.05)\n')
        command = runner._pytest_command(2, 'loadfile') + [
            '-p', 'getzilla.pytest_progress', '--getzilla-progress-dir', str(directory),
            '--getzilla-progress-nonce', NONCE, '--getzilla-progress-workers', '2', 'tests']
        environment = runner._environment(root, root / '.coverage')
        environment['PYTHONPATH'] += os.pathsep + str(Path(__file__).resolve().parents[1] / '.getzilla')
        result = runner.execute(command, root, environment, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        report = module.read_progress(directory, NONCE, 2)
        self.assertEqual(report['status'], 'observed')
        self.assertEqual({slot['worker'] for slot in report['slots']}, {0, 1})
        self.assertEqual([slot['state'] for slot in report['slots']], ['idle', 'idle'])

    def test_actual_timeout_retains_unmatched_start_and_collection_error_is_unknown(self):
        module = self.plugin()
        root, directory = self.directory()
        (root / 'tests').mkdir()
        path = root / 'tests/test_public.py'
        path.write_text('import time\ndef test_public():\n time.sleep(30)\n')
        command = runner._pytest_command(1, 'loadfile') + [
            '-p', 'getzilla.pytest_progress', '--getzilla-progress-dir', str(directory),
            '--getzilla-progress-nonce', NONCE, '--getzilla-progress-workers', '1', 'tests']
        environment = runner._environment(root, root / '.coverage')
        environment['PYTHONPATH'] += os.pathsep + str(Path(__file__).resolve().parents[1] / '.getzilla')
        result = runner.execute(command, root, environment, timeout=3)
        self.assertEqual(result.returncode, 124)
        self.assertEqual(result.terminal_state, 'timeout')
        report = module.read_progress(directory, NONCE, 1)
        self.assertEqual(report['slots'][0]['state'], 'active')
        (directory / 'worker-0.json').unlink()
        path.write_text('def broken(:\n COLLECTION_CANARY\n')
        result = runner.execute(command, root, environment, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(module.read_progress(directory, NONCE, 1)['status'], 'unavailable')
        self.assertEqual(list(directory.iterdir()), [])

    def test_progress_directory_io_failure_does_not_prevent_backend(self):
        self.plugin()
        root, _ = self.directory()
        calls = []
        real_mkdir = Path.mkdir
        def mkdir(path, *args, **kwargs):
            if path.name == 'progress':
                raise OSError('IO_CANARY')
            return real_mkdir(path, *args, **kwargs)
        def execute(command, cwd, environment, **kwargs):
            calls.append(command)
            return runner.ProcessResult(command, 0)
        with patch.object(runner, 'select_engine', return_value=(2, 'pytest-xdist')), \
             patch.object(runner, '_tool_versions', return_value={}), \
             patch.object(Path, 'mkdir', new=mkdir), \
             patch.object(runner, 'execute', side_effect=execute):
            try:
                result = runner.run_core_tests(root, 'fast', 2)
            except OSError:
                self.fail('diagnostic mkdir failure prevented the actual backend')
        self.assertEqual(result.tests.returncode, 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(result.progress['status'], 'unavailable')
        self.assertNotIn('IO_CANARY', json.dumps(result.progress))

    def test_64_slots_stay_bounded_and_malformed_worker_has_no_writer(self):
        module = self.plugin()
        _, directory = self.directory()
        for ordinal in range(64):
            writer = self.writer(module, directory, f'gw{ordinal}', 64)
            writer.pytest_runtest_logstart('tests/test_public.py::test_case', None)
        report = module.read_progress(directory, NONCE, 64)
        self.assertEqual(report['observed_workers'], 64)
        self.assertEqual(len(list(directory.iterdir())), 64)
        self.assertLessEqual(sum(path.stat().st_size for path in directory.iterdir()), 64 * 2048)
        self.assertEqual(module.read_progress(directory, NONCE, 65)['status'], 'not_supported')
        registered = []
        values = {'getzilla_progress_dir': str(directory), 'getzilla_progress_nonce': NONCE,
                  'getzilla_progress_workers': '64'}
        module.pytest_configure(SimpleNamespace(getoption=lambda name: values[name],
                               workerinput={'workerid': 'gw64'},
                               pluginmanager=SimpleNamespace(register=lambda *args: registered.append(args))))
        self.assertEqual(registered, [])

    def test_named_unittest_and_trust_paths_do_not_load_plugin(self):
        self.plugin()
        root, _ = self.directory()
        (root / 'tests').mkdir()
        (root / 'tests/__init__.py').write_text('')
        (root / 'tests/test_one.py').write_text(
            'import unittest\nclass Public(unittest.TestCase):\n def test_one(self):\n  self.assertEqual(1,1)\n')
        named = runner.run_named_tests(root, ['tests.test_one.Public.test_one'])
        self.assertEqual(named.returncode, 0, named.stderr)
        serial = runner.run_core_tests(root, 'fast', 0)
        self.assertEqual(serial.tests.returncode, 0, serial.tests.stderr)
        self.assertIsNone(serial.progress)
        self.assertNotIn('getzilla.pytest_progress', named.command)
        trust = root / 'trust-ci/tests'
        trust.mkdir(parents=True)
        with patch.object(runner, '_tool_versions', return_value={}), \
             patch.object(runner, 'select_engine', return_value=(2, 'pytest-xdist')), \
             patch.object(runner, 'execute', side_effect=lambda command, *a, **k: runner.ProcessResult(command, 0)):
            result = runner.run_trust_tests(root, 2)
        self.assertNotIn('getzilla.pytest_progress', result.command)
        self.assertNotIn('--getzilla-progress-dir', result.command)

    def test_progress_source_lookup_deadline_and_aggregate_limits_are_diagnostic(self):
        self.plugin()
        self.assertTrue(hasattr(verification, '_trusted_progress_metadata'))
        root, _ = self.directory()
        paths = [f'tests/test_{i}.py' for i in range(60)]
        reads = []
        def git(command, **kwargs):
            if command[1:3] == ['rev-parse', 'HEAD']:
                value = 'a' * 40
            elif command[1] == 'ls-files':
                self.assertLessEqual(len(command[5:]), 50)
                value = '\0'.join(paths)
            elif command[1] == 'cat-file':
                value = '990000'
            else:
                reads.append(command)
                value = '# ' + 'x' * 989970 + '\ndef test_public():\n pass\n'
            return subprocess.CompletedProcess(command, 0, value, '')
        with patch.object(verification, 'run', side_effect=git):
            result = verification._trusted_progress_metadata(root, paths)
        self.assertEqual(len(reads), 8)
        self.assertEqual(len(result), 8)
        with patch.object(verification, 'run', side_effect=AssertionError('deadline must precede Git')), \
             patch.object(verification.time, 'monotonic', side_effect=[0.0, 3.0]):
            self.assertEqual(verification._trusted_progress_metadata(root, paths), {})

    def test_progress_deadline_also_bounds_identity_resolution(self):
        self.plugin()
        root, _ = self.directory()
        progress = {'status': 'observed', 'selected_workers': 1, 'slots': [
            {'worker': 0, 'state': 'active', 'path': 'tests/test_public.py',
             'key': hashlib.sha256(b'tests/test_public.py::test_known').hexdigest()}]}
        with patch.object(verification, '_trusted_progress_metadata',
                          return_value={'tests/test_public.py': (2, {'test_known'})}), \
             patch.object(verification.time, 'monotonic', side_effect=[0.0, 3.0, 3.0, 3.0]):
            result = verification._core_progress_details(root, progress)
        self.assertIsNone(result['slots'][0]['identity'])
        self.assertEqual(result['status'], 'partial')

    def test_actual_managed_core_loads_running_engine_plugin_for_public_consumer(self):
        self.plugin()
        root, _ = self.directory()
        (root / 'tests').mkdir()
        (root / 'tests/test_public.py').write_text('def test_public():\n assert 1 == 1\n')
        with patch.dict(os.environ, {'PYTHONPATH': ''}), \
             patch.object(runner, '_tool_versions', return_value={}):
            result = runner.run_core_tests(root, 'fast', 1)
        self.assertEqual(result.tests.returncode, 0, result.tests.stderr[-2000:])
        self.assertEqual(result.progress['status'], 'observed')
        self.assertEqual(result.progress['slots'][0]['state'], 'idle')

    def test_core_consumer_reports_last_observation_without_private_options_or_verdict_change(self):
        self.plugin()
        root, _ = self.directory()
        (root / 'tests').mkdir()
        command = ['python', '-m', 'pytest', '--getzilla-progress-dir', '/PRIVATE_PATH_CANARY',
                   '--getzilla-progress-nonce', 'NONCE_CANARY', '--getzilla-progress-workers', '2']
        process = runner.ProcessResult(command, 124, seconds=900.272, terminal_state='timeout')
        core = runner.CoreTestRun(process, runner.ProcessResult(['coverage'], 1), 2,
                                  {'engine': 'pytest-xdist'}, {},
                                  {'status': 'unavailable', 'selected_workers': 2, 'slots': []})
        with patch.object(verification, 'core_worker_selection', return_value=runner.WorkerSelection(2, 'configuration')), \
             patch.object(verification, 'run_core_tests', return_value=core), \
             patch.object(verification, 'execute', side_effect=AssertionError('backend forbidden')), \
             patch.object(runner, 'execute', side_effect=AssertionError('backend forbidden')):
            checks = verification._core_python_checks(root, 'pr', False, keep_going=True)
        self.assertEqual([check.status for check in checks], ['fail', 'fail'])
        self.assertIn('exit=124', checks[0].summary)
        self.assertIn('test_timeout=900s', checks[0].summary)
        self.assertEqual(checks[0].details[0]['progress']['observation'], 'LAST_REPORTED_BEFORE_STOP')
        self.assertNotIn('CANARY', json.dumps(checks[0].command))
        self.assertIs(process.command, command)
        self.assertEqual(process.returncode, 124)

    def test_only_committed_ast_members_can_be_rendered(self):
        self.plugin()
        root, _ = self.directory()
        (root / 'tests').mkdir()
        (root / 'tests/test_public.py').write_text('def test_known():\n pass\n')
        for arguments in (['init', '-q'], ['add', 'tests/test_public.py'],
                          ['-c', 'user.name=PublicFixture', '-c', 'user.email=fixture@example.invalid',
                           'commit', '-qm', 'public fixture']):
            subprocess.run(['git', '-C', str(root), *arguments], check=True, capture_output=True)
        progress = {'status': 'observed', 'selected_workers': 2, 'observed_workers': 2,
                    'omitted_workers': 0, 'slots': [
                        {'worker': 0, 'sequence': 1, 'state': 'active', 'path': 'tests/test_public.py',
                         'key': hashlib.sha256(b'tests/test_public.py::test_known').hexdigest()},
                        {'worker': 1, 'sequence': 2, 'state': 'idle', 'path': 'tests/test_public.py',
                         'key': hashlib.sha256(b'tests/test_public.py::test_uncommitted_CANARY').hexdigest()}]}
        self.assertTrue(hasattr(verification, '_core_progress_details'), 'No committed-source progress validator')
        details = verification._core_progress_details(root, progress)
        self.assertEqual(details['observation'], 'LAST_REPORTED_BEFORE_STOP')
        self.assertEqual(details['slots'][0]['identity'], 'tests/test_public.py::test_known')
        self.assertIsNone(details['slots'][1]['identity'])
        self.assertNotIn('CANARY', json.dumps(details))
        self.assertLessEqual(len(json.dumps(details).encode()), 16384)


if __name__ == '__main__':
    unittest.main()
