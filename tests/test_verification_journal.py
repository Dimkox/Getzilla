"""Owned synthetic contracts for durable verification history; no real workload."""
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import io
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla import pytest_progress, verification
from getzilla import verification_journal as journal
from getzilla import util

ROOT = Path(__file__).resolve().parents[1]


class JournalStorageTests(unittest.TestCase):
    def root(self):
        temporary = tempfile.TemporaryDirectory(prefix='owned-history-', dir=ROOT / '.getzilla/runtime')
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def test_rotation_is_visible_bounded_and_retains_loss_counts(self):
        root = self.root()
        run = journal.Run(root, 'a' * 64, 'owned-tests')
        with patch.object(journal, 'SEGMENT_BYTES', 1024):
            for _ in range(40):
                self.assertTrue(run.writer.emit('call', 'start', nodeid='tests/test_owned.py::test_ok[PRIVATE]'))
                self.assertTrue(run.writer.emit('call', 'end', nodeid='tests/test_owned.py::test_ok[PRIVATE]', outcome='pass'))
        self.assertGreater(run.writer.rotated, 0)
        files = list(run.path.glob('controller-*.jsonl'))
        self.assertLessEqual(len(files), 4)
        self.assertLessEqual(sum(p.stat().st_size for p in files), 4096)
        self.assertNotIn(b'PRIVATE', b''.join(p.read_bytes() for p in files))
        run.close()
        self.assertEqual(run.status, 'closed')

    def test_duplicate_writer_and_replaced_stream_are_refused(self):
        run = journal.Run(self.root(), 'b' * 64, 'owned-tests')
        self.addCleanup(run.close)
        with self.assertRaises(OSError):
            journal.Writer(run.path, run.run_id, 'controller', run.nonce)
        path = run.path / run.writer.name
        path.unlink()
        path.write_bytes(b'owned replacement')
        self.assertFalse(run.writer.emit('call', 'start'))
        self.assertEqual(path.read_bytes(), b'owned replacement')

    def test_retention_never_evicts_active_or_unknown_and_closed_runs_rotate(self):
        root = self.root()
        runs = [journal.Run(root, None, 'owned-tests') for _ in range(4)]
        try:
            refused = journal.Run(root, None, 'owned-tests')
            self.assertIsNone(refused.path)
            self.assertEqual(len(list((root / '.getzilla/runtime/verification-history').glob('*/index.json'))), 4)
        finally:
            for run in runs:
                run.close()
        next_run = journal.Run(root, None, 'owned-tests')
        self.assertIsNotNone(next_run.writer)
        next_run.close()
        self.assertFalse(runs[0].path.exists())

    def test_error_text_and_parameter_values_do_not_persist(self):
        run = journal.Run(self.root(), 'a' * 64, 'owned-tests')
        self.assertTrue(run.writer.emit('call', 'end', nodeid='tests/test_owned.py::test_ok[PRIVATE]',
                                       error=ValueError('PRIVATE'), outcome='error'))
        raw = (run.path / run.writer.name).read_text()
        self.assertNotIn('PRIVATE', raw)
        self.assertIn('ValueError', raw)
        self.assertFalse(run.writer.emit('call', 'start', step='PRIVATE\nPAYLOAD'))
        self.assertNotIn('PRIVATE', ''.join(p.read_text() for p in run.path.glob('*') if p.is_file()))
        run.close()

    def test_open_child_span_is_incomplete_and_cannot_be_retention_victim(self):
        run = journal.Run(self.root(), None, 'owned-tests')
        worker = journal.Writer(run.path, run.run_id, 'worker-0', run.nonce)
        worker.emit('call', 'start', nodeid='tests/test_owned.py::test_ok')
        # A lost process has no truthful terminal event. Release only this fixture FD.
        worker.disabled = True
        worker.close()
        run.close()
        self.assertEqual(run.status, 'incomplete')

    def test_declared_missing_worker_cannot_be_reported_closed(self):
        run = journal.Run(self.root(), None, 'owned-tests')
        environment = run.child_environment({}, actor=0)
        self.assertEqual(set(environment), {'GETZILLA_JOURNAL_DIR', 'GETZILLA_JOURNAL_RUN',
                                          'GETZILLA_JOURNAL_NONCE', 'GETZILLA_JOURNAL_ACTOR'})
        run.close()
        self.assertEqual(run.status, 'incomplete')

    def test_safe_skip_classification_and_export_are_explicit_subsets(self):
        run = journal.Run(self.root(), None, 'owned-tests')
        run.writer.emit('call', 'end', nodeid='tests/test_owned.py::test_ok', outcome='skip',
                        skip=journal.skip_classification('PRIVATE'), location=('tests/test_owned.py', 12))
        root = run.root
        run.close()
        entries = dict(journal.export_entries(root))
        self.assertIn('journal/index.json', entries)
        self.assertIn(b'bounded-subset', entries['journal/index.json'])
        self.assertNotIn(b'PRIVATE', b''.join(entries.values()))

    def test_export_refuses_unknown_fields_and_foreign_nonce(self):
        run = journal.Run(self.root(), None, 'owned-tests')
        run.writer.emit('call', 'start', nodeid='tests/test_owned.py::test_ok')
        name = run.writer.name
        run.close()
        path = run.path / name
        row = json.loads(path.read_text().splitlines()[0])
        row['private_payload'] = 'PRIVATE'
        path.write_text(json.dumps(row) + '\n')
        entries = journal.export_entries(run.root)
        self.assertNotIn(b'PRIVATE', b''.join(raw for _, raw in entries))
        self.assertIn(b'unavailable', entries[0][1])
        with self.assertRaises(ValueError):
            journal.Writer(run.path, run.run_id, 'worker-1', 'b' * 32)

    def test_unittest_preserves_actual_lifecycle_skip_and_failure_without_private_text(self):
        events = []
        class Owned(unittest.TestCase):
            def setUp(self):
                events.append('setup')
            def test_pass(self):
                events.append('call')
            def test_skip(self):
                self.skipTest('PRIVATE_REASON')
            def test_failure(self):
                self.fail('PRIVATE_FAILURE')
            def tearDown(self):
                events.append('teardown')
        run = journal.Run(self.root(), None, 'owned-tests')
        worker = journal.Writer(run.path, run.run_id, 'worker-0', run.nonce)
        worker.emit('collection', 'start')
        result = journal.unittest_runner(worker)(stream=io.StringIO()).run(unittest.defaultTestLoader.loadTestsFromTestCase(Owned))
        worker.close()
        raw = b''.join(p.read_bytes() for p in run.path.glob('worker-*.jsonl'))
        records = [json.loads(line) for line in raw.splitlines()]
        self.assertEqual(result.testsRun, 3)
        self.assertEqual(len(result.skipped), 1)
        self.assertEqual(len(result.failures), 1)
        self.assertEqual(len(result.errors), 0)
        self.assertEqual(events.count('setup'), 3)
        self.assertEqual(events.count('teardown'), 3)
        self.assertEqual(events.count('call'), 1)
        self.assertNotIn(b'PRIVATE', raw)
        self.assertTrue(any(r.get('skip_class') == 'redacted-unknown' for r in records))
        self.assertTrue(any(r['stage'] == 'setup' and r['state'] == 'start' for r in records))
        self.assertTrue(any(r['stage'] == 'teardown' and r['state'] == 'end' for r in records))
        run.close()

    def test_abrupt_owned_child_retains_visible_unmatched_start(self):
        run = journal.Run(self.root(), None, 'owned-tests')
        program = run.root / 'child.py'
        program.write_text('import sys,os\nfrom pathlib import Path\nsys.path.insert(0,' + repr(str(ROOT / '.getzilla'))
            + ')\nfrom getzilla.verification_journal import child_writer\n'
            + "sys.addaudithook(lambda event,args: (_ for _ in ()).throw(RuntimeError('network denied')) if event.startswith('socket.') else None)\n"
            + "writer=child_writer()\nassert writer.emit('call','start',nodeid='tests/test_owned.py::test_ok')\nos._exit(3)\n")
        result = subprocess.run([sys.executable, '-I', '-B', str(program)], env=run.child_environment(os.environ),
                                capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 3)
        raw = b''.join(p.read_bytes() for p in run.path.glob('worker-*.jsonl'))
        self.assertIn(b'"state":"start"', raw)
        self.assertNotIn(b'"state":"end"', raw)
        run.close()
        self.assertEqual(run.status, 'incomplete')

    def test_actual_shared_unittest_script_covers_named_serial_and_shard_forms(self):
        root = self.root()
        module = root / 'test_owned.py'
        module.write_text("import unittest,sys\nsys.addaudithook(lambda e,a: (_ for _ in ()).throw(RuntimeError('network denied')) if e.startswith('socket.') else None)\n"
            + 'class Owned(unittest.TestCase):\n    def setUp(self): pass\n    def test_ok(self): pass\n    def tearDown(self): pass\n')
        home = root / 'home'
        home.mkdir(mode=0o700)
        forms = [('named', ['test_owned.Owned.test_ok']), ('serial', ['discover', '-s', str(root)]),
                 ('shard', ['discover', '-s', str(root), '-p', 'test_owned.py'])]
        for label, arguments in forms:
            run = journal.Run(root, None, 'owned-tests')
            environment = run.child_environment({'PATH': os.environ.get('PATH', ''), 'HOME': str(home), 'PYTHONPATH': str(root)})
            result_path = root / (label + '.json')
            result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/getzilla_unittest.py'),
                '--result', str(result_path), '--nonce', 'a' * 32, *arguments], cwd=root,
                env=environment, capture_output=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 0, label)
            self.assertEqual(json.loads(result_path.read_text())['tests_run'], 1)
            records = [json.loads(line) for p in run.path.glob('worker-*.jsonl') for line in p.read_bytes().splitlines()]
            self.assertEqual([(r['stage'], r['state']) for r in records],
                [('collection', 'start'), ('collection', 'end'), ('test', 'start'),
                 ('setup', 'start'), ('setup', 'end'), ('call', 'start'), ('call', 'end'),
                 ('teardown', 'start'), ('teardown', 'end'), ('test', 'end')])
            run.close()
            self.assertEqual(run.status, 'closed')

    def test_actual_pytest_plugin_loads_and_records_owned_current_run_phases(self):
        root = self.root()
        (root / 'tests').mkdir(mode=0o700)
        (root / 'pytest.ini').write_text('[pytest]\n')
        (root / 'tests/test_owned.py').write_text("import sys\nsys.addaudithook(lambda e,a: (_ for _ in ()).throw(RuntimeError('network denied')) if e.startswith('socket.') else None)\ndef test_ok():\n    assert True\n")
        run = journal.Run(root, None, 'owned-tests')
        environment = run.child_environment({'PATH': os.environ.get('PATH', ''), 'HOME': str(root),
            'PYTHONPATH': str(ROOT / '.getzilla'), 'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1'})
        result = subprocess.run([sys.executable, '-B', '-m', 'pytest', '-q', '-p', 'no:cacheprovider',
            '-p', 'getzilla.pytest_progress', '-c', str(root / 'pytest.ini'), '--rootdir', str(root),
            '--noconftest', 'tests/test_owned.py'], cwd=root, env=environment,
            capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0)
        records = [json.loads(line) for p in run.path.glob('worker-*.jsonl') for line in p.read_bytes().splitlines()]
        self.assertTrue(records)
        self.assertTrue(all(r['run_id'] == run.run_id for r in records))
        for stage in ('collection', 'setup', 'call', 'teardown'):
            self.assertTrue(any(r['stage'] == stage and r['state'] == 'start' for r in records), stage)
            self.assertTrue(any(r['stage'] == stage and r['state'] == 'end' for r in records), stage)
        run.close()
        self.assertEqual(run.status, 'closed')


class JournalIntegrationTests(unittest.TestCase):
    def test_unavailable_diagnostic_bootstrap_preserves_primary_dispatch_and_hides_error(self):
        spec = importlib.util.spec_from_file_location('owned_failed_logging_cli', ROOT / 'scripts/getzilla_cli.py')
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)
        error = io.StringIO()
        with patch.object(util, 'find_root', side_effect=NotImplementedError('PRIVATE_ROOT_REASON')), \
                patch.object(cli, 'project_python', return_value='owned-python'), \
                patch.object(cli, 'test_workers', return_value=2), \
                patch.object(cli.subprocess, 'run', side_effect=[subprocess.CompletedProcess([], 0),
                    subprocess.CompletedProcess([], 7)]) as calls, patch.object(sys, 'stderr', error):
            try:
                result = cli.run_tests(['tests/test_owned.py'], require_parallel=True)
            except Exception as exc:
                result = ('escaped-diagnostic-error', type(exc).__name__)
        self.assertEqual(result, 7)
        self.assertEqual(calls.call_count, 2)
        self.assertNotIn('getzilla.pytest_progress', calls.call_args.args[0])
        self.assertIn('unavailable', error.getvalue())
        self.assertNotIn('PRIVATE_ROOT_REASON', error.getvalue())

    def test_saturated_owned_history_does_not_load_unconfigured_plugin(self):
        with tempfile.TemporaryDirectory(prefix='owned-unavailable-cli-', dir=ROOT / '.getzilla/runtime') as temporary:
            root = Path(temporary)
            active = [journal.Run(root, None, 'owned-tests') for _ in range(4)]
            spec = importlib.util.spec_from_file_location('owned_saturated_cli', ROOT / 'scripts/getzilla_cli.py')
            cli = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cli)
            try:
                with patch.object(util, 'find_root', return_value=root), \
                        patch.object(cli, 'project_python', return_value='owned-python'), \
                        patch.object(cli, 'test_workers', return_value=2), \
                        patch.object(cli.subprocess, 'run', side_effect=[subprocess.CompletedProcess([], 0),
                            subprocess.CompletedProcess([], 7)]) as calls:
                    result = cli.run_tests(['tests/test_owned.py'])
                self.assertEqual(result, 7)
                self.assertNotIn('getzilla.pytest_progress', calls.call_args.args[0])
                self.assertEqual(len(list((root / '.getzilla/runtime/verification-history').glob('*/index.json'))), 4)
            finally:
                for run in active:
                    run.close()

    def test_installed_sdk_and_selected_project_keep_history_separate(self):
        with tempfile.TemporaryDirectory(prefix='owned-sdk-project-', dir=ROOT / '.getzilla/runtime') as temporary:
            root = Path(temporary)
            sdk, project = root / 'sdk', root / 'project'
            sdk.mkdir(mode=0o700)
            project.mkdir(mode=0o700)
            (project / '.getzilla').mkdir(mode=0o700)
            spec = importlib.util.spec_from_file_location('owned_logging_cli', ROOT / 'scripts/getzilla_cli.py')
            cli = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cli)
            def backend(args, *, require_parallel=False, history=None):
                self.assertEqual(history.root, project)
                self.assertIsNotNone(history.writer)
                self.assertEqual(history.summary()['source_status'], 'unavailable')
                self.assertEqual(history.summary()['session_status'], 'unavailable')
                return 0
            with patch.object(cli, 'HOME', sdk), patch.object(os, 'getcwd', return_value=str(project)), \
                    patch.object(cli, '_run_tests', side_effect=backend):
                self.assertEqual(cli.run_tests([]), 0)
            self.assertTrue((project / '.getzilla/runtime/verification-history').is_dir())
            self.assertFalse((sdk / '.getzilla').exists())

    def test_reported_source_and_canonical_session_are_explicit_integrity_observations(self):
        with tempfile.TemporaryDirectory(prefix='owned-source-binding-', dir=ROOT / '.getzilla/runtime') as temporary:
            run = journal.Run(Path(temporary), None, 'owned-tests')
            run.bind_source('a' * 64, '01a1a6ba-10e8-7bc1-81b1-684978be3580')
            index = json.loads((run.path / 'index.json').read_text())
            self.assertEqual(index['source'], 'a' * 64)
            self.assertEqual(index['source_status'], 'reported-integrity-only')
            self.assertEqual(index['session_status'], 'canonical-route-observation')
            run.close()

    def test_util_command_preserves_exact_result_and_arguments_with_safe_observation(self):
        with tempfile.TemporaryDirectory(prefix='owned-command-', dir=ROOT / '.getzilla/runtime') as temporary:
            root = Path(temporary)
            run = journal.Run(root, None, 'owned-tests')
            expected = subprocess.CompletedProcess(['owned-tool'], 7, 'PRIVATE_OUTPUT', 'PRIVATE_ERROR')
            def child(*args, **kwargs):
                self.assertIn(b'"state":"start"', (run.path / run.writer.name).read_bytes())
                self.assertEqual(args[0], ['owned-tool'])
                self.assertEqual(kwargs['timeout'], 7)
                self.assertFalse(kwargs['check'])
                return expected
            with journal.activate(run), patch.object(util, 'resolve_command', return_value=['owned-tool']), \
                    patch.object(util.subprocess, 'run', side_effect=child):
                actual = util.run(['owned-tool'], cwd=root, timeout=7)
            self.assertIs(actual, expected)
            self.assertNotIn(b'PRIVATE', (run.path / run.writer.name).read_bytes())
            run.close()

    def test_pytest_phase_hooks_and_collection_skip_use_one_safe_schema(self):
        with tempfile.TemporaryDirectory(prefix='owned-hooks-', dir=ROOT / '.getzilla/runtime') as temporary:
            run = journal.Run(Path(temporary), None, 'owned-tests')
            worker = journal.Writer(run.path, run.run_id, 'worker-0', run.nonce)
            hooks = pytest_progress._JournalHooks(worker)
            node = SimpleNamespace(nodeid='tests/test_owned.py::Case::test_ok[PRIVATE_PARAMETER]')
            for stage in ('setup', 'call', 'teardown'):
                callback = getattr(hooks, 'pytest_runtest_' + stage)(node)
                next(callback)
                with self.assertRaises(StopIteration):
                    next(callback)
                hooks.pytest_runtest_logreport(SimpleNamespace(failed=False, passed=True, skipped=False,
                    when=stage, nodeid=node.nodeid, location=('tests/test_owned.py', 7, 'test_ok')))
            hooks.pytest_collectreport(SimpleNamespace(failed=False, skipped=True, nodeid='tests/test_owned.py',
                longrepr=('tests/test_owned.py', 12, 'PRIVATE_REASON')))
            hooks.pytest_unconfigure(None)
            records = [json.loads(line) for p in run.path.glob('worker-*.jsonl') for line in p.read_bytes().splitlines()]
            self.assertEqual([(r['stage'], r['state']) for r in records[:6]],
                [(stage, state) for stage in ('setup', 'call', 'teardown') for state in ('start', 'end')])
            self.assertEqual(records[-1]['skip_class'], 'redacted-unknown')
            self.assertEqual(records[-1]['location'], {'path': 'tests/test_owned.py', 'line': 12})
            self.assertNotIn('PRIVATE', repr(records))
            run.close()

    def test_batch_error_is_observed_without_changing_exception_or_result(self):
        with tempfile.TemporaryDirectory(prefix='owned-batch-', dir=ROOT / '.getzilla/runtime') as temporary:
            run = journal.Run(Path(temporary), None, 'owned-tests')
            failure = ValueError('PRIVATE_EXCEPTION')
            def callback():
                raw = (run.path / run.writer.name).read_bytes()
                self.assertIn(b'"state":"start"', raw)
                raise failure
            with journal.activate(run), self.assertRaises(ValueError) as caught:
                verification._CheckDispatch([], 'fast').batch(['owned-check'], callback)
            self.assertIs(caught.exception, failure)
            raw = (run.path / run.writer.name).read_bytes()
            self.assertIn(b'"outcome":"error"', raw)
            self.assertNotIn(b'PRIVATE', raw)
            run.close()

    def test_actual_callback_start_precedes_callback_and_end_retains_outcome(self):
        events = []
        @contextmanager
        def span(name, **fields):
            events.append(('start', name))
            yield
            events.append(('end', name))
        fake = SimpleNamespace(span=span)
        def callback():
            self.assertEqual(events, [('start', 'owned-check')])
            return verification.CheckResult('owned-check', 'pass', 'owned')
        with patch.object(verification, 'diagnostics', fake, create=True):
            result = verification._CheckDispatch([], 'fast').run('owned-check', callback)
        self.assertEqual(result.status, 'pass')
        self.assertEqual(events, [('start', 'owned-check'), ('end', 'owned-check')])

    def test_passed_report_publishes_safe_phase_outcome_not_only_failures(self):
        events = []
        with tempfile.TemporaryDirectory(prefix='owned-journal-hooks-', dir=ROOT / '.getzilla/runtime') as temporary:
            writer = pytest_progress._WorkerProgress(Path(temporary), 'a' * 32, 0)
            self.addCleanup(writer.pytest_unconfigure, None)
            writer.journal = SimpleNamespace(emit=lambda *args, **kwargs: events.append((args, kwargs)))
            writer.pytest_runtest_logreport(SimpleNamespace(failed=False, passed=True, skipped=False,
                when='call', nodeid='tests/test_owned.py::Case::test_value[PRIVATE_PARAMETER]'))
        self.assertTrue(events, 'a passed call must retain its phase outcome')
        self.assertNotIn('PRIVATE_PARAMETER', repr(events))


if __name__ == '__main__':
    unittest.main()
