"""Owned synthetic contracts for durable verification history; no real workload."""
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch
import io
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla import pytest_progress, verification
from getzilla import verification_journal as journal
from getzilla import util
from getzilla import ci_evidence

ROOT = Path(__file__).resolve().parents[1]


class JournalRuntimeRepairTests(unittest.TestCase):
    def owned(self):
        temporary = tempfile.TemporaryDirectory(prefix='owned-runtime-repair-', dir=ROOT / '.getzilla/runtime')
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def sdk_coverage(self, archive=False, application_import=False):
        from coverage import Coverage
        from getzilla import python_test_runner
        root = self.owned()
        sdk, project = root / 'sdk', root / 'project'
        package = sdk / '.getzilla/getzilla'
        package.mkdir(parents=True)
        (sdk / 'scripts').mkdir()
        project.mkdir()
        (project / 'tests').mkdir()
        (project / 'tests/__init__.py').write_text('')
        (project / 'subject.py').write_text('VALUE=1\n')
        (project / 'tests/test_owned.py').write_text('import unittest\nimport subject\n'
            + ('import getzilla\n' if application_import else '')
            + 'class Owned(unittest.TestCase):\n def test_value(self): self.assertEqual(subject.VALUE,1)\n')
        initializer = package / '__init__.py'
        initializer.write_text('from pathlib import Path\n'
            '__path__.insert(0,str(Path(__file__).resolve().parents[1]/"getzilla.zip"/"getzilla"))\n'
            'Path(__file__).with_name("initializer-ran").write_text("owned")\n'
            'def unused_application_branch():\n return 9\n')
        members = {name: (ROOT / '.getzilla/getzilla' / name).read_bytes()
                   for name in ('fsx.py', 'verification_journal.py')}
        if archive:
            with zipfile.ZipFile(sdk / '.getzilla/getzilla.zip', 'w') as stream:
                for name, content in members.items():
                    stream.writestr('getzilla/' + name, content)
                stream.writestr('getzilla/__init__.py', 'raise AssertionError("archive initializer executed")\n')
            origins = sdk / '.getzilla/getzilla.zip/getzilla'
        else:
            for name, content in members.items():
                (package / name).write_bytes(content)
            origins = package
        harness = sdk / 'scripts/getzilla_unittest.py'
        harness.write_bytes((ROOT / 'scripts/getzilla_unittest.py').read_bytes())
        config = project / '.coveragerc'
        config.write_text('[report]\nfail_under=100\n')
        output = project / 'overlay'
        output.mkdir()
        with patch.object(python_test_runner, 'STACK_DIR', sdk / '.getzilla'), \
                patch.object(python_test_runner.fsx, '__file__', str(origins / 'fsx.py')), \
                patch.object(python_test_runner.diagnostics, '__file__', str(origins / 'verification_journal.py')):
            overlay = python_test_runner._application_coverage_config(config, output, root=project)
        run = journal.Run(project, None, 'owned-tests')
        self.addCleanup(run.close)
        home, temporary = root / 'home', root / 'tmp'
        home.mkdir(mode=0o700)
        temporary.mkdir(mode=0o700)
        env = run.child_environment({'PATH': os.defpath, 'HOME': str(home), 'TMPDIR': str(temporary),
            'PYTHONUTF8': '1', 'PYTHONIOENCODING': 'utf-8', 'COVERAGE_FILE': str(project / '.coverage'),
            'PYTHONPATH': str(sdk / '.getzilla') + os.pathsep + str(project)}, 0)
        result_file = project / 'result.json'
        child = subprocess.run([sys.executable, '-B', '-m', 'coverage', 'run', '--rcfile=' + str(overlay),
            str(harness), '--result', str(result_file), '--nonce', 'owned-count', 'discover', '-s', 'tests'],
            cwd=project, env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(json.loads(result_file.read_text())['tests_run'], 1)
        measured = Coverage(config_file=str(overlay), data_file=str(project / '.coverage'))
        measured.load()
        files = set(measured.get_data().measured_files())
        if application_import:
            self.assertIn(str(initializer), files)
            self.assertTrue(initializer.with_name('initializer-ran').exists())
            self.assertTrue(measured.analysis2(str(initializer))[3])
        else:
            self.assertNotIn(str(initializer), files)
            self.assertFalse(initializer.with_name('initializer-ran').exists())
            self.assertEqual(measured.get_option('report:fail_under'), 100)
            self.assertEqual(measured.report(file=io.StringIO()), 100)

    def test_file_sdk_observer_preserves_counted_full_application_coverage(self):
        self.sdk_coverage()

    def test_zip_sdk_observer_preserves_counted_full_application_coverage(self):
        self.sdk_coverage(archive=True)

    def test_explicit_public_sdk_import_remains_measured(self):
        self.sdk_coverage(application_import=True)

    def test_fake_pytest_config_never_attaches_journal_or_consumes_clock(self):
        config = SimpleNamespace(getoption=lambda name: None, pluginmanager=SimpleNamespace(register=lambda *args: None))
        with patch.dict(os.environ, {'GETZILLA_JOURNAL_DIR': 'owned-context'}), \
                patch.object(journal, 'child_writer', return_value=None) as child, \
                patch.object(journal.time, 'monotonic_ns') as clock:
            result = pytest_progress._configure_journal(config)
        self.assertFalse(result)
        child.assert_not_called()
        clock.assert_not_called()

    def test_native_invalid_worker_contexts_never_fall_back_or_register(self):
        import pytest
        samples = [None, {'workerid': 'gw00', 'workercount': 1}, {'workerid': 'gw64', 'workercount': 64},
                   {'workerid': 'gw0', 'workercount': True}, {'workerid': 'gw0'},
                   {'workerid': 'gw1', 'workercount': 1}]
        for worker in samples:
            with self.subTest(worker=worker):
                config = pytest.Config(pytest.PytestPluginManager())
                config.workerinput = worker
                with patch.dict(os.environ, {'GETZILLA_JOURNAL_DIR': 'owned-context'}), \
                        patch.object(journal, 'child_writer', return_value=None) as child, \
                        patch.object(config.pluginmanager, 'register') as register:
                    try:
                        result = pytest_progress._configure_journal(config)
                    except Exception as exc:
                        result = type(exc).__name__
                self.assertIs(result, True)
                child.assert_not_called()
                register.assert_not_called()

    def test_undeclared_child_actor_is_refused_before_writer_and_clock(self):
        run = journal.Run(self.owned(), None, 'owned-tests')
        self.addCleanup(run.close)
        env = run.child_environment({}, 0)
        with patch.object(journal, 'Writer', return_value=SimpleNamespace()) as writer, \
                patch.object(journal.time, 'monotonic_ns') as clock:
            result = journal.child_writer(env, ordinal=1)
        self.assertIsNone(result)
        writer.assert_not_called()
        clock.assert_not_called()

    def bootstrap_primary(self, mode):
        before_path = list(sys.path)
        public = {name: value for name, value in sys.modules.items()
                  if name == 'getzilla' or name.startswith('getzilla.')}
        spec = importlib.util.spec_from_file_location('owned_stdlib_harness', ROOT / 'scripts/getzilla_unittest.py')
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)
        run = journal.Run(self.owned(), None, 'owned-tests')
        self.addCleanup(run.close)
        env = {} if mode == 'absent' else run.child_environment({}, 0)
        if mode == 'malformed':
            env['GETZILLA_JOURNAL_RUN'] = 'not-a-run'
        name = '_getzilla_observer_' + run.run_id
        sentinel = ModuleType(name)
        primary = SimpleNamespace(result=SimpleNamespace(testsRun=1, wasSuccessful=lambda: True))
        error = io.StringIO()
        with patch.dict(os.environ, env, clear=True), patch.object(sys, 'argv', ['owned-harness', '--journal-only']), \
                patch.object(cli.unittest, 'main', return_value=primary) as calls, patch.object(sys, 'stderr', error):
            with patch.dict(sys.modules, {name: sentinel} if mode == 'collision' else {}):
                if mode == 'error':
                    with patch('importlib.machinery.PathFinder.find_spec', side_effect=ImportError('PRIVATE_BOOTSTRAP')):
                        self.assertEqual(cli.main(), 0)
                else:
                    self.assertEqual(cli.main(), 0)
                if mode == 'collision':
                    self.assertIs(sys.modules.get(name), sentinel)
                elif mode == 'error':
                    self.assertFalse(any(key == name or key.startswith(name + '.') for key in sys.modules))
            calls.assert_called_once()
        self.assertEqual(sys.path, before_path)
        self.assertEqual({key: value for key, value in sys.modules.items()
                          if key == 'getzilla' or key.startswith('getzilla.')}, public)
        self.assertNotIn('PRIVATE_BOOTSTRAP', error.getvalue())
        if mode == 'absent':
            self.assertEqual(error.getvalue(), '')
        else:
            self.assertIn('observer unavailable', error.getvalue())

    def test_absent_observer_context_keeps_stdlib_primary_and_public_namespace(self):
        self.bootstrap_primary('absent')

    def test_bootstrap_error_removes_only_its_new_private_bindings(self):
        self.bootstrap_primary('error')

    def test_malformed_observer_context_keeps_primary_and_public_namespace(self):
        self.bootstrap_primary('malformed')

    def test_private_namespace_collision_preserves_existing_module(self):
        self.bootstrap_primary('collision')

    def test_expected_actor_union_allows_a_smaller_later_job(self):
        run = journal.Run(self.owned(), None, 'owned-tests')
        self.addCleanup(run.close)
        run.expect_workers(4)
        env = run.child_environment({}, 1)
        worker = journal.child_writer(env, ordinal=1, worker_count=2)
        self.assertIsNotNone(worker)
        self.assertEqual(worker.actor, 'worker-1')
        worker.close()

    def test_native_controller_and_serial_contexts_are_separate(self):
        import pytest
        for count in (1, 64, True, 'auto'):
            config = pytest.Config(pytest.PytestPluginManager())
            with self.subTest(count=count), patch.dict(os.environ, {'GETZILLA_JOURNAL_DIR': 'owned-context'}), \
                    patch.object(config, 'getoption', return_value=count), patch.object(journal, 'child_writer') as child:
                self.assertIs(pytest_progress._configure_journal(config), True)
                child.assert_not_called()
        config = pytest.Config(pytest.PytestPluginManager())
        with patch.dict(os.environ, {'GETZILLA_JOURNAL_DIR': 'owned-context'}), \
                patch.object(config, 'getoption', return_value=None), patch.object(journal, 'child_writer', return_value=None) as child:
            self.assertIs(pytest_progress._configure_journal(config), True)
            child.assert_called_once_with()

    def test_real_one_test_xdist_child_keeps_both_protocols(self):
        root = self.owned()
        (root / 'tests').mkdir()
        (root / 'tests/test_owned.py').write_text('def test_owned():\n assert 1+1==2\n')
        progress = root / 'progress'
        progress.mkdir(mode=0o700)
        home, temporary = root / 'home', root / 'tmp'
        home.mkdir(mode=0o700)
        temporary.mkdir(mode=0o700)
        run = journal.Run(root, None, 'owned-tests')
        self.addCleanup(run.close)
        env = run.child_environment({'PATH': os.defpath, 'HOME': str(home), 'TMPDIR': str(temporary),
            'PYTHONUTF8': '1', 'PYTHONIOENCODING': 'utf-8', 'PYTHONPATH': str(ROOT / '.getzilla'),
            'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1'}, 0)
        child = subprocess.run([sys.executable, '-B', '-m', 'pytest', '-p', 'xdist.plugin',
            '-p', 'getzilla.pytest_progress', '-n', '1', '--getzilla-progress-dir', str(progress),
            '--getzilla-progress-nonce', run.nonce, '--getzilla-progress-workers', '1',
            '--getzilla-progress-phases', 'tests/test_owned.py', '-q'],
            cwd=root, env=env, capture_output=True, text=True, timeout=45)
        self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
        self.assertIn('1 passed', child.stdout)
        phases = [json.loads(line) for line in (progress / 'worker-0.phases.jsonl').read_text().splitlines()]
        self.assertEqual([row['phase'] for row in phases[1:]], ['configured', 'collection_finished', 'first_test_start'])
        self.assertEqual(json.loads((progress / 'worker-0.json').read_text())['state'], 'idle')
        events = [json.loads(line) for path in run.path.glob('worker-0-*.jsonl') for line in path.read_text().splitlines()]
        self.assertTrue({'setup', 'call', 'teardown'} <= {row['stage'] for row in events if row['state'] == 'end'})
        self.assertTrue(all(row['run_id'] == run.run_id and row['actor'] == 'worker-0' for row in events))
        health = json.loads((run.path / 'worker-0.json').read_text())
        self.assertEqual((health['run_id'], health['nonce'], health['actor']), (run.run_id, run.nonce, 'worker-0'))
        run.close()
        self.assertEqual(run.status, 'closed')


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

    def test_export_rejects_noncanonical_published_path(self):
        run = journal.Run(self.root(), None, 'owned-tests')
        run.writer.emit('call', 'start', nodeid='tests/test_owned.py::test_ok')
        name = run.writer.name
        run.close()
        path = run.path / name
        row = json.loads(path.read_text().splitlines()[0])
        row['path'] = 'tests/test_owned.py[PRIVATE_PARAMETER]'
        path.write_text(json.dumps(row) + '\n')
        self.assertNotIn(b'PRIVATE_PARAMETER', b''.join(raw for _, raw in journal.export_entries(run.root)))

    def test_export_keeps_health_provenance_and_missing_workers(self):
        run = journal.Run(self.root(), None, 'owned-tests')
        run.bind_source('a' * 64, '01a1a6ba-10e8-7bc1-81b1-684978be3580')
        run.child_environment({}, actor=0)
        run.close()
        summary = json.loads(dict(journal.export_entries(run.root))['journal/index.json'])
        for field, expected in [('status', 'incomplete'), ('export_status', 'bounded-subset'),
                ('source', 'a' * 64), ('session_status', 'canonical-route-observation'),
                ('expected', ['worker-0']), ('missing', ['worker-0'])]:
            with self.subTest(field=field):
                self.assertEqual(summary.get(field), expected)

    def test_unittest_decorated_skip_location_pairs_real_codefile_and_line(self):
        root = self.root()
        (root / 'tests').mkdir(mode=0o700)
        source = root / 'tests/test_owned.py'
        source.write_text("import unittest\n\nclass Owned(unittest.TestCase):\n @unittest.skip('Linux only')\n def test_skip(self): pass\n\n\n")
        namespace = {'__name__': 'tests.test_owned'}
        exec(compile(source.read_bytes(), str(source), 'exec'), namespace)
        run = journal.Run(root, None, 'owned-tests')
        writer = journal.Writer(run.path, run.run_id, 'worker-0', run.nonce)
        writer.emit('collection', 'start')
        result = journal.unittest_runner(writer)(stream=io.StringIO()).run(namespace['Owned']('test_skip'))
        writer.close()
        self.assertEqual(len(result.skipped), 1)
        records = [json.loads(line) for p in run.path.glob('worker-*.jsonl') for line in p.read_bytes().splitlines()]
        skip = next(row for row in records if row.get('outcome') == 'skip')
        self.assertEqual(skip.get('location'), {'path': 'tests/test_owned.py', 'line': 4})
        run.close()

    def test_ci_export_rejects_stale_journal_association(self):
        root = self.root()
        run = journal.Run(root, None, 'owned-tests')
        run.bind_source('a' * 64)
        run.close()
        evidence = root / '.getzilla/runtime/evidence'
        evidence.mkdir(mode=0o700)
        (evidence / 'verification.json').write_text(json.dumps({'ci_run_id': '123', 'git_head': 'c' * 40,
            'tree_fingerprint': 'b' * 64, 'diagnostics': {'run_id': run.run_id, 'index': run.relative_index}}))
        logs, output = root / 'logs', root / 'artifact'
        logs.mkdir(mode=0o700)
        with patch.object(ci_evidence, 'git_head', return_value='c' * 40), \
                patch.object(ci_evidence, 'git_output', return_value='d' * 40), \
                patch.object(ci_evidence, 'tree_fingerprint', return_value='b' * 64, create=True):
            ci_evidence.export_evidence(root, output, logs=logs, job='linux', status='failure', run_id='123')
        metadata = json.loads((output / 'provenance.json').read_text())
        self.assertEqual(metadata['diagnostics'].get('association'), 'unmatched')
        self.assertFalse((output / 'journal/controller.jsonl').exists())

    def test_export_matches_only_exact_run_source_session_and_labels_unbound(self):
        run = journal.Run(self.root(), None, 'owned-tests')
        session = '01a1a6ba-10e8-7bc1-81b1-684978be3580'
        run.bind_source('a' * 64, session)
        run.close()
        binding = {'run_id': run.run_id, 'source': 'a' * 64, 'session_id': session}
        summary = json.loads(dict(journal.export_entries(run.root, binding=binding))['journal/index.json'])
        self.assertEqual(summary['association'], 'source-run-matched')
        self.assertEqual(summary['run_status'], 'closed')
        self.assertEqual(summary['export_status'], 'bounded-subset')
        self.assertEqual(summary['missing'], [])
        self.assertEqual(json.loads(dict(journal.export_entries(run.root))['journal/index.json'])['association'], 'unbound')
        for key, wrong in [('run_id', 'b' * 32), ('source', 'b' * 64), ('session_id', None)]:
            entries = dict(journal.export_entries(run.root, binding={**binding, key: wrong}))
            self.assertEqual(json.loads(entries['journal/index.json'])['association'], 'unmatched')
            self.assertEqual(set(entries), {'journal/index.json'})

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
