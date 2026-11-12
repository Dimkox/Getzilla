import ast
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack, nullcontext
from dataclasses import FrozenInstanceError, replace
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla import python_test_runner as runner
from getzilla import verification_journal as journal


def strip_stop_annotations(node):
    def pure(value):
        allowed = {'replace', 'diagnostics.StopMetadata', 'diagnostics.child_stop', 'diagnostics.retain_stop'}
        names = {'stop_metadata', 'diagnostics', 'replace', 'original_returncode', 'retained', 'exc'}
        for part in ast.walk(value):
            if isinstance(part, ast.Call) and ast.unparse(part.func) not in allowed:
                raise AssertionError('nonmetadata call')
            if isinstance(part, ast.Name) and part.id not in names:
                raise AssertionError('nonmetadata input')
            if isinstance(part, (ast.NamedExpr, ast.Lambda, ast.Yield, ast.Await)):
                raise AssertionError('nonmetadata control')
    class Remove(ast.NodeTransformer):
        def visit_Assign(self, item):
            if len(item.targets) == 1 and ast.unparse(item.targets[0]) in {'stop_metadata', "retained['stop_metadata']"}:
                pure(item.value)
                return None
            return self.generic_visit(item)
        def visit_Expr(self, item):
            if isinstance(item.value, ast.Call) and ast.unparse(item.value.func) == 'diagnostics.retain_stop':
                pure(item.value)
                return None
            return self.generic_visit(item)
        def visit_Call(self, item):
            if isinstance(item.func, ast.Name) and item.func.id == 'ProcessResult':
                for keyword in item.keywords:
                    if keyword.arg == 'stop_metadata':
                        pure(keyword.value)
                item.keywords = [k for k in item.keywords if k.arg != 'stop_metadata']
                if len(item.args) == 9 and isinstance(item.args[-1], ast.Name) and item.args[-1].id == 'stop_metadata':
                    item.args.pop()
            return self.generic_visit(item)
    return Remove().visit(node)

class Capture(io.BytesIO):
    def fileno(self):
        return 10


class StopMetadataTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for owner, name in ((subprocess, 'Popen'), (socket, 'socket'), (os, 'kill')):
            self.stack.enter_context(patch.object(owner, name, side_effect=AssertionError('external effect forbidden')))
        if hasattr(os, 'killpg'):
            self.stack.enter_context(patch.object(os, 'killpg', side_effect=AssertionError('signal forbidden')))

    def details(self, result):
        self.assertTrue(callable(getattr(journal, 'stop_details', None)), 'missing stop projector')
        return journal.stop_details(result)

    def execute(self, *, code=0, deadline=False, output=False, late_output=False, cancel=False,
                late_cancel=False, primary=None, spawn_error=False):
        calls = []
        cancellation = runner.Cancellation()
        process = SimpleNamespace(returncode=None, pid=123, args=['PRIVATE'])
        def poll():
            calls.append('poll')
            if primary:
                raise primary
            if cancel:
                cancellation.signal_number = 15
            if not (deadline or output or cancel):
                process.returncode = code
            return process.returncode
        process.poll = poll
        def stop(value):
            self.assertIs(value, process)
            calls.append('stop')
            if process.returncode is None:
                process.returncode = -9
            if late_cancel:
                cancellation.signal_number = 2
        def size(_):
            calls.append('size')
            return SimpleNamespace(st_size=runner.OUTPUT_LIMIT if output or late_output and 'stop' in calls else 0)
        with ExitStack() as scope:
            enter = scope.enter_context
            enter(patch.object(journal, 'current', return_value=None))
            enter(patch.object(runner, '_cancellation', return_value=nullcontext(cancellation)))
            enter(patch.object(runner, '_output_file', side_effect=lambda *a, **k: nullcontext(Capture())))
            enter(patch.object(runner.fsx, 'owned_popen', side_effect=OSError('PRIVATE-SPAWN') if spawn_error else None,
                                            return_value=process))
            enter(patch.object(runner, '_stop', side_effect=stop))
            enter(patch.object(runner, 'os', SimpleNamespace(**dict(vars(os), fstat=size))))
            enter(patch.object(runner.time, 'monotonic', side_effect=[0, 2 if deadline else 0, 3]))
            result = runner.execute(['PRIVATE'], Path('.'), {}, timeout=1)
        return result, calls

    def test_fake_runner_preserves_real_outer_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            run = journal.Run(Path(directory), 'a' * 64, 'owned-control')
            try:
                self.assertIsNotNone(run.writer)
                with journal.bind_sink(run.writer, 'tests/test_stop_metadata.py::test_outer'):
                    try:
                        result, calls = self.execute(code=124)
                    except AttributeError as exc:
                        self.fail(f'fake runner corrupted real journal stat: {exc}')
                rows = [json.loads(line) for line in (run.path / run.writer.name).read_text().splitlines()]
                self.assertEqual([(row['stage'], row['state']) for row in rows],
                                 [('command', 'start'), ('command', 'end')])
                self.assertEqual((rows[-1]['outcome'], rows[-1]['exit']), ('fail', 124))
                self.assertEqual(result.returncode, 124)
                self.assertEqual(self.details(result)['decision'], 'child_exit')
                self.assertEqual(calls, ['poll', 'stop', 'size', 'size'])
                self.assertFalse(any(run.writer.active.values()))
            finally:
                run.close()

    def test_factory_primary_evidence_precedes_stop_diagnostic(self):
        from getzilla import factory_tests, verification
        identifier = 'factory.tests.test_owned.Probe.test_owned'
        binding = {'declared_ids': [identifier], 'source_inventory': {}, 'context': {}}
        report = {'schema_version': 3, 'check_id': 'factory-unit', 'status': 'pass', 'binding': binding,
                  'database_obligations': 'not_run_in_unit_mode', 'source_stable': True,
                  'collected': 1, 'tests_run': 1, 'failures': 0, 'errors': 0, 'loader_errors': 0,
                  'collected_ids': [identifier], 'expected_ids': [identifier], 'required_ids': [identifier],
                  'started': [identifier], 'executed': [identifier], 'unqualified_skips': [],
                  'missing_required': [], 'skipped': [], 'problems': []}
        process = runner.ProcessResult(['owned-fake'], 0, stop_metadata=journal.child_stop(0))
        def complete(command, root, environment, **kwargs):
            self.assertEqual(json.loads(Path(command[command.index('--request') + 1]).read_text()), binding)
            Path(command[command.index('--report') + 1]).write_text(json.dumps(report))
            return process
        with tempfile.TemporaryDirectory() as directory, ExitStack() as scope:
            root = Path(directory)
            (root / 'factory/tests').mkdir(parents=True)
            (root / 'factory/pyproject.toml').touch()
            scope.enter_context(patch.object(factory_tests, 'invocation', return_value=binding))
            scope.enter_context(patch.object(factory_tests, 'source_matches', return_value=True))
            scope.enter_context(patch.object(verification, 'execute', side_effect=complete))
            scope.enter_context(patch.object(verification, 'resolve_command', side_effect=lambda command, path: command))
            result = verification._factory_unit(root)[0]
        self.assertEqual(result.status, 'pass', result)
        self.assertEqual(result.details[0].get('collected'), 1)
        self.assertEqual(result.details[0]['executed'], [identifier])
        self.assertTrue(result.details[0]['source_stable'])
        self.assertEqual(result.details[1]['stop']['decision'], 'child_exit')

    def test_child124_does_not_become_deadline_or_limit(self):
        for code in (0, 3, 124, -15):
            with self.subTest(code=code):
                result, calls = self.execute(code=code)
                record = self.details(result)
                self.assertEqual(record['decision'], 'child_signal' if code < 0 and os.name != 'nt' else 'child_exit')
                self.assertEqual(record['result_policy'], 'child_status')
                self.assertEqual(result.returncode, code)
                self.assertEqual(calls, ['poll', 'stop', 'size', 'size'])
                self.assertNotIn('PRIVATE', json.dumps(record))

    def test_preservation_normalizer_refuses_hidden_effects(self):
        for text in ('stop_metadata = os.kill(1, 9)', 'stop_metadata = replace(stop_metadata, decision=probe())',
                     'stop_metadata = (value := 4)'):
            with self.subTest(text=text), self.assertRaises(AssertionError):
                strip_stop_annotations(ast.parse(text))

    def test_first_deadline_survives_late_output_policy(self):
        result, calls = self.execute(deadline=True, late_output=True)
        record = self.details(result)
        self.assertEqual((record['decision'], record['result_policy'], record['late_output']),
                         ('deadline', 'limit_124', 'exceeded'))
        self.assertEqual((result.returncode, result.terminal_state), (124, 'completed'))
        self.assertEqual(calls, ['poll', 'stop', 'size', 'size'])

    def test_output_stop_and_primary_exception_identity(self):
        result, calls = self.execute(output=True)
        self.assertEqual(self.details(result)['decision'], 'output_limit')
        self.assertEqual(calls, ['poll', 'size', 'size', 'stop', 'size', 'size'])
        error = RuntimeError('PRIVATE-PRIMARY')
        with self.assertRaises(RuntimeError) as caught:
            self.execute(primary=error)
        self.assertIs(caught.exception, error)
        self.assertEqual(self.details(error)['decision'], 'primary_exception')

    def test_owned_cancel_preserves_child_decision(self):
        for options, decision, policy, number in (({'cancel': True}, 'owned_cancel', 'cancel_128_signal', 'sigterm'),
                ({'code': 124, 'late_cancel': True}, 'child_exit', 'cancel_preserve_child', 'sigint')):
            with self.subTest(options=options), self.assertRaises(runner.RunCancelled) as caught:
                self.execute(**options)
            record = self.details(caught.exception.result)
            self.assertEqual((record['decision'], record['result_policy'], record['cancel']), (decision, policy, number))
            self.assertEqual(self.details(caught.exception), record)

    def test_invalid_metadata_grants_no_facts(self):
        result = runner.ProcessResult([], 124)
        unknown = self.details(result)
        self.assertEqual(unknown['decision'], 'unavailable')
        class Poison:
            @property
            def stop_metadata(self):
                raise RuntimeError('PRIVATE')
        self.assertEqual(self.details(Poison()), unknown)
        for value in (None, {}, SimpleNamespace(decision='deadline')):
            result.stop_metadata = value
            self.assertEqual(self.details(result), unknown)
        good, _ = self.execute()
        with self.assertRaises(FrozenInstanceError):
            good.stop_metadata.decision = 'deadline'
        good.stop_metadata = replace(good.stop_metadata, decision='PRIVATE')
        self.assertEqual(self.details(good), unknown)

    def test_spawn_failure_retains_status_without_private_text(self):
        result, calls = self.execute(spawn_error=True)
        record = self.details(result)
        self.assertEqual((record['decision'], record['result_policy']), ('spawn_error', 'spawn_127'))
        self.assertEqual(result.returncode, 127)
        self.assertEqual(calls, [])
        self.assertNotIn('PRIVATE', json.dumps(record))

    def test_consumer_records_preserve_child_status_and_refusal(self):
        from getzilla import verification_tools, security_tools, verification
        result, _ = self.execute(code=124)
        expected = self.details(result)
        self.assertEqual(verification_tools._execution(result).get('stop'), expected)
        self.assertIn(json.dumps(expected, sort_keys=True), security_tools._process_detail(result, 'process-failed'))
        with patch.object(verification, 'execute', return_value=result), \
                patch.object(verification, 'resolve_command', return_value=['fake']), \
                patch.object(verification, 'tool_search_path', return_value=''):
            check = verification._command_check(Path('owned-fake'), 'owned-fake', ['fake'])
        self.assertEqual(check.details[0]['stop'], expected)
        self.assertEqual(check.status, 'fail')

    def test_collection_refusal_preserves_child_decision(self):
        result, _ = self.execute()
        refused = runner._unittest_result(result, Path('not-read-without-nonce'))
        self.assertEqual(refused.returncode, 5)
        self.assertEqual(self.details(refused)['decision'], 'child_exit')
        self.assertEqual(self.details(refused)['result_policy'], 'collection_refusal')
        self.assertEqual(result.returncode, 0)

    def test_core_rotation_reopen_and_binding_restoration(self):
        self.assertTrue(callable(getattr(journal, 'core_stop_scope', None)), 'missing Core scope')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = journal.Run(root, 'a' * 64, 'owned-control')
            self.addCleanup(run.close)
            writer = run.writer
            result, _ = self.execute(deadline=True)
            baseline = journal.action_sink()
            with patch.object(journal, 'current', return_value=run):
                journal.record_core_stop(result)
                self.assertNotIn('core_stop', json.loads((run.path / 'controller.json').read_bytes()))
                with journal.core_stop_scope():
                    journal.record_core_stop(result)
                with journal.core_stop_scope():
                    journal.record_core_stop(runner.ProcessResult([], 0))
            self.assertEqual(journal.action_sink(), baseline)
            health = json.loads((run.path / 'controller.json').read_bytes())
            self.assertEqual(health['core_stop']['metadata']['decision'], 'deadline')
            self.assertEqual(health['core_stop']['attempt'], 1)
            for _ in range(5):
                writer._open_segment()
            writer.close()
            reopened = journal.Writer(run.path, run.run_id, 'controller', run.nonce)
            self.assertEqual(reopened._core_stop, health['core_stop'])
            reopened.close()
            run.close()
            entries = dict(journal.export_entries(root))
            summary = json.loads(entries['journal/index.json'])
            self.assertEqual(summary['core_stop']['snapshot']['metadata']['decision'], 'deadline')

    def test_event_carries_decision_without_changing_outcome(self):
        events = []
        writer = SimpleNamespace(emit=lambda *args, **kwargs: events.append((args, kwargs)))
        result, _ = self.execute(code=124)
        with journal.bind_sink(writer, None):
            returned = journal.observed('owned-command')(lambda: result)()
        self.assertIs(returned, result)
        self.assertEqual(events[-1][1]['outcome'], 'fail')
        self.assertEqual(events[-1][1].get('stop'), self.details(result))

    def test_bounds_lowest_priority_omission_and_closed_refusal(self):
        metadata = {'version': 1, 'decision': 'primary_exception', 'result_policy': 'cancel_preserve_child',
                    'cancel': 'unavailable', 'late_output': 'not_exceeded', 'scope': 'coverage_combine'}
        capsule = {'attempt': 2**63 - 1, 'repeated': False, 'overflow': False, 'metadata': metadata}
        self.assertLessEqual(len(journal._json(metadata)), 256)
        self.assertLessEqual(len(journal._json(capsule)), 320)
        self.assertEqual(journal._health_stop({'actor': 'controller', 'core_stop': capsule}), capsule)
        for bad in (None, {}, dict(capsule, attempt=True), dict(capsule, pid=123)):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                journal._health_stop({'actor': 'controller', 'core_stop': bad})
        with self.assertRaises(ValueError):
            journal._health_stop({'actor': 'worker-0', 'core_stop': capsule})
        for bad in (dict(metadata, version=True), dict(metadata, decision='PRIVATE'), dict(metadata, pid=1)):
            with self.assertRaises(ValueError):
                journal._validate_stop(bad)
        value = {'core_stop': capsule, 'ordinary': 'a' * 1800,
                 'observation_omissions': dict.fromkeys(journal._OMISSIONS, False)}
        before = json.dumps(value)
        with patch.object(journal.json, 'loads', side_effect=RecursionError):
            packed = journal._fit_observations(value, 2048)
        self.assertTrue(packed['observation_omissions']['stop_omitted'])
        self.assertEqual(packed['ordinary'], value['ordinary'])
        self.assertLessEqual(len(journal._json(packed)) + 1, 2048)
        self.assertEqual(json.dumps(value), before)

    def test_capture_exception_keeps_first_decision_and_primary(self):
        error = RuntimeError('PRIVATE')
        journal.retain_stop(error, journal.StopMetadata(decision='primary_exception'))
        with self.assertRaises(RuntimeError) as caught:
            with runner._output_resource(nullcontext(None), {}, 'fake', runner.Cancellation()):
                raise error
        self.assertIs(caught.exception, error)
        self.assertEqual(self.details(error)['decision'], 'primary_exception')

    def parallel(self, code, error=None):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            process = SimpleNamespace(args=['fake'], returncode=code, poll=lambda: code)
            enter = stack.enter_context
            enter(patch.object(runner.fsx, 'owned_popen', return_value=process))
            enter(patch.object(runner.fsx, 'owned_job', return_value=None))
            enter(patch.object(runner, '_cancellation', return_value=nullcontext(runner.Cancellation())))
            enter(patch.object(runner, '_unittest_result', side_effect=lambda result, path: result))
            enter(patch.object(journal, 'current', return_value=None))
            combined = runner.ProcessResult([], 124, stop_metadata=journal.StopMetadata(decision='deadline'))
            enter(patch.object(runner, 'execute', return_value=combined))
            if error:
                enter(patch.object(runner.time, 'monotonic', side_effect=[0, 901]))
                enter(patch.object(runner, '_stop', side_effect=error))
            return runner._parallel_coverage_unittest(root, root/'config', root/'data', 1, {}, test_files=['fake.py'])

    def test_parallel_aggregate_and_combine_retain_contributor(self):
        for code, scope, decision in ((3, 'selected_shard', 'child_exit'), (0, 'coverage_combine', 'deadline')):
            with self.subTest(code=code):
                result = self.parallel(code)
                self.assertEqual((self.details(result)['scope'], self.details(result)['decision']), (scope, decision))
                self.assertEqual(result.returncode, code or 124)

    def test_optional_core_binding_cannot_replace_primary(self):
        class Poison:
            @property
            def writer(self):
                raise RuntimeError('PRIVATE sink')
        error = ValueError('primary')
        with patch.object(journal, 'current', return_value=Poison()), self.assertRaises(ValueError) as caught:
            with journal.core_stop_scope():
                raise error
        self.assertIs(caught.exception, error)
        self.assertIsNone(journal._CORE_STOP.get())

    def test_same_origin_private_module_preserves_closed_metadata(self):
        name = '_getzilla_observer_' + 'a' * 32
        package = ModuleType(name)
        package.__path__ = [str(Path(journal.__file__).parent)]
        spec = importlib.util.spec_from_file_location(name + '.verification_journal', journal.__file__)
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {name: package, spec.name: module}):
            spec.loader.exec_module(module)
            result, _ = self.execute(code=124)
            self.assertEqual(module.stop_details(result), self.details(result))
            foreign = SimpleNamespace(stop_metadata=SimpleNamespace(**self.details(result)))
            self.assertEqual(module.stop_details(foreign)['decision'], 'unavailable')

    def test_closed_security_refusals_keep_execution_record(self):
        from getzilla import security_cli, security_tools
        result, _ = self.execute(code=124)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(security_cli, 'execute', return_value=result), \
                    patch.object(security_cli, '_environment', return_value={}):
                with self.assertRaises(security_cli.SecurityDataError) as caught:
                    security_cli._git(root, ['fake'], root)
                self.assertEqual(self.details(caught.exception), self.details(result))
                args = SimpleNamespace(tools=root/'tools', root=root, database=root, artifacts=root,
                    input_profile=root/'profile', json_out=root/'out.json', refresh=False,
                    provision_tools=False, family_records=None)
                report = security_cli._supervised_preparation(args, {})
                self.assertEqual(report['stop'], self.details(result))
                self.assertEqual(report['qualification'], 'UNVERIFIED')
            with patch.object(security_tools, '_json', side_effect=FileNotFoundError):
                with self.assertRaises(security_tools.SecurityDataError) as caught:
                    security_tools._process_report(root/'unused', result)
                self.assertEqual(self.details(caught.exception), self.details(result))

    def test_verification_cancellation_coverage_and_named_projections(self):
        from getzilla import verification as verify
        result, _ = self.execute(code=124)
        error = runner.RunCancelled(15, result)
        error.core_run = runner.CoreTestRun(result, result, 0, {}, {}, coverage_export=result)
        with patch.object(verify, '_python_checks', side_effect=error), self.assertRaises(runner.RunCancelled) as caught:
            verify._python(Path('owned'), 'pr')
        self.assertIs(caught.exception, error)
        self.assertEqual([c.details[0]['stop'] for c in error.checks], [self.details(result)] * 2)
        with patch.object(verify, 'git_head', return_value='a'*40), \
                patch.object(verify, 'run', return_value=SimpleNamespace(returncode=0, stdout='')), \
                patch.object(verify, 'tree_fingerprint', return_value='b'*64), \
                patch.object(verify, 'run_named_tests', return_value=result):
            report = verify.verify_named_tests(Path('owned'), ['tests.test_owned'])
        self.assertEqual(report['checks'][0]['details'][0]['stop'], self.details(result))
        self.assertEqual(report['status'], 'fail')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'tests').mkdir()
            core = runner.CoreTestRun(result, result, 0, {'engine': 'unittest'}, {}, coverage_export=result)
            selection = SimpleNamespace(workers=0, source='explicit', capacity=1)
            with patch.object(verify, 'core_worker_selection', return_value=selection), \
                    patch.object(verify, 'run_core_tests', return_value=core), \
                    patch.object(verify, '_trusted_pytest_metadata', return_value=None):
                checks = verify._core_python_run(root, 'pr', False, [], keep_going=False)
            self.assertEqual([c.details[0]['stop'] for c in checks], [self.details(result)] * 2)
            self.assertEqual(checks[1].details[0]['coverage_export_stop'], self.details(result))

    def test_combined_projection_omits_stop_before_original_facts(self):
        maximum = 2**63 - 1
        owner = {'version':1, 'case':'term-resistant-grandchild', 'attempt':maximum, 'repeated':False, 'overflow':False,
            'forms':[dict(form=f, phase='controller-reaped', status='cancelled', cleanup='none-reported', descendant='unavailable')
                     for f in ('exit', 'flood', 'timeout', 'controller')]}
        failure = dict(version=1, attempt=maximum, node_key='a'*64, phase='teardown', exception_kind='ModuleNotFoundError',
                       repeated=False, overflow=False, action_status='correlated', action=dict(op='owned-command', sequence=maximum))
        result, _ = self.execute(deadline=True)
        stop = dict(attempt=maximum, repeated=False, overflow=False, metadata=self.details(result))
        flags = dict.fromkeys(journal._OMISSIONS, False)
        projected = journal._observation_projection([owner], [failure, failure], True, flags, [stop])
        self.assertLessEqual(len(journal._json(projected)), 1536)
        self.assertEqual(projected['ownership']['snapshot'], owner)
        self.assertEqual(projected['first_failure']['capsules'], [failure, failure])
        self.assertTrue(projected['observation_omissions']['stop_omitted'])
        self.assertEqual(projected['core_stop']['status'], 'unavailable')
        self.assertEqual(journal._observation_projection([], [], True, flags, [stop, stop])['core_stop']['status'], 'ambiguous')

    def test_parallel_deadline_survives_stop_exception(self):
        error = RuntimeError('primary stop')
        with self.assertRaises(RuntimeError) as caught:
            self.parallel(None, error)
        self.assertIs(caught.exception, error)
        self.assertEqual((self.details(error)['decision'], self.details(error)['scope']), ('deadline', 'parallel_batch'))

    def test_core_missing_coverage_keeps_execution_and_refusal_separate(self):
        result, _ = self.execute(code=124)
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            (root/'.coveragerc').write_text('[run]\n')
            enter = stack.enter_context
            enter(patch.object(runner, 'select_engine', return_value=(0, 'unittest')))
            enter(patch.object(runner, '_tool_versions', return_value={}))
            enter(patch.object(runner, '_application_coverage_config', return_value=root/'.coveragerc'))
            enter(patch.object(runner, '_environment', return_value={}))
            enter(patch.object(runner, 'execute', return_value=result))
            enter(patch.object(journal, 'current', return_value=None))
            core = runner.run_core_tests(root, 'pr', 0)
            self.assertIs(core.tests, result)
            self.assertEqual(self.details(core.tests)['decision'], 'child_exit')
            self.assertEqual(self.details(core.coverage)['decision'], 'unavailable')
            self.assertEqual(self.details(core.coverage)['result_policy'], 'coverage_refusal')
