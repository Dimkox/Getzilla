import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla import verification_journal as journal, pytest_progress

NODE = 'tests/test_owned.py::Owned::test_value'
CASE = 'tests/test_python_test_runner.py::PythonTestRunnerTests::test_term_resistant_grandchild_is_killed_on_every_stop_path'


class FailureCapsuleTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(subprocess, 'Popen', side_effect=AssertionError('no child')))
        self.enterContext(patch.object(socket, 'socket', side_effect=AssertionError('no network')))
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.run = journal.Run(self.root, 'a' * 64, 'owned-capsule')
        self.writer = self.run.writer
        self.addCleanup(self.writer.close)
        self.assertTrue(callable(getattr(self.writer, 'record_test_failure', None)), 'missing generic retained-failure recorder')

    def health(self, actor='controller'):
        return json.loads((self.run.path / (actor + '.json')).read_bytes())

    def capsule(self):
        return self.health()['first_failure']

    def record_failure(self, node=NODE, phase='call', kind='AssertionError'):
        self.writer.record_test_failure(node, phase, kind)
        return self.capsule()

    def report(self, *, failed=False, skipped=False, wasxfail=None, node=NODE):
        return SimpleNamespace(nodeid=node, when='call', failed=failed, skipped=skipped,
                               wasxfail=wasxfail, location=None, longrepr=None)

    def exception_hook(self, node=NODE, error=None):
        hook = pytest_progress._JournalHooks(self.writer)
        call = SimpleNamespace(when='call', excinfo=None if error is None else SimpleNamespace(value=error))
        with patch.object(self.writer, 'emit', return_value=True):
            generator = hook.pytest_runtest_makereport(SimpleNamespace(nodeid=node), call)
            next(generator)
            with self.assertRaises(StopIteration):
                next(generator)

    def test_pytest_requires_confirmed_failure_not_skip_xfail_exception(self):
        for report in (self.report(skipped=True), self.report(skipped=True, wasxfail='private')):
            self.writer.begin_test_phase(NODE, 'call')
            self.exception_hook(error=AssertionError('PRIVATE'))
            pytest_progress._journal_report(self.writer, report)
            self.assertNotIn('first_failure', self.health())
        self.writer.begin_test_phase(NODE, 'call')
        self.exception_hook(error=ValueError('PRIVATE'))
        pytest_progress._journal_report(self.writer, self.report(failed=True))
        self.assertEqual(self.capsule()['exception_kind'], 'ValueError')
        self.assertEqual(self.capsule()['phase'], 'call')

    def test_failed_report_missing_or_mismatched_exception_is_unavailable(self):
        self.exception_hook(node='tests/test_other.py::test_value', error=AssertionError())
        pytest_progress._journal_report(self.writer, self.report(failed=True))
        self.assertEqual(self.capsule()['exception_kind'], 'unavailable')

    def test_first_failure_survives_passes_repeat_other_failure_and_reopen(self):
        first = self.record_failure()
        pytest_progress._journal_report(self.writer, self.report())
        self.assertEqual(self.capsule(), first)
        self.record_failure(kind='ValueError')
        self.record_failure('tests/test_other.py::test_value')
        expected = dict(first, repeated=True, overflow=True)
        self.assertEqual(self.capsule(), expected)
        self.writer.close()
        self.writer = journal.Writer(self.run.path, self.run.run_id, 'controller', self.run.nonce)
        self.addCleanup(self.writer.close)
        self.run.writer = self.writer
        self.record_failure(kind='OSError')
        self.assertEqual(self.capsule(), expected)
        self.assertEqual(self.writer.attempt, 2)
        self.assertEqual(expected['attempt'], 1)

    def test_closed_schema_rejects_unknown_types_fields_and_parameters(self):
        first = self.record_failure(NODE + '[PRIVATE-PARAM]')
        self.assertEqual(first['node_key'], journal.test_identity(NODE)['key'])
        self.assertNotIn('PRIVATE', json.dumps(first))
        for key, value in [('pid', 42), ('attempt', True), ('version', True), ('attempt', 0),
                           ('node_key', 'private-path'), ('phase', []), ('exception_kind', 'PrivateError'),
                           ('repeated', 1), ('action_status', 'cause'), ('action', {'op': 'secret'})]:
            bad = dict(first, **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                journal._validate_first_failure(bad)

    def test_exception_classification_never_reads_message_frames_or_locals(self):
        class PrivateError(Exception):
            def __str__(self):
                raise AssertionError('message read')
            def __getattribute__(self, name):
                if name in ('__traceback__', 'args'):
                    raise AssertionError('private exception read')
                return super().__getattribute__(name)
        self.writer.note_exception(NODE + '[PRIVATE]', 'call', PrivateError())
        self.writer.record_test_failure(NODE, 'call')
        value = self.capsule()
        self.assertEqual(value['exception_kind'], 'other')
        self.assertNotIn('PrivateError', json.dumps(value))
        self.assertNotIn('PRIVATE', json.dumps(value))

    def test_only_committed_same_phase_failed_action_correlates(self):
        self.writer.begin_test_phase(NODE, 'call')
        with journal.bind_sink(self.writer, NODE):
            self.writer.emit('command', 'end', nodeid=NODE, step='owned-command', outcome='fail')
        sequence = self.writer.sequence
        first = self.record_failure()
        self.assertEqual(first['action'], {'op': 'owned-command', 'sequence': sequence})
        self.assertEqual(first['action_status'], 'correlated')

    def test_prior_test_passed_unbound_and_unwritten_actions_do_not_correlate(self):
        other = 'tests/test_other.py::test_value'
        self.writer.begin_test_phase(other, 'call')
        with journal.bind_sink(self.writer, other):
            self.writer.emit('action', 'end', nodeid=other, outcome='fail')
        self.writer.begin_test_phase(NODE, 'call')
        with journal.bind_sink(self.writer, NODE):
            self.writer.emit('action', 'end', nodeid=NODE, outcome='pass')
        self.writer.emit('action', 'end', nodeid=NODE, outcome='fail')
        self.writer.disabled = True
        self.assertFalse(self.writer.emit('command', 'end', nodeid=NODE, outcome='fail'))
        first = self.record_failure()
        self.assertIsNone(first['action'])
        self.assertEqual(first['action_status'], 'unavailable')

    def test_arbitrary_step_never_enters_correlated_operation(self):
        self.writer.begin_test_phase(NODE, 'call')
        with journal.bind_sink(self.writer, NODE):
            self.writer.emit('action', 'end', nodeid=NODE, step='private-canary', outcome='fail')
        first = self.record_failure()
        self.assertEqual(first['action']['op'], 'action')
        self.assertNotIn('private-canary', json.dumps(first))

    def test_rotation_missing_segment_export_and_ownership_coexist(self):
        with journal.bind_sink(self.writer, CASE), journal.ownership_case('exit'):
            journal.ownership_mark('descendant-check', status='failed', descendant='nonzombie')
        first = self.record_failure(CASE)
        with patch.object(journal, 'SEGMENT_BYTES', 2048):
            for _ in range(50):
                self.writer.emit('action', 'unknown', step='later')
        self.run.close()
        (self.run.path / self.health()['segment']).unlink()
        index = json.loads(dict(journal.export_entries(self.root))['journal/index.json'])
        self.assertEqual(index['first_failure']['capsules'], [first])
        self.assertEqual(index['ownership']['snapshot']['forms'][0]['status'], 'failed')
        self.assertEqual(index['first_failure'], self.run.summary()['first_failure'])
        self.assertLessEqual(len(journal._json({k:index[k] for k in ('ownership','first_failure','observation_omissions')})), 1536)

    def test_multiple_actors_are_ambiguous_prefix_with_explicit_overflow(self):
        self.record_failure()
        for i in range(2):
            writer = journal.Writer(self.run.path, self.run.run_id, 'worker-' + str(i), self.run.nonce)
            try:
                writer.record_test_failure('tests/test_other.py::test_value', 'setup', 'OSError')
            finally:
                writer.close()
        self.run.close()
        view = self.run.summary()['first_failure']
        self.assertEqual(len(view['capsules']), 2)
        self.assertTrue(view['ambiguous'])
        self.assertTrue(view['overflow'])

    def test_literal_maximum_shapes_and_size_facts(self):
        maximum = 2**63 - 1
        failure = {'version':1,'attempt':maximum,'node_key':'f'*64,'phase':'teardown',
                   'exception_kind':'ModuleNotFoundError','repeated':False,'overflow':False,
                   'action_status':'correlated','action':{'op':'owned-command','sequence':maximum}}
        owner = {'version':1,'case':'term-resistant-grandchild','attempt':maximum,'repeated':False,'overflow':False,
                 'forms':[{'form':form,'phase':'controller-reaped','status':'cancelled','cleanup':'none-reported',
                           'descendant':'unavailable'} for form in ('exit','flood','timeout','controller')]}
        base = {'version':1,'run_id':'a'*32,'nonce':'b'*32,'actor':'controller','sequence':maximum,'generation':maximum,
                'rotated':maximum,'attempt':maximum,'dropped':maximum,'open_spans':maximum,'status':'unavailable','segment':'controller-3.jsonl'}
        flags = {'ownership_omitted':False,'failure_omitted':False,'action_omitted':False}
        health = dict(base, ownership=owner, first_failure=failure, observation_omissions=flags)
        projection = {'ownership':{'status':'reported','snapshot':owner},
                      'first_failure':{'status':'reported','ambiguous':True,'overflow':False,'capsules':[failure,failure]},
                      'observation_omissions':flags}
        self.assertEqual([len(journal._json(x)) for x in (failure,owner,base)], [305,604,362])
        self.assertEqual(len(journal._json(health))+1, 1401)
        self.assertEqual(len(journal._json(projection)), 1447)
        self.assertEqual(journal._validate_first_failure(failure), failure)
        self.assertEqual(journal._fit_observations(health, 2048), health)
        self.assertEqual(journal._fit_observations(projection, 1536, public=True), projection)
        for limit in (1300, 1000, 700):
            packed = journal._fit_observations(health, limit)
            self.assertLessEqual(len(journal._json(packed))+1, limit)
            self.assertTrue(any(packed['observation_omissions'].values()))
        before = journal._json(projection)
        with patch.object(journal.json, 'loads', side_effect=RecursionError):
            packed = journal._fit_observations(projection, 300, public=True)
            exported = journal.export_entries(self.root)
        self.assertEqual(journal._json(projection), before)
        self.assertEqual(json.loads(exported[0][1])['status'], 'unavailable')
        self.assertLessEqual(len(journal._json(packed)), 300)
        self.assertTrue(packed['observation_omissions']['failure_omitted'])

    def test_malformed_optional_health_and_io_preserve_ordinary_results(self):
        first = self.record_failure()
        with patch.object(self.writer, 'health', side_effect=OSError('PRIVATE')):
            self.assertIs(journal._observe(self.writer, 'record_test_failure', NODE, 'call'), None)
        self.writer._first_failure = {'private': 'x'*4096}
        self.assertTrue(self.writer.emit('action', 'unknown', step='ordinary'))
        self.assertNotIn('first_failure', self.health())
        self.assertTrue(self.health()['observation_omissions']['failure_omitted'])
        self.assertEqual(first['exception_kind'], 'AssertionError')

    def test_unittest_phase_subtest_cleanup_unexpected_success_and_forwarding(self):
        prior = journal.action_sink()
        cases = (('setup', 'setup', 'ValueError'), ('call', 'call', 'AssertionError'),
                 ('teardown', 'teardown', 'OSError'), ('subtest', 'call', 'AssertionError'),
                 ('cleanup', 'unknown', 'OSError'), ('unexpected', 'call', 'unavailable'))
        for index, (scenario, phase, kind) in enumerate(cases):
            writer = journal.Writer(self.run.path, self.run.run_id, 'worker-' + str(index), self.run.nonce)
            class Owned(unittest.TestCase):
                __module__ = 'test_owned'
                def setUp(self):
                    if scenario == 'setup':
                        raise ValueError('PRIVATE')
                    if scenario == 'cleanup':
                        self.addCleanup(lambda: (_ for _ in ()).throw(OSError('PRIVATE')))
                def tearDown(self):
                    if scenario == 'teardown':
                        raise OSError('PRIVATE')
                def test_value(self):
                    if scenario == 'call':
                        self.fail('PRIVATE')
                    if scenario == 'subtest':
                        with self.subTest(value='PRIVATE'):
                            self.fail('PRIVATE')
            if scenario == 'unexpected':
                Owned.test_value = unittest.expectedFailure(Owned.test_value)
            test = Owned('test_value')
            try:
                result = journal.unittest_runner(writer)(stream=io.StringIO()).run(test)
                self.assertFalse(result.wasSuccessful())
                self.assertEqual(result.testsRun, 1)
                self.assertEqual(sum(map(len,(result.failures,result.errors,result.unexpectedSuccesses))), 1)
                capsule = self.health('worker-' + str(index))['first_failure']
                self.assertEqual(capsule['phase'], phase)
                self.assertEqual(capsule['exception_kind'], kind)
                self.assertNotIn('_callTestMethod', test.__dict__)
                self.assertEqual(journal.action_sink(), prior)
            finally:
                writer.close()

    def test_unknown_identity_and_optional_failure_do_not_change_unittest_result(self):
        self.writer.record_test_failure(None, 'unknown', 'unavailable')
        self.assertIsNone(self.capsule()['node_key'])
        class Owned(unittest.TestCase):
            def test_value(self): self.fail('original')
        with patch.object(self.writer, 'record_test_failure', side_effect=OSError('PRIVATE')):
            result = journal.unittest_runner(self.writer)(stream=io.StringIO()).run(Owned('test_value'))
        self.assertEqual(len(result.failures),1)
        self.assertEqual(result.testsRun,1)


class ObservedOutcomeTests(unittest.TestCase):
    def test_codes_are_reported_without_magic_timeout_and_identity_is_preserved(self):
        rows = []
        sink = SimpleNamespace(emit=lambda *args, **fields: rows.append(fields))
        for code, expected in ((0,'pass'), (7,'fail'), (124,'fail')):
            value = SimpleNamespace(returncode=code, status='timeout')
            with journal.bind_sink(sink, NODE):
                result = journal.observed('owned-fake')(lambda: value)()
            self.assertIs(result, value)
            self.assertEqual(rows[-1]['outcome'], expected)
            self.assertEqual(rows[-1]['code'], code)

    def test_explicit_status_without_code_and_original_exception(self):
        rows = []
        sink = SimpleNamespace(emit=lambda *args, **fields: rows.append(fields))
        value = SimpleNamespace(status='timeout')
        with journal.bind_sink(sink, NODE):
            self.assertIs(journal.observed('owned-fake')(lambda: value)(), value)
        self.assertEqual(rows[-1]['outcome'], 'timeout')
        original = ValueError('PRIVATE')
        def raised():
            raise original
        with journal.bind_sink(sink, NODE), self.assertRaises(ValueError) as caught:
            journal.observed('owned-fake')(raised)()
        self.assertIs(caught.exception, original)
