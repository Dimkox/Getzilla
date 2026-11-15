import ast
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack, redirect_stderr
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla import verification_journal as journal

CASE = 'tests/test_python_test_runner.py::PythonTestRunnerTests::test_term_resistant_grandchild_is_killed_on_every_stop_path'


class RetainedObservationTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for owner, name in ((subprocess, 'Popen'), (socket, 'socket'), (os, 'kill')):
            self.stack.enter_context(patch.object(owner, name, side_effect=AssertionError('external effect forbidden')))
        if hasattr(os, 'killpg'):
            self.stack.enter_context(patch.object(os, 'killpg', side_effect=AssertionError('signal forbidden')))
        self.stack.enter_context(redirect_stderr(io.StringIO()))
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.run = journal.Run(self.root, 'a' * 64, 'owned-control')
        self.addCleanup(self.run.close)
        self.writer = self.run.writer

    def admit(self, form='exit'):
        self.assertTrue(callable(getattr(journal, 'ownership_case', None)), 'missing retained observation adapter')
        stack = ExitStack()
        stack.enter_context(journal.bind_sink(self.writer, CASE))
        stack.enter_context(journal.ownership_case(form))
        return stack

    def health(self):
        return json.loads((self.run.path / 'controller.json').read_bytes())

    def test_failure_phase_is_retained_through_later_forms(self):
        failure = AssertionError('PRIVATE-EXCEPTION-CANARY')
        with self.assertRaises(AssertionError) as caught, self.admit():
            journal.ownership_mark('descendant-check', descendant='nonzombie')
            raise failure
        self.assertIs(caught.exception, failure)
        with self.admit('flood'):
            journal.ownership_mark('result', status='returned', cleanup='none-reported')
        rows = self.health()['ownership']['forms']
        fields = ('form', 'phase', 'status', 'cleanup', 'descendant')
        self.assertEqual([tuple(row[key] for key in fields) for row in rows], [
            ('exit', 'descendant-check', 'failed', 'unavailable', 'nonzombie'),
            ('flood', 'finished', 'returned', 'none-reported', 'unavailable')])
        self.assertNotIn('PRIVATE-', json.dumps(self.health()['ownership']))

    def test_closed_snapshot_schema_rejects_private_and_ambiguous_values(self):
        with self.admit():
            journal.ownership_mark('result', status='returned')
        good = self.health()['ownership']
        self.assertEqual(journal._validate_ownership_snapshot(good), good)
        for key, value in [('pid', 123), ('attempt', True), ('version', True), ('attempt', 0), ('attempt', 2**63), ('forms', {}), ('repeated', 1)]:
            bad = copy.deepcopy(good)
            bad[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                journal._validate_ownership_snapshot(bad)
        for key in ('form', 'phase', 'status', 'cleanup', 'descendant'):
            for value in ('PRIVATE-CANARY', [], None):
                bad = copy.deepcopy(good)
                bad['forms'][0][key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    journal._validate_ownership_snapshot(bad)
        bad = copy.deepcopy(good)
        bad['forms'] *= 2
        with self.assertRaises(ValueError):
            journal._validate_ownership_snapshot(bad)
        class Borrowed(str):
            pass
        bad = copy.deepcopy(good)
        bad['case'] = Borrowed('term-resistant-grandchild')
        with self.assertRaises(ValueError):
            journal._validate_ownership_snapshot(bad)

    def test_four_maximum_rows_fit_existing_health_and_projection_caps(self):
        for form in ('exit', 'flood', 'timeout', 'controller'):
            with self.admit(form):
                journal.ownership_mark('controller-reaped', status='returned', cleanup='none-reported', descendant='nonzombie')
        health = self.health()
        self.assertLessEqual(len(journal._json(health)), 2048)
        self.assertLessEqual(len(journal._json(health['ownership'])), 1024)
        self.run.close()
        public = self.run.summary()['ownership']
        self.assertEqual(public['status'], 'reported')
        self.assertLessEqual(len(journal._json(public)), 1536)

    def test_unbound_wrong_case_and_invalid_form_produce_no_snapshot(self):
        self.assertTrue(callable(getattr(journal, 'ownership_case', None)))
        for node in (None, 'tests/test_other.py::test_other'):
            with journal.bind_sink(self.writer, node), journal.ownership_case('exit'):
                journal.ownership_mark('result', status='returned')
        with journal.bind_sink(self.writer, CASE), journal.ownership_case('PRIVATE-CANARY'):
            journal.ownership_mark('result')
        self.assertNotIn('ownership', self.health())

    def test_nesting_restores_form_and_later_binding_is_inert(self):
        with self.admit():
            with self.admit('flood'):
                journal.ownership_mark('result', cleanup='recorded')
            journal.ownership_mark('ready')
        before = self.health()['ownership']
        with journal.bind_sink(self.writer, 'tests/test_other.py::test_other'):
            journal.ownership_mark('result', cleanup='recorded')
        self.assertEqual(before, self.health()['ownership'])
        self.assertEqual(before['forms'][0]['cleanup'], 'unavailable')
        self.assertEqual(before['forms'][1]['cleanup'], 'recorded')

    def test_repeat_and_reopen_retain_first_invocation_and_attempt(self):
        with self.admit():
            journal.ownership_mark('result', cleanup='recorded')
        before = self.health()['ownership']
        with self.admit():
            journal.ownership_mark('result', cleanup='none-reported')
        self.assertEqual(self.health()['ownership'], dict(before, repeated=True))
        self.writer.close()
        self.writer = journal.Writer(self.run.path, self.run.run_id, 'controller', self.run.nonce)
        self.run.writer = self.writer
        with self.admit():
            journal.ownership_mark('result', cleanup='none-reported')
        after = self.health()['ownership']
        self.assertEqual(after, dict(before, repeated=True))
        self.assertEqual(self.writer.attempt, 2)
        self.assertEqual(after['attempt'], 1)

    def test_overflow_is_explicit_and_does_not_erase_failure(self):
        with self.admit():
            for _ in range(30):
                journal.ownership_mark('ready')
            journal.ownership_mark('descendant-check', status='failed', descendant='nonzombie')
        snapshot = self.health()['ownership']
        self.assertTrue(snapshot['overflow'])
        self.assertNotEqual(snapshot['forms'][0]['status'], 'returned')
        self.assertEqual(self.writer.sequence, 24)

    def test_optional_sink_failures_preserve_original_exception(self):
        prior = journal.action_sink()
        primary = RuntimeError('PRIVATE-CANARY')
        with patch.object(self.writer, 'record_ownership', side_effect=OSError('private path')), self.assertRaises(RuntimeError) as caught:
            with self.admit():
                journal.ownership_mark('execute')
                raise primary
        self.assertIs(caught.exception, primary)
        self.assertEqual(journal.action_sink(), prior)
        cancelled = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt) as caught, self.admit():
            raise cancelled
        self.assertIs(caught.exception, cancelled)
        self.assertEqual(self.health()['ownership']['forms'][0]['status'], 'cancelled')

    def test_legacy_missing_and_malformed_health_never_imply_observation_success(self):
        self.run.close()
        self.assertEqual(self.run.summary()['ownership']['status'], 'unavailable')
        path = self.run.path / 'controller.json'
        value = json.loads(path.read_bytes())
        value['ownership'] = {'pid': 123, 'private': 'CANARY'}
        path.write_text(json.dumps(value))
        exported = dict(journal.export_entries(self.root))
        index = json.loads(exported['journal/index.json'])
        self.assertEqual(index['export_status'], 'unavailable')
        self.assertNotIn('CANARY', exported['journal/index.json'].decode())

    def test_snapshot_survives_rotation_and_export_without_old_events(self):
        with self.admit():
            journal.ownership_mark('descendant-check', status='failed', descendant='nonzombie')
        with patch.object(journal, 'SEGMENT_BYTES', 2048):
            for _ in range(50):
                self.assertTrue(self.writer.emit('action', 'unknown', step='later-owned-action'))
        self.run.close()
        self.assertGreater(self.writer.rotated, 0)
        entries = dict(journal.export_entries(self.root))
        self.assertNotIn(b'own-exit', entries['journal/controller.jsonl'])
        index = json.loads(entries['journal/index.json'])
        self.assertEqual(index['ownership']['snapshot']['forms'][0]['status'], 'failed')
        self.assertEqual(self.run.summary()['ownership'], index['ownership'])
        self.assertNotIn('pid', index['ownership']['snapshot'])
        (self.run.path / self.health()['segment']).unlink()
        retained = json.loads(dict(journal.export_entries(self.root))['journal/index.json'])
        self.assertEqual(retained['ownership'], index['ownership'])

    def test_multiple_actor_snapshots_are_ambiguous_not_selected(self):
        with self.admit():
            pass
        second = journal.Writer(self.run.path, self.run.run_id, 'worker-0', self.run.nonce)
        try:
            with journal.bind_sink(second, CASE), journal.ownership_case('flood'):
                journal.ownership_mark('result')
        finally:
            second.close()
        self.run.close()
        self.assertEqual(self.run.summary()['ownership'], {'status': 'ambiguous'})
        index = json.loads(dict(journal.export_entries(self.root))['journal/index.json'])
        self.assertEqual(index['ownership'], {'status': 'ambiguous'})

    def test_projection_preserves_report_verdict_and_counts(self):
        report = {'status': 'fail', 'counts': {'passed': 3, 'failed': 1}}
        with journal.session(self.root, 'owned-report', report) as run:
            with journal.bind_sink(run.writer, CASE), journal.ownership_case('controller'):
                journal.ownership_mark('controller-reaped', status='returned')
        self.assertEqual(report['status'], 'fail')
        self.assertEqual(report['counts'], {'passed': 3, 'failed': 1})
        snapshot = report['diagnostics']['ownership']['snapshot']
        self.assertEqual(snapshot['forms'][0]['cleanup'], 'unavailable')
        self.assertNotIn('pid', journal._json(snapshot).decode())

class PassiveAnnotationTests(unittest.TestCase):
    def test_original_control_flow_assertions_and_deadlines_are_preserved(self):
        expected = {
            '_stop': '4913ce4ec0b26184ef8b44f29876bc6b1d0ad2fb66a0a5560ef4aa026499eed7',
            'execute': '0c0ad3051b7cd529ac8863ab0ccba44e911a9a254b7cf346f272c8ca0099ab7a',
            'assert_descendant_stopped': '1b661396307bfa332760ef1c90f3fb17451a10fd348d8b0e4846603ce3b4ec56',
            'test_term_resistant_grandchild_is_killed_on_every_stop_path': 'ebda8d4500995da02cfb2d08c0a3f9ca82d482cd5ed8670c0110fab7d5f7872c',
        }
        def diagnostic(call, name):
            return (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                    and isinstance(call.func.value, ast.Name) and call.func.value.id == 'diagnostics'
                    and call.func.attr == name)
        class RemoveAnnotations(ast.NodeTransformer):
            def visit_Expr(self, node):
                return None if diagnostic(node.value, 'ownership_mark') else self.generic_visit(node)
            def visit_With(self, node):
                node.items = [item for item in node.items if not diagnostic(item.context_expr, 'ownership_case')]
                return self.generic_visit(node)
        root = Path(__file__).resolve().parents[1]
        seen = set()
        for path in ('.getzilla/getzilla/python_test_runner.py', 'tests/test_python_test_runner.py'):
            tree = ast.parse((root / path).read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name in expected:
                    seen.add(node.name)
                    marks = [item for item in ast.walk(node) if diagnostic(item, 'ownership_mark')]
                    self.assertTrue(marks, 'missing passive marks: ' + node.name)
                    stripped = RemoveAnnotations().visit(node)
                    from tests._stop_annotations import strip_stop_annotations
                    stripped = strip_stop_annotations(stripped)
                    options = {'show_empty': True} if sys.version_info >= (3, 13) else {}
                    digest = hashlib.sha256(ast.dump(stripped, include_attributes=False, **options).encode()).hexdigest()
                    self.assertEqual(digest, expected[node.name], node.name)
        self.assertEqual(seen, set(expected))
