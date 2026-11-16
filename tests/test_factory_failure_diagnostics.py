"""New closed observation fixtures; never execute an installed Factory suite."""
from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import verification_failure_excerpt as excerpt

CANARY = 'PRIVATE_FACTORY_ASSERTION_CANARY_71'


def facts():
    return {'status': 'fail', 'collected': 4, 'executed': ['one', 'two'],
            'skipped': [{'reason': CANARY}], 'required_ids': ['one', 'two'],
            'failures': 1, 'errors': 0, 'loader_errors': 0,
            'unqualified_skips': [], 'missing_required': [], 'source_stable': True,
            'problems': [{'id': 'factory.tests.test_owned.' + CANARY,
                          'phase': 'case', 'kind': 'failure', 'exception': 'AssertionError',
                          'frames': [{'path': CANARY, 'line': 9}], 'raw_message': CANARY}],
            'summary': CANARY, 'stdout': CANARY, 'stderr': CANARY,
            'binding': {'private': CANARY}}


class FactoryFailureDiagnosticTests(unittest.TestCase):
    def helpers(self):
        names = ('factory_diagnostic', 'factory_assertion_message',
                 'factory_exception_diagnostic', 'valid_factory_diagnostic')
        self.assertTrue(all(callable(getattr(excerpt, name, None)) for name in names),
                        'closed Factory diagnostic channel is absent')
        return excerpt

    def test_closed_counts_hashes_and_no_private_values(self):
        helper = self.helpers()
        source = facts()
        value = helper.factory_diagnostic(source, outcome='fail',
                    digests={'collected_ids': 'a' * 64, 'source_inventory': 'b' * 64})
        self.assertTrue(helper.valid_factory_diagnostic(value))
        self.assertEqual(value['reason'], 'test-problems')
        self.assertEqual(value['counts']['executed'], 2)
        self.assertEqual(value['counts']['skipped'], 1)
        self.assertEqual(value['problems'][0]['id_sha256'],
                         hashlib.sha256(source['problems'][0]['id'].encode()).hexdigest())
        self.assertEqual(value['problems'][0]['exception'], 'AssertionError')
        self.assertEqual(value['digests']['source_inventory'], 'b' * 64)
        self.assertNotIn(CANARY, json.dumps(value))
        self.assertGreater(value['omitted']['fields'], 0)

    def test_only_real_builtin_assertion_exact_closed_value(self):
        helper = self.helpers()
        value = helper.factory_diagnostic(facts())
        message = helper.factory_assertion_message({'factory_diagnostic': value})
        case = unittest.TestCase()
        with patch.object(case, 'longMessage', False), self.assertRaises(AssertionError) as caught:
            case.assertEqual({'private': CANARY}, 'pass', message)
        self.assertEqual(helper.factory_exception_diagnostic(caught.exception), value)
        self.assertNotIn(CANARY, str(caught.exception))
        class Impostor:
            args = (message,)
        class Subclass(AssertionError):
            pass
        for error in (message, RuntimeError(message), Impostor(), Subclass(message),
                      AssertionError(message, CANARY), AssertionError(message + CANARY)):
            self.assertIsNone(helper.factory_exception_diagnostic(error))
        forged = copy.deepcopy(value)
        forged['raw_stdout'] = CANARY
        self.assertFalse(helper.valid_factory_diagnostic(forged))
        self.assertIsNone(helper.factory_exception_diagnostic(
            AssertionError('GETZILLA_FACTORY_DIAGNOSTIC ' + json.dumps(forged))))

    def test_bounded_omissions_and_closed_problem_types(self):
        helper = self.helpers()
        source = facts()
        source['problems'] *= 9
        source['problems'][0]['exception'] = CANARY
        value = helper.factory_diagnostic(source)
        self.assertLessEqual(len(value['problems']), 1)
        self.assertEqual(value['omitted']['problems'], 8)
        self.assertEqual(value['problems'][0]['exception'], 'other')
        self.assertNotIn(CANARY, helper.factory_assertion_message(source))
        self.assertLessEqual(len(json.dumps(value, separators=(',', ':')).encode()), 768)
        invalid = copy.deepcopy(value)
        invalid['counts']['collected'] = True
        self.assertFalse(helper.valid_factory_diagnostic(invalid))
        invalid = copy.deepcopy(value)
        invalid['problems'][0]['exception'] = CANARY
        self.assertFalse(helper.valid_factory_diagnostic(invalid))

    def progress_fixture(self):
        from getzilla import pytest_progress as progress
        temporary = tempfile.TemporaryDirectory(prefix='new-factory-diagnostic-', dir=ROOT / '.getzilla/runtime')
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        writer = progress._WorkerProgress(directory, '9' * 32, 0)
        self.addCleanup(writer.pytest_unconfigure, None)
        return progress, directory, writer

    def send(self, writer, error, node='tests/test_new_owned_factory.py::Owned::test_failure'):
        call = SimpleNamespace(when='call', excinfo=None if error is None else SimpleNamespace(value=error))
        hook = writer.pytest_runtest_makereport(SimpleNamespace(nodeid=node), call)
        next(hook)
        with self.assertRaises(StopIteration):
            next(hook)
        writer.pytest_runtest_logreport(SimpleNamespace(failed=True, when='call', nodeid=node,
            sections=[('Captured stdout', CANARY)], longrepr=CANARY))

    def test_owned_lifecycle_stream_and_closed_consumer(self):
        helper = self.helpers()
        progress, directory, writer = self.progress_fixture()
        value = helper.factory_diagnostic(facts())
        self.send(writer, None)  # Captured sections/longrepr never supply diagnostics.
        self.send(writer, AssertionError('GETZILLA_POLICY_DIAGNOSTIC decision=deny reason=budget'))
        self.send(writer, AssertionError(helper.factory_assertion_message({'factory_diagnostic': value})))
        writer.pytest_unconfigure(None)
        observation = progress.read_progress(directory, '9' * 32, 1)
        from getzilla.verification_progress_evidence import _progress_failure_rows, _failure_progress_details
        rows = _progress_failure_rows(observation, 1)
        self.assertEqual(len(rows), 1)
        events = rows[0]['events']
        self.assertNotIn('diagnostic', events[0])
        self.assertEqual(events[1]['diagnostic'], {'decision': 'deny', 'reason': 'budget'})
        self.assertEqual(events[2]['diagnostic'], value)
        node = 'tests/test_new_owned_factory.py::Owned::test_failure'
        identity = {progress._node_identity(node): node}
        rendered = _failure_progress_details(rows, identity, 1)
        self.assertTrue(rendered['prefix_only'])
        self.assertEqual(rendered['events'][2]['diagnostic'], value)
        self.assertNotIn(CANARY, json.dumps(rendered))
        self.assertNotIn(CANARY.encode(), (directory / 'worker-0.failures.jsonl').read_bytes())

    def test_fixed_stream_budget_explicit_diagnostic_omissions(self):
        helper = self.helpers()
        progress, directory, writer = self.progress_fixture()
        value = helper.factory_diagnostic(facts(), digests={'collected_ids': 'a' * 64,
                                                          'source_inventory': 'b' * 64})
        for _ in range(4):
            self.send(writer, AssertionError(helper.factory_assertion_message({'factory_diagnostic': value})))
        writer.pytest_unconfigure(None)
        observation = progress.read_progress(directory, '9' * 32, 1)
        events = observation['failure_events']['workers'][0]['events']
        self.assertEqual(len(events), 4)
        self.assertTrue(any(event.get('diagnostic_omitted') is True for event in events))
        self.assertEqual(progress.MAX_FAILURE_BYTES, 2048)
        self.assertEqual(progress.MAX_FAILURE_EVENTS, 4)
        self.assertLessEqual((directory / 'worker-0.failures.jsonl').stat().st_size, 2048)

    def test_optional_old_helper_preserves_policy_and_primary_report(self):
        helper = self.helpers()
        progress, directory, writer = self.progress_fixture()
        with patch.object(helper, 'factory_exception_diagnostic', None):
            self.send(writer, AssertionError('GETZILLA_POLICY_DIAGNOSTIC decision=deny reason=grant'))
            self.send(writer, AssertionError(helper.factory_assertion_message(facts())))
        writer.pytest_unconfigure(None)
        events = progress.read_progress(directory, '9' * 32, 1)['failure_events']['workers'][0]['events']
        self.assertEqual(events[0]['diagnostic'], {'decision': 'deny', 'reason': 'grant'})
        self.assertNotIn('diagnostic', events[1])

    def test_installed_complete_inventory_predicate_and_deadline_retained(self):
        self.helpers()
        tree = ast.parse((ROOT / 'tests/test_installer.py').read_bytes())
        method = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
            and node.name == 'test_archived_engine_verifier_runs_complete_installed_factory_inventory')
        source = ast.get_source_segment((ROOT / 'tests/test_installer.py').read_text(), method)
        self.assertIn('verification._factory_unit(root)[0]', source)
        self.assertIn('timeout=180', source)
        self.assertNotIn("patch.object(verification", source)
        assertions = [node for node in ast.walk(method) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute) and node.func.attr == 'assertEqual'
            and len(node.args) == 3 and isinstance(node.args[0], ast.Subscript)
            and isinstance(node.args[0].value, ast.Name) and node.args[0].value.id == 'evidence']
        status = next(node for node in assertions if isinstance(node.args[0].slice, ast.Constant)
                      and node.args[0].slice.value == 'status')
        self.assertEqual(status.args[1].value, 'pass')
        self.assertIsInstance(status.args[2], ast.Call)
        self.assertIn("'longMessage', False", source)

    def test_optional_helper_interception_covers_real_import_shapes(self):
        # Observe Python's import calling convention using a new closed module,
        # without loading or executing the retained availability test body.
        seen = []
        def capture(name, globals=None, locals=None, fromlist=(), level=0):
            seen.append((name, fromlist, level))
            return SimpleNamespace(verification_failure_excerpt=object())
        exec('from . import verification_failure_excerpt',
             {'__builtins__': {'__import__': capture}, '__package__': 'owned_fixture'})
        self.assertEqual(seen, [('', ('verification_failure_excerpt',), 1)])
        tree = ast.parse((ROOT / 'tests/test_verification_failure_excerpt.py').read_bytes())
        method = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
            and node.name == 'test_progress_import_survives_unavailable_optional_diagnostic_helper')
        hook = next(node for node in method.body if isinstance(node, ast.FunctionDef)
                    and node.name == 'without_helper')
        condition = next(node.test for node in hook.body if isinstance(node, ast.If))
        terms = {ast.unparse(node) for node in ast.walk(condition) if isinstance(node, ast.Compare)}
        self.assertIn("name.rsplit('.', 1)[-1] == 'verification_failure_excerpt'", terms)
        self.assertIn("'verification_failure_excerpt' in (kwargs.get('fromlist') or ())", terms)
        self.assertIn("'verification_failure_excerpt' in (args[2] or ())", terms)
        self.assertIn('len(args) >= 3', terms)
        assertions = {ast.unparse(node) for node in ast.walk(method) if isinstance(node, ast.Call)}
        self.assertIn('self.assertIsNone(holder._pending_diagnostic)', assertions)
        self.assertIn("self.assertEqual(len(blocked), 1, 'helper is attempted only inside the guarded diagnostic hook')",
                      assertions)

    def test_nullable_fromlist_predicate_uses_closed_import_records(self):
        tree = ast.parse((ROOT / 'tests/test_verification_failure_excerpt.py').read_bytes())
        method = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
            and node.name == 'test_progress_import_survives_unavailable_optional_diagnostic_helper')
        hook = next(node for node in method.body if isinstance(node, ast.FunctionDef)
                    and node.name == 'without_helper')
        condition = next(node.test for node in hook.body if isinstance(node, ast.If))
        # Evaluate only the source predicate, never the old method/hook body or
        # any import. Records are new closed fixtures of Python import arguments.
        code = compile(ast.Expression(condition), '<owned-import-predicate>', 'eval')
        cases = [('hashlib', (), {}, False),
                 ('hashlib', (None, None, None, 0), {}, False),
                 ('hashlib', (), {'fromlist': None}, False),
                 ('verification_failure_excerpt', (None, None, None), {}, True)]
        for value in ([], (), ['other'], ('other',),
                      ['verification_failure_excerpt'], ('verification_failure_excerpt',)):
            expected = 'verification_failure_excerpt' in value
            cases.extend([('', (None, None, value, 1), {}, expected),
                          ('getzilla', (), {'fromlist': value}, expected)])
        for name, args, kwargs, expected in cases:
            with self.subTest(name=name, args=args, kwargs=kwargs):
                try:
                    actual = eval(code, {'__builtins__': {'len': len}},
                                  {'name': name, 'args': args, 'kwargs': kwargs})
                except TypeError:
                    self.fail('valid nullable import shape raised TypeError')
                self.assertIs(actual, expected)


if __name__ == '__main__':
    unittest.main()
