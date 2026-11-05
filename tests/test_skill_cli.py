"""Public skill CLI preserves unknown custody without private exception text."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.component_state import ComponentTransaction  # noqa: E402
from tests import test_skill_onboarding as onboarding_tests  # noqa: E402

SPEC = importlib.util.spec_from_file_location('getzilla_skill_cli_contract_tests', ROOT / 'scripts/getzilla_skill_preflight.py')
CLI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLI)


class SkillCliTests(unittest.TestCase):
    def fixture(self, *, approve=True):
        fixture = onboarding_tests.PublicationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        if approve:
            fixture.grant()
        return fixture

    def invoke(self, fixture):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = CLI.main(['install', 'intake/example', '--root', str(fixture.root)])
        return code, json.loads(stdout.getvalue()), stdout.getvalue() + stderr.getvalue()

    def test_real_cli_retains_unverifiable_completion_for_valueerror_and_io_cause(self):
        for primary in (ValueError, OSError):
            with self.subTest(primary=primary.__name__):
                fixture = self.fixture()
                private = 'PRIVATE_CLI_ERROR /private/fixture-location payload=do-not-print'
                error = primary(private)
                write, read = ComponentTransaction.write, ComponentTransaction.read
                completed, failed_reads = [], []

                def lose_completion(transaction, name, content, mode, *, expected):
                    result = write(transaction, name, content, mode, expected=expected)
                    if name.endswith('/skill-publications/example.json') and json.loads(content)['status'] == 'complete':
                        completed.append(True)
                        raise error
                    return result

                def unavailable(transaction, name, **kwargs):
                    if completed and name.endswith('/skill-publications/example.json'):
                        failed_reads.append(True)
                        raise OSError(private)
                    return read(transaction, name, **kwargs)

                with mock.patch.object(ComponentTransaction, 'write', lose_completion), \
                        mock.patch.object(ComponentTransaction, 'read', unavailable):
                    code, result, output = self.invoke(fixture)
                self.assertEqual(code, 2)
                self.assertEqual(len(completed), 1)
                self.assertEqual(len(failed_reads), 2)
                self.assertEqual(error.publication_state, 'unknown')
                self.assertEqual(result['status'], 'unknown')
                self.assertEqual(result['reason'], 'PUBLICATION_CUSTODY_UNKNOWN')
                self.assertEqual(result['publication_state'], 'unknown')
                self.assertTrue(result['inspection_required'])
                self.assertFalse(result['retryable'])
                self.assertFalse(result['permissions_granted'])
                self.assertFalse(result['evidence_valid'])
                self.assertNotIn(private, output)
                self.assertNotIn(str(fixture.root), output)
                self.assertNotIn('PRIVATE_CLI_ERROR', output)
                # Serialization must not rewrite markers or claim restored denial.
                marker = fixture.root / '.getzilla/runtime/skill-publications/example.json'
                self.assertEqual(json.loads(marker.read_bytes())['status'], 'complete')
                self.assertFalse((fixture.root / '.agents').exists())

    def test_actual_cli_subprocess_success_stays_inert_and_ordinary_refusal_compatible(self):
        fixture = self.fixture(approve=False)
        command = [sys.executable, str(ROOT / 'scripts/getzilla_skill_preflight.py'),
                   'install', 'intake/example', '--root', str(fixture.root)]
        refused = subprocess.run(command, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'},
                                 capture_output=True, timeout=30, check=False)
        result = json.loads(refused.stdout)
        self.assertEqual(refused.returncode, 2)
        self.assertEqual(result, {'schema_version': 1, 'status': 'refused', 'reason': 'APPROVAL_REQUIRED',
                                  'reasons': [], 'permissions_granted': False, 'evidence_valid': False})
        fixture.grant()
        success = subprocess.run(command, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'},
                                 capture_output=True, timeout=30, check=False)
        result = json.loads(success.stdout)
        self.assertEqual(success.returncode, 0, success.stderr)
        self.assertEqual(result['status'], 'staged')
        self.assertEqual(result['activation'], 'unsupported')
        self.assertFalse(result['activated'])
        self.assertFalse(result['permissions_granted'])
        self.assertEqual((fixture.root / result['destination'] / 'SKILL.md').read_bytes(),
                         dict(fixture.source.files)['SKILL.md'])
        self.assertFalse((fixture.root / '.agents').exists())

    def test_actual_cli_redacts_an_ordinary_private_io_refusal(self):
        fixture = self.fixture()
        private = 'PRIVATE_IO_DETAIL /private/root payload=never-print'
        original = ComponentTransaction.write

        def private_failure(transaction, name, content, mode, *, expected):
            if name.endswith('/skill-publications/example.json'):
                raise OSError(private)
            return original(transaction, name, content, mode, expected=expected)

        with mock.patch.object(ComponentTransaction, 'write', private_failure):
            code, result, output = self.invoke(fixture)
        self.assertEqual(code, 2)
        self.assertEqual(result['status'], 'refused')
        self.assertEqual(result['reason'], 'AUTHORITY_OR_INPUT_REFUSED')
        self.assertNotIn('publication_state', result)
        self.assertNotIn('inspection_required', result)
        self.assertNotIn(private, output)
        self.assertNotIn(str(fixture.root), output)
        self.assertFalse((fixture.root / '.agents').exists())

    def test_wrapped_context_cycles_and_deep_causes_have_bounded_safe_unknown_output(self):
        fixture = self.fixture()
        private = 'PRIVATE_CHAIN_DETAIL /private/context/location'
        leaf = ValueError(private)
        leaf.publication_state = 'unknown'
        context = ValueError(private)
        context.__context__ = leaf
        cycle = ValueError(private)
        cycle.__cause__ = leaf
        leaf.__context__ = cycle
        deep = ValueError(private)
        for _ in range(32):
            wrapper = ValueError(private)
            wrapper.__cause__ = deep
            deep = wrapper
        for failure in (context, cycle, deep):
            with self.subTest(shape=type(failure).__name__), \
                    mock.patch.object(CLI, 'install_external', side_effect=failure):
                code, result, output = self.invoke(fixture)
                self.assertEqual(code, 2)
                self.assertEqual(result['status'], 'unknown')
                self.assertTrue(result['inspection_required'])
                self.assertFalse(result['retryable'])
                self.assertFalse(result['permissions_granted'])
                self.assertNotIn(private, output)
        self.assertFalse((fixture.root / '.agents').exists())

    def test_unknown_diagnostic_never_formats_private_exception_text_or_notes(self):
        class PrivateValueError(ValueError):
            def __str__(self):
                raise AssertionError('unknown serialization formatted private error')

        fixture = self.fixture()
        failure = PrivateValueError('PRIVATE_ERROR_BODY')
        failure.publication_state = 'unknown'
        failure.__notes__ = ['PRIVATE_NOTE /private/never-print']
        with mock.patch.object(CLI, 'install_external', side_effect=failure):
            code, result, output = self.invoke(fixture)
        self.assertEqual(code, 2)
        self.assertEqual(result['reason'], 'PUBLICATION_CUSTODY_UNKNOWN')
        self.assertEqual(result['reasons'], [])
        self.assertNotIn('PRIVATE', output)
        self.assertNotIn(str(fixture.root), output)
        self.assertFalse((fixture.root / '.agents').exists())

    def test_unrecognized_exception_data_cannot_serialize_raw_attributes(self):
        fixture = self.fixture()
        failure = ValueError('PRIVATE_DETAIL /private/ordinary/path')
        failure.private_payload = {'PRIVATE_ATTRIBUTE': 'never-print'}
        failure.__notes__ = ['PRIVATE_NOTE publication_state=unknown']
        with mock.patch.object(CLI, 'install_external', side_effect=failure):
            code, result, output = self.invoke(fixture)
        self.assertEqual(code, 2)
        self.assertEqual(result['status'], 'refused')
        self.assertEqual(result['reason'], 'AUTHORITY_OR_INPUT_REFUSED')
        self.assertNotIn('inspection_required', result)
        self.assertNotIn('PRIVATE', output)

    def test_actual_main_reports_unknown_interrupts_and_preserves_original_exceptions(self):
        class DirectInterruption(BaseException):
            pass

        for error in (KeyboardInterrupt('PRIVATE_INTERRUPT'), SystemExit(37), DirectInterruption('PRIVATE_BASE_EXIT')):
            with self.subTest(kind=type(error).__name__):
                fixture = self.fixture()
                write, read = ComponentTransaction.write, ComponentTransaction.read
                completed, failures = [], []
                stdout, stderr = io.StringIO(), io.StringIO()

                def complete_then_interrupt(transaction, name, content, mode, *, expected):
                    result = write(transaction, name, content, mode, expected=expected)
                    if name.endswith('/skill-publications/example.json') and json.loads(content)['status'] == 'complete':
                        completed.append(True)
                        raise error
                    return result

                def unavailable(transaction, name, **kwargs):
                    if completed and name.endswith('/skill-publications/example.json'):
                        failures.append(True)
                        raise OSError('PRIVATE_UNAVAILABLE /private/observation')
                    return read(transaction, name, **kwargs)

                with mock.patch.object(ComponentTransaction, 'write', complete_then_interrupt), \
                        mock.patch.object(ComponentTransaction, 'read', unavailable), \
                        contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    try:
                        CLI.main(['install', 'intake/example', '--root', str(fixture.root)])
                    except BaseException as observed:
                        self.assertIs(observed, error)
                    else:
                        self.fail('CLI swallowed the original interruption')
                self.assertEqual(len(failures), 2)
                result = json.loads(stdout.getvalue())
                self.assertEqual(result['status'], 'unknown')
                self.assertTrue(result['inspection_required'])
                self.assertFalse(result['retryable'])
                self.assertNotIn('PRIVATE', stdout.getvalue() + stderr.getvalue())
                self.assertFalse((fixture.root / '.agents').exists())

    def subprocess_fault(self, kind, *, unknown=True):
        fixture = self.fixture()
        driver = r'''
import json,runpy,sys
from pathlib import Path
from getzilla.component_state import ComponentTransaction
class DirectInterruption(BaseException):
    pass
script,root,kind,mode=sys.argv[1:]
private='PRIVATE_CHILD_DETAIL /private/child-location payload=never-print'
errors={'keyboard':KeyboardInterrupt(private),'system':SystemExit(37),'zero':SystemExit(0),
        'none':SystemExit(None),'wide':SystemExit(256),'too-wide':SystemExit(2**64),
        'system-text':SystemExit(private),'custom':DirectInterruption(private),
        'value':ValueError(private),'io':OSError(private)}
error=errors[kind]
write,read=ComponentTransaction.write,ComponentTransaction.read
complete=[]
def lose_completion(transaction,name,content,permissions,*,expected):
    result=write(transaction,name,content,permissions,expected=expected)
    if name.endswith('/skill-publications/example.json') and json.loads(content)['status']=='complete':
        complete.append(True)
        raise error
    return result
def observe(transaction,name,**kwargs):
    if mode=='unknown' and complete and name.endswith('/skill-publications/example.json'):
        raise OSError(private)
    return read(transaction,name,**kwargs)
ComponentTransaction.write=lose_completion
ComponentTransaction.read=observe
sys.argv=[script,'install','intake/example','--root',root]
runpy.run_path(script,run_name='__main__')
'''
        result = subprocess.run([sys.executable, '-c', driver, str(ROOT / 'scripts/getzilla_skill_preflight.py'),
                                 str(fixture.root), kind, 'unknown' if unknown else 'ordinary'],
                                env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}, capture_output=True,
                                timeout=30, check=False)
        self.assertFalse((fixture.root / '.agents').exists())
        return result, fixture

    def test_actual_terminal_unknown_exits_preserve_failure_semantics_without_private_output(self):
        for kind, expected in (('keyboard', 130), ('system', 37), ('custom', 1),
                               ('value', 2), ('io', 2), ('zero', 1), ('none', 1),
                               ('wide', 256 if os.name == 'nt' else 1), ('too-wide', 1), ('system-text', 1)):
            with self.subTest(kind=kind):
                process, fixture = self.subprocess_fault(kind)
                self.assertEqual(process.returncode, expected)
                self.assertNotEqual(process.returncode, 0)
                result = json.loads(process.stdout)
                self.assertEqual(result['status'], 'unknown')
                self.assertEqual(result['reason'], 'PUBLICATION_CUSTODY_UNKNOWN')
                self.assertTrue(result['inspection_required'])
                self.assertFalse(result['retryable'])
                self.assertNotIn(b'PRIVATE', process.stdout + process.stderr)
                self.assertNotIn(str(fixture.root).encode(), process.stdout + process.stderr)
                self.assertEqual(process.stderr, b'')
                marker = fixture.root / '.getzilla/runtime/skill-publications/example.json'
                self.assertEqual(json.loads(marker.read_bytes())['status'], 'complete')

    def test_ordinary_terminal_interrupt_exit_and_parser_help_keep_existing_behavior(self):
        keyboard, _ = self.subprocess_fault('keyboard', unknown=False)
        self.assertNotEqual(keyboard.returncode, 0)
        self.assertEqual(keyboard.stdout, b'')
        self.assertIn(b'KeyboardInterrupt', keyboard.stderr)
        for kind, expected in (('system', 37), ('zero', 0)):
            process, _ = self.subprocess_fault(kind, unknown=False)
            self.assertEqual(process.returncode, expected)
            self.assertEqual(process.stdout, b'')
            self.assertEqual(process.stderr, b'')
        script = str(ROOT / 'scripts/getzilla_skill_preflight.py')
        help_result = subprocess.run([sys.executable, script, '--help'], capture_output=True, check=False, timeout=15)
        self.assertEqual(help_result.returncode, 0)
        self.assertIn(b'usage:', help_result.stdout)
        parser_result = subprocess.run([sys.executable, script, '--not-an-operation'],
                                       capture_output=True, check=False, timeout=15)
        self.assertEqual(parser_result.returncode, 2)
        self.assertIn(b'usage:', parser_result.stderr)
