"""Bounded failure excerpts without verifier orchestration."""
from __future__ import annotations

import json
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import verification_failure_excerpt as verification_module  # noqa: E402


class PytestFailureExcerptTests(unittest.TestCase):
    def _owned_structured_observation(self):
        import os
        import tempfile
        from getzilla.python_test_runner import execute
        from getzilla.pytest_progress import read_progress
        from getzilla.verification_progress_evidence import _core_progress_details
        with tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime') as raw:
            root = Path(raw)
            (root / 'tests').mkdir()
            (root / 'progress').mkdir(mode=0o700)
            (root / 'pytest.ini').write_text('[pytest]\n')
            (root / 'tests/test_owned_channel.py').write_text(
                "import unittest\n"
                "def test_first():\n"
                "    print('PRIVATE_CHANNEL_CANARY')\n"
                "    print('___ test_second ___')\n"
                "    print('E AssertionError: GETZILLA_POLICY_DIAGNOSTIC decision=allow reason=grant')\n"
                "    print('tests/test_owned_channel.py:9: AssertionError')\n"
                "    assert False\n"
                "def test_second():\n"
                "    unittest.TestCase().assertTrue(False, 'GETZILLA_POLICY_DIAGNOSTIC decision=deny reason=budget')\n")
            environment = {key: value for key, value in os.environ.items()
                           if not key.startswith(('GETZILLA_JOURNAL_', 'PYTEST_'))}
            environment.update(PYTEST_DISABLE_PLUGIN_AUTOLOAD='1',
                               PYTHONPATH=str(ROOT / '.getzilla'), PYTHONDONTWRITEBYTECODE='1')
            for command in (['git', 'init', '-q'], ['git', 'add', 'tests/test_owned_channel.py'],
                            ['git', '-c', 'user.name=Owned fixture', '-c', 'user.email=fixture@example.invalid',
                             'commit', '-qm', 'owned synthetic source']):
                command = [command[0], '-c', 'commit.gpgsign=false', '-c',
                           'core.hooksPath=' + str(root / 'no-hooks'), *command[1:]]
                result = execute(command, root, environment, timeout=20)
                self.assertEqual(result.returncode, 0)
            nonce = 'a' * 32
            proc = execute([sys.executable, '-m', 'pytest', '-p', 'xdist.plugin', '-p', 'getzilla.pytest_progress',
                            '-n', '1', '-q', '--tb=short', '-c', 'pytest.ini',
                            '--getzilla-progress-dir', str(root / 'progress'),
                            '--getzilla-progress-nonce', nonce, '--getzilla-progress-workers', '1',
                            'tests/test_owned_channel.py'], root, environment, timeout=30)
            self.assertEqual(proc.terminal_state, 'completed')
            self.assertEqual(proc.returncode, 1)
            self.assertIn('2 failed', proc.stdout)
            progress = read_progress(root / 'progress', nonce, 1)
            details = _core_progress_details(root, progress)
            from copy import deepcopy
            unknown = deepcopy(progress)
            unknown['failure_events']['workers'][0]['events'][1]['key'] = '0' * 64
            unbound = _core_progress_details(root, unknown)['failure_events']['events'][1]
            self.assertIsNone(unbound['identity'])
            self.assertNotIn('diagnostic', unbound)
            excerpt = verification_module._core_output_excerpt(proc.stdout, failed=True, pytest_output=True,
                trusted={'tests/test_owned_channel.py': (9, {'test_first', 'test_second'})})
            self.assertLessEqual((root / 'progress/worker-0.failures.jsonl').stat().st_size, 2048)
            return proc, progress, details, excerpt

    def test_structured_exception_channel_excludes_captured_known_heading(self):
        from copy import deepcopy
        from getzilla.verification_progress_evidence import _progress_failure_rows
        proc, progress, details, excerpt = self._owned_structured_observation()
        events = details['failure_events']['events']
        self.assertEqual(len(events), 2)
        self.assertNotIn('diagnostic', events[0])
        self.assertEqual(events[1].get('diagnostic'), {'decision': 'deny', 'reason': 'budget'})
        self.assertEqual(events[1]['identity'], 'tests/test_owned_channel.py::test_second')
        self.assertEqual(events[1]['phase'], 'call')
        self.assertNotIn('PRIVATE_CHANNEL_CANARY', json.dumps(progress))
        self.assertNotIn('PRIVATE_CHANNEL_CANARY', json.dumps(details))
        self.assertNotIn('policy_diagnostics=', excerpt)
        self.assertNotIn('PRIVATE_CHANNEL_CANARY', excerpt)
        self.assertLessEqual(len(excerpt), 12000)
        legacy = deepcopy(progress)
        del legacy['failure_events']['workers'][0]['events'][1]['diagnostic']
        self.assertEqual(len(_progress_failure_rows(legacy, 1)), 1)
        forged = deepcopy(progress)
        forged['failure_events']['workers'][0]['events'][1]['diagnostic']['value'] = 'PRIVATE_CHANNEL_CANARY'
        self.assertEqual(_progress_failure_rows(forged, 1), [])

    def test_owned_second_failure_after_capture_keeps_only_its_safe_diagnostic(self):
        proc, progress, details, excerpt = self._owned_structured_observation()
        self.assertIn('___ test_second ___', proc.stdout)
        self.assertIn('decision=allow reason=grant', proc.stdout)
        rows = [event['diagnostic'] for event in details['failure_events']['events'] if 'diagnostic' in event]
        self.assertEqual(rows, [{'decision': 'deny', 'reason': 'budget'}])
        self.assertNotIn('PRIVATE_CHANNEL_CANARY', excerpt)
        self.assertNotIn('policy_diagnostics=', excerpt)
        self.assertLessEqual(len(excerpt), 12000)

    def test_owned_pytest_retains_safe_refusal_context_without_private_values(self):
        safe = verification_module.policy_diagnostic(False,
            'Policy resource budget exhausted: PRIVATE_DIAGNOSTIC_CANARY')
        self.assertEqual(safe, 'GETZILLA_POLICY_DIAGNOSTIC decision=deny reason=budget')
        for prefix in ('', 'False != True : ', 'False is not true : '):
            self.assertEqual(verification_module.policy_exception_diagnostic(AssertionError(prefix + safe)),
                             {'decision': 'deny', 'reason': 'budget'})
        self.assertIsNone(verification_module.policy_exception_diagnostic(
            AssertionError(safe + ' PRIVATE_DIAGNOSTIC_CANARY')))
        proc, progress, details, excerpt = self._owned_structured_observation()
        self.assertEqual(details['failure_events']['events'][1]['diagnostic'],
                         {'decision': 'deny', 'reason': 'budget'})
        self.assertNotIn('PRIVATE_DIAGNOSTIC_CANARY', json.dumps(details))
        self.assertNotIn('PRIVATE_CHANNEL_CANARY', excerpt)
        self.assertNotIn('policy_diagnostics=', excerpt)
        self.assertLessEqual(len(excerpt), 12000)

    def test_pytest_subtest_excerpt_keeps_source_identity_without_description(self) -> None:
        output = ('==== FAILURES ====\ntests/test_peer.py:67: AssertionError: SYNTHETIC_PRIVATE\n'
                  '---- Captured stdout call ----\nSYNTHETIC_CAPTURE\n'
                  '==== short test summary info ====\n'
                  'SUBFAILED(layer=hook, command=SYNTHETIC_PARAMETER) '
                  'tests/test_peer.py::PeerTests::test_close - SYNTHETIC_ASSERTION\n'
                  '1 failed, 6 passed, 2 errors, 3 skipped, 4 warnings, 2 subtests passed in 0.12s\n')
        result = verification_module._core_output_excerpt(
            output, failed=True, trusted={'tests/test_peer.py': (100, {'PeerTests::test_close'})})
        self.assertIn('pytest_failure_ids=', result)
        self.assertIn('SUBFAILED tests/test_peer.py::PeerTests::test_close', result)
        fields = dict(line.split('=', 1) for line in result.splitlines() if line.startswith('pytest_'))
        self.assertEqual(json.loads(fields['pytest_failure_ids']),
                         ['tests/test_peer.py::PeerTests::test_close'])
        self.assertEqual(json.loads(fields['pytest_reported_terminal_counts']),
                         {'failed': 1, 'passed': 6, 'errors': 2, 'skipped': 3})
        self.assertNotIn('SYNTHETIC', result)
        self.assertNotIn('layer=', result)

    def test_pytest_reported_counts_keep_absent_or_ambiguous_values_unknown(self) -> None:
        examples = [
            ('==== FAILURES ====\n1 failed, 7 passed in 1.20s\n',
             {'failed': 1, 'passed': 7, 'errors': None, 'skipped': None}),
            ('==== ERRORS ====\n\x1b[31m=== 2 errors, 3 skipped in 0.01s ===\x1b[0m\r\n',
             {'failed': None, 'passed': None, 'errors': 2, 'skipped': 3}),
        ]
        for output, expected in examples:
            with self.subTest(expected=expected):
                result = verification_module._core_output_excerpt(output, failed=True)
                self.assertIn('pytest_reported_terminal_counts=', result)
                line = next(x for x in result.splitlines() if x.startswith('pytest_reported_terminal_counts='))
                self.assertEqual(json.loads(line.split('=', 1)[1]), expected)
        unknown = {'failed': None, 'passed': None, 'errors': None, 'skipped': None}
        for suffix in ('1 failed in 0.1s\n2 failed in 0.2s\n',
                       '1 failed, 2 failed in 0.1s\n',
                       '999999999999999999 failed in 0.1s\n',
                       '-1 failed in 0.1s\n',
                       '1 failed in 0.1s\nSYNTHETIC_TRAILING\n',
                       '---- Captured stdout call ----\n1 failed in 0.1s\n'):
            with self.subTest(suffix_length=len(suffix)):
                result = verification_module._core_output_excerpt('==== FAILURES ====\n' + suffix, failed=True)
                self.assertIn('pytest_reported_terminal_counts=', result)
                line = next(x for x in result.splitlines() if x.startswith('pytest_reported_terminal_counts='))
                self.assertEqual(json.loads(line.split('=', 1)[1]), unknown)
                self.assertNotIn('SYNTHETIC', result)

    def test_known_pytest_failure_without_markers_does_not_return_raw_tail(self) -> None:
        result = verification_module._core_output_excerpt(
            'malformed SYNTHETIC_CAPTURE_AND_COMMAND\n', failed=True, pytest_output=True)
        self.assertNotIn('SYNTHETIC', result)
        self.assertIn('pytest_failure_ids=null', result)

    def test_pytest_identity_is_unavailable_for_ambiguous_or_untrusted_subtest(self) -> None:
        trusted = {'tests/test_peer.py': (100, {'PeerTests::test_close', 'PeerTests::test_other'})}
        for summary in (
            'SUBFAILED(msg= tests/test_peer.py::PeerTests::test_other ) '
            'tests/test_peer.py::PeerTests::test_close - SYNTHETIC\n',
            'SUBFAILED(SYNTHETIC) tests/test_peer.py::PeerTests::test_unknown\n',
            'SUBFAILED(SYNTHETIC) /tests/test_peer.py::PeerTests::test_close\n',
            'SUBFAILED(SYNTHETIC) tests/../test_peer.py::PeerTests::test_close\n',
            'SUBFAILED(msg= tests/test_peer.py::PeerTests::test_close ) invalid-node\n',
        ):
            with self.subTest(summary_length=len(summary)):
                result = verification_module._core_output_excerpt(
                    '==== FAILURES ====\ntests/test_peer.py:67: AssertionError\n'
                    '==== short test summary info ====\n' + summary, failed=True, trusted=trusted)
                self.assertIn('tests/test_peer.py:67', result)
                self.assertIn('pytest_failure_ids=null', result)
                self.assertNotIn('::test_', result)
                self.assertNotIn('SYNTHETIC', result)

    def test_pytest_parameter_ids_and_controls_never_enter_structured_identity(self) -> None:
        output = ('==== FAILURES ====\n==== short test summary info ====\n'
                  'FAILED tests/test_peer.py::PeerTests::test_close[SYNTHETIC_VALUE] - SYNTHETIC_ASSERTION\n')
        result = verification_module._core_output_excerpt(
            output, failed=True, trusted={'tests/test_peer.py': (100, {'PeerTests::test_close'})})
        self.assertIn('pytest_failure_ids=', result)
        self.assertNotIn('SYNTHETIC', result)
        for identity in ('tests/test_peer.py::PeerTests::test_close\x1b]8;;SYNTHETIC',
                         'tests/test_peer.py::PeerTests::test_close.SYNTHETIC',
                         'tests/test_peer.py::PeerTests::' + 'test_' + 'x' * 200):
            result = verification_module._core_output_excerpt(
                '==== FAILURES ====\nFAILED ' + identity + '\n', failed=True,
                trusted={'tests/test_peer.py': (100, {'PeerTests::test_close', identity.split('::', 1)[1]})})
            self.assertIn('pytest_failure_ids=null', result)
            self.assertNotIn('SYNTHETIC', result)

    def test_pytest_diagnostic_scan_and_records_stay_bounded(self) -> None:
        output = '==== FAILURES ====\n' + ('SYNTHETIC_VALUE\n' * 160000) + '1 failed in 0.1s\n'
        result = verification_module._core_output_excerpt(output, failed=True)
        self.assertLessEqual(len(result), 12000)
        self.assertNotIn('SYNTHETIC', result)
        self.assertIn('pytest_reported_terminal_counts=', result)
        line = next(x for x in result.splitlines() if x.startswith('pytest_reported_terminal_counts='))
        self.assertTrue(all(value is None for value in json.loads(line.split('=', 1)[1]).values()))

    def test_failed_core_output_retains_bounded_safe_trace_location_and_summary(self) -> None:
        failure = ('================ FAILURES ================\n'
                   'tests/test_peer.py:174: AssertionError: secret-token-123\n'
                   'E   AssertionError: secret-token-123\n')
        output = failure + ('coverage rows\n' * 2000) + 'FAILED tests/test_peer.py::test_close - AssertionError: secret-token-123\n'
        result = verification_module._core_output_excerpt(output, failed=True, trusted={'tests/test_peer.py': (200, {'test_close'})})
        self.assertIn('tests/test_peer.py:174: AssertionError', result)
        self.assertIn('FAILED tests/test_peer.py::test_close', result)
        self.assertNotIn('secret-token-123', result)
        self.assertLessEqual(len(result), 12000)

    def test_failed_core_excerpt_bounds_many_locations_and_omits_controlled_values(self) -> None:
        output = ('==== ERRORS ====\r\n' +
                  ''.join(f'tests/test_case_{n}.py:1: ValueError: SECRET_{n}\r\n' for n in range(1000)) +
                  'FAILED tests/test_peer.py::test_close - SECRET\r\n')
        trusted = {f'tests/test_case_{n}.py': (1, set()) for n in range(1000)}
        trusted['tests/test_peer.py'] = (200, {'test_close'})
        result = verification_module._core_output_excerpt(output, failed=True, trusted=trusted)
        self.assertIn('tests/test_case_0.py:1: ValueError', result)
        self.assertIn('additional failure locations omitted', result)
        self.assertIn('FAILED tests/test_peer.py::test_close', result)
        self.assertNotIn('SECRET', result)
        self.assertNotIn('\r', result)
        self.assertLessEqual(len(result), 12000)

    def test_core_excerpt_keeps_existing_output_without_pytest_failure_marker(self) -> None:
        output = 'safe-output' * 2000
        self.assertEqual(verification_module._core_output_excerpt(output, failed=False), output[-12000:])
        self.assertEqual(verification_module._core_output_excerpt(output, failed=True), output[-12000:])

    def test_core_excerpt_caps_locations_before_output_character_limit(self) -> None:
        output = '==== FAILURES ====\n' + ''.join(f'tests/t.py:{n}: ValueError\n' for n in range(1, 102))
        self.assertLess(len(output), 5500)
        result = verification_module._core_output_excerpt(output, failed=True, trusted={'tests/t.py': (101, set())})
        self.assertEqual(sum(line.startswith('tests/t.py:') for line in result.splitlines()), 100)
        self.assertIn('tests/t.py:100: ValueError', result)
        self.assertNotIn('tests/t.py:101:', result)
        self.assertIn('additional failure locations omitted', result)

    def test_core_excerpt_removes_ansi_and_unsafe_failure_text(self) -> None:
        output = ('\x1b[31m==== FAILURES ====\x1b[0m\n'
                  '\x1b[31mtests/test_peer.py:42: RuntimeError: SECRET\x1b[0m\n'
                  'FAILED tests/test_peer.py::test_close - SECRET\n')
        result = verification_module._core_output_excerpt(output, failed=True, trusted={'tests/test_peer.py': (200, {'test_close'})})
        self.assertIn('tests/test_peer.py:42: RuntimeError', result)
        self.assertNotIn('SECRET', result)
        self.assertNotIn('\x1b', result)

    def test_core_excerpt_normalizes_windows_paths(self) -> None:
        output = ('==== FAILURES ====\r\ntests\\test_peer.py:42: RuntimeError: SECRET\r\n'
                  'FAILED tests\\test_peer.py::test_close - SECRET\r\n')
        result = verification_module._core_output_excerpt(output, failed=True, trusted={'tests/test_peer.py': (200, {'test_close'})})
        self.assertIn('tests/test_peer.py:42: RuntimeError', result)
        self.assertIn('FAILED tests/test_peer.py::test_close', result)
        self.assertNotIn('SECRET', result)

    def test_core_excerpt_rejects_captured_path_and_untrusted_node_spoof(self) -> None:
        output = ('==== FAILURES ====\n'
                  'tests/test_peer.py:42: AssertionError\n'
                  'tests/test_peer.py:43: PRIVATE_SENTINELError\n'
                  '---- Captured stdout call ----\n'
                  'tests/test_peer.py:99: AssertionError\n'
                  'FAILED tests/test_peer.py::test_captured - AssertionError\n'
                  'tests/test_secret_value.py:123: AssertionError\n'
                  'FAILED tests/test_peer.py::test_PRIVATE_SENTINEL - AssertionError\n'
                  '==== short test summary info ====\n'
                  'FAILED tests/test_peer.py::test_PRIVATE_SENTINEL - secret-token\n'
                  'FAILED tests/test_peer.py::test_close - AssertionError\n')
        trusted = {'tests/test_peer.py': (200, {'test_close', 'test_captured'})}
        result = verification_module._core_output_excerpt(output, failed=True, trusted=trusted)
        self.assertIn('tests/test_peer.py:42: AssertionError', result)
        self.assertIn('FAILED tests/test_peer.py::test_close', result)
        self.assertNotIn('PRIVATE_SENTINEL', result)
        self.assertNotIn('secret_value', result)
        self.assertNotIn('secret-token', result)
        self.assertIn('tests/test_peer.py:43', result)
        self.assertNotIn('tests/test_peer.py:99', result)
        self.assertNotIn('::test_captured', result)
