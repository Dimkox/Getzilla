"""New pure QG controls for the exact PHP producer non-applicability result."""
import ctypes
import os
import socket
import subprocess
import sys
import unittest
from contextlib import contextmanager
from getzilla import quality_gates as qg

_ACTIVE = False


def _audit(event, args):
    if _ACTIVE and (event == 'open' or event in ('os.listdir', 'os.scandir', 'os.system', 'os.fork', 'os.posix_spawn')
                    or event.startswith(('socket.', 'subprocess.', 'ctypes.'))):
        raise AssertionError('pure QG fixture denies external effects')


sys.addaudithook(_audit)


@contextmanager
def pure():
    global _ACTIVE
    _ACTIVE = True
    try:
        yield
    finally:
        _ACTIVE = False


def completed():
    # Explicit synthetic result data; no verifier or check producer executes.
    names = ('git-diff-check', 'docs-state-scope', 'change-spec', 'architecture-inputs',
             'architecture', 'governance', 'workflow-artifacts', 'secret-scan', 'contract-structure',
             'sql-safety', 'source-stability', 'opengrep', 'ruff', 'bandit', 'python-unittest', 'coverage')
    return [dict(name=name, status='pass', summary='owned synthetic completed result') for name in names]


class QGPhpNonapplicabilityTests(unittest.TestCase):
    def test_exact_producer_nonapplicability_admitted(self):
        with pure():
            check = dict(name='php-lint', status='skip', summary='no changed PHP files')
            for mode in ('pr', 'release'):
                decision = qg.evaluate_quality_gate(mode=mode, checks=[*completed(), check])
                self.assertEqual(decision.status, 'pass', decision.details)
                self.assertEqual(decision.details, [])
                self.assertFalse(qg.required_check_refused(check, mode=mode))

    def test_other_or_missing_reasons_still_refuse(self):
        with pure():
            for reason in ('', 'no changed php files', 'no changed PHP files ', 'no changed PHP file',
                           'PHP is required to lint changed PHP files', 'php missing', 'tool unavailable'):
                check = dict(name='php-lint', status='skip', summary=reason)
                for mode in ('pr', 'release'):
                    decision = qg.evaluate_quality_gate(mode=mode, checks=[*completed(), check])
                    self.assertEqual(decision.status, 'fail', reason)
                    self.assertEqual([(d['code'], d['path']) for d in decision.details],
                                     [('mandatory-check-skipped', 'php-lint')])
                    self.assertTrue(qg.required_check_refused(check, mode=mode))

    def test_reason_cannot_authorize_another_check(self):
        with pure():
            for name in ('php', 'php-lint-extra', 'unknown-check', 'bandit'):
                check = dict(name=name, status='skip', summary='no changed PHP files')
                self.assertTrue(qg.required_check_refused(check, mode='pr'))

    def test_changed_php_failure_and_other_status_refusals_stay(self):
        with pure():
            for status in ('fail', 'cancelled', 'unknown'):
                for reason in ('no changed PHP files', 'PHP is required to lint changed PHP files', '1 files linted'):
                    check = dict(name='php-lint', status=status, summary=reason)
                    self.assertTrue(qg.required_check_refused(check, mode='pr'))
                    self.assertTrue(qg.required_check_refused(check, mode='release'))
            checks = [c for c in completed() if c['name'] != 'secret-scan']
            checks.append(dict(name='php-lint', status='skip', summary='no changed PHP files'))
            decision = qg.evaluate_quality_gate(mode='pr', checks=checks)
            self.assertIn(('mandatory-check-missing', 'secret-scan'),
                          [(d['code'], d['path']) for d in decision.details])

    def test_fixture_denies_io_native_process_and_network(self):
        with pure():
            for operation in (lambda: open('/etc/hosts'), lambda: os.listdir('/'), socket.socket,
                              lambda: subprocess.run(['true']), lambda: ctypes.CDLL(None)):
                with self.assertRaises(AssertionError):
                    operation()
