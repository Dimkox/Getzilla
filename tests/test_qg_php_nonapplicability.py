"""New pure QG controls for the exact PHP producer non-applicability result."""
import ctypes
import os
import socket
import subprocess
import sys
import unittest
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock
from getzilla import quality_gates as qg
from getzilla import verification_plan

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


def owned_admission(mode, checks, *, php_required):
    """Declare only this synthetic no-PHP/no-feed world, before the pure guard."""
    changed_php_files = ['owned-required.php'] if php_required else []
    rows = [verification_plan.obligation(check['name'],
            required=check['name'] != 'php-lint' or php_required,
            evidence={'kind': 'owned-unit-applicability', 'changed_php_files': changed_php_files})
            for check in checks]
    policy = {'schema_version': 1, 'inputs': {}, 'implementation': {}}
    policy['digest'] = verification_plan.digest(policy)
    with mock.patch.object(verification_plan, 'policy_binding', return_value=policy):
        plan = verification_plan.build_required_plan(Path('owned-php-unit-fixture'), mode=mode,
            context={'fixture': 'php-nonapplicability'}, source={'kind': 'owned-synthetic'},
            inventory={'changed_php_files': changed_php_files}, risk={}, selection={}, extra_obligations=rows)
    for check in checks:
        check['details'] = []
        verification_plan.bind_result(plan, check)
    def no_data_sources(source, **options):
        raise AssertionError('owned PHP unit fixture declares no external data sources')
    return dict(required_plan=plan, current_binding=plan['binding'],
                now_utc=datetime(2026, 11, 17, tzinfo=timezone.utc), data_source_validator=no_data_sources)


class QGPhpNonapplicabilityTests(unittest.TestCase):
    def test_exact_producer_nonapplicability_admitted(self):
        check = dict(name='php-lint', status='skip', summary='no changed PHP files')
        for mode in ('pr', 'release'):
            checks = [*completed(), check]
            admission = owned_admission(mode, checks, php_required=False)
            with pure():
                decision = qg.evaluate_quality_gate(mode=mode, checks=checks, **admission)
                self.assertEqual(decision.status, 'pass', decision.details)
                self.assertEqual(decision.details, [])
                self.assertFalse(qg.required_check_refused(check, mode=mode))
            required_checks = [*completed(), check]
            required_admission = owned_admission(mode, required_checks, php_required=True)
            with pure():
                required = qg.evaluate_quality_gate(mode=mode, checks=required_checks, **required_admission)
                self.assertEqual(required.status, 'fail')
                self.assertEqual([(d['code'], d['path']) for d in required.details],
                                 [('required-check-unverified', 'php-lint')])

    def test_other_or_missing_reasons_still_refuse(self):
        for reason in ('', 'no changed php files', 'no changed PHP files ', 'no changed PHP file',
                       'PHP is required to lint changed PHP files', 'php missing', 'tool unavailable'):
            check = dict(name='php-lint', status='skip', summary=reason)
            for mode in ('pr', 'release'):
                checks = [*completed(), check]
                admission = owned_admission(mode, checks, php_required=True)
                with pure():
                    decision = qg.evaluate_quality_gate(mode=mode, checks=checks, **admission)
                    self.assertEqual(decision.status, 'fail', reason)
                    self.assertEqual([(d['code'], d['path']) for d in decision.details
                                      if d['code'].startswith('mandatory-')],
                                     [('mandatory-check-skipped', 'php-lint')])
                    self.assertEqual([(d['code'], d['path']) for d in decision.details],
                                     [('required-check-unverified', 'php-lint'),
                                      ('mandatory-check-skipped', 'php-lint')])
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
