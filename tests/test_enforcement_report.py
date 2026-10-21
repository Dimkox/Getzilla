"""E01 and E04: report the enforcement actually in effect; plan branch protection without sending anything."""
from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla'), str(ROOT / 'scripts')]

from getzilla import ci_gate  # noqa: E402
from getzilla.enforcement import inspect_enforcement, installed_hooks  # noqa: E402
from tests._support import project_copy  # noqa: E402
import getzilla_ci  # noqa: E402

PROTECTED = {'required_status_checks': {'strict': True, 'contexts': ['linux', 'windows']}}


class EnforcementReportTests(unittest.TestCase):
    def test_hooks_only_is_advisory_and_unknown_protection_is_not_counted(self) -> None:
        report = inspect_enforcement(ROOT, run_self_test=False)  # read-only: no hook is run
        self.assertEqual(report.level, 'advisory')
        self.assertEqual(report.branch_protection['state'], 'unknown')
        self.assertTrue(any('not counted as enforced' in note for note in report.notes))
        self.assertTrue({'claude', 'codex', 'qwen', 'gemini', 'grok', 'copilot'} <= set(installed_hooks(ROOT)))
        self.assertEqual(report.ci_workflow, '.github/workflows/getzilla.yml')

    def test_protection_requiring_the_checks_is_ci_enforced(self) -> None:
        report = inspect_enforcement(ROOT, slug='o/r', github=lambda path: PROTECTED, run_self_test=False)
        self.assertEqual(report.level, 'ci-enforced')
        self.assertTrue(report.branch_protection['requires_getzilla'])
        self.assertTrue(any('enforce_admins is off' in note for note in report.notes))
        strict_admins = {**PROTECTED, 'enforce_admins': {'enabled': True}}
        quiet = inspect_enforcement(ROOT, slug='o/r', github=lambda path: strict_admins, run_self_test=False)
        self.assertFalse(any('enforce_admins' in note for note in quiet.notes))
        trust = {'required_status_checks': {'strict': True, 'contexts': ['linux', 'windows', 'getzilla-trust-ci']}}
        self.assertEqual(inspect_enforcement(ROOT, slug='o/r', github=lambda path: trust, run_self_test=False).level,
                         'external')

    def test_unprotected_or_partial_protection_stays_advisory(self) -> None:
        for answer in ({'_status': 404}, {'required_status_checks': {'strict': True, 'contexts': ['linux']}}):
            with self.subTest(answer=answer):
                report = inspect_enforcement(ROOT, slug='o/r', github=lambda path, a=answer: a, run_self_test=False)
                self.assertEqual(report.level, 'advisory')

    def test_self_test_proves_the_policy_runs(self) -> None:
        with project_copy() as root:
            (root / '.claude').mkdir(exist_ok=True)
            (root / '.claude' / 'settings.json').write_text('{"hooks": "pre_tool_use.py stop_gate.py"}', encoding='utf-8')
            # This product API spawns hooks directly, so bind both calls to the fixture.
            fixture_path = os.pathsep.join((str(root), str(root / '.getzilla')))
            with mock.patch.dict(os.environ, {'PYTHONPATH': fixture_path}):
                report = inspect_enforcement(root)
                self.assertEqual(report.self_test['status'], 'pass', report.self_test)
                (root / '.getzilla/getzilla/policy.py').write_text('raise ImportError("broken")\n', encoding='utf-8')
                broken = inspect_enforcement(root)
            self.assertEqual(broken.self_test['status'], 'fail')
            self.assertEqual(broken.level, 'none')

    def test_doctor_prints_the_level(self) -> None:
        with project_copy() as root:
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/getzilla_doctor.py'), '--enforcement', '--json'],
                                    cwd=root, capture_output=True, text=True, timeout=300, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(json.loads(result.stdout)['level'], {'advisory', 'ci-enforced', 'external'})


class ProtectionPlanTests(unittest.TestCase):
    def runner(self, calls):
        def run(args, cwd=None):
            calls.append(list(args))
            if args[:3] == ['git', 'remote', 'get-url'] or 'get-url' in args:
                return ci_gate.CommandResult(0, 'git@github.com:Dimkox/Getzilla.git\n', '')
            if 'rev-parse' in args and '--show-toplevel' in args:
                return ci_gate.CommandResult(0, str(ROOT) + '\n', '')
            if 'symbolic-ref' in args:
                return ci_gate.CommandResult(0, 'origin/main\n', '')
            return ci_gate.CommandResult(0, '', '')
        return run

    def test_plan_is_read_only_and_names_the_exact_checks(self) -> None:
        plan = ci_gate.protection_plan(ROOT, 'Dimkox/Getzilla', 'main')
        self.assertEqual(plan['body']['required_status_checks'], {'strict': True, 'contexts': ['linux', 'windows']})
        self.assertFalse(plan['body']['allow_force_pushes'])
        self.assertIn('gh api -X PUT repos/Dimkox/Getzilla/branches/main/protection', plan['command'])
        calls: list[list[str]] = []
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = getzilla_ci.main(['--protect-plan', '--target', str(ROOT)], runner=self.runner(calls))
        self.assertEqual(code, 0)
        self.assertIn('"strict": true', out.getvalue())
        self.assertFalse(any(call[:2] == ['gh', 'api'] for call in calls))

    def test_apply_needs_yes_and_then_puts_the_plan(self) -> None:
        calls: list[list[str]] = []
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(getzilla_ci.main(['--protect-apply', '--target', str(ROOT)], runner=self.runner(calls)), 2)
            self.assertFalse(any(call[:2] == ['gh', 'api'] for call in calls))
            self.assertEqual(getzilla_ci.main(['--protect-apply', '--yes', '--target', str(ROOT)],
                                              runner=self.runner(calls)), 0)
        put = next(call for call in calls if call[:2] == ['gh', 'api'])
        self.assertEqual(put[:5], ['gh', 'api', '-X', 'PUT', 'repos/Dimkox/Getzilla/branches/main/protection'])


if __name__ == '__main__':
    unittest.main()
