from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import verification as V  # noqa: E402
from getzilla.quality_gates import required_check_refused  # noqa: E402

RULES = ROOT / '.getzilla/sast/rules'


def _fake_opengrep(directory: Path, payload: dict | str, exit_code: int = 0) -> None:
    script = directory / 'opengrep'
    body = payload if isinstance(payload, str) else json.dumps(payload)
    script.write_text(textwrap.dedent(f'''\
        #!{sys.executable}
        import sys
        sys.stdout.write({body!r})
        sys.exit({exit_code})
    '''), encoding='utf-8')
    script.chmod(0o755)


class OpengrepCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / 'repo'
        shutil.copytree(RULES, self.root / V.OPENGREP_RULES)
        self.bin = Path(self._tmp.name) / 'bin'
        self.bin.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run(self, payload: dict | str | None, exit_code: int = 0) -> V.CheckResult:
        if payload is not None:
            _fake_opengrep(self.bin, payload, exit_code)
        path = str(self.bin) if payload is not None else '/nonexistent'
        with mock.patch.dict(os.environ, {'PATH': path}):
            return V._opengrep(self.root)

    def test_skips_without_the_binary_or_the_rules(self) -> None:
        self.assertEqual((self._run(None).status, self._run(None).summary), ('skip', 'opengrep not available'))
        shutil.rmtree(self.root / '.getzilla')
        self.assertEqual(self._run({'results': []}).summary, 'no OpenGrep rules installed')

    def test_findings_fail_with_details_and_clean_scans_pass(self) -> None:
        finding = {'check_id': 'getzilla.python.sql-injection', 'path': 'app.py', 'start': {'line': 12},
                   'extra': {'severity': 'ERROR', 'message': 'Untrusted input reaches a SQL string.'}}
        failed = self._run({'results': [finding], 'errors': []}, exit_code=1)
        self.assertEqual(failed.status, 'fail')
        self.assertEqual(failed.details[0]['rule'], 'getzilla.python.sql-injection')
        self.assertEqual(failed.details[0]['line'], '12')
        self.assertIn('--taint-intrafile', failed.command)
        self.assertIn(V.OPENGREP_RULES, failed.command)
        self.assertEqual(self._run({'results': [], 'errors': []}).status, 'pass')

    def test_crashes_and_scan_errors_fail_closed(self) -> None:
        self.assertEqual(self._run('not json', exit_code=2).status, 'fail')
        self.assertEqual(self._run({'results': []}, exit_code=7).status, 'fail')
        errored = self._run({'results': [], 'errors': [{'level': 'error', 'message': 'rule parse error'}]})
        self.assertEqual(errored.status, 'fail')
        warned = self._run({'results': [], 'errors': [{'level': 'warn', 'message': 'partial parse'}]})
        self.assertEqual(warned.status, 'pass')

    def test_missing_binary_is_refused_and_opengrep_is_mandatory_in_pr_and_release(self) -> None:
        # A machine without OpenGrep must not pass a PR/release gate with SAST silently skipped (#40).
        from getzilla.quality_gates import MANDATORY_PR_CHECKS

        skipped = SimpleNamespace(name='opengrep', status='skip', summary='opengrep not available')
        for mode in ('pr', 'release'):
            with self.subTest(mode=mode):
                self.assertTrue(required_check_refused(skipped, mode=mode))
        self.assertFalse(required_check_refused(skipped, mode='fast'))
        self.assertIn('opengrep', MANDATORY_PR_CHECKS)

    def test_only_the_rules_absent_skip_is_admitted_by_the_quality_gate(self) -> None:
        def result(summary: str) -> SimpleNamespace:
            return SimpleNamespace(name='opengrep', status='skip', summary=summary)

        self.assertTrue(required_check_refused(result('opengrep not available'), mode='pr'))
        self.assertFalse(required_check_refused(result('no OpenGrep rules installed'), mode='pr'))
        self.assertTrue(required_check_refused(result('opengrep timed out'), mode='pr'))


class OpengrepPinTests(unittest.TestCase):
    def test_free_actions_template_and_trust_ci_runner_pin_the_same_release(self) -> None:
        import re

        runner = (ROOT / 'trust-ci/runner.Dockerfile').read_text(encoding='utf-8')
        template = (ROOT / '.getzilla/templates/ci/github-actions-verify.yml').read_text(encoding='utf-8')
        version = re.search(r'ARG OPENGREP_VERSION=(\S+)', runner).group(1)
        digest = re.search(r'ARG OPENGREP_SHA256=([0-9a-f]{64})', runner).group(1)
        self.assertIn(f'OPENGREP_VERSION: "{version}"', template)
        self.assertIn(f'OPENGREP_SHA256: "{digest}"', template)
        self.assertIn('sha256sum -c -', template)


@unittest.skipUnless(shutil.which('opengrep'), 'opengrep is not installed (Trust CI and Getzilla CI install it)')
class OpengrepRuleTests(unittest.TestCase):
    def test_every_rule_matches_its_annotated_examples(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for item in RULES.iterdir():
                target = Path(tmp) / (item.name[:-len('.example')] if item.name.endswith('.example') else item.name)
                shutil.copyfile(item, target)
            proc = subprocess.run(['opengrep', 'scan', '--test', '--taint-intrafile', '--disable-version-check', tmp],
                                  capture_output=True, text=True, timeout=600, check=False)
        self.assertEqual(proc.returncode, 0, proc.stdout[-4000:] + proc.stderr[-4000:])
        self.assertIn('All tests passed', proc.stdout + proc.stderr)

    def test_rule_ids_are_namespaced_and_every_rule_file_has_examples(self) -> None:
        for rule_file in RULES.glob('*.yaml'):
            self.assertTrue(list(RULES.glob(rule_file.stem + '.*.example')), rule_file)
        for rule_file in RULES.glob('*.yaml'):
            for line in rule_file.read_text(encoding='utf-8').splitlines():
                if line.strip().startswith('- id:'):
                    self.assertTrue(line.split(':', 1)[1].strip().startswith('getzilla.'), line)


if __name__ == '__main__':
    unittest.main()
