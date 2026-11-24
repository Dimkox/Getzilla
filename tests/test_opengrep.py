from __future__ import annotations

import hashlib
import copy
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

from getzilla import updater  # noqa: E402
from getzilla import verification as V  # noqa: E402
from getzilla.quality_gates import required_check_refused  # noqa: E402

RULES = ROOT / '.getzilla/sast/rules'


# Windows finds a program through PATHEXT, so the fake there is a .cmd running the same Python.
FAKE_NAME = 'opengrep.cmd' if os.name == 'nt' else 'opengrep'


def _fake_opengrep(directory: Path, payload: dict | str, exit_code: int = 0, *, delay: float = 0) -> str:
    """Write a fake ``opengrep`` that records each run in ``ran`` and return its sha256."""
    body = payload if isinstance(payload, str) else json.dumps(payload)
    program = textwrap.dedent(f'''\
        import pathlib, sys, time
        pathlib.Path({str(directory / 'ran')!r}).touch()
        time.sleep({delay!r})
        sys.stdout.write({body!r})
        sys.exit({exit_code})
    ''')
    script = directory / FAKE_NAME
    if os.name == 'nt':
        (directory / 'opengrep.py').write_text(program, encoding='utf-8')
        script.write_text(f'@"{sys.executable}" "{directory / "opengrep.py"}" %*\r\n',
                          encoding='utf-8', newline='')
    else:
        script.write_text(f'#!{sys.executable}\n{program}', encoding='utf-8')
        script.chmod(0o755)
    return hashlib.sha256(script.read_bytes()).hexdigest()


def _pin(sha256: str) -> mock._patch:
    """Pin the running platform's OpenGrep digest to ``sha256``."""
    return mock.patch.dict(updater.OPENGREP_ASSETS, {updater._platform_key(): ('opengrep', sha256)})


class OpengrepCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / 'repo'
        shutil.copytree(RULES, self.root / V.OPENGREP_RULES)
        self.bin = Path(self._tmp.name) / 'bin'
        self.bin.mkdir()
        (self.root / 'app.py').write_text('print("inert source")\n', encoding='utf-8')

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_fixture_discovery_is_independent_of_a_competing_virtualenv_binary(self) -> None:
        competing = self.root / 'other-environment-bin'
        competing.mkdir()
        _fake_opengrep(competing, {'results': [], 'errors': []})
        with mock.patch.object(sys, 'prefix', str(self.root / 'other-environment')), \
             mock.patch('getzilla.util.sysconfig.get_path', return_value=str(competing)):
            result = self._run({'results': [], 'errors': []})
        self.assertEqual(result.status, 'pass', result.summary)
        self.assertTrue((self.bin / 'ran').exists())
        self.assertFalse((competing / 'ran').exists())

    def _run(self, payload: dict | str | None, exit_code: int = 0, *, pinned: bool = True, delay: float = 0) -> V.CheckResult:
        digest = _fake_opengrep(self.bin, payload, exit_code, delay=delay) if payload is not None else '0' * 64
        path = str(self.bin) if payload is not None else '/nonexistent'
        # Hide both resolver additions, so only this fixture PATH can supply opengrep.
        if payload is not None and (not sys.platform.startswith('linux') or not hasattr(os, 'memfd_create')):
            self.skipTest('the real sealed-core fixture profile is explicitly unavailable on this platform')
        from getzilla import security_opengrep as scanner
        original_run = scanner._run
        self._core_calls = []

        def fixture_frontend(language, *, deadline=None):
            # Report-decoder fixtures use the test interpreter's real compile
            # helper. OS custody/version qualification belongs to SyntaxProfileTests.
            self.assertEqual(language, 'python')
            executable = Path(sys.executable).resolve(strict=True)
            descriptor = os.open(executable, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                identity = scanner._identity(os.fstat(descriptor))
                with os.fdopen(os.dup(descriptor), 'rb') as stream:
                    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                return scanner.SyntaxFrontend(
                    executable, descriptor, identity, digest, language,
                    f'fixture-{sys.implementation.name}-{sys.version_info.major}.{sys.version_info.minor}')
            except BaseException:
                os.close(descriptor)
                raise

        def fixture_core(command, root, environment, deadline, **options):
            if '-json_nodots' not in command:
                return original_run(command, root, environment, deadline, **options)
            self._core_calls.append(command)
            # The inert worker supplies untrusted report bytes. Real installed
            # launcher/cache/core custody is exercised in ActualPinnedAdapterTests.
            result = V.run([str(self.bin / FAKE_NAME)], cwd=root, timeout=900, encoding='utf-8', errors='replace')
            if result.returncode == 124:
                raise scanner.OpenGrepError('scanner_timeout')
            if isinstance(payload, dict):
                report = copy.deepcopy(payload)
                report.setdefault('version', '1.30.1')
                source = command[-1]
                declared = [rule.identifier for rule in scanner.rule_catalog((RULES / 'python.yaml').read_bytes())]
                report.setdefault('rules_by_engine', [[identifier, 'OSS'] for identifier in declared])
                report.setdefault('engine_requested', 'OSS')
                report.setdefault('interfile_languages_used', [])
                report.setdefault('skipped_rules', [])
                if 'paths' not in report:
                    report['paths'] = {'scanned': [source]}
                elif isinstance(report['paths'], dict) and isinstance(report['paths'].get('scanned'), list):
                    report['paths']['scanned'] = [source if value == 'app.py' else value for value in report['paths']['scanned']]
                if isinstance(report.get('results'), list):
                    for finding in report['results']:
                        if not isinstance(finding, dict):
                            continue
                        if finding.get('path') == 'app.py':
                            finding['path'] = source
                        if isinstance(finding.get('start'), dict):
                            finding['start'].setdefault('col', 1)
                            finding['start'].setdefault('offset', 0)
                            finding.setdefault('end', {'line': finding['start'].get('line', 1), 'col': 2, 'offset': 1})
                        if isinstance(finding.get('extra', {}), dict):
                            finding['extra'] = {'metavars': {}, 'engine_kind': 'OSS', 'is_ignored': False,
                                                **finding.get('extra', {})}
                result.stdout = json.dumps(report)
                # CLI uses1 for findings; the demonstrated direct core uses0.
                if result.returncode == 1 and report.get('results') and report.get('errors') == []:
                    result.returncode = 0
            return result

        with mock.patch.dict(os.environ, {'PATH': path}), _pin(digest if pinned else '0' * 64), \
             mock.patch('getzilla.util.user_tool_dirs', return_value=[]), \
             mock.patch('getzilla.util.environment_scripts_dir', return_value=None), \
             mock.patch('getzilla.opengrep_releases.verify_active', side_effect=ValueError('fixture has no qualified managed release')), \
             mock.patch.object(scanner, 'syntax_frontend', side_effect=fixture_frontend), \
             mock.patch.object(scanner, '_bootstrap_core', return_value=Path('/usr/bin/true').read_bytes()), \
             mock.patch.object(scanner, '_run', side_effect=fixture_core):
            return V._opengrep(self.root)

    def test_binary_on_path_that_does_not_match_the_pin_is_refused_unexecuted(self) -> None:
        # A PATH opengrep (for example one an older updater took from `latest`) is not trusted
        # by name: its sha256 must equal the pinned release digest before it is ever run (#39).
        result = self._run({'results': []}, pinned=False)
        self.assertEqual(result.status, 'fail')
        self.assertIn('sha256', result.summary)
        self.assertIn(updater.OPENGREP_VERSION, result.summary)
        self.assertFalse((self.bin / 'ran').exists())
        self.assertTrue(required_check_refused(result, mode='pr'))

    def test_pinned_binary_runs_by_its_resolved_path(self) -> None:
        result = self._run({'results': [], 'errors': []})
        self.assertEqual(result.status, 'pass')
        self.assertTrue((self.bin / 'ran').exists())
        self.assertTrue(result.command[0].startswith('/proc/self/fd/'))
        self.assertIn('-json_nodots', result.command)

    def test_report_fixture_parses_without_the_exact_os_frontend_installation(self) -> None:
        from getzilla import security_opengrep as scanner
        (self.root / 'app.py').write_text('raise RuntimeError("fixture source must not execute")\n')
        unavailable = ('/nonexistent/protected/python3.12', ('-I', '-S', '--version'),
                       'Python 3.12.', 'python3.12')
        with mock.patch.dict(scanner._FRONTENDS, {'python': unavailable}):
            result = self._run({'results': [], 'errors': []})
        self.assertEqual(result.status, 'pass', result.summary)
        self.assertEqual(len(self._core_calls), 1)

    def test_report_fixture_still_rejects_invalid_syntax_before_core(self) -> None:
        from getzilla import security_opengrep as scanner
        (self.root / 'app.py').write_text('def broken(:\n  pass\n')
        unavailable = ('/nonexistent/protected/python3.12', ('-I', '-S', '--version'),
                       'Python 3.12.', 'python3.12')
        with mock.patch.dict(scanner._FRONTENDS, {'python': unavailable}):
            result = self._run({'results': [], 'errors': []})
        self.assertEqual(result.status, 'fail')
        self.assertIn('syntax_incomplete', result.summary)
        self.assertEqual(self._core_calls, [])
        self.assertFalse((self.bin / 'ran').exists())

    def test_skips_without_the_binary_or_the_rules(self) -> None:
        self.assertEqual((self._run(None).status, self._run(None).summary), ('skip', 'opengrep not available'))
        shutil.rmtree(self.root / '.getzilla')
        self.assertEqual(self._run({'results': []}).summary, 'no OpenGrep rules installed')

    def test_findings_fail_with_details_and_clean_scans_pass(self) -> None:
        finding = {'check_id': 'getzilla.python.sql-injection', 'path': 'app.py', 'start': {'line': 12},
                   'extra': {'severity': 'ERROR', 'message': 'Untrusted input reaches a SQL string.'}}
        failed = self._run({'results': [finding], 'errors': []}, exit_code=1)
        self.assertEqual(failed.status, 'fail')
        self.assertEqual(failed.details[0]['rule'], 'getzilla.sast.rules.getzilla.python.sql-injection')
        self.assertEqual(failed.details[0]['line'], '12')
        self.assertIn('-taint_intrafile', failed.command)
        self.assertIn('-rules', failed.command)
        self.assertEqual(self._run({'results': [], 'errors': []}).status, 'pass')

    def test_crashes_and_scan_errors_fail_closed(self) -> None:
        self.assertEqual(self._run('not json', exit_code=2).status, 'fail')
        self.assertEqual(self._run({'results': []}, exit_code=7).status, 'fail')
        errored = self._run({'results': [], 'errors': [{'level': 'error', 'message': 'rule parse error'}]})
        self.assertEqual(errored.status, 'fail')
        warned = self._run({'results': [], 'errors': [{'level': 'warn', 'message': 'partial parse'}]})
        self.assertEqual(warned.status, 'fail')
        for diagnostics in ([{'level': 'warn', 'type': 'PartialParsing'}],
                            [{'level': 'warn', 'type': 'Syntax error'}],
                            [None]):
            with self.subTest(diagnostics=diagnostics):
                self.assertEqual(self._run({'results': [], 'errors': diagnostics}).status, 'fail')

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


class NativeOpengrepReportTests(unittest.TestCase):
    setUp = OpengrepCheckTests.setUp
    tearDown = OpengrepCheckTests.tearDown
    _run = OpengrepCheckTests._run

    def check_report(self, report, exit_code=0, refusal=None):
        with mock.patch.object(V, '_unpinned_opengrep', return_value=refusal):
            result = self._run("null" if report is None else report, exit_code)
        calls = self._core_calls
        call = SimpleNamespace(args=[calls[-1]], kwargs={}) if calls else None
        return result, call, len(calls)

    def test_complete_clean_report_uses_strict_pinned_command_and_existing_scope(self):
        for exit_code in (0, 1):
            with self.subTest(exit_code=exit_code):
                result, call, count = self.check_report({'results': [], 'errors': []}, exit_code)
                # Direct core requires zero even when the CLI would accept one.
                self.assertEqual(result.status, 'pass' if exit_code == 0 else 'fail')
                self.assertEqual(count, 1)
                self.assertEqual(call.args[0], result.command)
                self.assertIn('-json_nodots', result.command)
                self.assertTrue(result.command[0].startswith('/proc/self/fd/'))
                self.assertTrue(result.command[-1].startswith('/proc/self/fd/'))

    def test_any_analysis_diagnostic_blocks_clean_regardless_of_level_or_exit(self):
        diagnostics = [{'level': level, 'message': 'PUBLIC-FIXTURE-NOTE'}
                       for level in ('warn', 'warning', 'info', 'unknown', 'error', '')]
        diagnostics.extend(({}, None, 'PUBLIC-FIXTURE-NOTE', 17))
        for diagnostic in diagnostics:
            for exit_code in (0, 1):
                with self.subTest(kind=type(diagnostic).__name__, exit_code=exit_code):
                    result, _, count = self.check_report({'results': [], 'errors': [diagnostic]}, exit_code)
                    self.assertEqual(result.status, 'fail')
                    self.assertEqual(count, 1)
                    self.assertNotIn('PUBLIC-FIXTURE-NOTE', result.summary + result.stderr + repr(result.details))

    def test_missing_or_malformed_report_collections_never_pass_or_crash(self):
        reports = [None, [], 17, 'not an object', {}, {'results': []}, {'errors': []}]
        for value in (None, {}, '', 0, 'diagnostic'):
            reports.extend(({'results': [], 'errors': value}, {'results': value, 'errors': []}))
        for report in reports:
            with self.subTest(kind=type(report).__name__):
                result, _, _ = self.check_report(report)
                self.assertEqual(result.status, 'fail')

    def test_malformed_finding_entries_return_structured_failure(self):
        findings = [None, [], 'finding', 17, {'start': []}, {'extra': []}, {'start': None}, {'extra': None}]
        for finding in findings:
            with self.subTest(kind=type(finding).__name__):
                result, _, _ = self.check_report({'results': [finding], 'errors': []})
                self.assertEqual(result.status, 'fail')

    def test_complete_findings_preserve_details(self):
        finding = {'check_id': 'getzilla.python.sql-injection', 'path': 'app.py', 'start': {'line': 12},
                   'extra': {'severity': 'ERROR', 'message': 'public finding'}}
        result, _, _ = self.check_report({'results': [finding], 'errors': []}, 1)
        self.assertEqual(result.status, 'fail')
        self.assertEqual(result.details, [{'rule': 'getzilla.sast.rules.getzilla.python.sql-injection', 'path': 'app.py', 'line': '12',
                                          'severity': 'ERROR', 'message': 'public finding'}])

    def test_pin_refusal_never_calls_runner(self):
        result, call, count = self.check_report({'results': [], 'errors': []}, refusal='pin mismatch; not run')
        self.assertEqual(result.status, 'fail')
        self.assertEqual(result.summary, 'pin mismatch; not run')
        self.assertEqual(count, 0)
        self.assertIsNone(call)

    def test_non_scan_exit_codes_still_fail(self):
        for exit_code in (2, 7, 124):
            with self.subTest(exit_code=exit_code):
                result, _, _ = self.check_report({'results': [], 'errors': []}, exit_code)
                self.assertEqual(result.status, 'fail')


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
