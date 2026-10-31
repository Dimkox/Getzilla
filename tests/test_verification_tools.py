"""Executable evidence must distinguish a passing test from an empty or stale run."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from getzilla import verification_tools as tools


class VerificationToolsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def configure(self, checks) -> None:
        (self.root / tools.CONFIG).write_text(json.dumps({'schema_version': 1, 'checks': checks}),
                                             encoding='utf-8', newline='\n')

    def check(self, **changes):
        value = {'id': 'properties', 'tool': 'hypothesis',
                 'commands': [[sys.executable, 'runner.py', '{report}']], 'timeout_seconds': 5}
        value.update(changes)
        return value

    def runner(self, source: str) -> None:
        (self.root / 'runner.py').write_text(source, encoding='utf-8', newline='\n')

    def passing_runner(self, exit_code=0) -> None:
        self.runner("from pathlib import Path\nimport sys\n"
                    "Path(sys.argv[1]).write_text('<testsuite tests=\"1\"><testcase classname=\"cart\" name=\"atomic\"/></testsuite>', encoding='utf-8')\n"
                    f'raise SystemExit({exit_code})\n')

    def run_one(self, value=None):
        self.configure([value or self.check()])
        return tools.run_check(self.root, tools.load_checks(self.root, 'pr')[0])

    def test_no_config_does_not_create_runtime_or_plan_checks(self):
        self.assertEqual(tools.load_checks(self.root, 'pr'), [])
        self.assertFalse((self.root / '.getzilla').exists())

    def test_enabled_profiles_are_selected_for_the_requested_mode(self):
        self.configure([self.check(), self.check(id='disabled', enabled=False),
                        self.check(id='quick', modes=['fast'])])
        self.assertEqual([c['id'] for c in tools.load_checks(self.root, 'pr')], ['properties'])
        self.assertEqual([c['id'] for c in tools.load_checks(self.root, 'fast')], ['quick'])

    def test_invalid_configuration_never_looks_unconfigured(self):
        invalid = [[], {'schema_version': True, 'checks': []},
                   {'schema_version': 1, 'checks': [], 'typo': True}]
        for data in invalid:
            with self.subTest(data=data):
                (self.root / tools.CONFIG).write_text(json.dumps(data), encoding='utf-8', newline='\n')
                with self.assertRaises(tools.ConfigurationError):
                    tools.load_checks(self.root, 'pr')
        (self.root / tools.CONFIG).write_text('{"schema_version":1,"schema_version":1,"checks":[]}',
                                            encoding='utf-8', newline='\n')
        with self.assertRaises(tools.ConfigurationError):
            tools.load_checks(self.root, 'pr')

    def test_invalid_check_fields_are_rejected_before_execution(self):
        for changes in ({'tool': 'invented'}, {'timeout_seconds': True}, {'timeout_seconds': 0},
                        {'timeout_seconds': 3601}, {'commands': ['echo ok']},
                        {'commands': [[]]}, {'modes': ['production']}, {'cwd': '../other'},
                        {'criteria': {'AC-1': []}}, {'unknown': 1}, {'enabled': 'false'}):
            with self.subTest(changes=changes):
                self.configure([self.check(**changes)])
                with self.assertRaises(tools.ConfigurationError):
                    tools.load_checks(self.root, 'pr')

    def test_duplicate_check_ids_cannot_overwrite_evidence(self):
        self.configure([self.check(), self.check()])
        with self.assertRaises(tools.ConfigurationError):
            tools.load_checks(self.root, 'pr')

    @unittest.skipIf(os.name == 'nt', 'symlink fixture requires POSIX privileges')
    def test_symlinked_config_and_working_directory_are_refused(self):
        outside = self.root / 'source.json'
        outside.write_text('{"schema_version":1,"checks":[]}', encoding='utf-8', newline='\n')
        (self.root / tools.CONFIG).symlink_to(outside)
        with self.assertRaises(tools.ConfigurationError):
            tools.load_checks(self.root, 'pr')
        (self.root / tools.CONFIG).unlink()
        (self.root / 'linked').symlink_to(self.root, target_is_directory=True)
        self.configure([self.check(cwd='linked')])
        with self.assertRaises(tools.ConfigurationError):
            tools.load_checks(self.root, 'pr')

    def test_real_subprocess_report_binds_exact_criterion(self):
        self.passing_runner()
        result = self.run_one(self.check(criteria={'AC-1': ['cart::atomic']}))
        self.assertEqual(result['status'], 'pass', result)
        detail = result['details'][0]
        self.assertEqual(detail['criteria'][0]['status'], 'pass')
        self.assertEqual(detail['report']['counts']['passed'], 1)
        self.assertEqual(len(detail['report_sha256']), 64)
        self.assertEqual(list((self.root / '.getzilla/runtime/verification-tools').glob('run-*')), [])

    def test_unknown_criterion_cannot_pass_with_an_unrelated_green_test(self):
        self.passing_runner()
        result = self.run_one(self.check(criteria={'AC-2': ['cart::rollback']}))
        self.assertEqual(result['status'], 'fail')
        self.assertEqual(result['details'][0]['criteria'][0]['missing'], ['cart::rollback'])

    def test_nonzero_exit_cannot_be_overridden_by_a_passing_report(self):
        self.passing_runner(exit_code=1)
        self.assertEqual(self.run_one()['status'], 'fail')

    def test_missing_or_old_report_is_not_reused(self):
        self.passing_runner()
        self.assertEqual(self.run_one()['status'], 'pass')
        self.runner('pass\n')
        result = self.run_one()
        self.assertEqual(result['status'], 'fail')
        self.assertIn('report', result['summary'].lower())

    def test_all_skipped_tests_do_not_pass(self):
        self.runner("from pathlib import Path\nimport sys\n"
                    "Path(sys.argv[1]).write_text('<testsuite tests=\"1\"><testcase name=\"docker\"><skipped/></testcase></testsuite>', encoding='utf-8')\n")
        self.assertEqual(self.run_one(self.check(tool='testcontainers-python'))['status'], 'fail')

    def test_missing_executable_is_a_failed_check(self):
        result = self.run_one(self.check(commands=[['getzilla-intentionally-absent-command']]))
        self.assertEqual(result['status'], 'fail')
        self.assertEqual(result['details'][0]['executions'][0]['returncode'], 127)

    def test_timeout_stops_the_check_and_cleans_its_workspace(self):
        self.runner('import time\ntime.sleep(10)\n')
        result = self.run_one(self.check(timeout_seconds=1))
        self.assertEqual(result['status'], 'fail')
        self.assertEqual(result['details'][0]['executions'][0]['terminal_state'], 'timeout')
        self.assertEqual(list((self.root / '.getzilla/runtime/verification-tools').glob('run-*')), [])

    def test_second_command_is_not_run_after_a_failure(self):
        self.runner('raise SystemExit(1)\n')
        self.configure([self.check(commands=[[sys.executable, 'runner.py'],
                                             [sys.executable, 'should-not-run.py']])])
        result = tools.run_check(self.root, tools.load_checks(self.root, 'pr')[0])
        self.assertEqual(result['status'], 'fail')
        self.assertEqual(len(result['details'][0]['executions']), 1)

    @unittest.skipIf(os.name == 'nt', 'symlink fixture requires POSIX privileges')
    def test_report_symlink_cannot_substitute_existing_evidence(self):
        (self.root / 'old.xml').write_text('<testsuite><testcase name="old"/></testsuite>', encoding='utf-8', newline='\n')
        self.runner("from pathlib import Path\nimport sys\nPath(sys.argv[1]).symlink_to(Path('old.xml').resolve())\n")
        self.assertEqual(self.run_one()['status'], 'fail')

    @unittest.skipIf(os.name == 'nt', 'symlink fixture requires POSIX privileges')
    def test_runtime_symlink_is_refused_without_writing_outside_project(self):
        (self.root / '.getzilla').mkdir()
        outside = self.root / 'outside'
        outside.mkdir()
        (self.root / '.getzilla/runtime').symlink_to(outside, target_is_directory=True)
        self.passing_runner()
        self.assertEqual(self.run_one()['status'], 'fail')
        self.assertEqual(list(outside.iterdir()), [])

    def test_mutmut_runs_on_current_source_without_reusing_mutants(self):
        (self.root / 'dirty.txt').write_text('current dirty bytes', encoding='utf-8', newline='\n')
        (self.root / 'mutants').mkdir()
        (self.root / 'mutants/stale').write_text('old', encoding='utf-8', newline='\n')
        self.runner("from pathlib import Path\nimport json\n"
                    "assert Path('dirty.txt').read_text() == 'current dirty bytes'\n"
                    "assert not Path('mutants/stale').exists()\n"
                    "Path('dirty.txt').write_text('mutated', encoding='utf-8')\n"
                    "Path('mutants').mkdir(exist_ok=True)\n"
                    "Path('mutants/mutmut-cicd-stats.json').write_text(json.dumps(dict(killed=1,total=1,survived=0,no_tests=0,skipped=0,suspicious=0,timeout=0,check_was_interrupted_by_user=0,segfault=0)), encoding='utf-8')\n")
        result = self.run_one(self.check(tool='mutmut', commands=[[sys.executable, 'runner.py']]))
        self.assertEqual(result['status'], 'pass', result)
        self.assertEqual((self.root / 'dirty.txt').read_text(encoding='utf-8'), 'current dirty bytes')
        self.assertEqual((self.root / 'mutants/stale').read_text(encoding='utf-8'), 'old')

    def test_mutation_aggregate_cannot_be_used_as_test_criterion_evidence(self):
        self.configure([self.check(tool='mutmut', criteria={'AC-1': ['unit-test']})])
        with self.assertRaises(tools.ConfigurationError):
            tools.load_checks(self.root, 'pr')

    def test_report_success_does_not_hide_source_mutation(self):
        self.passing_runner()
        script = (self.root / 'runner.py').read_text(encoding='utf-8')
        self.runner(script.replace('raise SystemExit(0)', "Path('application.py').write_text('changed')"))
        result = self.run_one()
        self.assertEqual(result['status'], 'fail')
        self.assertIn('source changed', result['summary'])

    def test_argument_metacharacters_are_passed_literally(self):
        self.passing_runner()
        value = '$(touch should-not-exist); spaces & `echo no`'
        script = (self.root / 'runner.py').read_text(encoding='utf-8')
        self.runner(script.replace('raise SystemExit(0)', f'assert sys.argv[2] == {value!r}'))
        result = self.run_one(self.check(commands=[[sys.executable, 'runner.py', '{report}', value]]))
        self.assertEqual(result['status'], 'pass', result)
        self.assertFalse((self.root / 'should-not-exist').exists())

    def test_verifier_dispatch_does_not_eagerly_execute_later_tools(self):
        from getzilla.verification import CheckResult, _CheckDispatch
        self.configure([self.check(id='first'), self.check(id='later')])
        results = []
        dispatch = _CheckDispatch(results, 'pr')
        with patch.object(tools, 'run_check', return_value={
                'name': 'tool:first', 'status': 'fail', 'summary': 'actual refusal'}) as execute:
            for name, callback in tools.planned_checks(self.root, 'pr', make=CheckResult):
                dispatch.run(name, callback)
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(results[1].status, 'skip')
        self.assertEqual(results[1].details[0]['blocked_by'], 'tool:first')

    def test_invalid_config_is_a_failed_verification_check(self):
        from getzilla.verification import CheckResult
        (self.root / tools.CONFIG).write_text('[]', encoding='utf-8', newline='\n')
        name, callback = list(tools.planned_checks(self.root, 'pr', make=CheckResult))[0]
        self.assertEqual(name, 'verification-tools-config')
        self.assertEqual(callback().status, 'fail')

    def test_cancellation_retains_a_typed_verifier_result_and_cleans_up(self):
        import signal
        from getzilla.python_test_runner import ProcessResult, RunCancelled
        from getzilla.verification import CheckResult
        self.configure([self.check()])
        cancellation = RunCancelled(signal.SIGINT, ProcessResult(['tool'], 130, terminal_state='cancelled'))
        with patch.object(tools, 'execute', side_effect=cancellation):
            _, callback = list(tools.planned_checks(self.root, 'pr', make=CheckResult))[0]
            with self.assertRaises(RunCancelled) as caught:
                callback()
        self.assertIsInstance(caught.exception.checks[0], CheckResult)
        self.assertEqual(caught.exception.checks[0].status, 'cancelled')
        self.assertEqual(list((self.root / '.getzilla/runtime/verification-tools').glob('run-*')), [])

    @unittest.skipIf(os.name == 'nt', 'symlink fixture requires POSIX privileges')
    def test_mutation_source_link_is_refused_before_any_command(self):
        (self.root / 'linked.py').symlink_to(self.root / 'outside.py')
        with patch.object(tools, 'execute', side_effect=AssertionError('command must not run')):
            self.assertEqual(self.run_one(self.check(tool='mutmut'))['status'], 'fail')

    def test_cli_catalog_and_plan_do_not_run_commands(self):
        script = Path(__file__).resolve().parents[1] / 'scripts/getzilla_verification_tools.py'
        self.configure([self.check(commands=[['intentionally-not-installed']])])
        for action in ('catalog', 'plan'):
            proc = subprocess.run([sys.executable, str(script), action, '--root', str(self.root), '--json'],
                                  capture_output=True, text=True, encoding='utf-8', timeout=10, check=False)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIsInstance(json.loads(proc.stdout), dict)
        self.assertFalse((self.root / '.getzilla').exists())

    def test_cli_never_calls_an_unconfigured_run_passed(self):
        script = Path(__file__).resolve().parents[1] / 'scripts/getzilla_verification_tools.py'
        proc = subprocess.run([sys.executable, str(script), 'run', '--root', str(self.root), '--json'],
                              capture_output=True, text=True, encoding='utf-8', timeout=10, check=False)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(json.loads(proc.stdout)['status'], 'not_configured')

    def test_deep_configuration_returns_a_structured_failure(self):
        (self.root / tools.CONFIG).write_text('[' * 10000 + '0' + ']' * 10000, encoding='utf-8', newline='\n')
        with self.assertRaises(tools.ConfigurationError):
            tools.load_checks(self.root, 'pr')

    def test_stryker_subproject_excludes_old_report_and_forces_fresh_incremental_path(self):
        from tests.test_verification_tool_reports import STRYKER
        web = self.root / 'web'
        (web / 'reports/mutation').mkdir(parents=True)
        old = web / 'reports/mutation/mutation.json'
        old.write_text('old result', encoding='utf-8', newline='\n')
        (web / 'custom-incremental.json').write_text('cached results', encoding='utf-8', newline='\n')
        (web / 'runner.py').write_text(
            "from pathlib import Path\nimport sys\n"
            "assert '--force' in sys.argv\n"
            "cache = Path(sys.argv[sys.argv.index('--incrementalFile') + 1])\n"
            "assert not cache.exists() and cache.parent == Path(sys.argv[2])\n"
            "report = Path(sys.argv[1])\nassert not report.exists()\n"
            "report.parent.mkdir(parents=True)\n"
            f"report.write_text({json.dumps(STRYKER)!r}, encoding='utf-8')\n",
            encoding='utf-8', newline='\n')
        result = self.run_one(self.check(tool='strykerjs', cwd='web',
                                       commands=[[sys.executable, 'runner.py', '{report}', '{output_dir}']]))
        self.assertEqual(result['status'], 'pass', result)
        self.assertEqual(old.read_text(encoding='utf-8'), 'old result')

    def test_schemathesis_keeps_native_cache_writes_in_a_disposable_project_copy(self):
        from tests.test_verification_tool_reports import SCHEMATHESIS
        (self.root / 'schemathesis.toml').write_text('[checks]\nnot_a_real_setting = true\n', encoding='utf-8', newline='\n')
        self.runner("from pathlib import Path\nimport sys\n"
                    "assert Path('schemathesis.toml').is_file()\n"
                    "cache = Path('.schemathesis/default/cache/crashes')\ncache.mkdir(parents=True)\n"
                    "(cache / 'manifest.json').write_text('{}')\n"
                    f"Path(sys.argv[1]).write_text({json.dumps(SCHEMATHESIS)!r}, encoding='utf-8')\n")
        result = self.run_one(self.check(tool='schemathesis'))
        self.assertEqual(result['status'], 'pass', result)
        self.assertFalse((self.root / '.schemathesis').exists())

    @unittest.skipIf(os.name == 'nt', 'portable emulation uses owned POSIX links')
    def test_windows_reparse_metadata_is_refused_at_all_workspace_boundaries(self):
        from getzilla import fsx, verification_tool_workspace as workspace
        original = Path.lstat
        with tempfile.TemporaryDirectory() as directory:
            outside = Path(directory)
            (outside / 'report.xml').write_text('<testsuite/>', encoding='utf-8', newline='\n')
            link = self.root / 'junction'
            link.symlink_to(outside, target_is_directory=True)
            def junction_metadata(path, *args, **kwargs):
                if path == link:
                    return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_size=0,
                                           st_file_attributes=fsx.FILE_ATTRIBUTE_REPARSE_POINT)
                return original(path, *args, **kwargs)
            with patch.object(Path, 'lstat', junction_metadata):
                for action in (lambda: workspace.checked_path(self.root, 'junction'),
                               lambda: workspace.read_report(link / 'report.xml', self.root),
                               lambda: workspace.copy_source(self.root, outside / 'copied')):
                    with self.subTest(action=action), self.assertRaises(workspace.WorkspaceError):
                        action()
            link.unlink()
            (self.root / '.getzilla').mkdir()
            link = self.root / '.getzilla/runtime'
            link.symlink_to(outside, target_is_directory=True)
            with patch.object(Path, 'lstat', junction_metadata), self.assertRaises(workspace.WorkspaceError):
                workspace.runtime_parent(self.root)
            self.assertFalse((outside / 'verification-tools').exists())


if __name__ == '__main__':
    unittest.main()
