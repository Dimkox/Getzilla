"""F02: the security and workflow baseline is mandatory, pinned to commits, and never overwrites a project."""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla import baseline, verification  # noqa: E402
from getzilla.quality_gates import evaluate_quality_gate  # noqa: E402

PINS = {name: item['pinned_commit'] for name, item in baseline.components().items()}


class FakeTools:
    """Stands in for git, npx, uv and specify; records every command."""

    def __init__(self, *, wrong_commit: str | None = None, fail: str | None = None) -> None:
        self.commands: list[list[str]] = []
        self.heads: dict[str, str] = {}
        self.wrong_commit = wrong_commit
        self.fail = fail

    def __call__(self, command: list[str], cwd: Path | None) -> subprocess.CompletedProcess:
        self.commands.append(command)
        done = subprocess.CompletedProcess(command, 0, '', '')
        if self.fail and self.fail in command:
            return subprocess.CompletedProcess(command, 1, '', f'{self.fail} failed')
        if command[:1] == ['git'] and 'clone' in command:
            target = Path(command[-1])
            component = target.name
            target.mkdir(parents=True)
            (target / 'LICENSE').write_text('MIT\n', encoding='utf-8')
            if component == 'superpowers':
                for skill in ('brainstorming', 'writing-plans'):
                    (target / 'skills' / skill).mkdir(parents=True)
                    (target / 'skills' / skill / 'SKILL.md').write_text(f'# {skill}\n', encoding='utf-8')
            self.heads[str(target)] = self.wrong_commit if component == self.wrong_commit_for else PINS[component]
            return done
        if command[:1] == ['git'] and command[-2:] == ['rev-parse', 'HEAD']:
            head = self.heads.get(command[2])
            return subprocess.CompletedProcess(command, 0 if head else 128, (head or '') + '\n', '')
        if command[:1] == ['npx']:
            stage = Path(command[command.index('--directory') + 1])
            (stage / '_bmad' / 'core').mkdir(parents=True)
            (stage / '_bmad' / 'core' / 'config.yaml').write_text('v: 6.12.1\n', encoding='utf-8')
            (stage / 'README.md').write_text('bmad readme\n', encoding='utf-8')
            return done
        if command[:2] == ['specify', 'init']:
            (cwd / '.specify' / 'memory').mkdir(parents=True)
            (cwd / '.specify' / 'memory' / 'constitution.md').write_text('# constitution\n', encoding='utf-8')
            (cwd / '.git').mkdir()
            (cwd / '.git' / 'HEAD').write_text('ref: refs/heads/main\n', encoding='utf-8')
            return done
        return done

    wrong_commit_for = None


def which_all(name: str) -> str:
    return f'/usr/bin/{name}'


class InstallerScriptTests(unittest.TestCase):
    def test_no_option_to_skip_and_failures_stop_the_install(self) -> None:
        shell = (ROOT / 'scripts' / 'install.sh').read_text(encoding='utf-8')
        powershell = (ROOT / 'scripts' / 'install.ps1').read_text(encoding='utf-8')
        for text in (shell, powershell):
            self.assertNotRegex(text, r'Superpowers, BMAD, Spec Kit[^\n]*\[y/N\]')
            self.assertNotIn('WARNING: vulnerability data is not up to date', text)
            self.assertIsNone(re.search(r'GETZILLA_SKIP_(BASELINE|WORKFLOW|SECURITY)', text))
            self.assertIn("'--only', 'baseline'" if text is powershell else '--only baseline', text)
            self.assertIn('getzilla_baseline.py', text)
        self.assertIn('fail "Vulnerability data did not install', shell)
        self.assertIn("throw ('Vulnerability data did not install", powershell)
        self.assertLess(shell.index('install_workflow_baseline "$home"'), shell.index('--materialize-new "$GETZILLA_NEW_PROJECT"'))


class InstallUserTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)

    def test_pinned_tags_are_cloned_and_their_commits_checked(self) -> None:
        tools = FakeTools()
        steps = baseline.install_user(self.home, run=tools, which=which_all)
        self.assertTrue(all(step.status == 'ok' for step in steps), steps)
        clones = [command for command in tools.commands if 'clone' in command]
        self.assertEqual({command[command.index('--branch') + 1] for command in clones},
                         {item['upstream_tag'] for item in baseline.components().values()})
        uv = next(command for command in tools.commands if command[1:3] == ['tool', 'install'])
        self.assertTrue(uv[-1].endswith('spec-kit.git@' + baseline.components()['spec-kit']['upstream_tag']))
        again = FakeTools()
        again.heads = tools.heads
        baseline.install_user(self.home, run=again, which=which_all)
        self.assertFalse([command for command in again.commands if 'clone' in command])

    def test_wrong_commit_behind_a_tag_is_refused(self) -> None:
        tools = FakeTools(wrong_commit='f' * 40)
        tools.wrong_commit_for = 'bmad'
        steps = {step.component: step for step in baseline.install_user(self.home, run=tools, which=which_all)}
        self.assertEqual(steps['baseline:bmad'].status, 'fail')
        self.assertIn('PINNED_COMMIT_MISMATCH', steps['baseline:bmad'].detail)
        self.assertFalse((baseline.pinned_checkout(self.home) / 'bmad').exists())

    def test_missing_prerequisites_fail(self) -> None:
        steps = {step.component: step for step in baseline.install_user(self.home, run=FakeTools(), which=lambda name: None)}
        self.assertEqual(steps['baseline:specify-cli'].status, 'fail')
        self.assertEqual(steps['baseline:node'].status, 'fail')


class ApplyProjectTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        self.home, self.project = base / 'home', base / 'project'
        self.project.mkdir()
        (self.project / 'README.md').write_text('my project\n', encoding='utf-8')
        self.tools = FakeTools()
        baseline.install_user(self.home, run=self.tools, which=which_all)

    def apply(self, agent='claude', tools=None):
        return {step.component: step for step in baseline.apply_project(self.project, agent, self.home,
                                                                         run=tools or self.tools, windows=False)}

    def test_baseline_is_connected_without_overwriting(self) -> None:
        steps = self.apply()
        self.assertTrue(all(step.status == 'ok' for step in steps.values()), steps)
        for directory in ('.agents/skills', '.claude/skills'):
            self.assertTrue((self.project / directory / 'brainstorming' / 'SKILL.md').is_file())
            self.assertTrue((self.project / directory / 'brainstorming' / 'LICENSE').is_file())
        self.assertTrue((self.project / '_bmad' / 'core' / 'config.yaml').is_file())
        self.assertTrue((self.project / '.specify' / 'memory' / 'constitution.md').is_file())
        self.assertEqual((self.project / 'README.md').read_text(encoding='utf-8'), 'my project\n')
        self.assertIn('existing files kept', steps['project:bmad'].detail)
        self.assertFalse((self.project / '.git').exists())
        npx = next(command for command in self.tools.commands if command[:1] == ['npx'])
        self.assertIn('bmad-method@' + baseline.components()['bmad']['pinned'], npx)
        self.assertEqual(npx[npx.index('--tools') + 1], 'claude-code')
        specify = next(command for command in self.tools.commands if command[:2] == ['specify', 'init'])
        self.assertEqual(specify[specify.index('--integration') + 1], 'claude')
        self.assertIn('--non-interactive', specify)

    def test_existing_tool_folders_are_left_alone(self) -> None:
        (self.project / '_bmad').mkdir()
        (self.project / '.specify').mkdir()
        steps = self.apply('qwen')
        self.assertIn('left as it is', steps['project:bmad'].detail)
        self.assertIn('left as it is', steps['project:spec-kit'].detail)
        self.assertTrue((self.project / '.qwen' / 'skills' / 'writing-plans' / 'SKILL.md').is_file())

    def test_installer_failure_and_unknown_agent_fail(self) -> None:
        steps = self.apply('codex', FakeTools(fail='npx'))
        self.assertEqual(steps['project:bmad'].status, 'fail')
        self.assertEqual(baseline.apply_project(self.project, 'notepad', self.home, run=self.tools)[0].status, 'fail')

    def test_inspect_reports_missing_then_complete(self) -> None:
        status = baseline.inspect(self.home, self.project, 'claude', run=self.tools, which=which_all,
                                  environ={'GETZILLA_OSV_ONLINE': '1'})
        self.assertIn('PROJECT_BASELINE_MISSING:bmad', status.missing)
        self.apply()
        status = baseline.inspect(self.home, self.project, 'claude', run=self.tools, which=which_all,
                                  environ={'GETZILLA_OSV_ONLINE': '1'})
        self.assertTrue(status.complete, status.missing)


class VerifyBaselineTests(unittest.TestCase):
    def test_check_runs_only_in_installed_projects_outside_ci(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            env = {key: value for key, value in os.environ.items() if key not in {'CI', 'GITHUB_ACTIONS'}}
            with mock.patch.dict(os.environ, env, clear=True):
                check, _ = verification._workflow_baseline_check(project, 'pr')
                self.assertEqual(check.status, 'skip')  # Getzilla's own source repository: an allowed skip
                self.assertFalse(any(detail['path'] == 'workflow-baseline'
                                     for detail in evaluate_quality_gate(mode='pr', checks=[check]).details))
                (project / '.getzilla').mkdir()
                (project / '.getzilla' / 'AGBP_SYNC.json').write_text('{}', encoding='utf-8')
                with mock.patch('getzilla.updater.home_dir', return_value=project / 'home'):
                    failing, metadata = verification._workflow_baseline_check(project, 'pr')
                    warning, _ = verification._workflow_baseline_check(project, 'fast')
                self.assertEqual(failing.status, 'fail')
                self.assertIn('WORKFLOW_BASELINE_MISSING', failing.summary)
                self.assertEqual(warning.status, 'pass')
                self.assertTrue(warning.summary.startswith('will fail pr/release'))
            with mock.patch.dict(os.environ, {**env, 'CI': 'true'}, clear=True):
                ci, _ = verification._workflow_baseline_check(project, 'pr')
            self.assertEqual(ci.status, 'skip')
            gate = evaluate_quality_gate(mode='pr', checks=[ci])
            self.assertFalse(any(detail['path'] == 'workflow-baseline' for detail in gate.details))


if __name__ == '__main__':
    unittest.main()
