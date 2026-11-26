"""Machine uninstaller: scripts/getzilla_self_uninstall.py and its uninstall.sh / uninstall.ps1 wrappers."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / 'scripts/getzilla_self_uninstall.py'
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import agent_setup  # noqa: E402

KEY = 'sk-or-v1-' + 'a' * 32
PATH_LINES = '\n# Getzilla: tools in ~/.getzilla/bin\ncase ":$PATH:" in *":$HOME/.getzilla/bin:"*) ;; *) export PATH="$HOME/.getzilla/bin:$PATH" ;; esac\n'


@unittest.skipIf(os.name == 'nt', 'POSIX profile layout')
class SelfUninstallTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.temp, True)
        self.user = self.temp / 'user'
        self.user.mkdir()
        (self.user / '.bashrc').write_text('alias ll="ls -l"\n' + PATH_LINES, encoding='utf-8')
        # Same writes as `setup-agent --agent qwen` and `--agent claude`.
        agent_setup._configure_qwen(self.user, 'qwen/qwen3-coder', KEY)
        agent_setup._configure_claude(self.user, KEY)
        settings = self.user / '.claude/settings.json'
        settings.write_text(settings.read_text().replace('"env"', '"theme": "dark", "env"'), encoding='utf-8')
        (self.user / '.getzilla/bin').mkdir(parents=True)
        (self.user / '.getzilla/bin/qwen').write_text('#!/bin/sh\n', encoding='utf-8')
        self.home = self.user / 'Getzilla'
        for rel in ('scripts/getzilla_cli.py', '.getzilla/getzilla/__init__.py', 'bin/getzilla'):
            (self.home / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.home / rel).write_text('', encoding='utf-8')
        (self.user / '.local/bin').mkdir(parents=True)
        (self.user / '.local/bin/getzilla').symlink_to(self.home / 'bin/getzilla')
        self.project = self.user / 'project'
        self.project.mkdir()
        (self.project / 'AGENTS.md').write_text('mine\n', encoding='utf-8')

    def run_core(self, *args: str) -> subprocess.CompletedProcess[str]:
        env = {k: v for k, v in os.environ.items() if not k.startswith('GETZILLA_')}
        env['HOME'] = str(self.user)
        return subprocess.run([sys.executable, str(CORE), '--home', str(self.home), *args],
                              capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL, timeout=60)

    def test_dry_run_changes_nothing(self) -> None:
        before = sorted(str(p) for p in self.user.rglob('*'))
        result = self.run_core('--dry-run')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Dry run', result.stdout)
        self.assertIn(str(self.home), result.stdout)
        self.assertEqual(sorted(str(p) for p in self.user.rglob('*')), before)

    def test_without_terminal_or_yes_it_refuses(self) -> None:
        result = self.run_core()
        self.assertEqual(result.returncode, 2)
        self.assertTrue(self.home.exists())

    def test_yes_removes_only_what_the_installer_wrote(self) -> None:
        result = self.run_core('--yes')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.home.exists())
        self.assertFalse((self.user / '.getzilla').exists())
        self.assertFalse((self.user / '.local/bin/getzilla').is_symlink())
        self.assertEqual((self.user / '.bashrc').read_text(encoding='utf-8'), 'alias ll="ls -l"\n')
        qwen = (self.user / '.qwen/settings.json').read_text(encoding='utf-8')
        self.assertNotIn('openrouter', qwen)
        claude = (self.user / '.claude/settings.json').read_text(encoding='utf-8')
        self.assertNotIn('openrouter', claude)
        self.assertIn('"theme": "dark"', claude)
        self.assertEqual((self.project / 'AGENTS.md').read_text(encoding='utf-8'), 'mine\n')

    def test_foreign_command_link_is_kept(self) -> None:
        link = self.user / '.local/bin/getzilla'
        link.unlink()
        link.symlink_to(self.temp / 'elsewhere')
        self.assertEqual(self.run_core('--yes', '--keep-checkout').returncode, 0)
        self.assertTrue(link.is_symlink())
        self.assertTrue(self.home.exists())

    def test_uncommitted_changes_block_checkout_removal(self) -> None:
        if not shutil.which('git'):
            self.skipTest('git is missing')
        git = ['git', '-C', str(self.home), '-c', 'user.name=t', '-c', 'user.email=t@t']
        subprocess.run([*git, 'init', '-q'], check=True)
        subprocess.run([*git, 'add', '-A'], check=True)
        subprocess.run([*git, 'commit', '-qm', 'x'], check=True)
        (self.home / 'scripts/getzilla_cli.py').write_text('local edit\n', encoding='utf-8')
        result = self.run_core('--yes')
        self.assertEqual(result.returncode, 2)
        self.assertIn('uncommitted changes', result.stderr)
        self.assertTrue(self.home.exists())
        self.assertTrue((self.user / '.getzilla').exists())
        self.assertEqual(self.run_core('--yes', '--force').returncode, 0)
        self.assertFalse(self.home.exists())

    def test_not_a_checkout_is_refused(self) -> None:
        self.home = self.user / 'project'
        result = self.run_core('--yes')
        self.assertEqual(result.returncode, 2)
        self.assertTrue((self.project / 'AGENTS.md').exists())

    def test_home_folder_as_state_is_refused(self) -> None:
        env = {k: v for k, v in os.environ.items() if not k.startswith('GETZILLA_')}
        env.update(HOME=str(self.user), GETZILLA_STATE_HOME=str(self.user))
        result = subprocess.run([sys.executable, str(CORE), '--home', str(self.home), '--yes'],
                                capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(result.returncode, 2)
        self.assertTrue(self.home.exists())

    def test_shell_wrapper_passes_options(self) -> None:
        env = {k: v for k, v in os.environ.items() if not k.startswith('GETZILLA_')}
        env.update(HOME=str(self.user), GETZILLA_HOME=str(self.home))
        shutil.copy(ROOT / 'scripts/uninstall.sh', self.home / 'scripts/uninstall.sh')
        shutil.copy(CORE, self.home / 'scripts/getzilla_self_uninstall.py')
        shutil.copytree(ROOT / '.getzilla/getzilla', self.home / '.getzilla/getzilla', dirs_exist_ok=True)
        result = subprocess.run(['bash', str(self.home / 'scripts/uninstall.sh'), '--dry-run'],
                                capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Dry run', result.stdout)


@unittest.skipUnless(os.name == 'nt', 'Windows registry and PowerShell wrapper')
class WindowsSelfUninstallTest(unittest.TestCase):
    """Run uninstall.ps1 for real: user PATH and variables in HKCU, and a running venv inside the checkout."""

    MARK = 'GETZILLA_UNINSTALL_TEST'

    def setUp(self) -> None:
        import winreg
        self.winreg = winreg
        self.temp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.temp, True)
        self.user = self.temp / 'user'
        self.local = self.temp / 'local'
        self.home = self.user / 'Getzilla'
        (self.home / 'scripts').mkdir(parents=True)
        (self.home / 'bin').mkdir()
        shutil.copy(CORE, self.home / 'scripts/getzilla_self_uninstall.py')
        shutil.copy(ROOT / 'scripts/uninstall.ps1', self.home / 'scripts/uninstall.ps1')
        (self.home / 'scripts/getzilla_cli.py').write_text('', encoding='utf-8')
        shutil.copytree(ROOT / '.getzilla/getzilla', self.home / '.getzilla/getzilla',
                        ignore=shutil.ignore_patterns('__pycache__'))
        subprocess.run([sys.executable, '-m', 'venv', '--without-pip', str(self.home / '.venv')], check=True, timeout=120)
        (self.user / '.getzilla/bin').mkdir(parents=True)
        runtimes = self.local / 'Programs/Getzilla/runtimes/node-1'
        runtimes.mkdir(parents=True)
        (runtimes / 'node.exe').write_bytes(b'')
        (self.user / '.claude').mkdir()
        (self.user / '.claude/settings.json').write_text(
            '{"theme": "dark", "env": {"ANTHROPIC_BASE_URL": "https://openrouter.ai/api", "ANTHROPIC_API_KEY": ""}}\n',
            encoding='utf-8')
        self.keep = str(self.temp / 'keep-me')
        self.ours = [str(self.home / 'bin'), str(self.home / '.venv/Scripts'), str(self.user / '.getzilla/bin'), str(runtimes)]
        self.original, self.kind = self._read_path()
        self.addCleanup(self._restore)
        self._write_path([*self.ours, self.keep, *self.original])
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Environment', 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, agent_setup.CLAUDE_TOKEN_ENV, 0, winreg.REG_SZ, KEY)

    def _read_path(self) -> tuple[list[str] | None, int]:
        with self.winreg.OpenKey(self.winreg.HKEY_CURRENT_USER, 'Environment') as key:
            try:
                value, kind = self.winreg.QueryValueEx(key, 'Path')
            except FileNotFoundError:
                return None, self.winreg.REG_EXPAND_SZ
        return [part for part in value.split(';') if part], kind

    def _write_path(self, parts: list[str]) -> None:
        with self.winreg.OpenKey(self.winreg.HKEY_CURRENT_USER, 'Environment', 0, self.winreg.KEY_SET_VALUE) as key:
            self.winreg.SetValueEx(key, 'Path', 0, self.kind, ';'.join(parts))

    def _restore(self) -> None:
        with self.winreg.OpenKey(self.winreg.HKEY_CURRENT_USER, 'Environment', 0, self.winreg.KEY_SET_VALUE) as key:
            if self.original is None:
                try:
                    self.winreg.DeleteValue(key, 'Path')
                except FileNotFoundError:
                    pass
            else:
                self.winreg.SetValueEx(key, 'Path', 0, self.kind, ';'.join(self.original))
            try:
                self.winreg.DeleteValue(key, agent_setup.CLAUDE_TOKEN_ENV)
            except FileNotFoundError:
                pass

    def _user_variable(self, name: str) -> str | None:
        with self.winreg.OpenKey(self.winreg.HKEY_CURRENT_USER, 'Environment') as key:
            try:
                return self.winreg.QueryValueEx(key, name)[0]
            except FileNotFoundError:
                return None

    def test_powershell_wrapper_removes_everything_it_owns(self) -> None:
        shell = shutil.which('pwsh') or shutil.which('powershell')
        self.assertIsNotNone(shell)
        env = {k: v for k, v in os.environ.items() if not k.startswith('GETZILLA_')}
        env.update(USERPROFILE=str(self.user), HOME=str(self.user), LOCALAPPDATA=str(self.local))
        result = subprocess.run([shell, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
                                 str(self.home / 'scripts/uninstall.ps1'), '--yes'],
                                capture_output=True, text=True, env=env, timeout=300, cwd=str(self.temp))
        output = result.stdout + result.stderr
        self.assertNotIn('ERROR', output, output)
        self.assertFalse(self.home.exists(), output)  # removed by PowerShell after the venv Python exited
        self.assertFalse((self.user / '.getzilla').exists(), output)
        self.assertFalse((self.local / 'Programs/Getzilla').exists(), output)
        path, _ = self._read_path()
        for entry in self.ours:
            self.assertNotIn(entry, path or [], output)
        self.assertIn(self.keep, path or [])
        self.assertIsNone(self._user_variable(agent_setup.CLAUDE_TOKEN_ENV), output)
        claude = (self.user / '.claude/settings.json').read_text(encoding='utf-8')
        self.assertNotIn('openrouter', claude)
        self.assertIn('"theme": "dark"', claude)


class SelfUninstallSourceTest(unittest.TestCase):
    def test_cli_runs_the_global_copy(self) -> None:
        text = (ROOT / 'scripts/getzilla_cli.py').read_text(encoding='utf-8')
        self.assertIn("'self-uninstall': ('getzilla_self_uninstall.py'", text)
        self.assertIn("command in ('update', 'self-uninstall')", text)

    def test_powershell_wrapper_removes_deferred_folders(self) -> None:
        text = (ROOT / 'scripts/uninstall.ps1').read_text(encoding='utf-8')
        self.assertIn('--deferred-file', text)
        self.assertIn('Remove-Item -LiteralPath $folder -Recurse -Force', text)


if __name__ == '__main__':
    unittest.main()
