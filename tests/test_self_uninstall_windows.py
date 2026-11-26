"""Real Windows run of scripts/uninstall.ps1: HKCU user PATH and variables, venv inside the checkout."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import agent_setup  # noqa: E402
from getzilla import machine_uninstall as mu  # noqa: E402


@unittest.skipUnless(os.name == 'nt', 'Windows registry and PowerShell')
class WindowsSelfUninstallTest(unittest.TestCase):
    def setUp(self) -> None:
        import winreg
        self.winreg = winreg
        temp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, temp, True)
        self.user, self.local, self.home = temp / 'user', temp / 'local', temp / 'user/Getzilla'
        (self.home / 'scripts').mkdir(parents=True)
        for name in ('getzilla_self_uninstall.py', 'uninstall.ps1'):
            shutil.copy(ROOT / 'scripts' / name, self.home / 'scripts' / name)
        (self.home / 'scripts/getzilla_cli.py').write_text('', encoding='utf-8')
        shutil.copytree(ROOT / '.getzilla/getzilla', self.home / '.getzilla/getzilla',
                        ignore=shutil.ignore_patterns('__pycache__'))
        subprocess.run([sys.executable, '-m', 'venv', '--without-pip', str(self.home / '.venv')], check=True, timeout=180)
        (self.user / '.getzilla/bin').mkdir(parents=True)
        runtime = self.local / 'Programs/Getzilla/runtimes/node'
        runtime.mkdir(parents=True)
        agent_setup._configure_claude(self.user, 'sk-or-v1-' + 'a' * 32)
        self.keep = str(temp / 'keep-me')
        self.ours = [str(self.home / 'bin'), str(self.home / '.venv/Scripts'), str(self.user / '.getzilla/bin'), str(runtime)]
        self.original, self.kind = mu.windows_user_path()
        self.addCleanup(mu.set_windows_user_path, self.original, self.kind)
        self.addCleanup(agent_setup._clear_windows_user_env, agent_setup.CLAUDE_TOKEN_ENV)
        mu.set_windows_user_path([*self.ours, self.keep, *self.original], self.kind)
        agent_setup._set_windows_user_env(agent_setup.CLAUDE_TOKEN_ENV, 'test-token')

    def variable(self, name: str) -> str | None:
        with self.winreg.OpenKey(self.winreg.HKEY_CURRENT_USER, 'Environment') as key:
            try:
                return self.winreg.QueryValueEx(key, name)[0]
            except FileNotFoundError:
                return None

    def test_powershell_wrapper_removes_everything_it_owns(self) -> None:
        shell = shutil.which('pwsh') or shutil.which('powershell')
        env = {k: v for k, v in os.environ.items() if not k.startswith('GETZILLA_')}
        env.update(USERPROFILE=str(self.user), HOME=str(self.user), LOCALAPPDATA=str(self.local))
        result = subprocess.run([shell, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
                                 str(self.home / 'scripts/uninstall.ps1'), '--yes'],
                                capture_output=True, text=True, env=env, timeout=300, cwd=str(self.user.parent))
        output = result.stdout + result.stderr
        self.assertNotIn('ERROR', output, output)
        self.assertFalse(self.home.exists(), output)  # PowerShell removes it after the venv Python exits
        self.assertFalse((self.user / '.getzilla').exists(), output)
        self.assertFalse((self.local / 'Programs/Getzilla').exists(), output)
        path, _ = mu.windows_user_path()
        self.assertEqual([entry for entry in self.ours if entry in path], [], output)
        self.assertIn(self.keep, path)
        self.assertIsNone(self.variable(agent_setup.CLAUDE_TOKEN_ENV), output)
        self.assertNotIn('openrouter', (self.user / '.claude/settings.json').read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
