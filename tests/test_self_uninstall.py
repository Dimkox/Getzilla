"""Machine uninstaller command: scripts/getzilla_self_uninstall.py on a fake POSIX home."""
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
PATH_LINES = '\n# Getzilla: tools in ~/.getzilla/bin\nexport PATH="$HOME/.getzilla/bin:$PATH"\n'


@unittest.skipIf(os.name == 'nt', 'POSIX home layout')
class SelfUninstallTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.temp, True)
        self.user = self.temp / 'user'
        self.user.mkdir()
        (self.user / '.bashrc').write_text('alias ll="ls -l"\n' + PATH_LINES, encoding='utf-8')
        agent_setup._configure_qwen(self.user, 'qwen/qwen3-coder', KEY)  # same writes as setup-agent
        agent_setup._configure_claude(self.user, KEY)
        (self.user / '.getzilla/bin').mkdir(parents=True)
        self.home = self.user / 'Getzilla'
        for rel in ('scripts/getzilla_cli.py', '.getzilla/getzilla/__init__.py', 'bin/getzilla'):
            (self.home / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.home / rel).write_text('', encoding='utf-8')
        (self.user / '.local/bin').mkdir(parents=True)
        (self.user / '.local/bin/getzilla').symlink_to(self.home / 'bin/getzilla')
        self.project = self.user / 'project'
        self.project.mkdir()
        (self.project / 'AGENTS.md').write_text('mine\n', encoding='utf-8')

    def run_core(self, *args: str, **extra: str) -> subprocess.CompletedProcess[str]:
        env = {k: v for k, v in os.environ.items() if not k.startswith('GETZILLA_')}
        env.update(HOME=str(self.user), **extra)
        return subprocess.run([sys.executable, str(CORE), '--home', str(self.home), *args], capture_output=True,
                              text=True, env=env, stdin=subprocess.DEVNULL, timeout=60)

    def test_dry_run_changes_nothing(self) -> None:
        before = sorted(map(str, self.user.rglob('*')))
        result = self.run_core('--dry-run')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'remove: {self.home}', result.stdout)
        self.assertEqual(sorted(map(str, self.user.rglob('*'))), before)
        self.assertEqual(self.run_core().returncode, 2)  # no terminal and no --yes
        self.assertTrue(self.home.exists())

    def test_yes_removes_only_what_the_installer_wrote(self) -> None:
        result = self.run_core('--yes')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.home.exists())
        self.assertFalse((self.user / '.getzilla').exists())
        self.assertFalse((self.user / '.local/bin/getzilla').is_symlink())
        self.assertEqual((self.user / '.bashrc').read_text(encoding='utf-8'), 'alias ll="ls -l"\n')
        for rel in ('.qwen/settings.json', '.claude/settings.json'):
            self.assertNotIn('openrouter', (self.user / rel).read_text(encoding='utf-8'))
        self.assertEqual((self.project / 'AGENTS.md').read_text(encoding='utf-8'), 'mine\n')

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
        self.assertTrue((self.user / '.getzilla').exists())
        self.assertEqual(self.run_core('--yes', '--force').returncode, 0)
        self.assertFalse(self.home.exists())

    def test_unsafe_targets_are_refused(self) -> None:
        self.home = self.project
        self.assertEqual(self.run_core('--yes').returncode, 2)
        self.home = self.user / 'Getzilla'
        self.assertEqual(self.run_core('--yes', GETZILLA_STATE_HOME=str(self.user)).returncode, 2)
        self.assertTrue(self.home.exists() and self.project.exists())


if __name__ == '__main__':
    unittest.main()
