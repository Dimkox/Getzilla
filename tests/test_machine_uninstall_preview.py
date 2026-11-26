"""Exercise the machine preview via the installed CLI, against an isolated user."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class MachineUninstallPreviewTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(temp.cleanup)
        self.home = Path(temp.name)
        self.project = self.home / 'project'
        scripts = self.project / 'scripts'
        scripts.mkdir(parents=True)
        (scripts / 'getzilla_self_uninstall.py').write_text("raise SystemExit(77)")
        self.state = self.home / 'private state'
        self.state.mkdir()
        self.marker = self.state / 'retained'
        self.marker.write_bytes(b'owned fixture')
        self.env = dict(os.environ, HOME=str(self.home), USERPROFILE=str(self.home),
                        LOCALAPPDATA=str(self.home / 'Local'), GETZILLA_HOME=str(ROOT),
                        GETZILLA_STATE_HOME=str(self.state), TEMP=str(self.home), TMP=str(self.home),
                        PYTHONDONTWRITEBYTECODE='1')
        self.env.pop('GETZILLA_TOOLCHAINS', None)

    def cli(self, *args):
        return subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/getzilla_cli.py'),
                               'self-uninstall', *args], cwd=self.project, env=self.env,
                              capture_output=True, text=True, timeout=20)

    def test_preview_uses_installed_cli_and_only_reports_paths(self):
        result = self.cli('--dry-run')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(str(self.state), result.stdout)
        self.assertIn(str(ROOT), result.stdout)
        self.assertNotIn('owned fixture', result.stdout)
        self.assertEqual(self.marker.read_bytes(), b'owned fixture')

    @unittest.skipIf(os.name == 'nt', 'POSIX command link')
    def test_identifies_only_the_installed_link(self):
        link = self.home / '.local/bin/getzilla'
        link.parent.mkdir(parents=True)
        link.symlink_to(os.path.relpath(ROOT / 'bin/getzilla', link.parent))
        self.assertIn(str(link), self.cli('--dry-run').stdout)
        link.unlink()
        link.symlink_to(self.project)
        result = self.cli('--dry-run')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(str(link), result.stdout)
        self.assertEqual(link.readlink(), self.project)

    def test_only_explicit_preview_is_accepted(self):
        for arguments in ((), ('--yes',), ('--dry-run', '--yes')):
            with self.subTest(arguments=arguments):
                self.assertEqual(self.cli(*arguments).returncode, 2)
                self.assertEqual(self.marker.read_bytes(), b'owned fixture')
