"""Exercise the machine preview via the installed CLI, against an isolated user."""
import os
import shutil
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
        (self.project / '.getzilla').mkdir()
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

    def test_keep_options_exclude_only_the_selected_roots(self):
        tools = self.home / 'custom-toolchains'
        tools.mkdir()
        self.env['GETZILLA_TOOLCHAINS'] = str(tools)
        result = self.cli('--dry-run', '--keep-checkout')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('Getzilla checkout [', result.stdout)
        self.assertIn(str(self.state), result.stdout)
        self.assertIn(str(tools), result.stdout)
        result = self.cli('--dry-run', '--keep-state')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(str(ROOT), result.stdout)
        self.assertNotIn(str(self.state), result.stdout)
        self.assertNotIn(str(tools), result.stdout)
        self.assertEqual(self.marker.read_bytes(), b'owned fixture')

    def test_preview_identifies_shared_checkouts_before_removal(self):
        checkout = self.home / 'install'
        scripts = checkout / 'scripts'
        scripts.mkdir(parents=True)
        shutil.copyfile(ROOT / 'scripts/getzilla_self_uninstall.py', scripts / 'getzilla_self_uninstall.py')
        env = {**self.env, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull}

        def git(*args):
            subprocess.run(['git', '-C', str(checkout), '-c', 'user.name=Fixture',
                            '-c', 'user.email=fixture@example.invalid', *args], env=env,
                           check=True, capture_output=True, timeout=20)

        def preview(path, user_home=None):
            return subprocess.run([sys.executable, '-I', '-B',
                                   str(path / 'scripts/getzilla_self_uninstall.py'), '--dry-run'],
                                  env={**env, 'HOME': str(user_home or self.home),
                                       'USERPROFILE': str(user_home or self.home)},
                                  cwd=self.project, check=True, capture_output=True,
                                  text=True, timeout=20).stdout

        self.assertIn('Git metadata unavailable', preview(checkout))
        self.assertIn('contains the user home', preview(checkout, checkout))
        git('init', '-q')
        self.assertIn('cannot verify local commits', preview(checkout))
        git('add', 'scripts/getzilla_self_uninstall.py')
        git('commit', '-qm', 'fixture')
        self.assertIn('locally held commits', preview(checkout))
        git('update-ref', 'refs/remotes/origin/main', 'HEAD')
        self.assertIn('Getzilla checkout [present]', preview(checkout))
        git('commit', '--allow-empty', '-qm', 'local change')
        git('reset', '--hard', 'HEAD~')
        self.assertIn('locally held commits', preview(checkout))  # reachable only via the reflog
        git('reflog', 'expire', '--expire=now', '--all')
        tracked = scripts / 'getzilla_self_uninstall.py'
        tracked.write_bytes(tracked.read_bytes() + b'\n# local changes\n')
        git('stash', 'push', '-q')
        self.assertIn('locally held commits', preview(checkout))
        git('stash', 'drop', '-q')
        self.assertIn('Getzilla checkout [present]', preview(checkout))
        linked = self.home / 'linked'
        git('worktree', 'add', '--detach', str(linked), 'HEAD')
        self.assertIn('registered worktrees', preview(checkout))
        self.assertIn('external Git metadata', preview(linked))
        self.assertTrue((linked / 'scripts/getzilla_self_uninstall.py').exists())
        self.assertEqual(self.marker.read_bytes(), b'owned fixture')

    def test_only_explicit_preview_is_accepted(self):
        for arguments in ((), ('--yes',), ('--dry-run', '--yes')):
            with self.subTest(arguments=arguments):
                self.assertEqual(self.cli(*arguments).returncode, 2)
                self.assertEqual(self.marker.read_bytes(), b'owned fixture')
