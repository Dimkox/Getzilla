"""The single `getzilla` command: dispatch, project-local resolution and the bin shims."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

import getzilla_cli as cli  # noqa: E402

CLI = ROOT / 'scripts/getzilla_cli.py'


def run(*args: str, cwd: Path = ROOT) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(CLI), *args], cwd=cwd, capture_output=True, text=True,
                          timeout=120, check=False)


class GetzillaCliTests(unittest.TestCase):
    def test_help_lists_every_command(self) -> None:
        for args in ((), ('help',), ('--help',)):
            with self.subTest(args=args):
                proc = run(*args)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                for name in [*cli.COMMANDS, 'test']:
                    self.assertIn(f'  {name} ', proc.stdout)

    def test_unknown_command_fails_with_usage(self) -> None:
        proc = run('no-such-command')
        self.assertEqual(proc.returncode, 2)
        self.assertIn("unknown command 'no-such-command'", proc.stderr)

    def test_every_command_maps_to_an_existing_script(self) -> None:
        for name, (script, _) in cli.COMMANDS.items():
            with self.subTest(command=name):
                self.assertTrue((ROOT / 'scripts' / script).is_file(), script)

    def test_windows_test_run_uses_utf8_mode(self) -> None:
        from unittest import mock
        calls = []

        def fake_run(command, **kwargs):
            calls.append((command, kwargs.get('env')))
            return subprocess.CompletedProcess(command, 0)

        for name, utf8 in (('nt', '1'), ('posix', None)):
            calls.clear()
            with mock.patch.object(cli.os, 'name', name), mock.patch.object(cli.subprocess, 'run', fake_run), \
                    mock.patch.object(cli, 'project_python', return_value='python'), \
                    mock.patch.object(cli, 'test_workers', return_value=2):
                self.assertEqual(cli.run_tests(['tests/test_x.py']), 0)
            command, environment = calls[-1]
            self.assertEqual(command[1:3], ['-m', 'pytest'], name)
            self.assertEqual((environment or {}).get('PYTHONUTF8'), utf8, name)

    def test_arguments_pass_through_to_the_script(self) -> None:
        proc = run('route', '--help')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('adaptive task route', proc.stdout)
        proc = run('compliance', '--help')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('scaffold', proc.stdout)

    def test_every_command_answers_help_with_usage(self) -> None:
        for name in cli.COMMANDS:
            with self.subTest(command=name):
                proc = run(name, '--help')
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertIn('usage:', proc.stdout.lower())

    def test_project_scripts_take_precedence_inside_a_project(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / 'project'
            (project / '.getzilla').mkdir(parents=True)
            (project / 'scripts').mkdir()
            (project / 'scripts/getzilla_status.py').write_text("print('project status')\n", encoding='utf-8')
            nested = project / 'src' / 'pkg'
            nested.mkdir(parents=True)
            self.assertEqual(cli.script_path('getzilla_status.py', nested), project / 'scripts/getzilla_status.py')
            proc = run('status', cwd=nested)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout.strip(), 'project status')
            outside = Path(tmp) / 'elsewhere'
            outside.mkdir()
            self.assertEqual(cli.script_path('getzilla_status.py', outside), ROOT / 'scripts/getzilla_status.py')


class ShimTests(unittest.TestCase):
    def test_windows_shim_is_a_crlf_batch_file(self) -> None:
        data = (ROOT / 'bin/getzilla.cmd').read_bytes()
        self.assertIn(b'\r\n', data)
        self.assertNotIn(b'\n', data.replace(b'\r\n', b''))
        self.assertIn(b'%~dp0..\\scripts\\getzilla_cli.py', data)

    @unittest.skipIf(os.name == 'nt', 'POSIX shell shim')
    def test_posix_shim_runs_the_cli(self) -> None:
        shim = ROOT / 'bin/getzilla'
        self.assertTrue(os.access(shim, os.X_OK))
        proc = subprocess.run([str(shim), 'help'], capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('usage: getzilla <command>', proc.stdout)


    @unittest.skipIf(os.name == 'nt', 'POSIX shell shim')
    def test_posix_shim_follows_the_installer_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            link = Path(tmp) / 'getzilla'
            link.symlink_to(ROOT / 'bin/getzilla')
            proc = subprocess.run([str(link), 'help'], capture_output=True, text=True, timeout=60, check=False)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn('usage: getzilla <command>', proc.stdout)

    def test_both_installers_put_getzilla_on_path(self) -> None:
        shell = (ROOT / 'scripts/install.sh').read_text(encoding='utf-8')
        powershell = (ROOT / 'scripts/install.ps1').read_text(encoding='utf-8')
        self.assertIn('ln -sf "$home/bin/getzilla" "$HOME/.local/bin/getzilla"', shell)
        self.assertLess(shell.index('  fetch_getzilla "$repo" "$ref" "$home"\n'),
                        shell.index('  link_getzilla_command "$home"\n'))
        self.assertIn("Add-UserPath (Join-Path $GetzillaHome 'bin')", powershell)
        for text in (shell, powershell):
            self.assertIn('getzilla help', text)

if __name__ == '__main__':
    unittest.main()
