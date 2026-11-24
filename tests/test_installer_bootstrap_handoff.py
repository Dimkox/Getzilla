"""A simulated 3.10 bootstrap hands off before any tomllib-dependent helper."""
import builtins
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'.getzilla'))
from getzilla import managed_software


class HandedOff(Exception):
    pass


class BootstrapHandoffTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('owned_bootstrap_cli', ROOT/'scripts/getzilla_install_managed.py')
        self.cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.cli)
        scratch = ROOT/'.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = tempfile.TemporaryDirectory(prefix='owned-bootstrap-', dir=scratch)
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.bootstrap = self.home/'bootstrap-python'
        self.bootstrap.write_bytes(b'inert bootstrap identity')
        self.selected = Path(sys.executable).resolve()

    def test_missing_tomllib_bootstrap_hands_exact_argv_to_selected_runtime_before_helper_import(self):
        original = builtins.__import__
        def missing(name, *args, **kwargs):
            if name == 'tomllib':
                raise ModuleNotFoundError('owned Python3.10 has no tomllib')
            return original(name, *args, **kwargs)
        argv = ['--environment-only', '--home', str(self.home/'space unicode Ω'),
                '--result', str(self.home/'result.json')]
        handoffs = []
        output = io.StringIO()
        def execute(path, args):
            handoffs.append((path, args))
            self.assertEqual(args, [str(self.selected), '-I', '-B', str(Path(self.cli.__file__).resolve()), *argv])
            # Only a bounded helper import executes, never the actual installer.
            probe = ("import sys,json;sys.path.insert(0,"+repr(str(ROOT/'.getzilla'))+");"
                     "from getzilla import managed_pyyaml;"
                     "print(json.dumps({'version':list(sys.version_info[:2]),'helper':managed_pyyaml.__name__}))")
            result = subprocess.run([path, '-I', '-B', '-c', probe], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            observed = json.loads(result.stdout)
            self.assertGreaterEqual(observed['version'], [3, 11])
            self.assertEqual(observed['helper'], 'getzilla.managed_pyyaml')
            raise HandedOff()
        with redirect_stdout(output), mock.patch.object(self.cli.sys, 'version_info', (3, 10, 16)), \
             mock.patch.object(self.cli.sys, 'executable', str(self.bootstrap)), \
             mock.patch.object(managed_software, 'ensure_python', return_value=self.selected), \
             mock.patch.object(self.cli, 'home_dir', return_value=self.home), \
             mock.patch.object(self.cli, 'install_environment', side_effect=AssertionError('bootstrap must not import helper')), \
             mock.patch.object(builtins, '__import__', side_effect=missing), \
             mock.patch.object(os, 'execv', side_effect=execute):
            spec = importlib.util.spec_from_file_location('getzilla.owned_missing_tomllib',
                                                        ROOT/'.getzilla/getzilla/managed_pyyaml.py')
            helper = importlib.util.module_from_spec(spec)
            with self.assertRaisesRegex(ModuleNotFoundError, '3.10'):
                spec.loader.exec_module(helper)
            with self.assertRaises(HandedOff):
                self.cli.main(argv)
        self.assertEqual(len(handoffs), 1)
        self.assertEqual(output.getvalue(), '')
        self.assertFalse((self.home/'result.json').exists())

    def test_current_runtime_keeps_normal_call_and_single_json_result(self):
        output = io.StringIO()
        with mock.patch.object(self.cli.sys, 'version_info', (3, 15, 2)), \
             mock.patch.object(managed_software, 'ensure_python', return_value=self.selected), \
             mock.patch.object(self.cli, 'home_dir', return_value=self.home), \
             mock.patch.object(self.cli, 'install_environment', return_value=self.selected) as install, \
             mock.patch.object(os, 'execv', side_effect=AssertionError('current runtime must not reexec')), redirect_stdout(output):
            result = self.cli.main(['--environment-only', '--home', str(self.home)])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue())['status'], 'complete')
        install.assert_called_once_with(self.home, str(self.selected), fetch=self.cli._release_fetch)

    def test_pending_selected_runtime_preserves_incomplete_failure_without_handoff(self):
        output = io.StringIO()
        with mock.patch.object(self.cli.sys, 'version_info', (3, 10, 16)), \
             mock.patch.object(managed_software, 'ensure_python', side_effect=ValueError('owned current release unavailable')), \
             mock.patch.object(os, 'execv', side_effect=AssertionError('no selected runtime')), \
             mock.patch.object(self.cli, 'install_environment', side_effect=AssertionError('no selected runtime')), redirect_stdout(output):
            result = self.cli.main(['--environment-only', '--home', str(self.home)])
        self.assertEqual(result, 1)
        self.assertEqual(json.loads(output.getvalue())['status'], 'incomplete')

    def test_old_bootstrap_cannot_reexec_itself_or_unproved_missing_path(self):
        for selected in (self.bootstrap, self.home/'missing-python', Path('relative-python')):
            with self.subTest(selected=str(selected)), redirect_stdout(io.StringIO()) as output, \
                 mock.patch.object(self.cli.sys, 'version_info', (3, 10, 16)), \
                 mock.patch.object(self.cli.sys, 'executable', str(self.bootstrap)), \
                 mock.patch.object(managed_software, 'ensure_python', return_value=selected), \
                 mock.patch.object(os, 'execv', side_effect=AssertionError('invalid selected path')), \
                 mock.patch.object(self.cli, 'install_environment', side_effect=AssertionError('invalid selected path')):
                self.assertEqual(self.cli.main(['--environment-only', '--home', str(self.home)]), 1)
                self.assertEqual(json.loads(output.getvalue())['status'], 'incomplete')

    def test_selected_process_failure_remains_incomplete_and_writes_requested_result(self):
        output = io.StringIO()
        result_path = self.home/'result.json'
        with mock.patch.object(self.cli.sys, 'version_info', (3, 10, 16)), \
             mock.patch.object(self.cli.sys, 'executable', str(self.bootstrap)), \
             mock.patch.object(managed_software, 'ensure_python', return_value=self.selected), \
             mock.patch.object(os, 'execv', side_effect=OSError('owned selected process refused')), \
             mock.patch.object(self.cli, 'install_environment', side_effect=AssertionError('failed handoff')), redirect_stdout(output):
            result = self.cli.main(['--environment-only', '--home', str(self.home), '--result', str(result_path)])
        self.assertEqual(result, 1)
        observed = json.loads(output.getvalue())
        self.assertEqual(observed, json.loads(result_path.read_text()))
        self.assertEqual(observed['status'], 'incomplete')
        self.assertIn('selected process refused', observed['error'])
