"""Own tiny wheel metadata and explicit inert pip/interpreter effects."""
import hashlib
import importlib.util
import io
from contextlib import redirect_stdout
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import managed_environment


class ManagedEnvironmentTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        owned = tempfile.TemporaryDirectory(prefix='owned-quality-env-', dir=scratch)
        self.addCleanup(owned.cleanup)
        self.root = Path(owned.name)
        self.payload = b'owned inert wheel bytes; never executed'
        self.url = 'https://files.pythonhosted.org/packages/pytest-10.0.0-py3-none-any.whl'
        self.digest = hashlib.sha256(self.payload).hexdigest()
        self.commands = []
        self.broken = False

    def fetch(self, url):
        if url == 'https://pypi.org/pypi/pytest/json':
            return json.dumps(dict(info=dict(name='pytest'), releases={'9.0.0': [{'yanked': False}], '10.0.0': [{'yanked': False}]})).encode()
        if url == 'https://pypi.org/pypi/pytest/10.0.0/json':
            return json.dumps(dict(info=dict(name='pytest', version='10.0.0'), urls=[dict(filename='pytest-10.0.0-py3-none-any.whl',
                  url=self.url, digests={'sha256': self.digest}, yanked=False, packagetype='bdist_wheel')])).encode()
        self.assertEqual(url, self.url)
        return self.payload

    def run_inert(self, command, cwd=None, *, env=None):
        self.commands.append(command)
        if command[1:3] == ['-m', 'venv']:
            directory = Path(command[3])
            (directory / 'bin').mkdir(parents=True)
            (directory / 'bin/python').write_bytes(b'inert owned interpreter')
        if '--report' in command:
            self.assertIn('pytest==10.0.0', command)
            if self.broken:
                return subprocess.CompletedProcess(command, 1, '', 'latest version incompatible')
            Path(command[command.index('--report')+1]).write_text(json.dumps({'version': '1', 'install': [dict(
                metadata=dict(name='pytest', version='10.0.0'), download_info=dict(url=self.url,
                archive_info=dict(hashes=dict(sha256=self.digest))))]}))
        if '-I' in command:
            if 'sysconfig' in command[command.index('-c')+1]:
                facts = dict(python_version='3.15.2', implementation='cpython',
                             version_info=[3, 15, 2], soabi='cpython-315-x86_64-linux-gnu',
                             cache_tag='cpython-315', executable=command[0])
                return subprocess.CompletedProcess(command, 0, json.dumps(facts), '')
            return subprocess.CompletedProcess(command, 0, json.dumps({'pytest': '10.0.0'}), '')
        return subprocess.CompletedProcess(command, 0, '', '')

    def test_new_major_wheel_graph_exact_hashes_and_actual_environment(self):
        path = managed_environment.install_environment(self.root, '/owned/python', fetch=self.fetch, run=self.run_inert,
                                                       projects=('pytest',))
        self.assertTrue(path.is_file())
        self.assertTrue((self.root / '.venv').is_symlink())
        self.assertTrue(any('--require-hashes' in command and '--no-index' in command for command in self.commands))
        self.assertTrue(any('-I' in command for command in self.commands))

    def test_incompatible_latest_preserves_old_environment_no_old_fallback(self):
        old = self.root / '.venv'
        old.mkdir()
        (old / 'user-file').write_text('keep')
        self.broken = True
        with self.assertRaisesRegex(ValueError, 'incompatible'):
            managed_environment.install_environment(self.root, '/owned/python', fetch=self.fetch, run=self.run_inert,
                                                    projects=('pytest',))
        self.assertEqual((old / 'user-file').read_text(), 'keep')
        self.assertFalse(any('--require-hashes' in command for command in self.commands))


    def test_ambient_pip_index_overrides_do_not_reach_exact_resolution(self):
        original = self.run_inert
        seen = []
        def run(command, cwd=None, *, env=None):
            if '--report' in command:
                seen.append(command)
                self.assertNotIn('--no-index', command)
                self.assertEqual(command[command.index('--index-url')+1], 'https://pypi.org/simple')
                for key in ('PIP_NO_INDEX', 'PIP_INDEX_URL', 'PIP_EXTRA_INDEX_URL', 'PIP_FIND_LINKS', 'PIP_NO_BINARY'):
                    self.assertNotIn(key, env)
                self.assertEqual(env['PIP_CONFIG_FILE'], os.devnull)
            return original(command, cwd, env=env)
        overrides = dict(PIP_NO_INDEX='1', PIP_INDEX_URL='https://untrusted.invalid/simple',
                         PIP_EXTRA_INDEX_URL='https://untrusted.invalid/extra', PIP_FIND_LINKS='/untrusted',
                         PIP_NO_BINARY='PyYAML')
        with mock.patch.dict(os.environ, overrides),                 mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('no actual process')):
            managed_environment.install_environment(self.root, '/owned/python', fetch=self.fetch, run=run, projects=('pytest',))
        self.assertEqual(len(seen), 1)

    def test_resolver_failure_retains_bounded_redacted_cause_without_activation(self):
        original = self.run_inert
        def run(command, cwd=None, *, env=None):
            if '--report' in command:
                stderr = ('INDEX-WARNING https://owned-user:owned-credential@mirror.invalid/simple?token=owned-token\n'
                          + 'x'*20000 + '\nPyYAML>=5.3.1: versions none')
                return subprocess.CompletedProcess(command, 1, '', stderr)
            return original(command, cwd, env=env)
        with self.assertRaises(ValueError):
            managed_environment.install_environment(self.root, '/owned/python', fetch=self.fetch, run=run, projects=('pytest',))
        records = list(self.root.glob('.getzilla/runtime/environments/current-*/failure.json'))
        self.assertEqual(len(records), 1, 'the first index warning must survive the final pip error')
        raw = records[0].read_bytes()
        self.assertLessEqual(len(raw), 65536)
        self.assertNotIn(b'owned-credential', raw)
        self.assertNotIn(b'owned-token', raw)
        report = json.loads(raw)
        self.assertEqual(report['phase'], 'resolve exact wheel closure')
        self.assertEqual(report['runtime']['python_version'], '3.15.2')
        self.assertEqual(report['runtime']['soabi'], 'cpython-315-x86_64-linux-gnu')
        self.assertIn('INDEX-WARNING', report['stderr']['retained'])
        self.assertIn('PyYAML', report['stderr']['retained'])
        self.assertGreater(report['stderr']['omitted_bytes'], 0)
        self.assertIn('--index-url', report['command'])
        self.assertNotIn('--no-index', report['command'])
        self.assertFalse((self.root/'.venv').exists())


    def test_cli_retains_redacted_failure_evidence_in_the_uploaded_command_output(self):
        original = self.run_inert
        def run(command, cwd=None, *, env=None):
            if '--report' in command:
                return subprocess.CompletedProcess(command, 1, '', 'INDEX-WARNING '+('x'*2000)+' PyYAML versions none')
            return original(command, cwd, env=env)
        try:
            managed_environment.install_environment(self.root, '/owned/python', fetch=self.fetch, run=run, projects=('pytest',))
        except managed_environment.EnvironmentFailure as error:
            captured = error
        spec = importlib.util.spec_from_file_location('owned_managed_cli', ROOT/'scripts/getzilla_install_managed.py')
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)
        from getzilla import managed_software
        output = io.StringIO()
        with mock.patch.object(managed_software, 'ensure_python', return_value=Path('/owned/python')),                 mock.patch.object(cli, 'home_dir', return_value=self.root),                 mock.patch.object(cli, 'install_environment', side_effect=captured), redirect_stdout(output):
            result = cli.main(['--environment-only', '--home', str(self.root)])
        self.assertEqual(result, 1)
        report = json.loads(output.getvalue())
        self.assertEqual(report['status'], 'incomplete')
        self.assertEqual(report['diagnostic']['phase'], 'resolve exact wheel closure')
        self.assertIn('INDEX-WARNING', report['diagnostic']['stderr']['retained'])
        self.assertIn('PyYAML', report['diagnostic']['stderr']['retained'])
        self.assertLessEqual(len(output.getvalue().encode()), 128*1024)
