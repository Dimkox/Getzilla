"""Own tiny wheel metadata and explicit inert pip/interpreter effects."""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
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
