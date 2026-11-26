"""Owned npm archives; all native npm/node effects are recorded, never executed."""
import base64
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import latest_releases, managed_npm


class ManagedNpmTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        owned = tempfile.TemporaryDirectory(prefix='owned-managed-npm-', dir=scratch)
        self.addCleanup(owned.cleanup)
        self.root = Path(owned.name)
        self.data = self.archive({'name': 'npm', 'version': '13.0.0', 'bin': {'npm': 'bin/npm-cli.js'}},
                                 {'bin/npm-cli.js': b'inert npm CLI'})
        self.target = latest_releases.Target('npm', '13.0.0', 'https://registry.npmjs.org/npm/-/npm-13.0.0.tgz',
             integrity='sha512-'+base64.b64encode(hashlib.sha512(self.data).digest()).decode(),filename='npm-13.0.0.tgz')

    def archive(self, metadata, files):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            for name, raw in {'package.json': json.dumps(metadata).encode(), **files}.items():
                item = tarfile.TarInfo('package/'+name)
                item.size = len(raw)
                item.mode = 0o644
                archive.addfile(item, io.BytesIO(raw))
        return stream.getvalue()

    def test_npm_uses_exact_independent_target_and_verified_node(self):
        calls = []
        def run(command, cwd=None, **kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, '13.0.0', '')
        path = managed_npm.install_npm(self.target, self.data, self.root, Path('/owned/node'), run=run)
        self.assertEqual(path.read_bytes(), b'inert npm CLI')
        self.assertEqual(calls[0][0], '/owned/node')
        self.assertEqual(calls[0][1], str(path))

    def test_identity_and_integrity_failure_never_executes(self):
        bad = self.archive({'name': 'other', 'version': '13.0.0'}, {'bin/npm-cli.js': b'inert'})
        with self.assertRaises(ValueError):
            managed_npm.install_npm(self.target, bad, self.root, Path('/owned/node'), run=lambda *a, **kw: self.fail())

    def test_user_command_cas_conflict_preserves_content(self):
        binary = self.root/'bin/qwen'
        binary.parent.mkdir()
        binary.write_text('user command')
        with self.assertRaisesRegex(ValueError, 'conflict'):
            managed_npm.publish_command(self.root, 'qwen', [str(self.root/'node'), str(self.root/'qwen.js')])
        self.assertEqual(binary.read_text(), 'user command')

    def test_agent_exact_lock_tarballs_and_audit_join_never_run_real_npm(self):
        name, version = '@qwen-code/qwen-code', '9.0.0'
        data = self.archive({'name': name, 'version': version, 'bin': {'qwen': 'cli.js'}}, {'cli.js': b'inert owned CLI'})
        integrity = 'sha512-'+base64.b64encode(hashlib.sha512(data).digest()).decode()
        url = 'https://registry.npmjs.org/@qwen-code/qwen-code/-/qwen-code-9.0.0.tgz'
        target = latest_releases.Target(name, version, url, integrity=integrity, filename='qwen-code-9.0.0.tgz')
        output = version
        calls = []
        def run(command, cwd=None, **kwargs):
            calls.append(command)
            self.assertNotIn('OPENROUTER_API_KEY', kwargs.get('env', {}))
            if '--package-lock-only' in command:
                (cwd/'package-lock.json').write_text(json.dumps(dict(lockfileVersion=3, packages={
                    '': dict(dependencies={name: version}), 'node_modules/'+name: dict(version=version, resolved=url, integrity=integrity)})))
            elif 'ci' in command:
                directory = cwd/'node_modules'/name
                directory.mkdir(parents=True)
                (directory/'package.json').write_text(json.dumps({'name': name, 'version': version, 'bin': {'qwen': 'cli.js'}}))
                (directory/'cli.js').write_bytes(b'inert owned CLI')
            return subprocess.CompletedProcess(command, 0, output, '')
        def fetch(request):
            if request == url:
                return data
            self.assertEqual(request, 'https://registry.npmjs.org/@qwen-code%2Fqwen-code/9.0.0')
            return json.dumps(dict(name=name, version=version, dist=dict(tarball=url, integrity=integrity))).encode()
        result = managed_npm.install_agent(target, self.root, self.root/'node', self.root/'npm', command='qwen', fetch=fetch, run=run)
        self.assertEqual(result.name, 'qwen.cmd' if sys.platform == 'win32' else 'qwen')
        self.assertTrue(any('signatures' in c for c in calls))
        self.assertTrue(any('ci' in c and '--offline' in c and '--ignore-scripts' in c for c in calls))
        self.assertFalse(any('rebuild' in c for c in calls))

        previous = result.read_bytes()
        output = '8.0.0\nUpdate available: 9.0.0'
        with self.assertRaisesRegex(ValueError, 'actual=8.0.0'):
            managed_npm.install_agent(target, self.root, self.root/'node', self.root/'npm',
                                      command='qwen', fetch=fetch, run=run)
        self.assertEqual(result.read_bytes(), previous)
