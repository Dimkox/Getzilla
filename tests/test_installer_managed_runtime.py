"""Verified tiny archives and inert probes for per-user runtime activation."""
import hashlib
import io
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla.latest_releases import Target
from getzilla import managed_runtime


class ManagedRuntimeTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        self.owned = tempfile.TemporaryDirectory(prefix='owned-runtime-', dir=scratch)
        self.addCleanup(self.owned.cleanup)
        self.root = Path(self.owned.name)

    def target(self, version='4.0.0', unsafe=False):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.writestr('../escape' if unsafe else 'python.exe', b'inert verified runtime ' + version.encode())
            archive.writestr('python.dll', b'inert companion')
        payload = stream.getvalue()
        return Target('python', version, 'https://www.python.org/owned.zip',
                      sha256=hashlib.sha256(payload).hexdigest(), filename='owned.zip'), payload

    def test_verified_archive_stage_and_exact_actual_probe(self):
        target, payload = self.target()
        calls = []
        def run(command, cwd):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, 'Python 4.0.0', '')
        path = managed_runtime.install(target, payload, self.root, executable='python.exe', run=run)
        self.assertEqual(path.read_bytes(), b'inert verified runtime 4.0.0')
        self.assertEqual((path.parent / 'python.dll').read_bytes(), b'inert companion')
        self.assertEqual(calls, [[str(path), '--version']])
        self.assertEqual(managed_runtime.install(target, payload, self.root, executable='python.exe', run=run), path)

    def test_integrity_traversal_and_probe_failure_do_not_activate(self):
        target, payload = self.target(unsafe=True)
        with self.assertRaises(ValueError):
            managed_runtime.install(target, payload, self.root, executable='python.exe', run=lambda *a: self.fail())
        target, payload = self.target()
        with self.assertRaises(ValueError):
            managed_runtime.install(target, payload+b'corruption', self.root, executable='python.exe', run=lambda *a: self.fail())
        with self.assertRaisesRegex(ValueError, 'probe'):
            managed_runtime.install(target, payload, self.root, executable='python.exe',
                run=lambda command, cwd: subprocess.CompletedProcess(command, 1, 'Python 4.0.0', 'failed'))
        self.assertFalse((self.root / 'active.json').exists())

    def test_new_major_does_not_delete_previous_or_user_modified_runtime(self):
        first, payload = self.target()
        old = managed_runtime.install(first, payload, self.root, executable='python.exe',
            run=lambda command, cwd: subprocess.CompletedProcess(command, 0, 'Python 4.0.0', ''))
        old.write_bytes(b'user modification')
        newer, payload = self.target('5.0.0')
        path = managed_runtime.install(newer, payload, self.root, executable='python.exe',
            run=lambda command, cwd: subprocess.CompletedProcess(command, 0, 'Python 5.0.0', ''))
        self.assertEqual(old.read_bytes(), b'user modification')
        self.assertNotEqual(old, path)
        with self.assertRaisesRegex(ValueError, 'conflict'):
            original, data = self.target()
            managed_runtime.install(original, data, self.root, executable='python.exe', run=lambda *a: self.fail())
