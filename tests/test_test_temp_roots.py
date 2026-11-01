"""Parallel unittest fixtures must not share a noisy temporary-file parent."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

_CHILD = """
import json, pathlib, tempfile
with tempfile.TemporaryDirectory() as directory:
    path = pathlib.Path(directory) / 'child.txt'
    path.write_bytes(b'child')
    print(json.dumps({'root': tempfile.gettempdir(), 'parent': str(path.parent.parent),
                      'payload': path.read_bytes() == b'child'}))
"""

_WORKER = """
import json, os, pathlib, subprocess, sys, tempfile
import tests
root = pathlib.Path(tempfile.gettempdir())
with tempfile.TemporaryDirectory() as directory:
    path = pathlib.Path(directory) / 'fixture.txt'
    path.write_bytes(b'fixture')
    fixture_parent = str(path.parent.parent)
    payload = path.read_bytes() == b'fixture'
child = subprocess.run([sys.executable, '-B', '-c', sys.argv[1]],
                       capture_output=True, text=True, check=True, timeout=15)
descendant = subprocess.run([sys.executable, '-B', '-c',
    'import tests, tempfile; print(tempfile.gettempdir())'],
    capture_output=True, text=True, check=True, timeout=15)
print(json.dumps({'root': str(root), 'fixture_parent': fixture_parent, 'payload': payload,
                  'environment': [os.environ[name] for name in ('TMPDIR', 'TEMP', 'TMP')],
                  'child': json.loads(child.stdout), 'descendant': descendant.stdout.strip()}))
"""

_CAPTURE_CHILD = """
import os, pathlib, sys
from unittest.mock import patch
from getzilla.git_binding_guard import GuardUnavailable, LinuxGitGuard
from getzilla.architecture import ArchitectureError
fixture = pathlib.Path(sys.argv[1])
guard = None
try:
    try:
        guard = LinuxGitGuard()
        guard.directory(fixture, 'fixture root')
        guard.protect(fixture, 'HEAD', 'HEAD selector')
        guard.seal()
    except GuardUnavailable:
        raise SystemExit(77)
    original_read = os.read
    def capture_activity(descriptor, length):
        if descriptor == guard._descriptor:
            os.write(1, b'.')
            os.write(2, b'.')
        return original_read(descriptor, length)
    with patch.object(os, 'read', capture_activity):
        guard.check()
    selector = fixture / 'HEAD'
    selector.write_bytes(b'transient')
    selector.unlink()
    try:
        guard.check()
    except ArchitectureError:
        print('protected-selector-refused')
    else:
        raise SystemExit('protected selector was admitted')
finally:
    if guard is not None:
        guard.close()
"""


class TestTemporaryRootsTests(unittest.TestCase):
    def _worker(self, parent: Path, identity: str | None) -> dict:
        environment = {**os.environ, 'TMPDIR': str(parent), 'TEMP': str(parent),
                       'TMP': str(parent), 'PYTHONDONTWRITEBYTECODE': '1'}
        environment.pop('PYTEST_XDIST_WORKER', None)
        if identity is not None:
            environment['PYTEST_XDIST_WORKER'] = identity
        process = subprocess.run([sys.executable, '-B', '-c', _WORKER, _CHILD],
                                 cwd=ROOT, env=environment, capture_output=True,
                                 text=True, timeout=45)
        self.assertEqual(process.returncode, 0, process.stderr)
        return json.loads(process.stdout)

    def test_workers_use_distinct_private_roots_within_the_owned_run(self):
        original = tempfile.gettempdir(), {key: os.environ.get(key) for key in ('TMPDIR', 'TEMP', 'TMP')}
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            results = [self._worker(parent, worker) for worker in ('gw0', 'gw1', 'gw0')]
            roots = [Path(result['root']) for result in results]
            self.assertEqual(len(set(roots)), 3)
            for result, root in zip(results, roots):
                self.assertEqual(root.parent, parent)
                self.assertEqual(result['fixture_parent'], str(root))
                self.assertTrue(result['payload'])
                if os.name != 'nt':
                    self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
        self.assertEqual((tempfile.gettempdir(), {key: os.environ.get(key)
                         for key in ('TMPDIR', 'TEMP', 'TMP')}), original)

    def test_child_cli_and_descendant_package_import_stay_in_the_worker_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            result = self._worker(parent, 'gw3')
            root = Path(result['root'])
            self.assertNotEqual(root, parent)
            self.assertEqual(result['environment'], [str(root)] * 3)
            self.assertEqual(result['child']['root'], str(root))
            self.assertEqual(result['child']['parent'], str(root))
            self.assertTrue(result['child']['payload'])
            self.assertTrue(Path(result['descendant']).is_relative_to(root))

    def test_nonworker_and_malformed_identities_keep_the_canonical_root(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            for identity in (None, '', 'controller', 'gw', 'gw../escape', 'gw1/escape', 'gw١'):
                with self.subTest(identity=identity):
                    result = self._worker(parent, identity)
                    self.assertEqual(Path(result['root']), parent)
                    self.assertEqual(Path(result['fixture_parent']), parent)

    def test_sibling_worker_activity_cannot_exhaust_the_native_guard_drain(self):
        from getzilla.git_binding_guard import GuardUnavailable, LinuxGitGuard
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            left = Path(self._worker(parent, 'gw0')['root'])
            right = Path(self._worker(parent, 'gw1')['root'])
            watched = left / 'watched-fixture'
            watched.mkdir()
            guard = None
            try:
                try:
                    guard = LinuxGitGuard()
                    guard.directory(watched, 'fixture root')
                    guard.seal()
                except GuardUnavailable:
                    self.skipTest('qualified native filesystem guard is unavailable')
                original_read = os.read
                cycles = 0

                def sibling_activity(descriptor, length):
                    nonlocal cycles
                    if descriptor == guard._descriptor:
                        path = right / ('activity-' + str(cycles))
                        path.write_bytes(b'')
                        path.unlink()
                        cycles += 1
                    return original_read(descriptor, length)

                # Real unrelated events arrive before each real inotify read. A
                # shared parent keeps the bounded drain busy; a worker sibling
                # sits outside these nonrecursive watches. Limits stay intact.
                with patch.object(os, 'read', sibling_activity):
                    guard.check()
                self.assertGreater(cycles, 0)
            finally:
                if guard is not None:
                    guard.close()

    def test_native_output_capture_cannot_exhaust_a_child_fixture_guard(self):
        from getzilla.python_test_runner import execute
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            fixture = parent / 'fixtures' / 'worker' / 'repo'
            fixture.mkdir(parents=True)
            child = parent / 'capture_child.py'
            child.write_text(_CAPTURE_CHILD, encoding='utf-8')
            environment = {**os.environ, 'PYTHONPATH': str(ROOT / '.getzilla'),
                           'PYTHONDONTWRITEBYTECODE': '1', 'TMPDIR': str(fixture.parent),
                           'TMP': str(fixture.parent), 'TEMP': str(fixture.parent)}
            with patch.object(tempfile, 'tempdir', str(parent)):
                result = execute([sys.executable, '-B', str(child), str(fixture)],
                                 parent, environment, timeout=20)
            if result.returncode == 77:
                self.skipTest('qualified native filesystem guard is unavailable')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(result.stdout.startswith('.'), result.stdout)
            self.assertTrue(result.stdout.endswith('protected-selector-refused\n'), result.stdout)
            self.assertEqual(result.cleanup_error, '')

    def test_native_capture_storage_is_private_and_removed(self):
        from getzilla.python_test_runner import execute
        original_file = tempfile.TemporaryFile
        locations = []
        modes = []

        def observe_file(*args, **kwargs):
            location = Path(kwargs.get('dir') or tempfile.gettempdir()).resolve()
            locations.append(location)
            modes.append(stat.S_IMODE(location.stat().st_mode))
            return original_file(*args, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            with patch.object(tempfile, 'tempdir', str(parent)), \
                 patch.object(tempfile, 'TemporaryFile', observe_file):
                result = execute([sys.executable, '-c', 'print("captured")'], parent, os.environ.copy())
            self.assertEqual((result.returncode, result.stdout, result.cleanup_error), (0, 'captured\n', ''))
            self.assertTrue(locations)
            for location, mode in zip(locations, modes):
                self.assertNotEqual(location, parent)
                self.assertTrue(location.is_relative_to(parent))
                if os.name != 'nt':
                    self.assertEqual(mode, 0o700)
                self.assertFalse(location.exists())
            self.assertEqual(list(parent.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
