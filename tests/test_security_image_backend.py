"""Owned data/ordinary-file controls. Kernel effects and registry are denied."""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import io
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import security_inventory as inventory
from getzilla import security_image_backend as backend
from getzilla import security_image_producer as producer
from getzilla import security_image_registry as registry


class OwnedControls(unittest.TestCase):
    def setUp(self):
        previous = os.umask(0o077)
        self.addCleanup(os.umask, previous)
        for name in ('socket.socket', 'socket.getaddrinfo', 'subprocess.Popen', 'subprocess.run'):
            port = mock.patch(name, side_effect=AssertionError('native/process/network effect denied'))
            port.start()
            self.addCleanup(port.stop)

    def test_five_uses_keep_four_recipes_and_fixture_context_bytes(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime') as directory:
            root = Path(directory)
            (root / 'fixtures').mkdir()
            (root / 'fixtures/owned.txt').write_text('fixture bytes are build inputs')
            (root / 'app').write_text('ordinary application bytes')
            services = {'migrate': 'api', 'api': 'api', 'worker': 'worker',
                        'runner-image': 'runner', 'postgres-integration': 'test'}
            files, uses = ['compose.yaml', 'app', 'fixtures/owned.txt'], []
            text = 'services:\n'
            for service, recipe in services.items():
                text += (f'  {service}:\n    platform: linux/amd64\n    build:\n      context: .\n'
                         f'      dockerfile: Dockerfile.{recipe}\n      args:\n'
                         '        PYTHON_BASE_IMAGE: python@sha256:' + '2' * 64 + '\n')
            (root / 'compose.yaml').write_text(text)
            for recipe in sorted(set(services.values())):
                name = 'Dockerfile.' + recipe
                body = 'ARG PYTHON_BASE_IMAGE\nFROM ${PYTHON_BASE_IMAGE}\nCOPY app /app\n'
                (root / name).write_text(body)
                files.append(name)
                uses.append(dict(manifest=name, line=2, source_sha256=hashlib.sha256(body.encode()).hexdigest(),
                                 source_reference='${PYTHON_BASE_IMAGE}', reference='python@sha256:' + '2' * 64,
                                 platform='linux/amd64'))
            with mock.patch.object(inventory, '_tracked_files', return_value=files):
                value = inventory.collect_inventory(root, image_bindings=uses)
            self.assertEqual(len(value['builds']), 5)
            self.assertEqual(len({row['recipe_sha256'] for row in value['builds']}), 4)
            self.assertIn('fixtures/owned.txt', value['files'])
            self.assertEqual(len(value['files']), len(set(value['files'])))
            recipe = value['builds'][0]
            (root / 'app').write_text('x' * len('ordinary application bytes'))
            with self.assertRaises(backend.BackendUnavailable):
                producer._copy_context(root, recipe, root / 'sealed-context')

    @unittest.skipUnless(sys.platform == 'linux', 'Linux namespace and cgroup model required')
    def test_kernel_model_refuses_measured_wrong_volume_capacity(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime') as directory, ExitStack() as stack:
            volume = Path(directory)
            cgroup = Path('/sys/fs/cgroup/getzilla-images-' + 'a' * 32)
            observed = {cgroup / 'cgroup.procs': '1\n', Path('/proc/self/cgroup'): '0::/\n'}
            observed.update({Path('/sys/fs/cgroup') / name: value for name, value in {
                'memory.max': '2147483648', 'memory.swap.max': '0', 'pids.max': '256', 'cpu.max': '200000 100000'}.items()})
            def read_text(path, *_args, **_kwargs):
                if path not in observed:
                    raise AssertionError('outside fixture read denied')
                return observed[path]
            stack.enter_context(mock.patch.object(Path, 'read_text', read_text))
            stack.enter_context(mock.patch.object(backend, '_fixed'))
            stack.enter_context(mock.patch.object(backend, '_filesystem', side_effect=lambda path:
                0x63677270 if str(path) == '/sys/fs/cgroup' else 0x01021994))
            held = os.open(volume, os.O_RDONLY | os.O_DIRECTORY)
            stack.callback(os.close, held)
            stack.enter_context(mock.patch.object(backend, '_Root', return_value=SimpleNamespace(fd=held, close=lambda: None)))
            stack.enter_context(mock.patch.object(os, 'fstatvfs', return_value=SimpleNamespace(
                f_flag=os.ST_NOSUID | os.ST_NODEV | os.ST_NOEXEC)))
            stack.enter_context(mock.patch.object(backend, '_reap_children'))
            stack.enter_context(mock.patch('builtins.open', return_value=io.BytesIO(b'nameserver 192.0.2.1\n')))
            stack.enter_context(mock.patch.object(os, 'getpid', return_value=1))
            stack.enter_context(mock.patch.object(os, 'sched_getaffinity', return_value={0, 1}))
            stack.enter_context(mock.patch.object(os, 'geteuid', return_value=0))
            stack.enter_context(mock.patch.object(os, 'kill'))
            stack.enter_context(mock.patch.object(os, 'statvfs', return_value=SimpleNamespace(f_blocks=1, f_frsize=4096)))
            with self.assertRaises(backend.BackendUnavailable):
                with backend.namespace_volume(volume, cgroup):
                    pass

    @unittest.skipUnless(sys.platform == 'linux', 'Linux cgroup CPU affinity model required')
    def test_owned_control_files_keep_lower_inherited_cpu_quota(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime') as directory:
            root = Path(directory)
            for name in ('memory.max', 'memory.swap.max', 'pids.max', 'cpu.max'):
                (root / name).write_text('max')
            bounds = dict(levels=[{'cpu.max': '50000 100000'}], effective_cpuset='2-3')
            with mock.patch.object(os, 'sched_getaffinity', return_value={2, 3, 4}):
                self.assertEqual(backend._configure_cgroup(root, bounds), [2, 3])
            self.assertEqual((root / 'cpu.max').read_text(), '50000 100000')
            self.assertEqual((root / 'memory.max').read_text(), '2147483648')
            self.assertEqual((root / 'pids.max').read_text(), '256')

    def test_reader_accepts_exact_bound_and_refuses_limit_plus_one_and_deadline(self):
        class Stream:
            status, headers = 200, {}
            def __init__(self, body, tick):
                self.body, self.tick = body, tick
            def __enter__(self):
                return self
            def __exit__(self, *_):
                pass
            def read1(self, maximum):
                self.tick[0] += .1
                part, self.body = self.body[:maximum], self.body[maximum:]
                return part
        request = dict(url='https://registry-1.docker.io/v2/library/owned/manifests/tag',
                       headers={}, maximum=3, seconds=1)
        for body, seconds, accepted in ((b'abc', 1, True), (b'abcd', 1, False), (b'abc', .05, False)):
            with self.subTest(size=len(body), seconds=seconds):
                tick = [0]
                stream = Stream(body, tick)
                parts = registry._http({**request, 'seconds': seconds},
                    opener=lambda *_args, **_kwargs: stream, clock=lambda: tick[0])
                if accepted:
                    self.assertEqual(b''.join(list(parts)[1:]), body)
                else:
                    with self.assertRaises(registry.RegistryError):
                        list(parts)


if __name__ == '__main__':
    unittest.main()
