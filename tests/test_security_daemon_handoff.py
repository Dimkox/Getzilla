"""Actual owned parent/child/pidfd regression; client work is a tiny owned child."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import security_image_backend as backend
from getzilla.architecture_diff import _run_capped


@unittest.skipUnless(sys.platform == 'linux', 'Linux held handles and private socket aliases required')
class DaemonHandoffControl(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, 'pidfd_open') and hasattr(os, 'fork'), 'Linux held process handles required')
    def test_client_child_observes_held_daemon_without_waiting_foreign_child(self):
        daemon = subprocess.Popen([sys.executable, '-I', '-S', '-B', '-c', 'import time;time.sleep(30)'],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        pidfd = os.pidfd_open(daemon.pid)
        reader, writer = os.pipe()
        with tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime') as directory:
            root = Path(directory)
            guard = (root, object(), [])  # Model only: no namespace/build qualification.
            builder = object.__new__(backend.BuildKit)
            builder.volume, builder.guard = root, guard
            builder.process, builder.pidfd = daemon, pidfd
            builder.client, builder.address, builder.runc = sys.executable, 'unix:///tmp/owned-fixture', ''
            builder.deadline, builder.env = time.monotonic() + 5, {'PATH': os.defpath}
            child = os.fork()
            if child == 0:
                os.close(reader)
                try:
                    def client(_command, **_kwargs):
                        return _run_capped([sys.executable, '-I', '-S', '-B', '-c', 'pass'], cwd=root,
                            env={'PATH': os.defpath}, stdin_data=None, stdout_limit=128, stderr_limit=128, timeout=2)
                    with mock.patch.object(backend, '_GUARD', guard), mock.patch(
                            'getzilla.architecture_diff._run_capped', side_effect=client):
                        marker = builder.build(dict(dockerfile='Dockerfile', context='.', platform='linux/amd64',
                                                    arguments={}), root, root / 'not-an-image')
                    os.write(writer, b'held-live' if marker is backend._ACTIVE and builder.process.returncode is None else b'bad')
                except BaseException:
                    os.write(writer, b'failed')
                os._exit(0)
            os.close(writer)
            try:
                self.assertEqual(os.read(reader, 128), b'held-live')
                self.assertEqual(os.waitpid(child, 0)[1], 0)
            finally:
                os.close(reader)
                try:
                    os.waitpid(child, 0)
                except ChildProcessError:
                    pass
                daemon.terminate()
                daemon.wait(timeout=5)
                os.close(pidfd)

    def test_long_runtime_uses_only_same_volume_short_socket_alias(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime') as directory:
            volume = Path(directory) / ('long-canonical-image-volume-' * 3)
            volume.mkdir(mode=0o700)
            (volume / 'tmp').mkdir(mode=0o700)
            held = os.open(volume / 'tmp', os.O_RDONLY | os.O_DIRECTORY)
            def extract(_archive, target):
                target.mkdir()
                result = {}
                for name in ('buildkitd', 'buildctl', 'buildkit-runc'):
                    path = target / name
                    path.write_bytes(b'owned model, never executable input')
                    result[name] = {'path': str(path), 'sha256': 'model-only'}
                return result
            try:
                with mock.patch.object(backend, '_GUARD', (volume, object(), [])), \
                        mock.patch.object(backend, '_fixed'), \
                        mock.patch('getzilla.security_image_provision.archive_bytes', return_value=b'owned model'), \
                        mock.patch('getzilla.security_image_provision.extract_tools', side_effect=extract), \
                        mock.patch.object(backend, '_Root', return_value=mock.Mock(fd=held)), \
                        mock.patch.object(backend, '_filesystem', return_value=0x01021994):
                    builder = backend.BuildKit(volume, archive='model-only', deadline=time.monotonic() + 1)
                    self.assertLess(len(os.fsencode(builder.address.removeprefix('unix://'))), 104)
                    self.assertEqual(builder.socket.parent, Path('/tmp'))
            finally:
                os.close(held)

    def test_foreign_short_alias_inode_is_refused(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime') as directory:
            root = Path(directory)
            (root / 'tmp').mkdir(mode=0o700)
            (root / 'foreign').mkdir(mode=0o700)
            a = os.open(root / 'tmp', os.O_RDONLY | os.O_DIRECTORY)
            b = os.open(root / 'foreign', os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch.object(backend, '_Root', side_effect=[mock.Mock(fd=a), mock.Mock(fd=b)]), \
                        mock.patch.object(backend, '_filesystem', return_value=0x01021994):
                    with self.assertRaises(backend.BackendUnavailable):
                        backend._socket_alias(root)
            finally:
                os.close(a)
                os.close(b)
