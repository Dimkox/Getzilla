from __future__ import annotations

import os
import signal
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import fsx  # noqa: E402


def _write(parent: fsx.DirHandle, name: str, data: bytes) -> None:
    descriptor = fsx.open_at(parent, name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        os.write(descriptor, data)
    finally:
        os.close(descriptor)


def _read(parent: fsx.DirHandle, name: str) -> bytes:
    descriptor = fsx.open_at(parent, name, os.O_RDONLY | fsx.O_NOFOLLOW)
    try:
        return os.read(descriptor, 1024)
    finally:
        os.close(descriptor)


@unittest.skipIf(fsx.WINDOWS, 'POSIX process groups')
class KillProcessTreeTests(unittest.TestCase):
    def test_a_group_that_already_exited_is_not_an_error(self) -> None:
        from unittest import mock
        with mock.patch.object(fsx.os, 'killpg', side_effect=ProcessLookupError), \
                mock.patch.object(fsx.os, 'kill') as kill:
            fsx.kill_process_tree(12345)
        kill.assert_not_called()

    def test_macos_eperm_for_an_unreaped_leader_falls_back_to_the_leader(self) -> None:
        from unittest import mock
        with mock.patch.object(fsx.os, 'killpg', side_effect=PermissionError(1, 'Operation not permitted')), \
                mock.patch.object(fsx.os, 'kill') as kill:
            fsx.kill_process_tree(12345)
        kill.assert_called_once_with(12345, signal.SIGKILL)
        with mock.patch.object(fsx.os, 'killpg', side_effect=PermissionError(1, 'Operation not permitted')), \
                mock.patch.object(fsx.os, 'kill', side_effect=PermissionError(1, 'Operation not permitted')):
            with self.assertRaises(PermissionError):
                fsx.kill_process_tree(12345)

    @unittest.skipUnless(hasattr(os, 'waitid'), 'os.waitid is missing (macOS before Python 3.13)')
    def test_an_exited_but_unreaped_child_is_killed_without_error(self) -> None:
        import subprocess
        process = subprocess.Popen([sys.executable, '-c', 'pass'], **fsx.process_group_kwargs())
        try:
            os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT)  # exited, still a zombie
            fsx.kill_process_tree(process.pid)
        finally:
            process.wait()


class FsxTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root_path = Path(self._tmp.name)
        self.root = fsx.open_dir(self.root_path)
        fsx.mkdir_at(self.root, 'sub')
        self.sub = fsx.open_dir_at(self.root, 'sub')

    def tearDown(self) -> None:
        fsx.close_dir(self.sub)
        fsx.close_dir(self.root)
        self._tmp.cleanup()

    def test_create_read_scan_and_remove_relative_to_a_directory_handle(self) -> None:
        _write(self.sub, 'a.txt', b'alpha\r\n')
        self.assertEqual(_read(self.sub, 'a.txt'), b'alpha\r\n')
        self.assertEqual(sorted(entry.name for entry in fsx.scandir(self.sub)), ['a.txt'])
        self.assertEqual(fsx.listdir(self.sub), ['a.txt'])
        info = fsx.lstat_at(self.sub, 'a.txt')
        self.assertFalse(fsx.is_link(info))
        self.assertEqual(info.st_size, 7)
        fsx.unlink_at(self.sub, 'a.txt')
        self.assertEqual(fsx.listdir(self.sub), [])

    def test_exclusive_create_refuses_an_existing_entry(self) -> None:
        _write(self.sub, 'a.txt', b'one')
        with self.assertRaises(FileExistsError):
            _write(self.sub, 'a.txt', b'two')
        self.assertEqual(_read(self.sub, 'a.txt'), b'one')

    def test_replace_overwrites_and_link_refuses_an_existing_target(self) -> None:
        _write(self.sub, 'new.txt', b'new')
        _write(self.sub, 'old.txt', b'old')
        with self.assertRaises(FileExistsError):
            fsx.link_at(self.sub, 'new.txt', self.sub, 'old.txt')
        fsx.replace_at(self.sub, 'new.txt', self.sub, 'old.txt')
        self.assertEqual(_read(self.sub, 'old.txt'), b'new')
        self.assertEqual(fsx.listdir(self.sub), ['old.txt'])

    def test_links_are_refused_instead_of_followed(self) -> None:
        target = self.root_path / 'outside.txt'
        target.write_bytes(b'outside')
        try:
            (self.root_path / 'sub' / 'link.txt').symlink_to(target)
            (self.root_path / 'linkdir').symlink_to(self.root_path / 'sub', target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f'symbolic links unavailable here: {exc}')
        self.assertTrue(fsx.is_link(fsx.lstat_at(self.sub, 'link.txt')))
        with self.assertRaises(OSError):
            _read(self.sub, 'link.txt')
        with self.assertRaises(OSError):
            fsx.open_dir_at(self.root, 'linkdir')

    def test_entry_names_cannot_escape_the_directory(self) -> None:
        if not fsx.WINDOWS:
            self.skipTest('POSIX dir_fd calls already resolve names relative to the descriptor')
        for name in ('..', 'x/y', 'x\\y', 'c:evil', ''):
            with self.subTest(name=name), self.assertRaises(OSError):
                fsx.lstat_at(self.sub, name)

    def test_windows_no_replace_rename_and_exchange(self) -> None:
        if not fsx.WINDOWS:
            self.skipTest('Windows-only primitives')
        _write(self.sub, 'a.txt', b'new')
        _write(self.sub, 'b.txt', b'old')
        with self.assertRaises(FileExistsError):
            fsx.rename_noreplace_at(self.sub, 'a.txt', self.sub, 'b.txt')
        fsx.exchange_at(self.sub, 'a.txt', 'b.txt')
        self.assertEqual(_read(self.sub, 'b.txt'), b'new')
        self.assertEqual(_read(self.sub, 'a.txt'), b'old')

    def test_lock_and_unlock_a_file(self) -> None:
        _write(self.sub, 'lock', b'x')
        descriptor = fsx.open_at(self.sub, 'lock', os.O_RDWR)
        try:
            fsx.lock_file(descriptor)
            fsx.unlock_file(descriptor)
            fsx.lock_file(descriptor, blocking=False)
            fsx.unlock_file(descriptor)
        finally:
            os.close(descriptor)

    def test_directory_identity_and_removal(self) -> None:
        before = fsx.fstat_dir(self.sub)
        _write(self.sub, 'a.txt', b'a')
        after = fsx.fstat_dir(self.sub)
        self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
        fsx.unlink_at(self.sub, 'a.txt')
        fsx.mkdir_at(self.sub, 'inner')
        fsx.rmdir_at(self.sub, 'inner')
        self.assertEqual(fsx.listdir(self.sub), [])

    def test_owned_popen_starts_a_stoppable_process_tree(self) -> None:
        process = fsx.owned_popen([sys.executable, '-c', 'import time; time.sleep(60)'])
        try:
            if fsx.WINDOWS:
                job = fsx.owned_job(process)
                self.assertIsNotNone(job)
                self.assertTrue(fsx.process_jobs_supported())
                self.assertTrue(job.terminate(5))
                job.close()
            else:
                # POSIX keeps the new session the runner always used.
                self.assertIsNone(fsx.owned_job(process))
                self.assertFalse(fsx.process_jobs_supported())
                self.assertEqual(os.getsid(process.pid), process.pid)
                os.killpg(process.pid, signal.SIGKILL)
            self.assertIsNotNone(process.wait(timeout=5))
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)



class BoundRootReaderTests(unittest.TestCase):
    def test_shared_snapshot_error_identity_and_legacy_serialization(self) -> None:
        import dataclasses
        import hashlib
        import pickle
        from getzilla import component_state
        for name in ('FileSnapshot', 'ComponentStateError', '_FileSnapshotChanged',
                     'path_parts', '_identity', '_file_identity'):
            self.assertIs(getattr(fsx, name, None), getattr(component_state, name))
        snapshot = fsx.FileSnapshot(b'public fixture', 0o644, (1, 2, 3))
        self.assertEqual([field.name for field in dataclasses.fields(snapshot)],
                         ['content', 'mode', 'identity'])
        self.assertEqual(snapshot.sha256, hashlib.sha256(snapshot.content).hexdigest())
        self.assertEqual(hash(snapshot), hash(component_state.FileSnapshot(*(
            snapshot.content, snapshot.mode, snapshot.identity))))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            snapshot.mode = 0
        self.assertTrue(issubclass(fsx._FileSnapshotChanged, fsx.ComponentStateError))
        self.assertTrue(issubclass(fsx.ComponentStateError, ValueError))
        self.assertIs(pickle.loads(b'cgetzilla.component_state\nFileSnapshot\n.'),
                      fsx.FileSnapshot)
        for value in (snapshot, fsx.ComponentStateError('public'),
                      fsx._FileSnapshotChanged('public')):
            self.assertEqual(type(value).__module__, 'getzilla.component_state')
            for protocol in (2, 4, pickle.HIGHEST_PROTOCOL):
                payload = pickle.dumps(value, protocol=protocol)
                self.assertIn(b'getzilla.component_state', payload)
                restored = pickle.loads(payload)
                self.assertIs(type(restored), type(value))
                if isinstance(value, BaseException):
                    self.assertEqual(restored.args, value.args)
                else:
                    self.assertEqual(restored, value)

    def test_independent_import_orders_preserve_legacy_types(self) -> None:
        import json
        import subprocess
        for first in ('getzilla.fsx', 'getzilla.component_state', 'getzilla.factory_tests'):
            with self.subTest(first=first):
                script = (
                    'import importlib,json,sys,pickle; '
                    f'sys.path.insert(0,{str(ROOT / ".getzilla")!r}); '
                    f'importlib.import_module({first!r}); '
                    'initial="getzilla.component_state" in sys.modules; '
                    'from getzilla import fsx,component_state as c; '
                    'available=hasattr(fsx,"ReadOnlyBoundRoot"); '
                    'same=all(getattr(fsx,n,None) is getattr(c,n) for n in '
                    '("FileSnapshot","ComponentStateError","_FileSnapshotChanged")); '
                    'print(json.dumps({"available":available,"same":same,"initial_upper":initial}))'
                )
                result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', script],
                                        capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0)
                facts = json.loads(result.stdout)
                self.assertTrue(facts['available'])
                self.assertTrue(facts['same'])
                self.assertEqual(facts['initial_upper'], first == 'getzilla.component_state')

    def test_read_path_limits_context_and_descriptor_lifetime(self) -> None:
        from unittest import mock
        reader = getattr(fsx, 'ReadOnlyBoundRoot', None)
        self.assertTrue(callable(reader))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'data.txt').write_bytes(b'abc')
            with mock.patch.object(fsx, 'close_dir', wraps=fsx.close_dir) as closed:
                binding = reader(root)
                handles = list(binding._handles)
                with binding as entered:
                    self.assertIs(entered, binding)
                    self.assertEqual(binding.read('data.txt').content, b'abc')
                    self.assertIsNone(binding.read('absent.txt'))
                    self.assertEqual(binding.read('data.txt', limit=3).content, b'abc')
                    with self.assertRaises(ValueError):
                        binding.read('data.txt', limit=2)
                    for path in ('../escape', 'CON.txt', 'trailing.', 'drive:name'):
                        with self.subTest(path=path), self.assertRaises(ValueError):
                            binding.read(path)
                    self.assertFalse(hasattr(binding, 'write'))
                    self.assertFalse(hasattr(binding, 'remove'))
                    with self.assertRaises(TypeError):
                        binding.parent('not-created/file', create=True)
                    self.assertFalse((root / 'not-created').exists())
                self.assertEqual(binding._handles, [])
                self.assertEqual([call.args[0] for call in closed.call_args_list],
                                 list(reversed(handles)))

    def test_constructor_failure_rolls_back_opened_ancestry(self) -> None:
        from unittest import mock
        reader = getattr(fsx, 'ReadOnlyBoundRoot', None)
        self.assertTrue(callable(reader))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'owned-reader-fixture'
            root.mkdir()
            binding = reader.__new__(reader)
            opened = []
            real = fsx.open_dir_at
            def fail_leaf(parent, name, **kwargs):
                if name == root.name:
                    opened.extend(binding._handles)
                    raise OSError(5, 'public constructor refusal')
                return real(parent, name, **kwargs)
            with mock.patch.object(fsx, 'open_dir_at', side_effect=fail_leaf), \
                    mock.patch.object(fsx, 'close_dir', wraps=fsx.close_dir) as closed:
                with self.assertRaises(OSError):
                    reader.__init__(binding, root)
            self.assertTrue(opened)
            self.assertEqual(binding._handles, [])
            self.assertEqual([call.args[0] for call in closed.call_args_list],
                             list(reversed(opened)))

if __name__ == '__main__':
    unittest.main()
