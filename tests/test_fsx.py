from __future__ import annotations

import os
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


if __name__ == '__main__':
    unittest.main()
