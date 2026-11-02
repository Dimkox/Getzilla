"""The shared harness writer detects moved parents and cleans its private temp.

These controls cover observed movement before publication, not OS isolation
from every hostile same-user final-syscall race.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import fsx  # noqa: E402
from getzilla.component_state import component_transaction  # noqa: E402


class HarnessWriteRaceTests(unittest.TestCase):
    def publish(self, root: Path) -> None:
        with component_transaction(root) as transaction:
            transaction.write('.cursor/rules/getzilla.mdc', b'rule\n', 0o644,
                              expected=transaction.read('.cursor/rules/getzilla.mdc'))

    @unittest.skipIf(os.name == 'nt', 'POSIX permits renaming an open directory')
    def _run(self, when: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, outside = Path(tmp) / 'repo', Path(tmp) / 'outside'
            (root / '.cursor' / 'rules').mkdir(parents=True)
            outside.mkdir()
            real_open, real_chmod = fsx.open_at, fsx.fchmod
            moved = []
            temporary_descriptors = set()

            def move() -> None:
                if not moved:
                    os.rename(root / '.cursor', outside / 'moved')
                    moved.append(True)

            def open_at(parent, name, flags, mode=0o777):
                temporary_file = name.startswith('.getzilla-component-')
                if temporary_file and when == 'open':
                    move()
                descriptor = real_open(parent, name, flags, mode)
                if temporary_file:
                    temporary_descriptors.add(descriptor)
                return descriptor

            def chmod(descriptor, mode):
                if descriptor in temporary_descriptors and when == 'after_write':
                    move()
                return real_chmod(descriptor, mode)

            with mock.patch.object(fsx, 'open_at', open_at), mock.patch.object(fsx, 'fchmod', chmod):
                with self.assertRaises(ValueError):
                    self.publish(root)
            self.assertTrue(moved)
            self.assertEqual(sorted(p.name for p in (outside / 'moved' / 'rules').iterdir()), [],
                             'nothing, not even the temporary file, may remain in the moved directory')
            self.assertFalse((root / '.cursor').exists())

    def test_parent_moved_before_the_temporary_file_is_opened(self) -> None:
        self._run('open')

    def test_parent_moved_after_the_content_is_written(self) -> None:
        self._run('after_write')

    def test_an_unmoved_parent_is_written_normally(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.publish(root)
            self.assertEqual((root / '.cursor' / 'rules' / 'getzilla.mdc').read_bytes(), b'rule\n')


if __name__ == '__main__':
    unittest.main()
