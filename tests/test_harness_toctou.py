"""#71.1: a generated parent renamed out of the repository between open and write is never written."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import fsx, harnesses  # noqa: E402


class HarnessWriteRaceTests(unittest.TestCase):
    def _run(self, when: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, outside = Path(tmp) / 'repo', Path(tmp) / 'outside'
            (root / '.cursor' / 'rules').mkdir(parents=True)
            outside.mkdir()
            real_open, real_replace = fsx.open_at, fsx.replace_at
            moved = []

            def move() -> None:
                if not moved:
                    os.rename(root / '.cursor', outside / 'moved')
                    moved.append(True)

            def open_at(*args, **kwargs):
                if when == 'open':
                    move()
                return real_open(*args, **kwargs)

            def replace_at(*args, **kwargs):
                if when == 'replace':
                    move()
                return real_replace(*args, **kwargs)

            with mock.patch.object(harnesses.fsx, 'open_at', open_at), \
                    mock.patch.object(harnesses.fsx, 'replace_at', replace_at):
                if when == 'replace':
                    # The race lands after the last check, inside replace itself: patch the check to move first.
                    real_check = harnesses._still_inside
                    calls = []

                    def check(*args):
                        calls.append(True)
                        if len(calls) == 2:
                            move()
                        return real_check(*args)

                    with mock.patch.object(harnesses, '_still_inside', check), self.assertRaises(ValueError):
                        harnesses._write_file(root, '.cursor/rules/getzilla.mdc', b'rule\n')
                else:
                    with self.assertRaises(ValueError):
                        harnesses._write_file(root, '.cursor/rules/getzilla.mdc', b'rule\n')
            self.assertTrue(moved)
            self.assertEqual(sorted(p.name for p in (outside / 'moved' / 'rules').iterdir()), [],
                             'nothing, not even the temporary file, may remain in the moved directory')
            self.assertFalse((root / '.cursor').exists())

    def test_parent_moved_before_the_temporary_file_is_opened(self) -> None:
        self._run('open')

    def test_parent_moved_after_the_content_is_written(self) -> None:
        self._run('replace')

    def test_an_unmoved_parent_is_written_normally(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            harnesses._write_file(root, '.cursor/rules/getzilla.mdc', b'rule\n')
            self.assertEqual((root / '.cursor' / 'rules' / 'getzilla.mdc').read_bytes(), b'rule\n')


if __name__ == '__main__':
    unittest.main()
