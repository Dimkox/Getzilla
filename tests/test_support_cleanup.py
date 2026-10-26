"""The shared test fixture removes its directory even when one cleanup pass races a late write (#196)."""
from __future__ import annotations

import errno
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests import _support


class ProjectCopyCleanupTests(unittest.TestCase):
    def test_a_transient_cleanup_error_is_retried(self) -> None:
        real = tempfile.TemporaryDirectory.cleanup
        calls = []

        def racing_cleanup(directory: tempfile.TemporaryDirectory) -> None:
            calls.append(directory.name)
            if len(calls) == 1:
                # A late writer adds a file while rmtree runs: the first pass fails as on CI.
                raise OSError(errno.ENOTEMPTY, 'Directory not empty', directory.name)
            real(directory)

        with mock.patch.object(tempfile.TemporaryDirectory, 'cleanup', racing_cleanup), \
                mock.patch.object(_support.time, 'sleep') as sleep:
            with _support.project_copy() as root:
                self.assertTrue(root.is_dir())
        self.assertEqual(len(calls), 2)
        sleep.assert_called_once()
        self.assertFalse(Path(calls[0]).exists())

    def test_a_lasting_cleanup_error_is_raised(self) -> None:
        def failing(directory: tempfile.TemporaryDirectory) -> None:
            directory._finalizer.detach()  # no implicit cleanup warning when the object is collected
            raise OSError(errno.ENOTEMPTY, 'Directory not empty', directory.name)

        calls = mock.Mock(side_effect=failing)
        with mock.patch.object(tempfile.TemporaryDirectory, 'cleanup', lambda self: calls(self)), \
                mock.patch.object(_support.time, 'sleep'):
            with self.assertRaises(OSError):
                with _support._test_directory() as name:
                    pass
        self.assertEqual(calls.call_count, _support.CLEANUP_ATTEMPTS)
        shutil.rmtree(name)  # what the failing cleanup left behind

    def test_the_git_fixture_turns_off_auto_maintenance(self) -> None:
        with _support.project_copy(git=True) as root:
            for key, value in (('maintenance.auto', 'false'), ('gc.auto', '0')):
                with self.subTest(key=key):
                    shown = subprocess.run(['git', 'config', '--local', '--get', key], cwd=root,
                                           capture_output=True, text=True, check=True)
                    self.assertEqual(shown.stdout.strip(), value)


if __name__ == '__main__':
    unittest.main()
