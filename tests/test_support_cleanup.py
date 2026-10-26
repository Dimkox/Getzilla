"""The shared test fixture removes its directory even when one cleanup pass races a late write (#196)."""
from __future__ import annotations

import errno
import shutil
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
        failing = mock.Mock(side_effect=OSError(errno.ENOTEMPTY, 'Directory not empty'))
        with mock.patch.object(tempfile.TemporaryDirectory, 'cleanup', failing), \
                mock.patch.object(_support.time, 'sleep'):
            with self.assertRaises(OSError):
                with _support._test_directory() as name:
                    pass
        self.assertEqual(failing.call_count, _support.CLEANUP_ATTEMPTS)
        # What the failing cleanup left behind, unless the directory's finalizer already removed it.
        shutil.rmtree(name, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
