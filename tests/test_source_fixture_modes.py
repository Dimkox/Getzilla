"""Public test-source copies retain working bytes and declared checkout modes."""
from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))

from tests import _support as support


class PublicSourceFixtureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.source = Path(temporary.name) / 'source'
        self.source.mkdir()
        self.regular = self.source / '.getzilla/getzilla/fixture.py'
        self.executable = self.source / '.grok/public.sh'
        for path, content, mode in ((self.regular, b'# staged source\n', 0o644),
                                    (self.executable, b'#!/bin/sh\n# staged\n', 0o755)):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            path.chmod(mode)
        subprocess.run(['git', 'init', '-q'], cwd=self.source, check=True)
        subprocess.run(['git', 'add', '.'], cwd=self.source, check=True)
        subprocess.run(['git', 'update-index', '--chmod=+x', '.grok/public.sh'], cwd=self.source, check=True)
        self.regular.write_bytes(b'# current uncommitted TDD source\n')
        self.executable.write_bytes(b'#!/bin/sh\n# current uncommitted TDD source\n')
        self.regular.chmod(0o664)
        self.executable.chmod(0o775)

    def assert_copy(self, root):
        for original in (self.regular, self.executable):
            copied = root / original.relative_to(self.source)
            self.assertEqual(copied.read_bytes(), original.read_bytes())
            if os.name == 'posix':
                expected = 0o755 if original == self.executable else 0o644
                self.assertEqual(stat.S_IMODE(copied.stat().st_mode), expected)

    def test_project_copy_uses_logical_modes_and_current_working_bytes(self):
        before = [path.stat() for path in (self.regular, self.executable)]
        with patch.object(support, 'PROJECT', self.source), support.project_copy() as root:
            self.assert_copy(root)
        for path, original in zip((self.regular, self.executable), before):
            after = path.stat()
            self.assertEqual((after.st_ino, after.st_mode, after.st_mtime_ns),
                             (original.st_ino, original.st_mode, original.st_mtime_ns))

    def test_public_source_copy_preserves_working_bytes_and_later_custom_mode(self):
        with support.public_source_copy(self.source) as root:
            self.assert_copy(root)
            copied = root / self.regular.relative_to(self.source)
            copied.chmod(0o600)
            before = copied.stat()
            with self.assertRaises(FileExistsError):
                support.copy_public_source(self.source, root)
            self.assertEqual(copied.read_bytes(), self.regular.read_bytes())
            self.assertEqual((copied.stat().st_ino, copied.stat().st_mode),
                             (before.st_ino, before.st_mode))

    def test_public_source_copy_excludes_git_and_untracked_user_inputs(self):
        (self.source / 'untracked-user-note.txt').write_text('owned public test canary\n')
        with support.public_source_copy(self.source) as root:
            self.assert_copy(root)
            self.assertFalse((root / '.git').exists())
            self.assertFalse((root / 'untracked-user-note.txt').exists())

    def test_public_source_copy_refuses_existing_empty_root_without_writes(self):
        target = self.source.parent / 'existing-target'
        target.mkdir(mode=0o700)
        before = target.stat()
        with self.assertRaises(FileExistsError):
            support.copy_public_source(self.source, target)
        self.assertEqual(list(target.iterdir()), [])
        self.assertEqual((target.stat().st_ino, target.stat().st_mode, target.stat().st_mtime_ns),
                         (before.st_ino, before.st_mode, before.st_mtime_ns))

    def test_public_source_copy_cannot_borrow_an_ancestor_repository(self):
        target = self.source.parent / 'not-created'
        with self.assertRaisesRegex(ValueError, 'worktree root'):
            support.copy_public_source(self.source / '.getzilla', target)
        self.assertFalse(target.exists())

    def test_installer_uses_only_logical_modes_from_owned_fixture_source(self):
        from tests.test_installer import MODULE, ROOT

        original = ROOT / '.getzilla/getzilla/known_vulns.py'
        before = original.stat()
        with support.public_source_copy(ROOT) as source, tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'consumer'
            MODULE.materialize_new(source, target,
                                   selection=MODULE.PayloadSelection((), factory=True, engine_archive=True))
            self.assertEqual((target / '.getzilla/runtime/.gitignore').read_bytes(),
                             (source / '.getzilla/runtime/.gitignore').read_bytes())
            self.assertTrue((target / 'factory/tests/test_result_admission_api.py').is_file())
            self.assertTrue((target / MODULE.ENGINE_ARCHIVE).is_file())
            if os.name == 'posix':
                self.assertEqual(stat.S_IMODE((target / '.getzilla/runtime/.gitignore').stat().st_mode), 0o644)
        after = original.stat()
        self.assertEqual((after.st_ino, after.st_mode, after.st_mtime_ns),
                         (before.st_ino, before.st_mode, before.st_mtime_ns))
