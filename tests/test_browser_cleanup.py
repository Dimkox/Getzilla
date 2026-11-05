from __future__ import annotations

import errno
import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('browser_owned_cleanup', ROOT / 'side-projects/seo-landing-showcase/cleanup-owned-directory.py')
CLEANUP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLEANUP)
NATIVE_FD = os.name == 'posix' and shutil.rmtree.avoids_symlink_attacks


def identity(directory):
    observed = directory.lstat()
    return {'dev': str(observed.st_dev), 'ino': str(observed.st_ino), 'uid': str(observed.st_uid)}


class BrowserOwnedCleanupTests(unittest.TestCase):
    def test_normal_contents_are_cleared_but_root_and_foreign_target_are_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            owned = base / 'owned'
            owned.mkdir(mode=0o700)
            nested = owned / 'nested'
            nested.mkdir()
            (nested / 'cache').write_text('owned cache')
            foreign = base / 'foreign'
            foreign.mkdir()
            (foreign / 'canary').write_text('foreign bytes')
            if os.name == 'posix':
                (owned / 'foreign-link').symlink_to(foreign, target_is_directory=True)
            result = CLEANUP.cleanup_owned_directory(owned, identity(owned))
            self.assertFalse(result['root_removed'])
            self.assertTrue(owned.is_dir())
            self.assertEqual((foreign / 'canary').read_text(), 'foreign bytes')
            self.assertEqual(result['contents_cleaned'], NATIVE_FD)
            if NATIVE_FD:
                self.assertEqual(list(owned.iterdir()), [])
                self.assertEqual(result['reason'], 'contents-cleaned-root-retained')
            else:
                self.assertTrue((nested / 'cache').is_file())

    def test_replacement_before_open_preserves_both_foreign_and_original_contents(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            owned, held = base / 'owned', base / 'held'
            owned.mkdir(mode=0o700)
            (owned / 'original').write_text('owned bytes')
            expected = identity(owned)
            real_open = os.open
            swapped = False

            def open_replacement(name, *arguments, **keywords):
                nonlocal swapped
                if os.fspath(name) == str(owned) and not swapped:
                    swapped = True
                    owned.rename(held)
                    owned.mkdir(mode=0o700)
                    (owned / 'canary').write_text('foreign replacement')
                return real_open(name, *arguments, **keywords)

            with patch.object(CLEANUP.os, 'open', side_effect=open_replacement):
                result = CLEANUP.cleanup_owned_directory(owned, expected)
            self.assertFalse(result['contents_cleaned'])
            self.assertFalse(result['root_removed'])
            self.assertEqual(swapped, NATIVE_FD)
            if NATIVE_FD:
                self.assertEqual((owned / 'canary').read_text(), 'foreign replacement')
                self.assertEqual((held / 'original').read_text(), 'owned bytes')
                self.assertEqual(result['path_state'], 'changed')

    def test_replacement_after_verified_descriptor_cleans_only_original_contents(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            owned, held = base / 'owned', base / 'held'
            owned.mkdir(mode=0o700)
            (owned / 'original').write_text('owned bytes')
            expected = identity(owned)
            real_fstat = os.fstat
            swapped = False

            def replace_after_observation(descriptor):
                nonlocal swapped
                observed = real_fstat(descriptor)
                if str(observed.st_ino) == expected['ino'] and not swapped:
                    swapped = True
                    owned.rename(held)
                    owned.mkdir(mode=0o700)
                    (owned / 'canary').write_text('foreign replacement')
                return observed

            with patch.object(CLEANUP.os, 'fstat', side_effect=replace_after_observation):
                result = CLEANUP.cleanup_owned_directory(owned, expected)
            self.assertEqual(swapped, NATIVE_FD)
            self.assertEqual(result['contents_cleaned'], NATIVE_FD)
            self.assertFalse(result['root_removed'])
            if NATIVE_FD:
                self.assertEqual((owned / 'canary').read_text(), 'foreign replacement')
                self.assertTrue(held.is_dir())
                self.assertEqual(list(held.iterdir()), [])
                self.assertEqual(result['path_state'], 'changed')

    def test_wrong_inode_uid_and_public_mode_preserve_owned_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            owned = Path(temporary) / 'owned'
            owned.mkdir(mode=0o700)
            marker = owned / 'canary'
            marker.write_text('preserve bytes')
            original = identity(owned)
            for field in ('ino', 'uid'):
                with self.subTest(field=field):
                    expected = {**original, field: str(int(original[field]) + 1)}
                    result = CLEANUP.cleanup_owned_directory(owned, expected)
                    self.assertFalse(result['contents_cleaned'])
                    self.assertEqual(marker.read_text(), 'preserve bytes')
            if os.name == 'posix':
                with patch.object(CLEANUP.os, 'getuid', return_value=os.getuid() + 1):
                    result = CLEANUP.cleanup_owned_directory(owned, original)
                self.assertFalse(result['contents_cleaned'])
                self.assertEqual(marker.read_text(), 'preserve bytes')
                owned.chmod(0o755)
                result = CLEANUP.cleanup_owned_directory(owned, original)
                self.assertFalse(result['contents_cleaned'])
                self.assertEqual(marker.read_text(), 'preserve bytes')

    def test_files_symlinks_fifo_and_missing_path_do_not_enter_recursive_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            owned = base / 'owned'
            owned.mkdir(mode=0o700)
            marker = owned / 'canary'
            marker.write_text('foreign target bytes')
            plain = base / 'plain'
            plain.write_text('plain bytes')
            paths = [plain, base / 'missing']
            if os.name == 'posix':
                link = base / 'link'
                link.symlink_to(owned, target_is_directory=True)
                paths.append(link)
            if hasattr(os, 'mkfifo'):
                fifo = base / 'fifo'
                os.mkfifo(fifo, 0o600)
                paths.append(fifo)
            for candidate in paths:
                with self.subTest(path=candidate.name):
                    result = CLEANUP.cleanup_owned_directory(candidate, identity(owned))
                    self.assertFalse(result['contents_cleaned'])
                    self.assertFalse(result['root_removed'])
                    self.assertEqual(marker.read_text(), 'foreign target bytes')
                    self.assertEqual(plain.read_text(), 'plain bytes')

    def test_unsupported_fd_policy_retains_contents_without_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            owned = Path(temporary)
            marker = owned / 'canary'
            marker.write_text('preserve bytes')
            with patch.object(CLEANUP.shutil.rmtree, 'avoids_symlink_attacks', False):
                result = CLEANUP.cleanup_owned_directory(owned, identity(owned))
            self.assertFalse(result['contents_cleaned'])
            self.assertEqual(result['reason'], 'fd-cleanup-unavailable')
            self.assertEqual(marker.read_text(), 'preserve bytes')

    def test_nested_permission_error_is_not_reported_as_cleaned(self):
        with tempfile.TemporaryDirectory() as temporary:
            owned = Path(temporary)
            blocked = owned / 'blocked'
            blocked.write_text('owned but retained bytes')
            real_unlink = os.unlink

            def refuse_child(name, *arguments, **keywords):
                if name == 'blocked':
                    raise PermissionError(errno.EACCES, 'controlled owned child refusal')
                return real_unlink(name, *arguments, **keywords)

            with patch.object(CLEANUP.os, 'unlink', side_effect=refuse_child):
                result = CLEANUP.cleanup_owned_directory(owned, identity(owned))
            self.assertFalse(result['contents_cleaned'])
            self.assertEqual(blocked.read_text(), 'owned but retained bytes')
            if NATIVE_FD:
                self.assertEqual(result['reason'], 'cleanup-refused-EACCES')

    def test_other_final_root_error_is_not_swallowed(self):
        with tempfile.TemporaryDirectory() as temporary:
            owned = Path(temporary)
            real_rmdir = os.rmdir

            def refuse_root(name, *arguments, **keywords):
                if name == '.':
                    raise OSError(errno.EBUSY, 'controlled different root refusal')
                return real_rmdir(name, *arguments, **keywords)

            with patch.object(CLEANUP.os, 'rmdir', side_effect=refuse_root):
                result = CLEANUP.cleanup_owned_directory(owned, identity(owned))
            self.assertFalse(result['contents_cleaned'])
            self.assertTrue(owned.is_dir())
            if NATIVE_FD:
                self.assertEqual(result['reason'], 'cleanup-refused-EBUSY')
