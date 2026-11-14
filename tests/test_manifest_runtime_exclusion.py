from __future__ import annotations

import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla import manifest


class ManifestRuntimeExclusionTests(unittest.TestCase):
    def setUp(self):
        runtime = Path(__file__).resolve().parents[1] / '.getzilla/runtime'
        fixture = tempfile.TemporaryDirectory(prefix='new-manifest-', dir=runtime)
        self.addCleanup(fixture.cleanup)
        self.root = Path(fixture.name).resolve()
        self.live = self.write('README.md')

    def write(self, relative):
        path = self.root / relative
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_text('owned public fixture\n', encoding='utf-8')
        return path

    def enumerate(self, entries, vanished=None):
        root = self.root

        def rows(path, pattern):
            self.assertEqual(path, root)
            self.assertEqual(pattern, '*')
            for entry in entries:
                if entry == vanished:
                    entry.unlink()
                yield entry

        return patch.object(Path, 'rglob', rows)

    def test_exact_membership_and_relative_sort_on_real_tiny_root(self):
        included = ['README.md', 'zeta.py', 'src/alpha.py', '.env.example',
                    '.getzilla/runtime/.gitkeep']
        excluded = ['.getzilla/runtime/.gitignore', '.getzilla/runtime/record.gitkeep',
                    '.getzilla/runtime/nested/.gitkeep', '.getzilla/runtime/ephemeral.tmp',
                    'build/out.py', '.git/HEAD', '.env', 'key.pem', 'module.pyc',
                    'bundle.zip', 'MANIFEST.sha256', '.coverage.worker', 'data.sha256']
        for name in included + excluded:
            self.write(name)
        actual = manifest.included_files(self.root)
        self.assertEqual(actual, [self.root / name for name in sorted(included)])
        for name in included:
            self.assertTrue(manifest.is_included_relative_path(name), name)
        for name in excluded:
            self.assertFalse(manifest.is_included_relative_path(name), name)

    def test_disappearing_excluded_leaves_never_refuse_included_source(self):
        for name in ('.getzilla/runtime/ephemeral.tmp', 'build/out.py', '.env'):
            with self.subTest(relative=name):
                ignored = self.write(name)
                with self.enumerate((ignored, self.live), vanished=ignored):
                    try:
                        actual = manifest.included_files(self.root)
                    except manifest.ManifestError as error:
                        self.assertIsInstance(error.__cause__, FileNotFoundError)
                        self.fail('excluded leaf metadata was inspected before lexical rejection')
                self.assertEqual(actual, [self.live])

    def test_excluded_denied_symlink_and_fifo_metadata_are_not_requested(self):
        entries = [self.root / name for name in ('.getzilla/runtime/denied.tmp',
                   '.getzilla/runtime/link', '.getzilla/runtime/fifo')]
        original_lstat = Path.lstat
        inspected = []

        def inspect(path, *args, **kwargs):
            if path in entries:
                inspected.append(path)
                raise PermissionError('owned excluded metadata trap')
            return original_lstat(path, *args, **kwargs)

        with self.enumerate((*entries, self.live)), patch.object(Path, 'lstat', inspect):
            with patch.object(Path, 'open', side_effect=AssertionError('no target open')):
                try:
                    actual = manifest.included_files(self.root)
                except manifest.ManifestError:
                    self.fail('excluded metadata trap reached')
        self.assertEqual(actual, [self.live])
        self.assertEqual(inspected, [])

    def test_included_source_and_exact_sentinel_disappearance_still_refuse(self):
        for name in ('README.md', '.getzilla/runtime/.gitkeep'):
            with self.subTest(relative=name):
                admitted = self.write(name)
                with self.enumerate((admitted,), vanished=admitted):
                    with self.assertRaises(manifest.ManifestError) as caught:
                        manifest.included_files(self.root)
                self.assertEqual(str(caught.exception), f'cannot inspect package source path: {Path(name)}')
                self.assertIsInstance(caught.exception.__cause__, FileNotFoundError)

    def test_included_metadata_denial_retains_exact_error_and_cause(self):
        for name in ('README.md', '.getzilla/runtime/.gitkeep'):
            with self.subTest(relative=name):
                admitted = self.write(name)
                denial = PermissionError('owned admitted metadata failure')
                original_lstat = Path.lstat

                def inspect(path, *args, **kwargs):
                    if path == admitted:
                        raise denial
                    return original_lstat(path, *args, **kwargs)

                with self.enumerate((admitted,)), patch.object(Path, 'lstat', inspect):
                    with self.assertRaises(manifest.ManifestError) as caught:
                        manifest.included_files(self.root)
                self.assertEqual(str(caught.exception), f'cannot inspect package source path: {Path(name)}')
                self.assertIs(caught.exception.__cause__, denial)

    def test_included_nonregular_types_keep_lstat_skip_without_following(self):
        entries = [self.root / name for name in ('link.py', 'fifo.py', 'directory.py')]
        modes = dict(zip(entries, (stat.S_IFLNK, stat.S_IFIFO, stat.S_IFDIR)))
        original_lstat = Path.lstat
        inspected = []

        def inspect(path, *args, **kwargs):
            if path in modes:
                inspected.append(path)
                return os.stat_result((modes[path] | 0o600, 0, 0, 1, 0, 0, 0, 0, 0, 0))
            return original_lstat(path, *args, **kwargs)

        with self.enumerate((*entries, self.live)), patch.object(Path, 'lstat', inspect):
            with patch.object(Path, 'open', side_effect=AssertionError('no nonregular target open')):
                self.assertEqual(manifest.included_files(self.root), [self.live])
        self.assertEqual(inspected, entries)

    def test_traversal_error_and_interrupt_are_not_suppressed(self):
        for error in (PermissionError('owned traversal refusal'), KeyboardInterrupt(), SystemExit(7)):
            with self.subTest(kind=type(error).__name__):
                with patch.object(Path, 'rglob', side_effect=error):
                    with self.assertRaises(type(error)) as caught:
                        manifest.included_files(self.root)
                self.assertIs(caught.exception, error)


if __name__ == '__main__':
    unittest.main()
