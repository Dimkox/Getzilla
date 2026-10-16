"""Z02: read-only inventory without executing the source; Z03 path/alias rules."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla import source_inventory as inventory_module  # noqa: E402
from getzilla.source_inventory import inventory_source  # noqa: E402
from getzilla.source_models import IngestPolicy  # noqa: E402
from getzilla.source_paths import path_problem, source_target_problem, validate_paths  # noqa: E402
from tests.zero_git_support import clean_source, tree_state, write_tree  # noqa: E402


class InventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix='zg-inventory-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def test_inventory_is_read_only(self) -> None:
        source = clean_source(self.base / 'src')
        before = tree_state(source)
        result = inventory_source(source, IngestPolicy())
        self.assertEqual(tree_state(source), before)
        self.assertTrue(result.complete, result.blockers)
        self.assertEqual([entry.path for entry in result.entries],
                         ['.env.example', 'README.md', 'app/__init__.py', 'app/main.py', 'scripts/run.sh'])

    def test_limits_fail_without_truncation(self) -> None:
        source = write_tree(self.base / 'src', {'big.bin': b'x' * 100, 'small.txt': 'ok'})
        result = inventory_source(source, IngestPolicy(max_file_bytes=50, max_buffered_file_bytes=50))
        self.assertIn(('big.bin', 'FILE_TOO_LARGE'), [(b.path, b.reason_code) for b in result.blockers])
        self.assertNotIn('big.bin', [entry.path for entry in result.entries])
        result = inventory_source(source, IngestPolicy(max_files=1))
        self.assertIn('LIMIT_FILES', [b.reason_code for b in result.blockers])
        self.assertFalse(result.complete)

    @unittest.skipUnless(os.name == 'posix' and os.geteuid() != 0, 'POSIX permission bits; root reads everything')
    def test_unreadable_file_is_not_silently_skipped(self) -> None:
        source = write_tree(self.base / 'src', {'secret.txt': 'x', 'ok.txt': 'y'})
        (source / 'secret.txt').chmod(0)
        self.addCleanup((source / 'secret.txt').chmod, 0o600)
        result = inventory_source(source, IngestPolicy())
        self.assertIn(('secret.txt', 'UNREADABLE'), [(b.path, b.reason_code) for b in result.blockers])

    def test_client_entrypoint_never_executed(self) -> None:
        sentinel = self.base / 'executed'
        source = write_tree(self.base / 'src', {
            'setup.py': f'open({str(sentinel)!r}, "w").write("ran")\n',
            'package.json': '{"scripts": {"preinstall": "touch executed"}}',
            'conftest.py': f'open({str(sentinel)!r}, "w").write("ran")\n',
        })
        inventory_source(source, IngestPolicy())
        self.assertFalse(sentinel.exists())

    def test_file_replaced_during_read_is_rejected(self) -> None:
        source = write_tree(self.base / 'src', {'a.txt': 'original', 'b.txt': 'b'})
        real = inventory_module.read_regular_file
        swapped = []

        def swap(parent, name, expected, limit):
            if name == 'a.txt' and not swapped:
                swapped.append(name)
                (source / 'a.txt').unlink()
                (source / 'a.txt').write_text('replacement', encoding='utf-8')
            return real(parent, name, expected, limit)

        with mock.patch.object(inventory_module, 'read_regular_file', side_effect=swap):
            result = inventory_source(source, IngestPolicy())
        self.assertIn(('a.txt', 'SOURCE_CHANGED_DURING_READ'), [(b.path, b.reason_code) for b in result.blockers])
        self.assertNotIn('a.txt', [entry.path for entry in result.entries])

    def test_git_metadata_blocks_zero_git(self) -> None:
        source = write_tree(self.base / 'src', {'.git/HEAD': 'ref: refs/heads/main\n', 'a.txt': 'a',
                                                 'vendor/lib/.git': 'gitdir: ../../x\n'})
        codes = {(b.path, b.reason_code) for b in inventory_source(source, IngestPolicy()).blockers}
        self.assertIn(('.git', 'GIT_PRESENT'), codes)
        self.assertIn(('vendor/lib/.git', 'NESTED_GIT'), codes)

    @unittest.skipUnless(hasattr(os, 'symlink') and os.name == 'posix', 'POSIX symlinks')
    def test_links_are_not_followed(self) -> None:
        outside = write_tree(self.base / 'outside', {'secret.txt': 'outside'})
        source = write_tree(self.base / 'src', {'a.txt': 'a'})
        os.symlink(outside / 'secret.txt', source / 'link.txt')
        os.symlink(outside, source / 'dirlink')
        result = inventory_source(source, IngestPolicy())
        codes = {(b.path, b.reason_code) for b in result.blockers}
        self.assertEqual(codes, {('link.txt', 'LINK_OR_REPARSE_POINT'), ('dirlink', 'LINK_OR_REPARSE_POINT')})

    def test_exclusions_are_explicit_and_visible(self) -> None:
        source = write_tree(self.base / 'src', {'a.txt': 'a', 'node_modules/x/index.js': 'x', 'dist/out.js': 'y'})
        result = inventory_source(source, IngestPolicy(exclude=('node_modules', 'dist/*')))
        self.assertEqual([(e.path, e.policy_ref) for e in result.excluded],
                         [('dist/out.js', 'exclude:dist/*'), ('node_modules', 'exclude:node_modules')])
        self.assertEqual([entry.path for entry in result.entries], ['a.txt'])

    @unittest.skipUnless(os.name == 'posix', 'executable bit is POSIX mode')
    def test_executable_bit_read_on_posix(self) -> None:
        source = clean_source(self.base / 'src')
        entries = {entry.path: entry.executable for entry in inventory_source(source, IngestPolicy()).entries}
        self.assertTrue(entries['scripts/run.sh'])
        self.assertFalse(entries['README.md'])


class PathTests(unittest.TestCase):
    def test_parent_escape_blocked(self) -> None:
        for path in ('../x', 'a/../b', '/etc/passwd', 'C:/x', 'a//b', './a'):
            with self.subTest(path=path):
                self.assertIsNotNone(path_problem(path))

    def test_case_collision_blocked(self) -> None:
        result = validate_paths(['README.md', 'readme.md', 'ok.txt'])
        self.assertEqual({(b.path, b.reason_code) for b in result.blockers},
                         {('README.md', 'PATH_CASE_COLLISION'), ('readme.md', 'PATH_CASE_COLLISION')})
        result = validate_paths(['Src/a.py', 'src/b.py'])
        self.assertEqual(len(result.blockers), 2)
        result = validate_paths(['docs', 'Docs/x.md'])
        self.assertIn('PATH_FILE_DIRECTORY_COLLISION', {b.reason_code for b in result.blockers})

    def test_non_nfc_path_not_renamed(self) -> None:
        decomposed = 'cafe\u0301.txt'
        result = validate_paths([decomposed])
        self.assertEqual([b.reason_code for b in result.blockers], ['PATH_NOT_NFC'])

    def test_windows_aliases_blocked(self) -> None:
        for path in ('CON', 'nul.txt', 'dir/COM1.log', 'trailing.', 'space ', 'a:stream', 'q?.txt', 'back\\slash'):
            with self.subTest(path=path):
                self.assertIsNotNone(path_problem(path))
        self.assertIsNone(path_problem('console.txt'))

    @unittest.skipUnless(hasattr(os, 'link'), 'hard links')
    def test_hardlink_identity_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = write_tree(Path(tmp) / 'src', {'a.txt': 'a'})
            os.link(source / 'a.txt', source / 'b.txt')
            codes = {(b.path, b.reason_code) for b in inventory_source(source, IngestPolicy()).blockers}
            self.assertIn(('a.txt', 'HARDLINK_SHARED_IDENTITY'), codes)
            self.assertIn(('b.txt', 'HARDLINK_SHARED_IDENTITY'), codes)

    def test_same_object_source_target_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'src'
            source.mkdir()
            self.assertEqual(source_target_problem(source, source), 'TARGET_IS_SOURCE')
            self.assertEqual(source_target_problem(source, source / 'out'), 'TARGET_INSIDE_SOURCE')
            self.assertEqual(source_target_problem(source / 'inner', source), 'SOURCE_INSIDE_TARGET')
            self.assertIsNone(source_target_problem(source, Path(tmp) / 'out'))
            if os.name == 'posix':
                os.symlink(source, Path(tmp) / 'alias')
                self.assertEqual(source_target_problem(source, Path(tmp) / 'alias'), 'TARGET_IS_SOURCE')


if __name__ == '__main__':
    unittest.main()
