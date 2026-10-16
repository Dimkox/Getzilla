"""Z16: Linux and native Windows filesystem parity for Zero-Git adoption.

Each platform runs its own cases for real; a Windows case skipped on Linux (or the reverse) is
not evidence for the other platform. The shared suites also run on both.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla import project_adoption, source_inventory  # noqa: E402
from getzilla.source_admission import plan_source  # noqa: E402
from getzilla.source_baseline import source_digest  # noqa: E402
from getzilla.source_inventory import inventory_source  # noqa: E402
from getzilla.source_models import IngestPolicy, SourceEntry  # noqa: E402
from getzilla.source_snapshot import AdoptionError  # noqa: E402
from tests.zero_git_support import clean_source, plan_and_adopt, tree_state, write_tree  # noqa: E402

WINDOWS = os.name == 'nt'


class _Case(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix='zg-platform-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)


class SharedPlatformTests(_Case):
    def test_unicode_space_paths_adopt(self) -> None:
        source = write_tree(self.base / 'папка с пробелом', {'Документ с пробелом.txt': 'текст\n',
                                                            'sub dir/файл.py': 'print("ok")\n'})
        target = self.base / 'итог workspace'
        before = tree_state(source)
        _plan, receipt = plan_and_adopt(source, target, self.base / 'state')
        self.assertEqual(receipt['integrity_status'], 'verified')
        self.assertEqual((target / 'Документ с пробелом.txt').read_text(encoding='utf-8'), 'текст\n')
        self.assertEqual(tree_state(source), before)

    def test_portable_manifest_vectors_equal_under_equal_mode_policy(self) -> None:
        source = write_tree(self.base / 'src', {'a.txt': 'a', 'b/c.txt': 'c'})
        policy = IngestPolicy(executable_mode='policy-manifest')
        entries = inventory_source(source, policy).entries
        # Same bytes, paths and executable policy on any OS: the digest is a literal here.
        self.assertEqual([entry.executable for entry in entries], [False, False])
        expected = source_digest((SourceEntry('a.txt', False, 1, 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb'),
                                  SourceEntry('b/c.txt', False, 1, '2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6')),
                                 'portable-v1', 'policy-manifest')
        self.assertEqual(source_digest(entries, 'portable-v1', 'policy-manifest'), expected)

    def test_unsupported_fs_fails_closed(self) -> None:
        source = clean_source(self.base / 'src')
        weak = source_inventory.probe_filesystem(source).__class__(
            platform='test', nofollow_reads=False, link_detection=True, hardlink_detection=True,
            atomic_no_replace_publish=True)
        with mock.patch.object(source_inventory, 'probe_filesystem', return_value=weak):
            plan = plan_source(source, self.base / 'out', IngestPolicy())
        self.assertEqual(plan.status, 'BLOCKED_UNSUPPORTED_FS')


@unittest.skipUnless(WINDOWS, 'native Windows filesystem cases')
class WindowsPlatformTests(_Case):
    def test_windows_junction_rejected(self) -> None:
        outside = write_tree(self.base / 'outside', {'secret.txt': 'outside'})
        source = write_tree(self.base / 'src', {'a.txt': 'a'})
        subprocess.run(['cmd', '/c', 'mklink', '/J', str(source / 'junction'), str(outside)], check=True,
                       capture_output=True)
        codes = {(item.path, item.reason_code) for item in inventory_source(source, IngestPolicy()).blockers}
        self.assertIn(('junction', 'LINK_OR_REPARSE_POINT'), codes)

    def test_windows_reserved_alias_rejected(self) -> None:
        source = write_tree(self.base / 'src', {'a.txt': 'a'})
        # Names Win32 cannot normally create are reached through the \\?\ namespace.
        raw = '\\\\?\\' + str(source / 'trailing.')
        with open(raw, 'wb') as handle:
            handle.write(b'x')
        self.addCleanup(lambda: os.path.exists(raw) and os.unlink(raw))
        result = inventory_source(source, IngestPolicy())
        blocked = {item.path: item.reason_code for item in result.blockers}
        # Win32 opens 'trailing' for 'trailing.': the alias is refused, never imported as another file.
        self.assertIn(blocked.get('trailing.'), {'PATH_WINDOWS_TRAILING_DOT_OR_SPACE', 'SOURCE_CHANGED_DURING_READ'})
        self.assertNotIn('trailing.', [entry.path for entry in result.entries])
        self.assertEqual([entry.path for entry in result.entries], ['a.txt'])

    def test_windows_lock_failure_no_partial_publish(self) -> None:
        source = clean_source(self.base / 'src')
        target = self.base / 'adopted'
        plan = plan_source(source, target, IngestPolicy())

        def locked(staging, final):
            raise PermissionError(32, 'The process cannot access the file because it is being used by another process')

        with mock.patch.object(project_adoption, 'rename_noreplace', side_effect=locked), self.assertRaises(PermissionError):
            project_adoption.run_adoption(plan, plan.plan_id, quiesced=True, home=ROOT, state_root=self.base / 'state')
        self.assertFalse(target.exists())

    def test_windows_existing_target_not_replaced(self) -> None:
        staging = write_tree(self.base / 'staging', {'a.txt': 'new'})
        target = write_tree(self.base / 'target', {'keep.txt': 'old'})
        with self.assertRaises(OSError):
            project_adoption.rename_noreplace(staging, target)
        self.assertEqual((target / 'keep.txt').read_text(encoding='utf-8'), 'old')


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux filesystem cases')
class LinuxPlatformTests(_Case):
    def test_linux_symlink_race_rejected(self) -> None:
        outside = write_tree(self.base / 'outside', {'secret.txt': 'outside secret'})
        source = write_tree(self.base / 'src', {'a.txt': 'a', 'dir/b.txt': 'b'})
        real = source_inventory.read_regular_file
        swapped = []

        def swap(parent, name, expected, limit):
            if name == 'b.txt' and not swapped:
                swapped.append(name)
                (source / 'dir/b.txt').unlink()
                os.symlink(outside / 'secret.txt', source / 'dir/b.txt')
            return real(parent, name, expected, limit)

        with mock.patch.object(source_inventory, 'read_regular_file', side_effect=swap):
            result = inventory_source(source, IngestPolicy())
        self.assertIn(('dir/b.txt', 'SOURCE_CHANGED_DURING_READ'), [(b.path, b.reason_code) for b in result.blockers])

    def test_linux_existing_target_not_replaced(self) -> None:
        staging = write_tree(self.base / 'staging', {'a.txt': 'new'})
        target = self.base / 'target'
        target.mkdir()  # an empty directory: plain rename(2) would replace it
        with self.assertRaises(AdoptionError) as caught:
            project_adoption.rename_noreplace(staging, target)
        self.assertEqual(caught.exception.reason_code, 'TARGET_EXISTS')
        self.assertTrue(staging.exists())


if __name__ == '__main__':
    unittest.main()
