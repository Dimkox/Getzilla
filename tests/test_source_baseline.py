"""Z04: canonical source-baseline-v1 bytes and digest, pinned by independent golden vectors."""
from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.source_baseline import canonical_manifest_bytes, source_digest  # noqa: E402
from getzilla.source_inventory import inventory_source  # noqa: E402
from getzilla.source_models import ContractError, IngestPolicy, SourceEntry  # noqa: E402
from tests.zero_git_support import write_tree  # noqa: E402

VECTORS = ROOT / 'tests/fixtures/zero_git/canonical'
ABC = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
EMPTY = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
ENTRIES = (SourceEntry('bin/run', True, 0, EMPTY), SourceEntry('a.txt', False, 3, ABC))


class SourceBaselineTests(unittest.TestCase):
    def test_golden_bytes_exact(self) -> None:
        # Written by hand, not produced by the function under test.
        expected = (VECTORS / 'v1-two-entries.json').read_bytes()
        self.assertEqual(canonical_manifest_bytes(ENTRIES, 'portable-v1', 'posix-mode'), expected)
        pinned = (VECTORS / 'v1-two-entries.sha256').read_text(encoding='ascii').strip()
        self.assertEqual(hashlib.sha256(b'getzilla-source-baseline-v1\n' + expected).hexdigest(), pinned)
        self.assertEqual(source_digest(ENTRIES, 'portable-v1', 'posix-mode'), pinned)
        self.assertFalse(expected.endswith(b'\n'))
        self.assertNotIn(b' ', expected)

    def test_order_does_not_change_digest(self) -> None:
        self.assertEqual(source_digest(ENTRIES, 'portable-v1'), source_digest(tuple(reversed(ENTRIES)), 'portable-v1'))

    def test_one_byte_changes_digest(self) -> None:
        changed = (ENTRIES[0], SourceEntry('a.txt', False, 3, hashlib.sha256(b'abd').hexdigest()))
        self.assertNotEqual(source_digest(ENTRIES, 'portable-v1'), source_digest(changed, 'portable-v1'))

    def test_lf_crlf_are_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lf = write_tree(Path(tmp) / 'lf', {'a.txt': b'x\n'})
            crlf = write_tree(Path(tmp) / 'crlf', {'a.txt': b'x\r\n'})
            policy = IngestPolicy()
            digest = lambda root: source_digest(inventory_source(root, policy).entries, 'portable-v1')  # noqa: E731
            self.assertNotEqual(digest(lf), digest(crlf))

    def test_mtime_and_root_path_do_not_change_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            one = write_tree(Path(tmp) / 'one', {'a.txt': 'same', 'b/c.txt': 'same'})
            two = write_tree(Path(tmp) / 'elsewhere/two', {'a.txt': 'same', 'b/c.txt': 'same'})
            later = time.time() + 3600
            os.utime(two / 'a.txt', (later, later))
            policy = IngestPolicy()
            self.assertEqual(source_digest(inventory_source(one, policy).entries, 'portable-v1'),
                             source_digest(inventory_source(two, policy).entries, 'portable-v1'))

    def test_executable_policy_changes_identity(self) -> None:
        plain = (SourceEntry('run', False, 0, EMPTY),)
        executable = (SourceEntry('run', True, 0, EMPTY),)
        self.assertNotEqual(source_digest(plain, 'portable-v1'), source_digest(executable, 'portable-v1'))
        self.assertNotEqual(source_digest(plain, 'portable-v1', 'posix-mode'),
                            source_digest(plain, 'portable-v1', 'policy-manifest'))

    def test_empty_directories_not_in_file_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            one = write_tree(Path(tmp) / 'one', {'a.txt': 'a'})
            two = write_tree(Path(tmp) / 'two', {'a.txt': 'a'})
            (two / 'empty').mkdir()
            policy = IngestPolicy()
            left, right = inventory_source(one, policy), inventory_source(two, policy)
            self.assertEqual(source_digest(left.entries, 'portable-v1'), source_digest(right.entries, 'portable-v1'))
            self.assertEqual(right.empty_directories, 1)

    def test_duplicate_or_unsafe_paths_refused(self) -> None:
        with self.assertRaises(ContractError):
            source_digest((ENTRIES[1], ENTRIES[1]), 'portable-v1')
        with self.assertRaises(ContractError):
            source_digest((SourceEntry('../x', False, 0, EMPTY),), 'portable-v1')


if __name__ == '__main__':
    unittest.main()
