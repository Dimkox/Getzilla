"""Metadata storage facts never substitute for operation authority."""
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from getzilla.retrieval import public_study_storage as storage


class StorageObservationTests(unittest.TestCase):
    def test_nested_roots_and_hardlinks_count_each_inode_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'child').mkdir()
            (root / 'a').write_bytes(b'123')
            os.link(root / 'a', root / 'child/b')
            observed = storage._observe((('whole', root), ('nested', root / 'child')),
                                        deadline=time.monotonic() + 2)
            self.assertEqual(observed.logical_bytes, 3)
            self.assertEqual(observed, storage._observe((('whole', root),), deadline=time.monotonic() + 2))

    def test_links_special_files_missing_roots_and_deadline_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'a').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError):
                storage._observe((('whole', root),), deadline=time.monotonic() + 2)
            (root / 'a').unlink()
            os.mkfifo(root / 'fifo')
            with self.assertRaises(ValueError):
                storage._observe((('whole', root),), deadline=time.monotonic() + 2)
            (root / 'fifo').unlink()
            with self.assertRaises(ValueError):
                storage._observe((('whole', root),), deadline=0)
            with self.assertRaises(OSError):
                storage._observe((('missing', root / 'absent'),), deadline=time.monotonic() + 2)

    def test_changed_scan_and_byte_entry_bounds_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'a').write_bytes(b'123')
            roots = (('whole', root),)
            with patch.object(storage, 'MAX_BYTES', 2), self.assertRaises(ValueError):
                storage._observe(roots, deadline=time.monotonic() + 2)
            with patch.object(storage, 'MAX_ENTRIES', 1), self.assertRaises(ValueError):
                storage._observe(roots, deadline=time.monotonic() + 2)
            original = storage._scan
            calls = 0
            def changed(*args):
                nonlocal calls
                calls += 1
                if calls == 2:
                    (root / 'a').write_bytes(b'changed')
                return original(*args)
            with patch.object(storage, '_scan', side_effect=changed), self.assertRaises(ValueError):
                storage._observe(roots, deadline=time.monotonic() + 2)

    def test_public_entry_requires_actual_operation_before_scanning(self):
        with patch.object(storage, '_observe', side_effect=AssertionError('must not scan')):
            with self.assertRaises(ValueError):
                storage.study_storage_observation({'allow': True}, 'invented')
