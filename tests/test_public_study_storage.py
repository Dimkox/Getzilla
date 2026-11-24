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

    def test_bootstrap_requires_running_record_and_original_empty_reserved_folder(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reserved = root / '.getzilla/runtime/par/owned-stamp'
            reserved.mkdir(parents=True, mode=0o700)
            info = reserved.stat()
            observed = SimpleNamespace(relative_path='.getzilla/runtime/par/owned-stamp',
                                       device=info.st_dev, inode=info.st_ino)
            self.assertEqual(storage._validate_bootstrap_directory(root, observed, 'running'), reserved)
            for status in ('succeeded', 'failed', 'cancel_requested'):
                with self.subTest(status=status), self.assertRaises(ValueError):
                    storage._validate_bootstrap_directory(root, observed, status)
            (reserved / 'unexpected').write_bytes(b'x')
            with self.assertRaises(ValueError):
                storage._validate_bootstrap_directory(root, observed, 'running')
            (reserved / 'unexpected').unlink()
            for value in (SimpleNamespace(relative_path='../foreign', device=info.st_dev, inode=info.st_ino),
                          SimpleNamespace(relative_path=observed.relative_path, device=info.st_dev, inode=info.st_ino + 1)):
                with self.assertRaises(ValueError):
                    storage._validate_bootstrap_directory(root, value, 'running')

    def test_missing_artifact_without_genuine_live_owner_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for output in (None, {'artifact': None}):
                with self.subTest(output=output), self.assertRaises(ValueError):
                    storage._output_directory(root, object(), 'invented-execution',
                                              {'execution_status': 'running', 'output': output})
            with self.assertRaises(ValueError):
                storage._output_directory(root, object(), 'invented-execution',
                                          {'execution_status': 'succeeded', 'output': None})

    def test_conservative_candidate_par_counts_orphans_and_deduplicates_current(self):
        self.assertIn('par', storage.CANDIDATE_ROOTS)
        self.assertNotIn('par', storage.CANONICAL_ROOTS)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            par = root / '.getzilla/runtime/par'
            current, failed = par / 'current', par / 'failed-orphan'
            current.mkdir(parents=True, mode=0o700)
            failed.mkdir(mode=0o700)
            (current / '000.log').write_bytes(b'123')
            orphan = failed / 'partial.log'
            orphan.write_bytes(b'abcd')
            scopes = (('candidate:par', par), ('execution:current', current))
            first = storage._observe(scopes, deadline=time.monotonic() + 2)
            self.assertEqual(first.logical_bytes, 7)
            self.assertEqual(first, storage._observe((('candidate:par', par),), deadline=time.monotonic() + 2))
            orphan.write_bytes(b'larger-orphan')
            second = storage._observe(scopes, deadline=time.monotonic() + 2)
            self.assertEqual(second.logical_bytes, 16)
            self.assertNotEqual(first.identity_digest, second.identity_digest)
            descriptor = os.open(orphan, os.O_RDONLY)
            try:
                orphan.unlink()
                orphan.write_bytes(b'larger-orphan')
                third = storage._observe(scopes, deadline=time.monotonic() + 2)
                self.assertEqual(second.logical_bytes, third.logical_bytes)
                self.assertNotEqual(second.identity_digest, third.identity_digest)
            finally:
                os.close(descriptor)
