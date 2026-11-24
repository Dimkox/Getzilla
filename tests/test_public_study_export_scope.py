"""Fixed export scope tests use synthetic bytes only."""
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from getzilla.retrieval import public_study_storage as storage


class ExportScopeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.runtime = Path(self.temporary.name)
        (self.runtime / 'scratch').mkdir(mode=0o700)
        self.container = self.runtime / 'study-export-preparations'
        self.deadline = time.monotonic() + 5

    def tearDown(self):
        self.temporary.cleanup()

    def observation(self):
        with storage.retained_legacy_exports(self.runtime, deadline=self.deadline) as legacy:
            return storage._observe([('fixed-preparations', self.container), *legacy], deadline=self.deadline)

    def test_all_children_failed_and_orphan_files_count(self):
        (self.container / 'current/model').mkdir(parents=True)
        (self.container / 'failed/model').mkdir(parents=True)
        (self.container / 'orphan').mkdir()
        (self.container / 'current/model/a').write_bytes(b'123')
        (self.container / 'failed/model/a').write_bytes(b'12345')
        (self.container / 'orphan/diagnostic').write_bytes(b'12')
        self.assertEqual(self.observation().logical_bytes, 10)
        with patch.object(storage, 'MAX_BYTES', 9), self.assertRaises(ValueError):
            self.observation()

    def test_missing_container_refuses_even_with_legacy(self):
        legacy = self.runtime / storage.LEGACY_EXPORT
        legacy.mkdir(mode=0o700)
        (legacy / 'a').write_bytes(b'123')
        self.assertIn('study-export-preparations', storage.CANDIDATE_ROOTS)
        with self.assertRaises(OSError):
            self.observation()

    def test_fixed_legacy_root_is_additional_storage(self):
        self.container.mkdir(mode=0o700)
        (self.container / 'a').write_bytes(b'123')
        legacy = self.runtime / storage.LEGACY_EXPORT
        legacy.mkdir(mode=0o700)
        (legacy / 'failed-copy').write_bytes(b'12345')
        self.assertEqual(self.observation().logical_bytes, 8)

    def test_legacy_absent_stays_absent_without_creation(self):
        self.container.mkdir(mode=0o700)
        self.assertEqual(self.observation().logical_bytes, 0)
        self.assertFalse((self.runtime / storage.LEGACY_EXPORT).exists())

    def test_legacy_symlink_and_unsafe_mode_refuse(self):
        self.container.mkdir(mode=0o700)
        legacy = self.runtime / storage.LEGACY_EXPORT
        legacy.symlink_to(self.container, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.observation()
        legacy.unlink()
        legacy.mkdir(mode=0o700)
        legacy.chmod(0o777)
        with self.assertRaises(ValueError):
            self.observation()

    def test_legacy_appears_during_observation_refuses(self):
        self.container.mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            with storage.retained_legacy_exports(self.runtime, deadline=self.deadline):
                (self.runtime / storage.LEGACY_EXPORT).mkdir(mode=0o700)

    def test_export_paths_require_same_child_and_fixed_view_names(self):
        def roots(child):
            return {name + '_root': '.getzilla/runtime/study-export-preparations/' + child + '/' + name
                    for name in ('worker', 'software', 'model')}
        self.assertEqual(storage.fixed_export_attempt(roots('fresh-1')), 'fresh-1')
        for field, value in (
            ('model_root', '.getzilla/runtime/scratch/old/model'),
            ('model_root', '.getzilla/runtime/study-export-preparations/other/model'),
            ('model_root', '.getzilla/runtime/study-export-preparations/fresh-1/model/escape'),
            ('model_root', '.getzilla/runtime/study-export-preparations/../escape/model'),
            ('worker_root', '.getzilla/runtime/study-export-preparations/fresh-1/software')):
            request = roots('fresh-1')
            request[field] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                storage.fixed_export_attempt(request)

    def test_caps_unchanged(self):
        self.assertEqual(storage.MAX_BYTES, 12 * 1024**3)
        self.assertEqual(storage.MAX_ENTRIES, 100000)
        self.assertEqual(storage.MAX_SECONDS, 30)


if __name__ == '__main__':
    unittest.main()
