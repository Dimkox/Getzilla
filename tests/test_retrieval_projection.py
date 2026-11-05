from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from tests.test_retrieval_engine import document, snapshot


@unittest.skipUnless(os.name == 'posix', 'private descriptor projection requires POSIX')
class ProjectionTests(unittest.TestCase):
    def test_private_descriptor_atomic_publication_cas_and_content_free_projection(self):
        from getzilla.retrieval.extract import build_generation
        from getzilla.retrieval.projection import PrivateProjectionStore
        g = build_generation(snapshot(document()))
        with tempfile.TemporaryDirectory() as folder:
            fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
            self.addCleanup(os.close, fd)
            with PrivateProjectionStore(fd) as store:
                self.assertIsNone(store.read_active())
                store.publish(g, expected_active=None)
                result = store.read_active()
                self.assertEqual(result['generation_id'], g.identity)
                self.assertNotIn('newest_secret', str(result))
                with self.assertRaisesRegex(ValueError, '^generation_conflict$'):
                    store.publish(g, expected_active=None)
            self.assertEqual(os.stat(Path(folder) / 'active.json').st_mode & 0o777, 0o600)

    def test_unsafe_directory_and_symlink_pointer_fail_closed(self):
        from getzilla.retrieval.projection import PrivateProjectionStore
        with tempfile.TemporaryDirectory() as folder:
            fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
            self.addCleanup(os.close, fd)
            os.chmod(folder, 0o755)
            with self.assertRaisesRegex(ValueError, '^unsafe_projection$'):
                PrivateProjectionStore(fd)
            os.chmod(folder, 0o700)
            outside = Path(folder) / 'outside'
            outside.write_text('UNCHANGED')
            (Path(folder) / 'active.json').symlink_to(outside)
            with PrivateProjectionStore(fd) as store:
                with self.assertRaisesRegex(ValueError, '^unsafe_projection$'):
                    store.read_active()
            self.assertEqual(outside.read_text(), 'UNCHANGED')

    def test_malformed_cache_cannot_expose_arbitrary_source_snapshot_fields(self):
        import json
        from getzilla.retrieval.projection import PrivateProjectionStore
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'active.json'
            path.write_text(json.dumps({'schema_version': 1, 'generation_id': 'a' * 64,
                'source_snapshot': {'kind': 'gitless', 'snapshot_digest': 'b' * 64,
                    'prompt': 'PRIVATE_SENTINEL'}, 'chunks': 0, 'authority': 'metadata_only'}))
            path.chmod(0o600)
            fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
            self.addCleanup(os.close, fd)
            with PrivateProjectionStore(fd) as store:
                with self.assertRaisesRegex(ValueError, '^unsafe_projection$'):
                    store.read_active()


if __name__ == '__main__':
    unittest.main()
