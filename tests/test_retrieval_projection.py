from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from tests.test_retrieval_engine import document, snapshot


@unittest.skipUnless(os.name == 'posix', 'private descriptor projection requires POSIX')
class ProjectionTests(unittest.TestCase):
    def empty_generation(self, marker='a'):
        from getzilla.retrieval.contracts import Generation
        return Generation('ordinary-metadata', {'kind': 'gitless', 'snapshot_digest': marker * 64}, (), (), 0, ())

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

    def test_constructor_validates_its_owned_duplicate_and_closes_refused_descriptor(self):
        from getzilla.retrieval.projection import PrivateProjectionStore
        with tempfile.TemporaryDirectory() as folder:
            bound, other = Path(folder) / 'bound', Path(folder) / 'other'
            bound.mkdir(mode=0o700)
            other.mkdir(mode=0o755)
            incoming = os.open(bound, os.O_RDONLY | os.O_DIRECTORY)
            replacement = os.open(other, os.O_RDONLY | os.O_DIRECTORY)
            duplicates, stores = [], []
            real_dup = os.dup
            def switch_before_dup(fd):
                self.assertEqual(fd, incoming)
                os.dup2(replacement, incoming)
                owned = real_dup(incoming)
                duplicates.append(owned)
                return owned
            try:
                with patch('getzilla.retrieval.projection.os.dup', side_effect=switch_before_dup):
                    with self.assertRaisesRegex(ValueError, '^unsafe_projection$'):
                        stores.append(PrivateProjectionStore(incoming))
                self.assertEqual(len(duplicates), 1)
                with self.assertRaises(OSError):
                    os.fstat(duplicates[0])
            finally:
                for store in stores:
                    store.__exit__()
                os.close(incoming)
                os.close(replacement)

    def test_closed_store_refuses_every_operation_before_any_io(self):
        from getzilla.retrieval.projection import PrivateProjectionStore
        with tempfile.TemporaryDirectory() as folder:
            incoming = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
            try:
                store = PrivateProjectionStore(incoming)
            finally:
                os.close(incoming)
            store.__exit__()
            actions = (store.read_active, lambda: store.publish(self.empty_generation(), expected_active=None),
                store.__enter__)
            for action in actions:
                with self.subTest(action=action):
                    with patch('getzilla.retrieval.projection.os.open', side_effect=AssertionError('unexpected I/O')):
                        with self.assertRaisesRegex(ValueError, '^projection_closed$'):
                            action()
            self.assertEqual(list(Path(folder).iterdir()), [])

    def test_live_operations_keep_original_anchor_through_close_and_fd_reuse(self):
        from getzilla.retrieval.projection import PrivateProjectionStore
        first, second = self.empty_generation('a'), self.empty_generation('b')
        for action in ('read', 'publish'):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as folder:
                bound, other = Path(folder) / 'bound', Path(folder) / 'other'
                bound.mkdir(mode=0o700)
                other.mkdir(mode=0o700)
                incoming = os.open(bound, os.O_RDONLY | os.O_DIRECTORY)
                store = PrivateProjectionStore(incoming)
                os.close(incoming)
                store.publish(first, expected_active=None)
                master = store.fd
                entered, release = threading.Event(), threading.Event()
                results, errors = [], []
                real_open = os.open
                gate = 'active.json' if action == 'read' else 'publish.lock'
                def paused_open(path, flags, *args, **kwargs):
                    if path == gate:
                        entered.set()
                        if not release.wait(3):
                            raise AssertionError('operation synchronization timed out')
                    if kwargs.get('dir_fd') is None:
                        raise AssertionError('missing owned operation anchor')
                    return real_open(path, flags, *args, **kwargs)
                def run():
                    try:
                        if action == 'read':
                            results.append(store.read_active())
                        else:
                            store.publish(second, expected_active=first.identity)
                            results.append('published')
                    except BaseException as error:
                        errors.append(error)
                replacement = None
                with patch('getzilla.retrieval.projection.os.open', side_effect=paused_open):
                    worker = threading.Thread(target=run)
                    worker.start()
                    try:
                        self.assertTrue(entered.wait(3))
                        store.__exit__()
                        replacement = real_open(other, os.O_RDONLY | os.O_DIRECTORY)
                        if replacement != master:
                            os.dup2(replacement, master)
                        release.set()
                        worker.join(3)
                        self.assertFalse(worker.is_alive())
                    finally:
                        release.set()
                        worker.join(3)
                        if replacement is not None:
                            os.close(replacement)
                            if replacement != master:
                                os.close(master)
                        store.__exit__()
                self.assertEqual(errors, [])
                self.assertEqual(list(other.iterdir()), [])
                if action == 'read':
                    self.assertEqual(results[0]['generation_id'], first.identity)
                else:
                    fd = real_open(bound, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        with PrivateProjectionStore(fd) as check:
                            self.assertEqual(check.read_active()['generation_id'], second.identity)
                    finally:
                        os.close(fd)


if __name__ == '__main__':
    unittest.main()
