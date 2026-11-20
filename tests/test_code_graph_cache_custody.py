"""Safe cache admission controls; rejected names never reach SQLite."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.code_graph.cli import run  # noqa: E402
from getzilla.code_graph.models import GraphError  # noqa: E402
from getzilla.code_graph.store import GraphStore  # noqa: E402


class CacheCustodyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cache = self.root / 'cache' / 'graph.sqlite'
        self.cache.parent.mkdir(mode=0o700)

    def refused_without_sqlite(self, path):
        with patch('getzilla.code_graph.store.sqlite3.connect') as connect:
            with self.assertRaises(GraphError):
                GraphStore(path)
        connect.assert_not_called()

    def test_blocked_input_never_opens_or_creates_cache(self):
        for command in ('build', 'status', 'impact', 'export'):
            with self.subTest(command=command), patch(
                'getzilla.code_graph.cli.discover_scope', side_effect=GraphError('INPUT_BLOCKED')
            ), patch('getzilla.code_graph.store.sqlite3.connect') as connect:
                with self.assertRaises(GraphError):
                    run([command, '--root', str(self.root), '--cache', str(self.cache)])
                connect.assert_not_called()
                self.assertFalse(self.cache.exists())

    def test_unknown_owned_bytes_are_preserved_without_sqlite(self):
        content = b'harmless unrecognized owned fixture'
        self.cache.write_bytes(content)
        self.refused_without_sqlite(self.cache)
        self.assertEqual(self.cache.read_bytes(), content)
        self.assertEqual(sorted(p.name for p in self.cache.parent.iterdir()), ['graph.sqlite'])

    def test_orphan_sidecar_is_preserved_before_creating_cache(self):
        for suffix in ('-wal', '-shm', '-journal'):
            with self.subTest(suffix=suffix):
                sidecar = Path(str(self.cache) + suffix)
                content = b'harmless owned orphan fixture'
                sidecar.write_bytes(content)
                self.refused_without_sqlite(self.cache)
                self.assertFalse(self.cache.exists())
                self.assertEqual(sidecar.read_bytes(), content)
                sidecar.unlink()

    @unittest.skipUnless(hasattr(os, 'symlink'), 'links unavailable')
    def test_file_and_parent_links_refuse_without_sqlite(self):
        target = self.root / 'harmless.txt'
        target.write_text('harmless owned fixture')
        self.cache.symlink_to(target)
        self.refused_without_sqlite(self.cache)
        self.assertEqual(target.read_text(), 'harmless owned fixture')
        linked_parent = self.root / 'linked'
        linked_parent.symlink_to(self.cache.parent, target_is_directory=True)
        self.refused_without_sqlite(linked_parent / 'new.sqlite')
        self.assertFalse((self.cache.parent / 'new.sqlite').exists())

    @unittest.skipUnless(hasattr(os, 'link'), 'hardlinks unavailable')
    def test_hardlinked_owned_file_refuses_without_sqlite(self):
        target = self.root / 'harmless.txt'
        target.write_text('harmless owned fixture')
        os.link(target, self.cache)
        self.refused_without_sqlite(self.cache)
        self.assertEqual(target.read_text(), 'harmless owned fixture')

    @unittest.skipUnless(os.name == 'posix', 'POSIX owner/mode checks')
    def test_unsafe_parent_and_foreign_owner_refuse_without_sqlite(self):
        self.cache.parent.chmod(0o777)
        self.refused_without_sqlite(self.cache)
        self.cache.parent.chmod(0o700)
        with patch('getzilla.code_graph.cache_custody.os.getuid', return_value=os.getuid() + 1):
            self.refused_without_sqlite(self.cache)

    def test_unknown_sqlite_metadata_never_opens_writable(self):
        content = b'SQLite format 3\x00' + b'\x00' * 100
        self.cache.write_bytes(content)
        connection = Mock()
        connection.execute.return_value.fetchall.return_value = []
        with patch('getzilla.code_graph.store.sqlite3.connect', return_value=connection) as connect:
            with self.assertRaises(GraphError) as error:
                GraphStore(self.cache)
        self.assertEqual(error.exception.reason_code, 'CACHE_UNRECOGNIZED')
        self.assertEqual(connect.call_count, 1)
        self.assertIn('mode=ro&immutable=1', connect.call_args.args[0])
        self.assertTrue(connect.call_args.kwargs['uri'])
        self.assertEqual(self.cache.read_bytes(), content)
        connection.close.assert_called_once()

    @unittest.skipUnless(hasattr(os, 'symlink'), 'links unavailable')
    def test_linked_sidecar_refuses_before_sqlite(self):
        GraphStore(self.cache).close()
        target = self.root / 'harmless.txt'
        target.write_text('harmless owned fixture')
        Path(str(self.cache) + '-wal').symlink_to(target)
        self.refused_without_sqlite(self.cache)
        self.assertEqual(target.read_text(), 'harmless owned fixture')

    def test_missing_readonly_cache_creates_nothing(self):
        with patch('getzilla.code_graph.store.sqlite3.connect') as connect:
            store = GraphStore(self.cache, readonly=True)
            try:
                self.assertIsNone(store.read_active())
            finally:
                store.close()
            connect.assert_not_called()
        self.assertFalse(self.cache.exists())

    def test_owned_cache_reopens_readonly_without_writable_connection(self):
        GraphStore(self.cache).close()
        before = self.cache.read_bytes()
        import sqlite3
        original = sqlite3.connect
        with patch('getzilla.code_graph.store.sqlite3.connect', wraps=original) as connect:
            store = GraphStore(self.cache, readonly=True)
            self.assertIsNone(store.read_active())
            with self.assertRaises(GraphError) as error:
                store.publish(None, expected_active=None)
            self.assertEqual(error.exception.reason_code, 'CACHE_READ_ONLY')
            store.close()
        for call in connect.call_args_list:
            self.assertTrue(call.kwargs.get('uri'))
            self.assertIn('mode=ro&immutable=1', call.args[0])
        self.assertEqual(self.cache.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
