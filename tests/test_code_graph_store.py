"""G05: generations are published transactionally; a broken cache is rebuilt, never trusted."""
from __future__ import annotations

import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.code_graph.builder import build_generation  # noqa: E402
from getzilla.code_graph.cli import discover_scope  # noqa: E402
from getzilla.code_graph.models import GraphConfig, GraphError, make_graph_input  # noqa: E402
from getzilla.code_graph.store import GraphStore, build_full_index  # noqa: E402
from tests.code_graph_support import graph_input  # noqa: E402

V1 = {'a.py': 'def f():\n    pass\n', 'b.py': 'from a import f\nf()\n'}
V2 = {**V1, 'a.py': 'def f():\n    return 2\ndef g():\n    pass\n'}


class GraphStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / 'index' / 'graph.sqlite'

    def store(self) -> GraphStore:
        store = GraphStore(self.path)
        self.addCleanup(store.close)
        return store

    def test_reader_sees_old_or_new_complete_generation(self) -> None:
        writer = self.store()
        old = build_full_index(graph_input(V1), writer)
        new = build_generation(graph_input(V2))
        reader = self.store()
        seen = []
        stop = threading.Event()

        def read() -> None:
            local = GraphStore(self.path)
            while not stop.is_set():
                generation = local.read_active()
                seen.append(generation.generation_id)
            local.close()

        thread = threading.Thread(target=read)
        thread.start()
        writer.publish(new, expected_active=old.generation_id)
        stop.set()
        thread.join()
        self.assertTrue(set(seen) <= {old.generation_id, new.generation_id})
        self.assertEqual(reader.read_active().export(), new.export())

    def test_interrupted_write_not_active(self) -> None:
        store = self.store()
        old = build_full_index(graph_input(V1), store)
        with self.assertRaises(RuntimeError):
            store.publish(build_generation(graph_input(V2)), expected_active=old.generation_id, _fail_before_commit=True)
        self.assertEqual(store.active_id(), old.generation_id)
        self.assertEqual(store.read_active().export(), old.export())

    def test_unrecognized_cache_is_preserved(self) -> None:
        self.path.parent.mkdir(parents=True, mode=0o700)
        content = b'not a database' * 100
        self.path.write_bytes(content)
        with self.assertRaises(GraphError) as caught:
            self.store()
        self.assertEqual(caught.exception.reason_code, 'CACHE_UNRECOGNIZED')
        self.assertEqual(self.path.read_bytes(), content)

    def test_schema_mismatch_is_preserved(self) -> None:
        store = self.store()
        build_full_index(graph_input(V1), store)
        store.db.execute("UPDATE meta SET value = 'getzilla-code-graph-store-v0' WHERE key = 'schema'")
        store.close()
        before = self.path.read_bytes()
        with self.assertRaises(GraphError) as caught:
            self.store()
        self.assertEqual(caught.exception.reason_code, 'CACHE_SCHEMA_MISMATCH')
        self.assertEqual(self.path.read_bytes(), before)

    def test_tampered_generation_rejected(self) -> None:
        store = self.store()
        generation = build_full_index(graph_input(V1), store)
        store.db.execute("UPDATE generations SET body = replace(body, '\"a.py\"', '\"z.py\"')")
        with self.assertRaises(GraphError):
            store.read_generation(generation.generation_id)

    def test_cache_not_in_source_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / 'a.py').write_text('x = 1\n', encoding='utf-8')
            # The runner's private TMPDIR can be inside the source worktree.
            # Give this scope its own Git identity instead of inheriting it.
            subprocess.run(['git', 'init', '-q', str(project)], check=True, capture_output=True)
            subprocess.run(['git', '-C', str(project), 'add', 'a.py'], check=True, capture_output=True)
            subprocess.run(['git', '-C', str(project), '-c', 'user.name=Fixture',
                            '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture'],
                           check=True, capture_output=True)
            before = make_graph_input(*discover_scope(project)[:2], GraphConfig()).identity
            store = GraphStore(project / '.getzilla' / 'index' / 'graph.sqlite')
            build_full_index(make_graph_input(*discover_scope(project)[:2], GraphConfig()), store)
            store.close()
            baseline, scope, _ = discover_scope(project)
            self.assertNotIn('.getzilla/index/graph.sqlite', scope)
            self.assertEqual(make_graph_input(baseline, scope, GraphConfig()).identity, before)
        ignore = (ROOT / '.gitignore').read_text(encoding='utf-8')
        self.assertIn('.getzilla/index/', ignore)

    def test_concurrent_writers_cannot_publish_mixed_generation(self) -> None:
        first, second = self.store(), self.store()
        base = build_full_index(graph_input(V1), first)
        expected = second.active_id()
        first.publish(build_generation(graph_input(V2)), expected_active=base.generation_id)
        with self.assertRaises(GraphError) as caught:
            second.publish(build_generation(graph_input({**V1, 'c.py': ''})), expected_active=expected)
        self.assertEqual(caught.exception.reason_code, 'CONCURRENT_PUBLISH')
        self.assertEqual(second.read_active().export(), build_generation(graph_input(V2)).export())
        check = sqlite3.connect(str(self.path))
        try:
            counts = check.execute('SELECT count(*) FROM generations WHERE complete = 1').fetchone()
        finally:
            check.close()
        self.assertEqual(counts[0], 2)


if __name__ == '__main__':
    unittest.main()
