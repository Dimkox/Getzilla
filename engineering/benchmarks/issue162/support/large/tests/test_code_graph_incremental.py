"""G06: incremental updates produce exactly the full-rebuild graph; only parsing is reused."""
from __future__ import annotations

import random
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.code_graph.builder import build_generation  # noqa: E402
from getzilla.code_graph.incremental import update_index  # noqa: E402
from getzilla.code_graph.models import GraphConfig  # noqa: E402
from getzilla.code_graph.store import GraphStore, build_full_index  # noqa: E402
from tests.code_graph_support import graph_input  # noqa: E402

BASE = {
    'pkg/__init__.py': '',
    'pkg/a.py': 'def fa():\n    pass\n',
    'pkg/b.py': 'from pkg.a import fa\ndef fb():\n    fa()\n',
    'pkg/c.py': 'from pkg import b\ndef fc():\n    b.fb()\n',
}


class IncrementalTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = GraphStore(Path(tmp.name) / 'graph.sqlite')
        self.addCleanup(self.store.close)

    def step(self, previous, files, config=None, **kwargs):
        return update_index(previous, graph_input(files, config), self.store, **kwargs)

    def assert_equals_full(self, generation, files, config=None) -> None:
        self.assertEqual(generation.export(), build_generation(graph_input(files, config)).export())

    def test_incremental_equals_full_on_add_modify_delete_rename(self) -> None:
        previous = build_full_index(graph_input(BASE), self.store)
        rng = random.Random(20261016)
        files = dict(BASE)
        for index in range(40):
            operation = rng.choice(['add', 'modify', 'delete', 'rename'])
            names = sorted(path for path in files if path != 'pkg/__init__.py')
            if operation == 'add' or not names:
                target = rng.choice(names) if names else 'pkg/a.py'
                module = target[:-3].replace('/', '.')
                files[f'pkg/n{index}.py'] = f'import {module}\ndef n{index}():\n    {module}.f{index}()\n'
            elif operation == 'modify':
                path = rng.choice(names)
                files[path] = files[path] + f'def extra{index}():\n    pass\n'
            elif operation == 'delete':
                files.pop(rng.choice(names))
            else:
                path = rng.choice(names)
                files[f'pkg/r{index}.py'] = files.pop(path)
            previous = self.step(previous, files)
            self.assert_equals_full(previous, files)

    def test_deleted_symbol_leaves_no_stale_edge(self) -> None:
        previous = build_full_index(graph_input(BASE), self.store)
        files = {**BASE, 'pkg/a.py': '# fa removed\n'}
        current = self.step(previous, files)
        self.assertNotIn('sym:pkg/a.py::fa', {s.id for s in current.symbols})
        self.assertFalse(any('sym:pkg/a.py::fa' in edge.targets for edge in current.calls))
        fa = next(edge for edge in current.calls if edge.expression == 'fa')
        self.assertEqual(fa.resolution, 'unresolved')

    def test_equal_bytes_renamed_module_reresolves(self) -> None:
        previous = build_full_index(graph_input(BASE), self.store)
        files = dict(BASE)
        files['pkg/a2.py'] = files.pop('pkg/a.py')
        current = self.step(previous, files)
        edge = next(e for e in current.imports if e.source_file == 'pkg/b.py')
        self.assertEqual((edge.resolution, edge.target_file), ('unresolved', None))
        self.assertIn('sym:pkg/a2.py::fa', {s.id for s in current.symbols})
        self.assert_equals_full(current, files)

    def test_resolver_config_change_forces_revalidation(self) -> None:
        previous = build_full_index(graph_input(BASE), self.store)
        config = GraphConfig(namespace_packages=True)
        current = self.step(previous, BASE, config)
        self.assertEqual(current.counters['full_rebuild_reason'], 'CONFIG_OR_EXTRACTOR_CHANGED')
        self.assertEqual(current.counters['reused'], 0)
        self.assert_equals_full(current, BASE, config)

    def test_content_hash_cache_hit_avoids_reparse(self) -> None:
        previous = build_full_index(graph_input(BASE), self.store)
        current = self.step(previous, {**BASE, 'pkg/c.py': BASE['pkg/c.py'] + '\n'})
        self.assertEqual((current.counters['parsed'], current.counters['reused']), (1, 3))
        self.assertEqual(current.counters['resolved_files'], 4)

    def test_corrupt_diff_falls_back_to_full(self) -> None:
        previous = build_full_index(graph_input(BASE), self.store)
        files = {**BASE, 'pkg/c.py': 'x = 1\n'}
        current = self.step(previous, files, declared_changes=['pkg/b.py'])
        self.assertEqual(current.counters['full_rebuild_reason'], 'CHANGE_SET_INCONSISTENT')
        self.assertEqual(current.counters['parsed'], 4)
        self.assert_equals_full(current, files)


if __name__ == '__main__':
    unittest.main()
