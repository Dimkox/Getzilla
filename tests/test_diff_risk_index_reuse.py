"""Tiny real graphs: memoize pure work, never current risk/source decisions."""
from dataclasses import replace
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import diff_risk
from getzilla.code_graph import builder, models


class DependencyIndexReuseTests(unittest.TestCase):
    def setUp(self):
        getattr(diff_risk, '_DEPENDENCY_INDEX_CACHE', {}).clear()
        self.builds = 0
        self.original = builder.build_generation
        self.contents = {'a.py': b'def f():\n    return 1\n',
                         'b.py': b'from a import f\ndef g():\n    return f()\n',
                         'c.py': b'from b import g\ndef h():\n    return g()\n'}
        def measured(*args, **kwargs):
            self.builds += 1
            return self.original(*args, **kwargs)
        self.enterContext(patch.object(builder, 'build_generation', measured))

    def graph(self, changed=('a.py',), *, contents=None, tree='a' * 40):
        return diff_risk._one_hop_dependents(self.contents if contents is None else contents, set(changed), tree)

    def test_identical_graph_reuses_work_but_filters_new_changed_set(self):
        self.assertEqual(self.graph(), ({'a.py': {'b.py'}}, []))
        self.assertEqual(self.graph(('b.py',)), ({'b.py': {'c.py'}}, []))
        self.assertEqual(self.graph(('a.py', 'b.py')), ({'b.py': {'c.py'}}, []))
        self.assertEqual(self.builds, 1, 'unchanged complete graph must not be rebuilt for a new changed-set')

    def test_returned_mutable_sets_cannot_poison_reused_index(self):
        dependents, gaps = self.graph()
        dependents['a.py'].add('foreign.py')
        dependents['other.py'] = {'foreign.py'}
        gaps.append('forged')
        self.assertEqual(self.graph(), ({'a.py': {'b.py'}}, []))
        self.assertEqual(self.builds, 1)

    def test_source_bytes_path_scope_and_tree_each_invalidate(self):
        variants = (
            ({**self.contents, 'b.py': b'from c import h\n'}, 'a' * 40, {}),
            ({'a.py': self.contents['a.py'], 'client.py': self.contents['b.py']}, 'a' * 40, {'a.py': {'client.py'}}),
            ({'a.py': self.contents['a.py']}, 'a' * 40, {}),
            (self.contents, 'b' * 40, {'a.py': {'b.py'}}),
        )
        for contents, tree, expected in variants:
            with self.subTest(tree=tree, paths=tuple(contents)):
                getattr(diff_risk, '_DEPENDENCY_INDEX_CACHE', {}).clear()
                self.builds = 0
                self.assertEqual(self.graph(), ({'a.py': {'b.py'}}, []))
                self.assertEqual(self.graph(contents=contents, tree=tree), (expected, []))
                self.assertEqual(self.builds, 2)

    def test_config_and_extractor_each_invalidate(self):
        original = models.GraphConfig
        for config, expected in ((original(max_file_bytes=1), {}),
                                 (original(extractor='owned-extractor-v2'), {'a.py': {'b.py'}})):
            with self.subTest(config=config):
                getattr(diff_risk, '_DEPENDENCY_INDEX_CACHE', {}).clear()
                self.builds = 0
                self.assertEqual(self.graph(), ({'a.py': {'b.py'}}, []))
                with patch.object(models, 'GraphConfig', return_value=config):
                    self.assertEqual(self.graph(), (expected, []))
                self.assertEqual(self.builds, 2)

    def test_replaced_builder_cannot_borrow_an_old_index(self):
        self.assertEqual(self.graph(), ({'a.py': {'b.py'}}, []))
        def replacement(*args, **kwargs):
            self.builds += 1
            return replace(self.original(*args, **kwargs), imports=(), calls=())
        with patch.object(builder, 'build_generation', replacement):
            self.assertEqual(self.graph(), ({}, []))
        self.assertEqual(self.builds, 2)

    def test_incomplete_paths_remain_selected_by_current_changed_scope(self):
        contents = {'a.py': b'value = 1\n', 'broken.py': b'def broken(\n'}
        self.assertEqual(self.graph(('broken.py',), contents=contents), ({}, ['PARSE_INCOMPLETE:broken.py']))
        self.assertEqual(self.graph(('a.py',), contents=contents), ({}, []))
        self.assertEqual(self.builds, 1)
        self.assertEqual(self.graph(('broken.py',), contents={**contents, 'broken.py': b'value = 2\n'}), ({}, []))
        self.assertEqual(self.builds, 2)

    def test_two_entry_eviction_keeps_bounded_recent_work(self):
        for tree in ('a' * 40, 'b' * 40, 'c' * 40, 'c' * 40):
            self.assertEqual(self.graph(tree=tree), ({'a.py': {'b.py'}}, []))
        self.assertEqual(self.builds, 3)
        self.assertEqual(self.graph(), ({'a.py': {'b.py'}}, []))
        self.assertEqual(self.builds, 4)

    def test_oversize_path_data_or_row_budget_runs_uncached_without_truncation(self):
        for setting in ('_DEPENDENCY_INDEX_BYTES', '_DEPENDENCY_INDEX_ROWS'):
            with self.subTest(setting=setting):
                getattr(diff_risk, '_DEPENDENCY_INDEX_CACHE', {}).clear()
                self.builds = 0
                with patch.object(diff_risk, setting, 1, create=True):
                    for _ in range(2):
                        self.assertEqual(self.graph(), ({'a.py': {'b.py'}}, []))
                self.assertEqual(self.builds, 2)


if __name__ == '__main__':
    unittest.main()
