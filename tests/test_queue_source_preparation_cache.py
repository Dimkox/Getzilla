"""Exact immutable source facts avoid repeat walks without avoiding ledger charges."""
import ast
from pathlib import Path
import unittest
from unittest import mock

from getzilla import architecture_fitness as fitness
from tests.test_batch_composition_joins import pure

SOURCE = (b'from rq import Queue\ndef make(): return Queue()\n'
          b'def first(): return 1\ndef second(): return 2\n')


def cache(source=SOURCE):
    return fitness._QueueResolutionCache(('owned',), ('owned.py',), {
        'owned': fitness._QueueAdapterResolution('prefetched', 'owned source',
                                                sources=(('owned.py', source, ''),))}, {})


def resolve(source=SOURCE, *, requested=frozenset({'first'}), callable_only=True, resolving=None):
    budget = fitness._QueueBudget('head')
    def no_source_read(root, diff, paths, side):
        if paths:
            raise AssertionError('fixture permits no source I/O')
        return {}
    with mock.patch.object(fitness, 'read_diff_files', side_effect=no_source_read):
        result = fitness._local_queue_resolution(Path('owned-inert'), None, 'owned', 'head', cache(source),
            set() if resolving is None else resolving, set(), (), requested, callable_only, budget)
    return result, budget


class QueuePreparationCacheTests(unittest.TestCase):
    def test_repeated_prepared_module_demands_do_not_walk_whole_trees(self):
        with pure():
            for name in ('first', 'second'):
                resolve(requested=frozenset({name}))
            original = fitness.ast.walk
            with mock.patch.object(fitness.ast, 'walk', wraps=original) as walked:
                results = [resolve(requested=frozenset({name})) for name in ('first', 'second') * 12]
            self.assertEqual(walked.call_count, 0)
            footprints = [result.footprint for result, _ in results]
            self.assertTrue(all(item.sources for item in footprints))
            self.assertTrue(all(budget.source_bytes == len(SOURCE) for _, budget in results))
            expected_nodes = sum(1 for _ in original(ast.parse(SOURCE)))
            self.assertTrue(all(budget.ast_nodes == expected_nodes for _, budget in results))
            self.assertTrue(all(budget.logical_work == 1 for _, budget in results))

    def test_same_path_changed_bytes_refresh_nodes_exports_and_classification(self):
        changed = SOURCE + b'def third(): return 3\n'
        with pure():
            first, first_budget = resolve(requested=frozenset({'make'}), callable_only=False)
            current, current_budget = resolve(changed, requested=frozenset({'make'}), callable_only=False)
            self.assertEqual((first.state, first.signals, first.exports),
                             (current.state, current.signals, current.exports))
            self.assertIn('third', current.declared_exports)
            self.assertNotIn('third', first.declared_exports)
            self.assertGreater(current_budget.ast_nodes, first_budget.ast_nodes)
            self.assertEqual(current_budget.source_bytes, len(changed))
            self.assertNotEqual(first.footprint.sources[0].digest, current.footprint.sources[0].digest)

    def test_original_node_boundary_refusal_is_identical_with_warm_facts(self):
        # A closed fixture ledger represents already-inspected other source nodes.
        nodes = sum(1 for _ in ast.walk(ast.parse(SOURCE)))
        refusals = []
        with pure():
            for _ in range(2):
                budget = fitness._QueueBudget('head')
                budget.source('owned-prior.py', b'prior measured source',
                              fitness.MAX_QUEUE_ANALYSIS_AST_NODES - nodes + 1)
                with self.assertRaises(fitness.ArchitectureError) as raised:
                    fitness._budgeted_queue_tree('boundary-owned.py', SOURCE, budget)
                refusals.append((str(raised.exception), raised.exception.code,
                                 raised.exception.queue_refusal, budget.source_bytes, budget.ast_nodes))
            self.assertEqual(refusals[0], refusals[1])
            self.assertEqual(refusals[0][2]['category'], 'nodes')
            self.assertEqual(refusals[0][2]['limit'], fitness.MAX_QUEUE_ANALYSIS_AST_NODES)
            self.assertEqual(refusals[0][2]['observed'], fitness.MAX_QUEUE_ANALYSIS_AST_NODES + 1)

    def test_warm_preparation_cannot_reuse_an_ordinary_answer_in_a_cycle(self):
        with pure():
            ordinary, _ = resolve(requested=frozenset({'make'}), callable_only=False)
            active = {'owned'}
            cyclic, _ = resolve(requested=frozenset({'make'}), callable_only=False, resolving=active)
            self.assertEqual(ordinary.state, 'resolved')
            self.assertEqual((cyclic.state, cyclic.reason), ('unsupported', 'cyclic_local_queue_adapter'))
            self.assertEqual(active, {'owned'})
