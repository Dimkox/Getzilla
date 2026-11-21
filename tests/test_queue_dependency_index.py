"""One fresh AST inventory keeps operation-demand closure and exhaustion exact."""
import ast
import unittest
from unittest import mock

from getzilla import architecture_fitness as fitness
from tests.test_batch_composition_joins import pure

SOURCE = ('from runtime import service, other\nfirst = service\nsecond = first\n'
          'def operate(): return second()\n')


class OperationDependencyIndexTests(unittest.TestCase):
    def test_one_root_traversal_per_fresh_dependency_analysis(self):
        tree = ast.parse(SOURCE)
        walked = []
        original = ast.walk
        def inventory(node):
            if node is tree:
                walked.append(node)
            return original(node)
        with mock.patch.object(fitness.ast, 'walk', side_effect=inventory), pure():
            result = fitness._operation_dependencies(tree)
        self.assertEqual(len(walked), 1)
        self.assertEqual(result.names, frozenset({'second', 'first', 'service'}))
        self.assertFalse(result.exhausted)

    def test_original_dependency_work_frontier_and_imports_are_preserved(self):
        expected = [
            ({'second'}, {'second', 'first', 'service'}, {'service'}, True),
            ({'second', 'first'}, {'first', 'service'}, {'service'}, True),
            ({'second', 'first', 'service'}, {'service'}, {'service'}, True),
            ({'second', 'first', 'service'}, set(), set(), False),
        ]
        with pure():
            for limit, values in enumerate(expected):
                with self.subTest(work_limit=limit):
                    result = fitness._operation_dependencies(ast.parse(SOURCE), work_limit=limit)
                    self.assertEqual(tuple(result), tuple(frozenset(v) if isinstance(v, set) else v for v in values))
            requested = fitness._operation_dependencies(ast.parse(SOURCE), requested=frozenset({'other'}), work_limit=1)
            self.assertEqual(requested.names, frozenset({'other', 'second'}))
            self.assertEqual(requested.frontier, frozenset({'second', 'first', 'service'}))
            self.assertEqual(requested.frontier_imports, frozenset({'service'}))
            self.assertTrue(requested.exhausted)

    def test_caller_mutation_is_reindexed_without_a_stale_ast_identity_cache(self):
        tree = ast.parse(SOURCE)
        with pure():
            before = fitness._operation_dependencies(tree)
            tree.body.insert(3, ast.parse('second = other').body[0])
            after = fitness._operation_dependencies(tree)
        self.assertNotIn('other', before.names)
        self.assertIn('other', after.names)
        self.assertFalse(after.exhausted)

    def test_container_and_starred_assignment_dependencies_keep_all_bodies(self):
        source = ('from provider import job\ncallbacks = []\ncallbacks.append(job)\n'
                  'head, *tail = callbacks\nregistry["active"] = tail\n'
                  'def invoke(): return registry["active"]()\n')
        with pure():
            result = fitness._operation_dependencies(ast.parse(source))
        self.assertEqual(result.names, frozenset({'callbacks', 'registry', 'job', 'tail'}))
        self.assertFalse(result.exhausted)
