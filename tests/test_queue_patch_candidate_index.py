"""No special mock-patch facts is distinct from absence of a real queue."""
import ast
import unittest
from unittest import mock

from getzilla import queue_provenance as queue
from getzilla import architecture_fitness as fitness
from tests.test_batch_composition_joins import pure

CALL = 'with patch.object(library, "factory", return_value=work):\n    pass\n'
IMPORT = 'from unittest.mock import patch\nimport library\n'


class PatchCandidateIndexTests(unittest.TestCase):
    def test_no_candidate_import_needs_no_namespace_proof_or_repeated_root_walk(self):
        tree = ast.parse('import rq\njobs = rq.Queue("owned")\njobs.enqueue(work)\n')
        original = ast.walk
        roots = []
        def walk(node):
            if node is tree:
                roots.append(node)
            return original(node)
        with mock.patch.object(queue, 'namespace_is_closed', wraps=queue.namespace_is_closed) as proof, \
                mock.patch.object(queue.ast, 'walk', side_effect=walk), pure():
            self.assertEqual(queue.literal_patch_members(tree), {})
        self.assertEqual(proof.call_count, 0)
        self.assertEqual(len(roots), 1)
        with pure():
            analysis = queue.analyze_queue_tree(tree)
        self.assertTrue(analysis.signals, 'empty patch metadata must not waive real queue operations')

    def test_candidate_import_keeps_complete_proof_and_member_metadata(self):
        tree = ast.parse(IMPORT + CALL)
        with mock.patch.object(queue, 'namespace_is_closed', wraps=queue.namespace_is_closed) as proof, pure():
            result = queue.literal_patch_members(tree)
        self.assertEqual(proof.call_count, 1)
        self.assertEqual(len(result), 1)
        target, member, value, factory = next(iter(result.values()))
        self.assertEqual((target, member, value.id, factory), ('library', 'factory', 'work', False))

    def test_reflection_rebinding_and_unproved_members_keep_no_special_facts(self):
        cases = [IMPORT + 'globals()\n' + CALL,
                 IMPORT + 'from builtins import __dict__\n' + CALL,
                 IMPORT + 'patch = replacement\n' + CALL,
                 IMPORT + 'with patch.object(library, selected): pass\n',
                 IMPORT + 'with patch.object(library, "factory", **unknown): pass\n']
        for source in cases:
            with self.subTest(source=source), pure():
                self.assertEqual(queue.literal_patch_members(ast.parse(source)), {})

    def test_caller_mutation_rechecks_and_unproved_mock_loader_stays_unrecognized(self):
        tree = ast.parse(CALL)
        with pure():
            self.assertEqual(queue.literal_patch_members(tree), {})
            tree.body[:0] = ast.parse(IMPORT).body
            self.assertEqual(len(queue.literal_patch_members(tree)), 1)
            literal = ast.parse('patch = __import__("unittest.mock", fromlist=["patch"]).patch\n' +
                                'import library\n' + CALL)
            normalized = fitness._queue_import_equivalent_tree(literal)
            self.assertIs(normalized, literal)
            self.assertEqual(queue.literal_patch_members(normalized), {})
