"""Public inert source controls for complete lexical/namespace prerequisites."""
from __future__ import annotations

import ast
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.python_source_proof import binding_events, binding_owner
from getzilla.queue_provenance import analyze_queue_tree, local_byte_channel_projection
from tests import test_detector_data_boundaries as fixtures
from tests.test_architecture_fitness import ARCHITECTURE, DIFF, FIT, GitArchitectureRepo
from tests.test_architecture_model import _rules, _system


# These literal cohorts are independent expected inputs, not copies of a
# production capability set. They must still fail if a source branch is lost.
PLAIN_CAPABILITIES = (
    ('locals', 'locals()'),
    ('vars', 'vars()'),
    ('exec', "exec('pass')"),
    ('eval', "eval('1')"),
    ('setattr', "setattr(record, 'field', value)"),
    ('delattr', "delattr(record, 'field')"),
)
REFLECTIVE_ATTRIBUTES = (
    '__dict__', '__builtins__', '__class__', '__bases__', '__mro__',
    '__globals__', '__closure__', '__code__', '__func__', '__getattribute__',
    '__setattr__', '__delattr__', '__import__', 'import_module', 'modules',
)
MEMBER_READ = "import adapter\nselected = getattr(adapter, 'ordinary', None)\nselected()\n"
TYPE_PARAMETER_GRAMMAR = sys.version_info >= (3, 12)


class SourceConsumerControls:
    def assert_source_consumers(self, prefix, *, governed):
        channel = ast.parse(prefix + '\n' + fixtures.PIPE_CHANNEL)
        original = ast.dump(channel, include_attributes=True)
        projected = local_byte_channel_projection(channel)
        result = analyze_queue_tree(channel)
        if governed:
            self.assertIs(projected, channel)
            self.assertTrue(result.signals, 'Unsafe source must retain queue policy signals')
        else:
            self.assertEqual(result.signals, ())
            self.assertFalse(result.uncertain)
        self.assertEqual(ast.dump(channel, include_attributes=True), original)
        consumer = ast.parse(prefix + '\n' + MEMBER_READ)
        original = ast.dump(consumer, include_attributes=True)
        self.assertEqual(FIT._module_member_demands(consumer, 'adapter'),
                         None if governed else frozenset({'ordinary'}))
        self.assertEqual(ast.dump(consumer, include_attributes=True), original)

    def assert_source_fitness(self, prefix, *, governed):
        repo = GitArchitectureRepo(self)
        system = _system()
        system['nodes'][0]['repository_paths'] = ['src']
        repo.model(system, _rules())
        repo.write_text('src/adapter.py',
                        'from rq import Queue\njobs = Queue()\ndef ordinary(): return None\n')
        base = repo.commit('queue-bearing and ordinary exports')
        repo.write_text('src/consumer.py', prefix + '\n' + MEMBER_READ)
        head = repo.commit('public namespace family consumer')
        snapshot = ARCHITECTURE.load_architecture(repo.root)
        diff = DIFF.diff_architecture(repo.root, base_sha=base, head_sha=head)
        report = FIT.evaluate_fitness(repo.root, snapshot, diff, diff.changed_paths, pre_risk='green')
        result = next(item for item in report.results if item.category == 'background_job')
        self.assertEqual(result.status, 'unsupported' if governed else 'not_applicable')
        self.assertEqual('new_queue' in report.triggers, governed)


class NamespaceFamilyTests(SourceConsumerControls, unittest.TestCase):
    def test_plain_and_bound_namespace_capabilities_keep_both_consumers_governed(self):
        for name, operation in PLAIN_CAPABILITIES:
            for bound in (False, True):
                with self.subTest(capability=name, bound=bound):
                    declaration = f'def {name}(*args): return None\n' if bound else ''
                    self.assert_source_consumers(declaration + operation, governed=True)

    def test_reflective_attributes_and_literal_names_keep_both_consumers_governed(self):
        for attribute in REFLECTIVE_ATTRIBUTES:
            for expression in ('holder.' + attribute, repr(attribute)):
                with self.subTest(attribute=attribute, expression=expression):
                    self.assert_source_consumers('view = ' + expression, governed=True)

    def test_guard_attribute_store_and_delete_keep_both_consumers_governed(self):
        for attribute in ('type', 'bytes', 'len', 'OSError', 'getattr'):
            for statement in (f'holder.{attribute} = replacement', f'del holder.{attribute}'):
                with self.subTest(statement=statement):
                    self.assert_source_consumers(statement, governed=True)

    def test_ordinary_attributes_and_bound_functions_preserve_precise_positives(self):
        for prefix in ('metadata = holder.status', "metadata = 'plain field'",
                       'def snapshot(*args): return {}\nmetadata = snapshot()',
                       'metadata = holder.type'):
            with self.subTest(prefix=prefix):
                self.assert_source_consumers(prefix, governed=False)
                self.assert_source_fitness(prefix, governed=False)

    def test_source_bound_fitness_retains_each_plain_and_reflective_family(self):
        for name, operation in PLAIN_CAPABILITIES:
            for bound in (False, True):
                with self.subTest(capability=name, bound=bound):
                    declaration = f'def {name}(*args): return None\n' if bound else ''
                    self.assert_source_fitness(declaration + operation, governed=True)
        for attribute in REFLECTIVE_ATTRIBUTES:
            with self.subTest(attribute=attribute):
                self.assert_source_fitness('view = holder.' + attribute, governed=True)


@unittest.skipUnless(TYPE_PARAMETER_GRAMMAR, 'Python3.11 cannot parse genuine PEP695 type parameters; Python3.12+ required')
class TypeParameterFamilyTests(SourceConsumerControls, unittest.TestCase):

    def test_real_typevar_paramspec_and_typevartuple_bindings_have_lexical_owners(self):
        for marker, node_type in (('', 'TypeVar'), ('**', 'ParamSpec'), ('*', 'TypeVarTuple')):
            with self.subTest(node_type=node_type):
                source = f'def scope[{marker}getattr]():\n    return getattr\n'
                tree = ast.parse(source)
                compile(tree, '<public-type-parameter-fixture>', 'exec')
                parameters = [event for event in binding_events(tree) if event.name == 'getattr']
                self.assertEqual(len(parameters), 1)
                self.assertEqual(type(parameters[0].node).__name__, node_type)
                parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
                self.assertIs(binding_owner(parameters[0].node, parents), tree.body[0])

    def test_each_type_parameter_family_keeps_channel_dependencies_governed(self):
        for marker in ('', '**', '*'):
            for name in ('type', 'bytes', 'len', 'OSError', 'Queue', 'Thread', 'CHUNK_BYTES'):
                with self.subTest(marker=marker, binding=name):
                    source = fixtures.PIPE_CHANNEL.replace('def drain(runner):', f'def drain[{marker}{name}](runner):')
                    tree = ast.parse(source)
                    compile(tree, '<public-channel-type-parameter-fixture>', 'exec')
                    original = ast.dump(tree, include_attributes=True)
                    self.assertIs(local_byte_channel_projection(tree), tree)
                    self.assertTrue(analyze_queue_tree(tree).signals)
                    self.assertEqual(ast.dump(tree, include_attributes=True), original)

    def test_each_type_parameter_family_keeps_getter_export_closure(self):
        for marker in ('', '**', '*'):
            with self.subTest(marker=marker):
                prefix = f'def scope[{marker}getattr]():\n    return getattr\n'
                tree = ast.parse(prefix + MEMBER_READ)
                compile(tree, '<public-member-type-parameter-fixture>', 'exec')
                original = ast.dump(tree, include_attributes=True)
                self.assertIsNone(FIT._module_member_demands(tree, 'adapter'))
                self.assertEqual(ast.dump(tree, include_attributes=True), original)
                self.assert_source_fitness(prefix, governed=True)

    def test_ordinary_type_parameters_keep_local_bytes_and_selected_member(self):
        for marker in ('', '**', '*'):
            with self.subTest(marker=marker):
                tree = ast.parse(fixtures.PIPE_CHANNEL.replace('def drain(runner):', f'def drain[{marker}Payload](runner):'))
                compile(tree, '<public-ordinary-type-parameter-fixture>', 'exec')
                result = analyze_queue_tree(tree)
                self.assertEqual(result.signals, ())
                self.assertFalse(result.uncertain)
                prefix = f'def scope[{marker}Payload]():\n    return None\n'
                self.assertEqual(FIT._module_member_demands(ast.parse(prefix + MEMBER_READ), 'adapter'),
                                 frozenset({'ordinary'}))
                self.assert_source_fitness(prefix, governed=False)


if __name__ == '__main__':
    unittest.main()
