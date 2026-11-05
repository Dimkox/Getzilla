"""Bounded local byte channels and precise adapter member demands."""
from __future__ import annotations

import ast
import copy
import sys
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.queue_provenance import analyze_queue_tree
from tests.test_architecture_fitness import ARCHITECTURE, DIFF, FIT, GitArchitectureRepo
from tests.test_architecture_model import _rules, _system


LOCAL_CHANNEL = '''\
from queue import Queue, Empty, Full
def drain():
    chunks = Queue(maxsize=2)
    def read():
        chunks.put(b'bytes', timeout=0.05)
    read()
    return len(chunks.get(timeout=0.05))
'''


PIPE_CHANNEL = '''
import subprocess
from threading import Thread
from queue import Queue, Empty, Full
CHUNK_BYTES = 65536
def drain(runner):
    process = runner(stdout=subprocess.PIPE)
    chunks: Queue[bytes] = Queue(maxsize=2)
    def read():
        chunk = process.stdout.read(CHUNK_BYTES)
        if type(chunk) is not bytes:
            raise OSError('non-byte payload')
        if len(chunk) > CHUNK_BYTES:
            raise OSError('payload exceeds bound')
        chunks.put(chunk, timeout=0.05)
    reader = Thread(target=read)
    reader.start()
    data = chunks.get(timeout=0.05)
    reader.join(timeout=1)
    return len(data)
'''


def binding_statement(name, kind):
    return {
        'except': f'try:\n    opaque()\nexcept Exception as {name}:\n    pass',
        'as': f'match opaque:\n    case {name}:\n        pass',
        'star': f'match opaque:\n    case [*{name}]:\n        pass',
        'mapping': f'match opaque:\n    case {{**{name}}}:\n        pass',
    }[kind]


NAMESPACE_CAPABILITIES = (
    "from builtins import __dict__ as namespace\nnamespace['bytes'] = Payload",
    "from builtins import __dict__ as namespace\nnamespace.update({'getattr': replacement})",
    "import builtins\nbuiltins.__dict__.update({'getattr': replacement})",
    "import builtins\nbuiltins.__setattr__('bytes', Payload)",
    "import builtins\nbuiltins.__delattr__('getattr')",
    "__builtins__['bytes'] = Payload",
    "__builtins__ = replacement",
    "namespace = __builtins__\nnamespace.update({'getattr': replacement})",
    "from builtins import __setattr__ as mutate\nmutate('bytes', Payload)",
    "__setattr__ = replacement\n__setattr__('bytes', Payload)",
    "namespace = __dict__\nnamespace.update({'getattr': replacement})",
    "__import__('builtins').__setattr__('getattr', replacement)",
    "loader = __import__\nnamespace = loader(name)",
    "from importlib import import_module as loader\nnamespace = loader('builtins')",
    "from unittest.mock import patch\nwith patch('builtins.getattr', replacement):\n    pass",
)


class CompleteSourceProofTests(unittest.TestCase):
    def test_each_consumed_result_and_escaping_closure_keeps_source_demand(self):
        operations = {
            'inline-method': 'class Holder:\n    def select(self): return bridge.helper()\nHolder().select().enqueue(work)',
            'assigned-method': 'class Holder:\n    def select(self): return bridge.helper()\nholder = Holder()\nholder.select().enqueue(work)',
            'nested-receiver': 'class Holder:\n    def select(self): return bridge.helper()\n(Holder() if flag else Holder()).select().enqueue(work)',
            'class-attribute': 'class Holder:\n    jobs = bridge.helper()\nHolder.jobs.enqueue(work)',
            'closure': 'def select():\n    def inner(): return bridge.helper()\n    return inner\nselect()().enqueue(work)',
            'closure-list': 'def select():\n    def inner(): return bridge.helper()\n    return [inner]\nselect()[0]().enqueue(work)',
            'lambda': 'def select(): return lambda: bridge.helper()\nselect()().enqueue(work)',
            'lambda-list': 'def select(): return [lambda: bridge.helper()]\nselect()[0]().enqueue(work)',
            'nested-closure': 'def select():\n    def middle(): return lambda: bridge.helper()\n    return [middle]\nselect()[0]()().enqueue(work)',
            'named-expression': 'if (jobs := bridge.helper()):\n    jobs.put(work())',
            'match': 'match bridge.helper():\n    case jobs:\n        jobs.put(work())',
            'with': 'with bridge.helper() as jobs:\n    jobs.enqueue(work)',
            'for': 'for jobs in bridge.helper():\n    jobs.enqueue(work)',
            'getter-result': "if (jobs := getattr(bridge, 'helper')()):\n    jobs.put(work())",
            'attribute-protocol': 'bridge.helper().trigger',
            'subscript-protocol': "bridge.helper()['trigger']",
            'operator-protocol': 'bridge.helper() + 1',
            'comparison-protocol': 'bridge.helper() == 1',
            'truth-protocol': 'bridge.helper() and 1',
            'hash-protocol': '{bridge.helper()}',
            'iteration-protocol': '[*bridge.helper()]',
            'stored-argument': 'saved = []\ndef store(value): saved.append(value)\nstore(bridge.helper())\nsaved[0].enqueue(work)',
            'default-capture': 'jobs = bridge.helper()\ndef select(value=jobs): return value\nselect().enqueue(work)',
            'comprehension-capture': 'jobs = bridge.helper()\n[jobs.put(work()) for jobs in (jobs,)]',
            'yield': 'def select(): yield bridge.helper()\nnext(select()).enqueue(work)',
        }
        providers = (
            ('rq', 'from rq import Queue\ndef helper(): return Queue()\n'),
            ('stdlib', 'from queue import Queue\ndef helper(): return Queue()\n'),
            ('ordinary', 'class Ordinary:\n    def enqueue(self, work): pass\n    def put(self, work): pass\ndef helper(): return Ordinary()\n'),
        )
        for provider_name, provider in providers:
            for label, operation in operations.items():
                with self.subTest(provider=provider_name, operation=label):
                    repo = GitArchitectureRepo(self)
                    repo.model(_system(), _rules())
                    repo.write_text('provider.py', provider)
                    repo.write_text('bridge.py', 'from provider import helper\n')
                    base = repo.commit('queue-returning or ordinary source')
                    # With/for are source-policy contrasts, not a claim that real
                    # queue classes implement context/iteration protocols.
                    if provider_name == 'stdlib':
                        operation = operation.replace('.enqueue(work)', '.put(work)')
                    repo.write_text('consumer.py', 'import bridge\n' + operation + '\n')
                    head = repo.commit('consumed result or escaping closure')
                    snapshot = ARCHITECTURE.load_architecture(repo.root)
                    diff = DIFF.diff_architecture(repo.root, base_sha=base, head_sha=head)
                    report = FIT.evaluate_fitness(repo.root, snapshot, diff, diff.changed_paths, pre_risk='green')
                    result = next(item for item in report.results if item.category == 'background_job')
                    self.assertEqual(result.status, 'not_applicable' if provider_name == 'ordinary' else 'unsupported')
                    self.assertEqual('new_queue' in report.triggers, provider_name != 'ordinary')

    def test_discarded_result_proof_preserves_lexical_bindings_and_unknown_escapes(self):
        for source in ('import bridge\nbridge.helper()\n',
                       'import bridge\nunused = bridge.helper()\n',
                       'import bridge\nunused = [bridge.helper()]\n'):
            with self.subTest(discarded=source):
                observed = FIT._callable_use_proof(ast.parse(source), namespace_closed=True, patches={})
                self.assertIn('bridge.helper', observed.identity)
        source = ('import left\nimport right\ndef first():\n    value = left.helper()\n'
                  'def second():\n    value = right.helper()\n    value.enqueue(work)\n')
        observed = FIT._callable_use_proof(ast.parse(source), namespace_closed=True, patches={})
        self.assertIn('left.helper', observed.identity)
        self.assertIn('right.helper', observed.returns)
        observed = FIT._callable_use_proof(ast.parse('import bridge\nclass Holder:\n    jobs = bridge.helper()\n'),
                                           namespace_closed=True, patches={})
        self.assertIn('bridge.helper', observed.returns)
        for escape in ('sink(value)', 'def select(): return value',
                       'def select(other=value): return other',
                       'def select():\n    global value\n    return value',
                       '[item for item in value]', 'match value:\n    case selected: selected.put(work)',
                       'value = replacement', 'try: pass\nexcept Exception as value: pass',
                       'match other:\n    case value: pass'):
            with self.subTest(escape=escape):
                tree = ast.parse('import bridge\nvalue = bridge.helper()\n' + escape + '\n')
                observed = FIT._callable_use_proof(tree, namespace_closed=True, patches={})
                self.assertIn('bridge.helper', observed.returns)

    def test_result_use_proof_rechecks_caller_bytes_and_exhaustion(self):
        source = b'import bridge\nbridge.helper()\n'
        changed = b'import bridge\nif (value := bridge.helper()): value.put(work)\n'
        caller = ast.parse(source)
        caller.proof_payload = {'mutable': ['unchanged']}
        original = ast.dump(caller, include_attributes=True)
        initial = FIT._callable_use_proof(caller, namespace_closed=True, patches={})
        self.assertIn('bridge.helper', initial.identity)
        self.assertEqual(ast.dump(caller, include_attributes=True), original)
        self.assertEqual(caller.proof_payload, {'mutable': ['unchanged']})
        caller.body[:] = ast.parse(changed).body
        observed = FIT._callable_use_proof(caller, namespace_closed=True, patches={})
        self.assertIn('bridge.helper', observed.returns)
        first = FIT._queue_source_preparation('result-version.py', source)
        current = FIT._queue_source_preparation('result-version.py', changed)
        self.assertIn('bridge.helper', first.callable_uses.identity)
        self.assertIn('bridge.helper', current.callable_uses.returns)
        default = first.callable_uses
        owned_tree = ast.dump(first.tree, include_attributes=True)
        for forced in (True, False, True):
            FIT._inventory_use_proof(first.inventory, returns=forced)
            self.assertEqual(first.callable_uses, default)
            self.assertEqual(ast.dump(first.tree, include_attributes=True), owned_tree)
        with self.assertRaises(TypeError):
            first.inventory.reads['bridge'] = ()
        with self.assertRaises(TypeError):
            first.inventory.scope_counts[(None, 'bridge')] = 0
        chain = 'import bridge\nfirst = bridge.helper()\nsecond = first\nthird = second\n'
        with patch.object(FIT, 'MAX_QUEUE_DEPENDENCY_WORK', 2):
            observed = FIT._callable_use_proof(ast.parse(chain), namespace_closed=True, patches={})
        self.assertNotIn('bridge.helper', observed.identity)
        self.assertIn('bridge.helper', observed.returns)

    def test_repeated_identical_imports_keep_direct_calls_within_source_budget(self):
        repo = GitArchitectureRepo(self)
        repo.model(_system(), _rules())
        imports = []
        for index in range(FIT.MAX_QUEUE_ADAPTER_MODULES):
            repo.write_text(f'leaf{index}.py', 'def ordinary(): return None\n')
            imports.append(f'from leaf{index} import ordinary as value{index}\n')
        repo.write_text('provider.py', ''.join(imports) + 'def helper(): return [' +
                        ', '.join(f'value{index}()' for index in range(FIT.MAX_QUEUE_ADAPTER_MODULES)) + ']\n')
        base = repo.commit('ordinary callable behind a long import closure')
        source = ('def first():\n    from provider import helper\n    helper()\n'
                  'def second():\n    from provider import helper\n    helper()\n')
        repo.write_text('consumer.py', source)
        head = repo.commit('identical imports in separate lexical scopes')
        diff = DIFF.diff_architecture(repo.root, base_sha=base, head_sha=head)
        cache = FIT._queue_module_inventory(repo.root, diff, 'head', ('',))
        result = FIT._queue_signals(repo.root, diff, ast.parse(source), 'head', cache, '', ('',),
                                   source_path='consumer.py', source=source.encode())
        self.assertEqual(result.state, 'not_queue')
        self.assertEqual(result.signals, ())

    def test_uniform_import_identity_requires_all_bindings_and_closed_namespace(self):
        source = ('def first():\n    from bridge import helper\n    helper()\n'
                  'def second():\n    from bridge import helper\n    helper()\n')
        proof = FIT._queue_source_preparation('uniform.py', source.encode()).callable_uses
        self.assertIn('helper', proof.stable_imports)
        negatives = (
            'helper = replacement', 'del helper', 'def shadow(helper): pass',
            'shadow = lambda helper: None', 'def scope():\n    global helper',
            'def scope():\n    nonlocal helper', '[None for helper in values]',
            '[(helper := replacement) for _ in values]',
            'try: pass\nexcept Exception as helper: pass',
            'match value:\n    case helper: pass', 'match value:\n    case [*helper]: pass',
            'match value:\n    case {**helper}: pass', 'if False:\n    helper = replacement',
            'from other import helper', 'from bridge import other as helper',
            'from .bridge import helper', 'from bridge import helper as helper',
            'from bridge import *', "globals()['helper'] = replacement",
        )
        for mutation in negatives:
            with self.subTest(mutation=mutation):
                changed = (source + mutation + '\n').encode()
                proof = FIT._queue_source_preparation('uniform.py', changed).callable_uses
                self.assertNotIn('helper', proof.stable_imports)

    def test_repeated_imports_preserve_returned_queue_carriers(self):
        operations = ('helper().enqueue(work)', 'consume([helper]).enqueue(work)',
                      'consume({"factory": helper}).enqueue(work)',
                      'selected, = (helper,)\nselected().enqueue(work)',
                      'def select(): return helper\nselect()().enqueue(work)')
        for governed, provider in ((False, 'def helper(): return None\n'),
                                   (True, 'from rq import Queue\ndef helper(): return Queue()\n')):
            for operation in operations:
                with self.subTest(governed=governed, operation=operation):
                    repo = GitArchitectureRepo(self)
                    repo.model(_system(), _rules())
                    repo.write_text('provider.py', provider)
                    base = repo.commit('ordinary or queue-bearing callable')
                    source = ('def first():\n    from provider import helper\n    helper()\n'
                              'def second():\n    from provider import helper\n    helper()\n'
                              'from provider import helper\ndef consume(items): return items\n' + operation + '\n')
                    repo.write_text('consumer.py', source)
                    head = repo.commit('repeated provider imports and returned carrier')
                    snapshot = ARCHITECTURE.load_architecture(repo.root)
                    diff = DIFF.diff_architecture(repo.root, base_sha=base, head_sha=head)
                    report = FIT.evaluate_fitness(repo.root, snapshot, diff, diff.changed_paths, pre_risk='green')
                    result = next(item for item in report.results if item.category == 'background_job')
                    self.assertEqual(result.status, 'unsupported' if governed else 'not_applicable')
                    self.assertEqual('new_queue' in report.triggers, governed)

    def test_scalar_source_preparation_clones_once_across_member_requests(self):
        source = b'def first(): return str(1)\ndef second(): return str(2)\n'
        FIT._queue_owned_export_slice.cache_clear()
        FIT._queue_source_preparation.cache_clear()
        FIT._queue_owned_scalar_source.cache_clear()
        owned = FIT._queue_source_preparation('scalar-once.py', source)
        with patch('copy.deepcopy', wraps=copy.deepcopy) as cloned:
            first = FIT._queue_owned_export_slice('scalar-once.py', source, frozenset({'first'}))
            second = FIT._queue_owned_export_slice('scalar-once.py', source, frozenset({'second'}))
        self.assertEqual(sum(call.args[0] is owned.tree for call in cloned.call_args_list), 1)
        self.assertEqual([node.name for node in first.body if isinstance(node, ast.FunctionDef)], ['first'])
        self.assertEqual([node.name for node in second.body if isinstance(node, ast.FunctionDef)], ['second'])
        changed = b'from rq import Queue\nstr = Queue\n' + source
        rebound = FIT._queue_owned_export_slice('scalar-once.py', changed, frozenset({'first'}))
        self.assertTrue(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'str'
                            for node in ast.walk(rebound)))
        caller = ast.parse(source)
        baseline = FIT._queue_export_slice(caller, frozenset({'first'}))
        self.assertFalse(any(isinstance(node, ast.Call) for node in ast.walk(baseline)))
        caller.body.insert(0, ast.parse('str = Queue\n').body[0])
        refreshed = FIT._queue_export_slice(caller, frozenset({'first'}))
        self.assertTrue(any(isinstance(node, ast.Call) for node in ast.walk(refreshed)))

    def test_owned_scalar_tree_stays_unchanged_across_slice_analysis_and_order(self):
        source = (b'from rq import Queue\ndef make(): return Queue()\n'
                  b'def ordinary(): return str(1)\n')
        results = []
        for order in (('make', 'ordinary'), ('ordinary', 'make')):
            FIT._queue_owned_export_slice.cache_clear()
            FIT._queue_owned_scalar_source.cache_clear()
            scalar = FIT._queue_owned_scalar_source('scalar-order.py', source)
            original = ast.dump(scalar, include_attributes=True)
            observed = {}
            for name in order:
                requested = frozenset({name})
                view = FIT._queue_owned_export_slice('scalar-order.py', source, requested)
                before = ast.dump(view, include_attributes=True)
                factories = FIT._queue_return_exports(view, frozenset())
                analyzed = analyze_queue_tree(view)
                FIT._queue_import_equivalent_tree(view)
                FIT._queue_export_slice(view, requested)
                self.assertEqual(ast.dump(view, include_attributes=True), before)
                self.assertEqual(ast.dump(scalar, include_attributes=True), original)
                observed[name] = (factories, analyzed.signals)
                self.assertIs(FIT._queue_owned_export_slice('scalar-order.py', source, requested), view)
            results.append(observed)
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0]['make'][0], {'make'})
        self.assertEqual(results[0]['ordinary'], (set(), ()))

    def test_unproved_callable_carriers_and_selections_retain_source_governance(self):
        consume = 'def consume(factory): return factory()\n'
        literal = "__import__('bridge', fromlist=['helper']).helper"
        variants = {
            'direct': consume + 'consume(bridge.helper).enqueue(work)',
            'list': 'def consume(items): return items[0]()\nconsume([bridge.helper]).enqueue(work)',
            'tuple': 'def consume(items): return items[0]()\nconsume((bridge.helper,)).enqueue(work)',
            'set': 'def consume(items): return items.pop()()\nconsume({bridge.helper}).enqueue(work)',
            'comprehension': 'def consume(items): return items[0]()\nconsume([bridge.helper for _ in (0,)]).enqueue(work)',
            'dict': 'def consume(items): return items["factory"]()\nconsume({"factory": bridge.helper}).enqueue(work)',
            'aliased-list': 'def consume(items): return items[0]()\nholder = [bridge.helper]\nconsume(holder).enqueue(work)',
            'starred': consume + 'consume(*(bridge.helper,)).enqueue(work)',
            'starred-keywords': consume + 'consume(**{"factory": bridge.helper}).enqueue(work)',
            'keyword-container': 'def consume(*, items): return items[0]()\nconsume(items=[bridge.helper]).enqueue(work)',
            'tuple-selection': consume + 'consume((bridge.helper,)[0]).enqueue(work)',
            'dict-selection': consume + 'consume({"selected": bridge.helper}["selected"]).enqueue(work)',
            'conditional': consume + 'consume(bridge.helper if enabled else bridge.helper).enqueue(work)',
            'unpacked': 'selected, = (bridge.helper,)\nselected().enqueue(work)',
            'nested-unpacked': '((selected,),) = ((bridge.helper,),)\nselected().enqueue(work)',
            'returned-member': 'def select(): return bridge.helper\nselect()().enqueue(work)',
            'returned-invocation': 'def select(): return bridge.helper()\nselect().enqueue(work)',
            'returned-invocation-alias': 'def select():\n    result = bridge.helper()\n    return result\nselect().enqueue(work)',
            'returned-literal': 'def select(): return ' + literal + '\nselect()().enqueue(work)',
            'lambda-returned-literal': 'select = lambda: ' + literal + '\nselect()().enqueue(work)',
            'nested-carrier': 'def consume(items): return items[0]["selected"][0]()\nconsume([{"selected": (bridge.helper,)}]).enqueue(work)',
            'nested-return': 'def select(): return [{"selected": bridge.helper}]\n'
                             'def consume(items): return items[0]["selected"]()\nconsume(select()).enqueue(work)',
            'generator-carrier': 'def consume(items): return next(items)()\nconsume(item for item in [bridge.helper]).enqueue(work)',
        }
        providers = ((True, 'from rq import Queue\ndef helper(): return Queue()\n'),
                     (False, 'class Ordinary:\n    def enqueue(self, work): return None\ndef helper(): return Ordinary()\n'))
        for governed, provider in providers:
            for label, operation in variants.items():
                with self.subTest(label=label, governed=governed):
                    repo = GitArchitectureRepo(self)
                    system = _system()
                    system['nodes'][0]['repository_paths'] = ['src']
                    repo.model(system, _rules())
                    repo.write_text('src/provider.py', provider)
                    repo.write_text('src/bridge.py', 'from provider import helper\n')
                    base = repo.commit('existing callable reexport')
                    repo.write_text('src/consumer.py', 'import bridge\n' + operation + '\n')
                    head = repo.commit('callable value use')
                    snapshot = ARCHITECTURE.load_architecture(repo.root)
                    diff = DIFF.diff_architecture(repo.root, base_sha=base, head_sha=head)
                    report = FIT.evaluate_fitness(repo.root, snapshot, diff, diff.changed_paths, pre_risk='green')
                    result = next(item for item in report.results if item.category == 'background_job')
                    self.assertEqual(result.status, 'unsupported' if governed else 'not_applicable')
                    self.assertEqual('new_queue' in report.triggers, governed)

    def test_complete_use_proof_rechecks_caller_mutation_and_source_byte_versions(self):
        original = b'import bridge\nbridge.helper()\n'
        changed = b'import bridge\nconsume([bridge.helper]).enqueue(work)\n'
        caller = ast.parse(original)
        first = FIT._callable_use_proof(caller, namespace_closed=True, patches={})
        self.assertIn('bridge.helper', first.identity)
        caller.body[:] = ast.parse(changed).body
        current = FIT._callable_use_proof(caller, namespace_closed=True, patches={})
        self.assertIn('bridge.helper', current.opaque)
        self.assertNotIn('bridge.helper', current.identity)
        self.assertIn('bridge.helper', first.identity)
        owned = FIT._queue_source_preparation('changed-use.py', original)
        refreshed = FIT._queue_source_preparation('changed-use.py', changed)
        self.assertIn('bridge.helper', owned.callable_uses.identity)
        self.assertIn('bridge.helper', refreshed.callable_uses.opaque)
        self.assertIsNot(owned, refreshed)

    def test_unproved_wildcard_callable_use_cannot_gain_identity_admission(self):
        for governed, provider in ((True, 'from rq import Queue\ndef helper(): return Queue()\n'),
                                   (False, 'def helper(): return None\n')):
            for operation in ('def consume(items): return items[0]()\nconsume([helper]).enqueue(work)',
                              'def select(): return helper\nselect()().enqueue(work)'):
                with self.subTest(governed=governed, operation=operation):
                    repo = GitArchitectureRepo(self)
                    repo.model(_system(), _rules())
                    repo.write_text('provider.py', provider)
                    repo.write_text('bridge.py', 'from provider import helper\n')
                    base = repo.commit('wildcard callable provider')
                    repo.write_text('consumer.py', 'from bridge import *\n' + operation + '\n')
                    head = repo.commit('wildcard value carrier')
                    snapshot = ARCHITECTURE.load_architecture(repo.root)
                    diff = DIFF.diff_architecture(repo.root, base_sha=base, head_sha=head)
                    report = FIT.evaluate_fitness(repo.root, snapshot, diff, diff.changed_paths, pre_risk='green')
                    result = next(item for item in report.results if item.category == 'background_job')
                    self.assertEqual(result.status, 'unsupported' if governed else 'not_applicable')
                    self.assertEqual('new_queue' in report.triggers, governed)

    def test_ordinary_callback_field_does_not_inherit_a_queue_sibling(self):
        repo = GitArchitectureRepo(self)
        repo.model(_system(), _rules())
        repo.write_text('provider.py', 'from rq import Queue\nclass Box: pass\nbox = Box()\n'
                        'box.queue = Queue()\nbox.ordinary = lambda: None\n')
        repo.write_text('bridge.py', 'from provider import box\n')
        base = repo.commit('separate ordinary and queue fields')
        repo.write_text('consumer.py', 'import bridge\ndef consume(items): return items[0]()\n'
                        'consume([bridge.box.ordinary]).enqueue(work)\n')
        head = repo.commit('ordinary callable field carrier')
        snapshot = ARCHITECTURE.load_architecture(repo.root)
        diff = DIFF.diff_architecture(repo.root, base_sha=base, head_sha=head)
        report = FIT.evaluate_fitness(repo.root, snapshot, diff, diff.changed_paths, pre_risk='green')
        result = next(item for item in report.results if item.category == 'background_job')
        self.assertEqual(result.status, 'not_applicable')
        self.assertNotIn('new_queue', report.triggers)

    def test_namespace_without_importer_never_expands_literal_import_proof(self):
        for source, closed in (("import adapter\nselected = getattr(adapter, 'ordinary')\n", True),
                               ('from builtins import __dict__ as namespace\n', False)):
            with self.subTest(source=source):
                with patch('getzilla.python_source_proof.literal_import_reads',
                           side_effect=AssertionError('absent importer proof expanded')):
                    self.assertEqual(FIT.namespace_is_closed(ast.parse(source), allow_instrumentation=True,
                                                            static_import_reads=True), closed)

    def test_absent_literal_importer_never_expands_binding_or_parent_inventory(self):
        with patch('getzilla.python_source_proof.binding_events',
                   side_effect=AssertionError('absent importer binding inventory expanded')):
            self.assertEqual(FIT.literal_import_reads(ast.parse('def ordinary(): return 1\n')), {})

    def test_one_importer_analysis_prepares_namespace_proof_once_for_all_module_aliases(self):
        repo = GitArchitectureRepo(self)
        repo.model(_system(), _rules())
        repo.write_text('left.py', 'def ordinary(): return None\n')
        repo.write_text('right.py', 'def ordinary(): return None\n')
        base = repo.commit('ordinary modules')
        source = 'import left\nimport right\nleft.ordinary()\nright.ordinary()\n'
        repo.write_text('consumer.py', source)
        head = repo.commit('ordinary alias consumers')
        diff = DIFF.diff_architecture(repo.root, base_sha=base, head_sha=head)
        tree = ast.parse(source)
        cache = FIT._queue_module_inventory(repo.root, diff, 'head', ('',))
        with patch.object(FIT, 'namespace_is_closed', wraps=FIT.namespace_is_closed) as proof:
            result = FIT._queue_adapter_names(repo.root, diff, tree, 'head', cache, source_roots=('',))
        self.assertEqual(result.names, frozenset())
        self.assertEqual(sum(call.args[0] is tree for call in proof.call_args_list), 1)

    def test_exact_source_preparation_shares_proof_across_member_requests(self):
        for namespace_prefix in ('', "marker = '__dict__'\n"):
            with self.subTest(namespace_prefix=namespace_prefix):
                repo = GitArchitectureRepo(self)
                repo.model(_system(), _rules())
                provider = namespace_prefix + 'def first(): return None\ndef second(): return None\n'
                repo.write_text('library.py', provider)
                base = repo.commit('stable or full-fallback source')
                source = 'import library\nlibrary.first()\nlibrary.second()\n'
                repo.write_text('consumer.py', source)
                head = repo.commit('two source member demands')
                diff = DIFF.diff_architecture(repo.root, base_sha=base, head_sha=head)
                cache = FIT._queue_module_inventory(repo.root, diff, 'head', ('',))
                declaration = FIT._queue_source_tree('library.py', provider.encode())
                FIT._queue_source_preparation.cache_clear()
                with patch.object(FIT, 'namespace_is_closed', wraps=FIT.namespace_is_closed) as proof:
                    result = FIT._queue_adapter_names(repo.root, diff, ast.parse(source), 'head', cache, source_roots=('',))
                self.assertEqual(result.names, frozenset())
                self.assertEqual(sum(call.args[0] is declaration for call in proof.call_args_list), 1)

    def test_comprehension_walrus_rebinding_after_guards_retains_queue_signals(self):
        for expression in ("[(chunk := work) for _ in (0,)]",
                           "{(chunk := work) for _ in (0,)}",
                           "{0: (chunk := work) for _ in (0,)}",
                           "tuple((chunk := work) for _ in (0,))",
                           "[[(chunk := work) for _ in (0,)] for _ in (0,)]"):
            source = PIPE_CHANNEL.replace('        chunks.put(chunk, timeout=0.05)',
                                          '        ' + expression + '\n        chunks.put(chunk, timeout=0.05)')
            self.assert_governed(source, expression)

    def test_ordinary_comprehension_and_lambda_bindings_leave_guarded_payload_stable(self):
        for expression in ('[chunk for chunk in (0,)]', '(lambda chunk: chunk)(0)',
                           '(lambda: [(chunk := 0) for _ in (0,)])()'):
            with self.subTest(expression=expression):
                source = PIPE_CHANNEL.replace('        chunks.put(chunk, timeout=0.05)',
                                              '        ' + expression + '\n        chunks.put(chunk, timeout=0.05)')
                self.assertEqual(analyze_queue_tree(ast.parse(source)).signals, ())

    def test_literal_import_reads_keep_local_reexport_provenance(self):
        providers = (
            ('object', 'from rq import Queue\nhelper = Queue()\n', 'helper.enqueue(work)', True),
            ('factory', 'from rq import Queue\ndef helper(): return Queue()\n', 'helper().enqueue(work)', True),
            ('ordinary', 'def helper(): return None\n', 'helper()', False),
        )
        for label, provider, operation, governed in providers:
            literal = "__import__('bridge', fromlist=['helper']).helper"
            for imported, action in (('from bridge import helper', operation),
                                     ('helper = ' + literal, operation),
                                     ('import bridge\nhelper = bridge.helper', operation),
                                     ('', operation.replace('helper', literal))):
                with self.subTest(provider=label, imported=imported):
                    repo = GitArchitectureRepo(self)
                    system = _system()
                    system['nodes'][0]['repository_paths'] = ['src']
                    repo.model(system, _rules())
                    repo.write_text('src/adapter.py', 'from rq import Queue\njobs = Queue()\ndef ordinary(): return None\n')
                    repo.write_text('src/provider.py', provider)
                    repo.write_text('src/bridge.py', 'from provider import helper\n')
                    base = repo.commit('local member reexports')
                    repo.write_text('src/consumer.py', 'import adapter\n' + imported + '\n' + action
                                    + "\nselected = getattr(adapter, 'ordinary', None)\nselected()\n")
                    head = repo.commit('literal or ordinary import consumer')
                    snapshot = ARCHITECTURE.load_architecture(repo.root)
                    diff = DIFF.diff_architecture(repo.root, base_sha=base, head_sha=head)
                    report = FIT.evaluate_fitness(repo.root, snapshot, diff, diff.changed_paths, pre_risk='green')
                    result = next(item for item in report.results if item.category == 'background_job')
                    self.assertEqual(result.status, 'unsupported' if governed else 'not_applicable')
                    self.assertEqual('new_queue' in report.triggers, governed)

    def test_owned_preparation_binds_each_source_version_and_caller_wrappers_stay_fresh(self):
        original = b'def helper(): return None\n'
        first = FIT._queue_source_preparation('versioned.py', original)
        self.assertTrue(first.namespace_closed)
        self.assertIn('helper', first.plain_callables)
        self.assertIs(FIT._queue_source_preparation('versioned.py', original), first)
        changed = FIT._queue_source_preparation('versioned.py', b'from builtins import __dict__\n' + original)
        self.assertFalse(changed.namespace_closed)
        self.assertEqual(changed.plain_callables, frozenset())
        rebound = FIT._queue_source_preparation('versioned.py', original + b'helper = replacement\n')
        self.assertNotIn('helper', rebound.plain_callables)
        caller = ast.parse(original)
        self.assertTrue(FIT._plain_callable_declaration(caller, frozenset({'helper'})))
        caller.body.extend(ast.parse(binding_statement('helper', 'except')).body)
        self.assertFalse(FIT._plain_callable_declaration(caller, frozenset({'helper'})))

    def test_reexport_demands_distinguish_callable_identity_from_queue_returns_and_escapes(self):
        factory = 'from rq import Queue\ndef helper(): return Queue()\n'
        for label, provider, operation, governed in (
                ('ordinary-call', 'def helper(): return None\n', 'bridge.helper()', False),
                ('ordinary-higher-order', 'def helper(): return None\n',
                 'def consume(factory): return factory()\nconsume(bridge.helper).ordinary()', False),
                ('queue-return', factory, 'bridge.helper().enqueue(work)', True),
                ('alias-return', factory, 'selected = bridge.helper\nselected().enqueue(work)', True),
                ('higher-order', factory, 'def consume(factory): return factory()\nconsume(bridge.helper).enqueue(work)', True),
                ('escaped-callback', factory, 'export(bridge.helper).enqueue(work)', True)):
            with self.subTest(label=label):
                repo = GitArchitectureRepo(self)
                repo.model(_system(), _rules())
                repo.write_text('provider.py', provider)
                repo.write_text('bridge.py', 'from provider import helper\n')
                base = repo.commit('callable reexport')
                source = 'import bridge\n' + operation + '\n'
                repo.write_text('consumer.py', source)
                head = repo.commit('callable or returned queue demand')
                diff = DIFF.diff_architecture(repo.root, base_sha=base, head_sha=head)
                cache = FIT._queue_module_inventory(repo.root, diff, 'head', ('',))
                with patch.object(FIT, '_local_queue_resolution_impl', wraps=FIT._local_queue_resolution_impl) as resolution:
                    if label in ('higher-order', 'escaped-callback'):
                        with self.assertRaises(ARCHITECTURE.ArchitectureError) as caught:
                            FIT._queue_signals(repo.root, diff, ast.parse(source), 'head', cache, '', ('',),
                                               source_path='consumer.py', source=source.encode())
                        self.assertEqual(caught.exception.code, 'fitness')
                        self.assertIn('queue-bearing callback return', str(caught.exception))
                    else:
                        result = FIT._queue_signals(repo.root, diff, ast.parse(source), 'head', cache, '', ('',),
                                                   source_path='consumer.py', source=source.encode())
                        self.assertEqual(bool(result.signals), governed)
                provider_calls = [call for call in resolution.call_args_list if call.args[2] == 'provider']
                self.assertTrue(provider_calls)
                self.assertTrue(all(call.args[9] is (label == 'ordinary-call') for call in provider_calls))
                if label in ('higher-order', 'escaped-callback'):
                    snapshot = ARCHITECTURE.load_architecture(repo.root)
                    report = FIT.evaluate_fitness(repo.root, snapshot, diff, diff.changed_paths, pre_risk='green')
                    result = next(item for item in report.results if item.category == 'background_job')
                    self.assertEqual(result.status, 'unsupported')
                    self.assertIn('new_queue', report.triggers)

    def test_import_normalization_is_analysis_only_and_cannot_capture_source_names(self):
        source = ("__getzilla_literal_import_0 = original\n"
                  "helper = __import__('bridge', fromlist=['helper']).helper\nhelper.enqueue(work)\n")
        tree = ast.parse(source)
        original = ast.dump(tree, include_attributes=True)
        projected = FIT._queue_import_equivalent_tree(tree)
        self.assertEqual(ast.dump(tree, include_attributes=True), original)
        self.assertIsNot(projected, tree)
        imports = [node for node in projected.body if isinstance(node, ast.ImportFrom)]
        self.assertEqual(len(imports), 1)
        self.assertEqual((imports[0].module, imports[0].names[0].name), ('bridge', 'helper'))
        self.assertNotEqual(imports[0].names[0].asname, '__getzilla_literal_import_0')
        self.assertFalse(any(isinstance(node, ast.Name) and node.id == '__import__' for node in ast.walk(projected)))
        self.assertIs(FIT._queue_import_equivalent_tree(projected), projected)

    def test_import_normalization_rechecks_mutated_caller_ast(self):
        for replacement in ('module', 'assignment', 'except', 'as', 'star', 'mapping'):
            with self.subTest(replacement=replacement):
                tree = ast.parse("helper = __import__('bridge', fromlist=['helper']).helper\n")
                self.assertIsNot(FIT._queue_import_equivalent_tree(tree), tree)
                if replacement == 'module':
                    tree.body[0].value.value.args[0] = ast.Constant(value='rq')
                else:
                    statement = ('__import__ = replacement' if replacement == 'assignment'
                                 else binding_statement('__import__', replacement))
                    tree.body.extend(ast.parse(statement).body)
                self.assertIs(FIT._queue_import_equivalent_tree(tree), tree)

    def test_simple_literal_assignment_normalizes_in_its_original_scope_and_order(self):
        source = ("import adapter\nclass Fixture:\n    def prepare(self):\n        before()\n"
                  "        selected = __import__('bridge', fromlist=['helper']).helper\n        return selected\n")
        tree = ast.parse(source)
        original = ast.dump(tree, include_attributes=True)
        projected = FIT._queue_import_equivalent_tree(tree)
        self.assertEqual(ast.dump(tree, include_attributes=True), original)
        self.assertEqual(len(projected.body), 2)
        self.assertIsInstance(projected.body[0], ast.Import)
        statements = projected.body[1].body[0].body
        self.assertIsInstance(statements[0], ast.Expr)
        imported = statements[1]
        self.assertIsInstance(imported, ast.ImportFrom)
        self.assertEqual((imported.module, imported.names[0].name, imported.names[0].asname),
                         ('bridge', 'helper', 'selected'))

    def test_string_field_bindings_keep_all_channel_dependencies_governed(self):
        for kind in ('except', 'as', 'star', 'mapping'):
            for name in ('type', 'bytes', 'len', 'OSError', 'Queue', 'Thread', 'CHUNK_BYTES'):
                source = PIPE_CHANNEL.replace('def drain(runner):', binding_statement(name, kind) + '\ndef drain(runner):')
                self.assert_governed(source, (name, kind))
            for name, marker, indentation in (
                    ('chunk', '        chunks.put(chunk, timeout=0.05)', 8),
                    ('chunks', '    def read():', 4),
                    ('read', '    reader = Thread(target=read)', 4),
                    ('reader', '    reader.start()', 4)):
                source = PIPE_CHANNEL.replace(marker, textwrap.indent(binding_statement(name, kind), ' ' * indentation) + '\n' + marker)
                self.assert_governed(source, (name, kind))

    def assert_governed(self, source, label):
        with self.subTest(label=label):
            tree = ast.parse(source)
            original = ast.dump(tree, include_attributes=True)
            self.assertTrue(analyze_queue_tree(tree).signals)
            self.assertEqual(ast.dump(tree, include_attributes=True), original)

    def test_getter_bindings_and_namespace_capabilities_retain_full_closure(self):
        prefixes = [binding_statement('getattr', kind) for kind in ('except', 'as', 'star', 'mapping')]
        for prefix in [*prefixes, *NAMESPACE_CAPABILITIES]:
            with self.subTest(prefix=prefix):
                tree = ast.parse('import adapter\n' + prefix + "\nselected = getattr(adapter, 'ordinary', None)\nselected()\n")
                self.assertIsNone(FIT._module_member_demands(tree, 'adapter'))

    def test_namespace_capabilities_never_prove_local_byte_payloads(self):
        for prefix in NAMESPACE_CAPABILITIES:
            self.assert_governed(prefix + '\n' + PIPE_CHANNEL, prefix)

    def test_plain_mock_imports_keep_real_consumer_literal_member_demand(self):
        source = ("import unittest\nfrom unittest.mock import patch\nimport verification_module\n"
                  "selector = getattr(verification_module, 'select_static_seo_landing_scope', None)\nselector()\n")
        self.assertEqual(FIT._module_member_demands(ast.parse(source), 'verification_module'),
                         frozenset({'select_static_seo_landing_scope'}))

    def test_actual_verification_consumer_keeps_ordinary_literal_member_demand(self):
        content = (ROOT / 'tests/test_verification_doctor.py').read_text(encoding='utf-8')
        demanded = FIT._module_member_demands(ast.parse(content), 'verification_module')
        self.assertIsNotNone(demanded)
        self.assertIn('select_static_seo_landing_scope', demanded)

    def test_patch_alias_string_field_rebinding_retains_full_member_closure(self):
        for kind in ('except', 'as', 'star', 'mapping'):
            with self.subTest(kind=kind):
                source = ('from unittest.mock import patch\nimport adapter\n'
                          + binding_statement('patch', kind) + "\npatch.object(adapter, 'ordinary')\n")
                self.assertIsNone(FIT._module_member_demands(ast.parse(source), 'adapter'))

    def test_source_bound_fitness_keeps_unknown_getters_governed(self):
        lookup = "selected = getattr(adapter, 'ordinary', None)\nselected()\n"
        variants = (
            ('ordinary', 'import unittest\nfrom unittest.mock import patch\n' + lookup, False),
            ('ordinary-import', "real_check = __import__('ordinary', fromlist=['helper']).helper\n" + lookup, False),
            ('external-queue-import', "real_check = __import__('rq', fromlist=['Queue']).Queue\n" + lookup, True),
            ('exception', 'class Lookup(Exception):\n    def __call__(self, module, name, default=None): return module.jobs\n'
             'try:\n    raise Lookup()\nexcept Lookup as getattr:\n' + textwrap.indent(lookup, '    '), True),
            ('capture', binding_statement('getattr', 'as') + '\n' + lookup, True),
            ('namespace', "from builtins import __dict__ as namespace\nnamespace.update({'getattr': replacement})\n" + lookup, True),
            ('dunder-setter', "import builtins\nbuiltins.__setattr__('getattr', replacement)\n" + lookup, True),
        )
        for label, source, governed in variants:
            with self.subTest(label=label):
                repo = GitArchitectureRepo(self)
                system = _system()
                system['nodes'][0]['repository_paths'] = ['src']
                repo.model(system, _rules())
                repo.write_text('src/adapter.py', 'from rq import Queue\njobs = Queue()\ndef ordinary(): return None\n')
                base = repo.commit('queue-bearing adapter')
                repo.write_text('src/consumer.py', 'import adapter\n' + source)
                head = repo.commit('getter source')
                snapshot = ARCHITECTURE.load_architecture(repo.root)
                diff = DIFF.diff_architecture(repo.root, base_sha=base, head_sha=head)
                report = FIT.evaluate_fitness(repo.root, snapshot, diff, diff.changed_paths, pre_risk='green')
                result = next(item for item in report.results if item.category == 'background_job')
                self.assertEqual(result.status, 'unsupported' if governed else 'not_applicable')
                self.assertEqual('new_queue' in report.triggers, governed)

    def test_static_import_equivalent_read_preserves_ordinary_getter_demand(self):
        for imported in ("__import__('ordinary', fromlist=['helper']).helper",
                         "__import__('ordinary.module', fromlist=('helper',), level=0).helper"):
            with self.subTest(imported=imported):
                source = ('import adapter\nreal_check = ' + imported
                          + "\nselected = getattr(adapter, 'ordinary', None)\nselected()\n")
                self.assertEqual(FIT._module_member_demands(ast.parse(source), 'adapter'), frozenset({'ordinary'}))

    def test_dynamic_namespace_shadowed_and_escaped_importers_keep_full_closure(self):
        imports = [f"__import__('{module}', fromlist=['helper']).helper"
                   for module in ('builtins', 'sys', 'importlib', 'queue', 'threading', 'rq')]
        imports.extend((
            "__import__(module, fromlist=['helper']).helper",
            "__import__('ordinary', fromlist=members).helper",
            "__import__('ordinary', fromlist=['different']).helper",
            "__import__('ordinary', fromlist=['__dict__']).__dict__",
            "__import__('ordinary', fromlist=['setattr']).setattr",
            "__import__('ordinary', fromlist=['eval']).eval",
            "__import__('ordinary.class', fromlist=['helper']).helper",
            "__import__('ordinary', fromlist=['helper'], level=1).helper",
            "__import__('ordinary', fromlist=['helper'], extra=True).helper",
            "__import__(*arguments).helper",
            "__import__('ordinary', **options).helper",
            "__import__('ordinary', fromlist=['helper'])",
            "__import__('ordinary', fromlist=['helper']).helper.namespace",
        ))
        prefixes = ['value = ' + imported for imported in imports]
        prefixes.append('loader = __import__')
        prefixes.extend(binding_statement('__import__', kind)
                        + "\nvalue = __import__('ordinary', fromlist=['helper']).helper"
                        for kind in ('except', 'as', 'star', 'mapping'))
        for prefix in prefixes:
            with self.subTest(prefix=prefix):
                source = 'import adapter\n' + prefix + "\nselected = getattr(adapter, 'ordinary')\nselected()\n"
                self.assertIsNone(FIT._module_member_demands(ast.parse(source), 'adapter'))


class LocalByteChannelTests(unittest.TestCase):
    def test_bounded_non_escaping_bytes_are_not_a_background_job(self):
        result = analyze_queue_tree(ast.parse(LOCAL_CHANNEL))
        self.assertEqual(result.signals, ())
        self.assertFalse(result.uncertain)

    def test_dictionary_and_list_work_does_not_acquire_queue_provenance(self):
        source = LOCAL_CHANNEL + '''
def metadata():
    data = {}
    data.setdefault('count', 0)
    rows = []
    rows.append(data.get('count'))
    return rows
'''
        result = analyze_queue_tree(ast.parse(source))
        self.assertEqual(result.signals, ())
        self.assertFalse(result.uncertain)

    def test_bounded_pipe_reader_and_local_thread_keep_annotations_as_data(self):
        result = analyze_queue_tree(ast.parse(PIPE_CHANNEL))
        self.assertEqual(result.signals, ())

    def test_instrumentation_capability_keeps_byte_channel_projection_closed(self):
        source = '''
from queue import Queue
from unittest.mock import patch
class Payload:
    def __len__(self): return 1
    def __call__(self): return 'work'
def local(reader):
    chunks = Queue(maxsize=2)
    chunk = reader.read(32)
    if type(chunk) is not bytes:
        raise OSError('not bytes')
    if len(chunk) > 32:
        raise OSError('too large')
    chunks.put(chunk, timeout=.05)
    return chunks.get(timeout=.05)()
with patch('builtins.bytes', Payload):
    local(reader)
'''
        for imported in ('from unittest.mock import patch', 'from unittest import mock',
                         'import unittest', 'import unittest.mock', 'import mock',
                         'import pytest', 'from pytest import MonkeyPatch', 'import _pytest'):
            with self.subTest(imported=imported):
                candidate = source.replace('from unittest.mock import patch', imported)
                self.assertTrue(analyze_queue_tree(ast.parse(candidate)).signals)

    def test_actual_parallel_byte_capture_remains_local(self):
        source = (ROOT / '.getzilla/getzilla/parallel.py').read_text(encoding='utf-8')
        result = analyze_queue_tree(ast.parse(source))
        self.assertEqual(result.signals, ())
        self.assertFalse(result.uncertain)

    def test_unguarded_unknown_reader_and_incomplete_or_shadowed_guards_stay_governed(self):
        type_guard = "        if type(chunk) is not bytes:\n            raise OSError('non-byte payload')\n"
        size_guard = "        if len(chunk) > CHUNK_BYTES:\n            raise OSError('payload exceeds bound')\n"
        variants = [
            PIPE_CHANNEL.replace(type_guard + size_guard, ''),
            PIPE_CHANNEL.replace(type_guard, ''),
            PIPE_CHANNEL.replace(size_guard, ''),
            PIPE_CHANNEL.replace(type_guard + size_guard, size_guard + type_guard),
            PIPE_CHANNEL.replace('        chunks.put(chunk, timeout=0.05)',
                                 '        chunks.put(chunk, timeout=0.05)\n' + type_guard + size_guard).replace(type_guard + size_guard, '', 1),
            PIPE_CHANNEL.replace("raise OSError('non-byte payload')", 'pass'),
            PIPE_CHANNEL.replace('if type(chunk) is not bytes:', 'if isinstance(chunk, bytes):'),
            PIPE_CHANNEL.replace('def drain(runner):', 'def drain(runner, type):'),
            PIPE_CHANNEL.replace('def drain(runner):', 'def drain(runner, bytes):'),
            PIPE_CHANNEL.replace('def drain(runner):', 'def drain(runner, len):'),
            PIPE_CHANNEL.replace('def drain(runner):', 'def drain(runner, OSError):'),
            PIPE_CHANNEL.replace('def drain(runner):', 'from opaque import bytes\ndef drain(runner):'),
            PIPE_CHANNEL.replace('def drain(runner):', 'Thread.start = opaque\ndef drain(runner):'),
            PIPE_CHANNEL.replace('def drain(runner):', "Thread.__dict__['start'] = opaque\ndef drain(runner):"),
            PIPE_CHANNEL.replace('def drain(runner):', "import sys\nsys.modules['threading'] = opaque\ndef drain(runner):"),
            PIPE_CHANNEL.replace('def drain(runner):', 'publish(Thread)\ndef drain(runner):'),
            PIPE_CHANNEL.replace('def drain(runner):', 'import threading\nthreading.Thread.start = opaque\ndef drain(runner):'),
            PIPE_CHANNEL.replace('def drain(runner):', 'import threading\npublish(threading.Thread)\ndef drain(runner):'),
            PIPE_CHANNEL.replace('def drain(runner):', 'from opaque import *\ndef drain(runner):'),
            PIPE_CHANNEL.replace('def drain(runner):', "from sys import modules as loaded\nloaded['threading'].Thread = opaque\ndef drain(runner):"),
            PIPE_CHANNEL.replace('def drain(runner):', 'import builtins\nbuiltins.bytes = opaque\ndef drain(runner):'),
            PIPE_CHANNEL.replace('def drain(runner):', "__import__('threading').Thread.start = opaque\ndef drain(runner):"),
            PIPE_CHANNEL.replace('def drain(runner):', "from importlib import import_module as load\nload('threading').Thread.start = opaque\ndef drain(runner):"),
        ]
        for source in variants:
            with self.subTest(source=source):
                self.assertTrue(analyze_queue_tree(ast.parse(source)).signals)

    def test_exported_expression_and_producer_wrappers_cannot_capture_channel(self):
        variants = (
            LOCAL_CHANNEL.replace('return len(chunks.get(timeout=0.05))',
                                  'return lambda: chunks.get(timeout=0.05)'),
            LOCAL_CHANNEL.replace('return len(chunks.get(timeout=0.05))',
                                  'return (chunks.get(timeout=0.05) for _ in range(1))'),
            LOCAL_CHANNEL.replace('read()\n    return len(chunks.get(timeout=0.05))',
                                  'return lambda: read()'),
            LOCAL_CHANNEL.replace('read()\n    return len(chunks.get(timeout=0.05))',
                                  'def leaked():\n        read()\n    return leaked'),
            ('from threading import Thread\n' + LOCAL_CHANNEL).replace(
                'read()\n    return len(chunks.get(timeout=0.05))',
                'def leaked():\n        reader = Thread(target=read)\n        reader.start()\n    return leaked'),
            ('from threading import Thread\n' + LOCAL_CHANNEL).replace(
                'read()\n    return len(chunks.get(timeout=0.05))',
                'reader = Thread(target=read)\n    return lambda: reader.start()'),
            ('from threading import Thread\n' + LOCAL_CHANNEL).replace(
                'read()\n    return len(chunks.get(timeout=0.05))',
                'reader = Thread(target=read)\n    def leaked():\n        reader.start()\n    return leaked'),
        )
        for source in variants:
            with self.subTest(source=source):
                self.assertTrue(analyze_queue_tree(ast.parse(source)).signals)

    def test_unbounded_escaping_callable_and_external_queues_remain_governed(self):
        variants = (
            LOCAL_CHANNEL.replace('maxsize=2', 'maxsize=0'),
            LOCAL_CHANNEL.replace('maxsize=2', 'maxsize=limit'),
            LOCAL_CHANNEL.replace('return len(chunks.get(timeout=0.05))', 'return chunks'),
            LOCAL_CHANNEL.replace("b'bytes'", 'work'),
            LOCAL_CHANNEL.replace('read()\n    return', 'publish(chunks)\n    read()\n    return'),
            LOCAL_CHANNEL.replace('read()\n    return', 'publish(read)\n    read()\n    return'),
            LOCAL_CHANNEL + '\nfrom rq import Queue as Jobs\njobs = Jobs()\njobs.enqueue(work)\n',
            LOCAL_CHANNEL.replace('def drain():', 'from rq import Queue\ndef drain():'),
            LOCAL_CHANNEL.replace('def drain():', 'from client import Queue\ndef drain():'),
            LOCAL_CHANNEL.replace('def drain():', 'def Queue(**kwargs): return external\ndef drain():'),
            ('from threading import Thread\n' + LOCAL_CHANNEL).replace(
                'read()\n    return len(chunks.get(timeout=0.05))', 'return Thread(target=read)'),
            ('from threading import Thread\n' + LOCAL_CHANNEL).replace(
                'read()\n    return len(chunks.get(timeout=0.05))',
                'global reader\n    reader = Thread(target=read)\n    reader.start()\n    return len(chunks.get(timeout=0.05))'),
            LOCAL_CHANNEL.replace('    chunks =', '    global read\n    chunks ='),
        )
        for source in variants:
            with self.subTest(source=source):
                self.assertTrue(analyze_queue_tree(ast.parse(source)).signals)

    def test_pipe_bounds_and_payload_bindings_cannot_be_replaced(self):
        source = PIPE_CHANNEL
        variants = (
            source.replace('    process =', '    CHUNK_BYTES = unknown\n    process ='),
            source.replace('        chunks.put', '        chunk: object = work\n        chunks.put'),
            source.replace('CHUNK_BYTES = 65536', 'CHUNK_BYTES = 65536\nCHUNK_BYTES: int = unknown'),
        )
        for candidate in variants:
            with self.subTest(source=candidate):
                self.assertTrue(analyze_queue_tree(ast.parse(candidate)).signals)

    def test_fitness_accepts_channel_but_keeps_external_dispatch_required(self):
        for external in (False, True):
            with self.subTest(external=external):
                repo = GitArchitectureRepo(self)
                system = _system()
                system['nodes'][0]['repository_paths'] = ['src']
                repo.model(system, _rules())
                base = repo.commit('base')
                source = LOCAL_CHANNEL
                if external:
                    source += '\nfrom rq import Queue as Jobs\nJobs().enqueue(work)\n'
                repo.write_text('src/channel.py', source)
                head = repo.commit('channel')
                snapshot = ARCHITECTURE.load_architecture(repo.root)
                diff = DIFF.diff_architecture(repo.root, base_sha=base, head_sha=head)
                report = FIT.evaluate_fitness(repo.root, snapshot, diff, diff.changed_paths, pre_risk='green')
                result = next(item for item in report.results if item.category == 'background_job')
                self.assertEqual(result.status, 'unsupported' if external else 'not_applicable')
                self.assertEqual('new_queue' in report.triggers, external)

    def test_repository_module_cannot_impersonate_the_stdlib_queue(self):
        repo = GitArchitectureRepo(self)
        system = _system()
        system['nodes'][0]['repository_paths'] = ['src']
        repo.model(system, _rules())
        repo.write_text('src/queue.py', 'from rq import Queue, Queue as Empty, Queue as Full\n')
        base = repo.commit('local queue adapter')
        repo.write_text('src/channel.py', LOCAL_CHANNEL)
        head = repo.commit('claimed local channel')
        snapshot = ARCHITECTURE.load_architecture(repo.root)
        diff = DIFF.diff_architecture(repo.root, base_sha=base, head_sha=head)
        report = FIT.evaluate_fitness(repo.root, snapshot, diff, diff.changed_paths, pre_risk='green')
        result = next(item for item in report.results if item.category == 'background_job')
        self.assertEqual(result.status, 'unsupported')

    def test_repository_threading_module_cannot_impersonate_local_execution(self):
        repo = GitArchitectureRepo(self)
        system = _system()
        system['nodes'][0]['repository_paths'] = ['src']
        repo.model(system, _rules())
        repo.write_text('src/threading.py', 'from rq import Queue as Thread\n')
        base = repo.commit('local threading adapter')
        repo.write_text('src/channel.py', PIPE_CHANNEL)
        head = repo.commit('claimed local thread')
        snapshot = ARCHITECTURE.load_architecture(repo.root)
        diff = DIFF.diff_architecture(repo.root, base_sha=base, head_sha=head)
        report = FIT.evaluate_fitness(repo.root, snapshot, diff, diff.changed_paths, pre_risk='green')
        result = next(item for item in report.results if item.category == 'background_job')
        self.assertEqual(result.status, 'unsupported')


class LiteralModuleMemberTests(unittest.TestCase):
    def test_literal_getattr_demands_only_the_selected_member(self):
        tree = ast.parse("import adapter\nselected = getattr(adapter, 'ordinary', None)\nselected()\n")
        self.assertEqual(FIT._module_member_demands(tree, 'adapter'), frozenset({'ordinary'}))

    def test_dynamic_escaping_and_shadowed_getters_keep_full_closure(self):
        variants = (
            "selected = getattr(adapter, member)\nselected()",
            "publish(adapter)",
            "getattr = opaque\nselected = getattr(adapter, 'ordinary')\nselected()",
            "from provider import getattr\nselected = getattr(adapter, 'ordinary')\nselected()",
            "def probe(getattr):\n    return getattr(adapter, 'ordinary')",
        )
        for source in variants:
            with self.subTest(source=source):
                self.assertIsNone(FIT._module_member_demands(ast.parse('import adapter\n' + source), 'adapter'))

    def test_literal_queue_member_remains_governed_without_unrelated_import_closure(self):
        for member in ('ordinary', 'jobs'):
            with self.subTest(member=member):
                repo = GitArchitectureRepo(self)
                system = _system()
                system['nodes'][0]['repository_paths'] = ['src']
                repo.model(system, _rules())
                for index in range(FIT.MAX_QUEUE_ADAPTER_MODULES + 1):
                    repo.write_text(f'src/noise{index}.py', 'def unrelated():\n    return None\n')
                imports = ''.join(f'from noise{index} import unrelated as other{index}\n' for index in range(FIT.MAX_QUEUE_ADAPTER_MODULES + 1))
                repo.write_text('src/adapter.py', imports + 'from rq import Queue\njobs = Queue()\ndef ordinary():\n    return None\n')
                base = repo.commit('unchanged wide module')
                repo.write_text('src/consumer.py', f"import adapter\nselected = getattr(adapter, '{member}', None)\nselected()\n")
                head = repo.commit('literal member consumer')
                snapshot = ARCHITECTURE.load_architecture(repo.root)
                diff = DIFF.diff_architecture(repo.root, base_sha=base, head_sha=head)
                report = FIT.evaluate_fitness(repo.root, snapshot, diff, diff.changed_paths, pre_risk='green')
                result = next(item for item in report.results if item.category == 'background_job')
                self.assertEqual(result.status, 'not_applicable' if member == 'ordinary' else 'unsupported')
                if member == 'jobs':
                    self.assertNotIn('analysis_limit_exceeded', str(result))
