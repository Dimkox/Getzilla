"""Bounded local byte channels and precise adapter member demands."""
from __future__ import annotations

import ast
import sys
import textwrap
import unittest
from pathlib import Path

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
