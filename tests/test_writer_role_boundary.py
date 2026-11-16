"""NEW bounded role parsing controls; no lifecycle or policy engine executes."""
import ast
import builtins
from collections.abc import Callable  # noqa: F401 - preload before the I/O deny window
from contextlib import ExitStack
import io
import os
from pathlib import Path
import socket
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / '.getzilla/getzilla/writer_roles.py'
SOURCE = PATH.read_bytes() if PATH.exists() else None
LEGACY = ast.parse((ROOT / '.getzilla/getzilla/_policy_legacy.py').read_bytes())
LIFECYCLE = ast.parse((ROOT / '.getzilla/getzilla/agent_lifecycle.py').read_bytes())
EXPECTED = {'general_implementer', 'php_implementer', 'bitrix_implementer', 'frontend_implementer',
            'integration_implementer', 'data_implementer', 'ai_implementer'}


class WriterRoleBoundaryTests(unittest.TestCase):
    def setUp(self):
        guard = ExitStack()
        self.addCleanup(guard.close)
        def deny(*args, **kwargs):
            raise AssertionError('owned role control denies undeclared I/O/process/network')
        for module, name in ((builtins, 'open'), (io, 'open'), (os, 'open'),
                             (os, 'stat'), (os, 'lstat'), (os, 'scandir'), (os, 'listdir'),
                             (subprocess, 'Popen'), (os, 'system'), (socket, 'socket')):
            guard.enter_context(patch.object(module, name, side_effect=deny))

    def module(self):
        self.assertIsNotNone(SOURCE, 'writer-role parsing still lives in the full policy engine')
        tree = ast.parse(SOURCE)
        imports = [node for node in tree.body if isinstance(node, ast.ImportFrom) and node.level]
        self.assertEqual([(v.module, [n.name for n in v.names]) for v in imports], [('util', ['load_json'])])
        tree.body = [node for node in tree.body if node not in imports]
        def outside_read(*args, **kwargs):
            raise AssertionError('role adapter requires an explicitly declared fixture reader')
        namespace = {'load_json': outside_read}
        exec(compile(tree, '<owned-writer-roles>', 'exec'), namespace)
        return namespace

    def test_lifecycle_uses_the_role_leaf_without_importing_policy(self):
        imports = [node.module for node in ast.walk(LIFECYCLE) if isinstance(node, ast.ImportFrom)]
        self.assertIn('writer_roles', imports)
        self.assertNotIn('policy', imports)

    def test_configured_roles_filter_nonstrings_and_trim_without_default_union(self):
        module = self.module()
        actual = module['parse_write_roles']({'write_roles': [' custom_writer ', '', ' ', 1, None, 'custom_writer']})
        self.assertEqual(actual, {'custom_writer'})

    def test_invalid_or_empty_configuration_retains_all_original_defaults(self):
        module = self.module()
        self.assertEqual(module['WRITE_ROLES'], EXPECTED)
        for data in (None, [], {}, {'write_roles': None}, {'write_roles': 'custom_writer'}, {'write_roles': [None, '', ' ']}):
            with self.subTest(kind=type(data).__name__):
                self.assertEqual(module['parse_write_roles'](data), EXPECTED)
        first = module['parse_write_roles']({})
        first.clear()
        self.assertEqual(module['parse_write_roles']({}), EXPECTED)

    def test_adapter_reads_only_declared_routing_path_and_preserves_injected_defaults(self):
        module = self.module()
        root = Path('/owned-fixture')
        calls = []
        def read(path, default):
            calls.append((path, default))
            return {'write_roles': []}
        self.assertEqual(module['write_roles'](root, read_json=read, defaults={'injected_writer'}), {'injected_writer'})
        self.assertEqual(calls, [(root / '.getzilla/config/routing.json', None)])

    def test_legacy_wrapper_preserves_live_loader_and_default_global_seams(self):
        module = self.module()
        wrapper = next(node for node in LEGACY.body if isinstance(node, ast.FunctionDef) and node.name == 'write_roles')
        calls = []
        def read(path, default):
            calls.append((path, default))
            return {'write_roles': [' legacy_writer ']}
        namespace = {'Path': Path, 'load_json': read, 'WRITE_ROLES': {'legacy_default'},
                     '_configured_write_roles': module['write_roles']}
        exec(compile(ast.Module(body=[wrapper], type_ignores=[]), '<owned-legacy-role-wrapper>', 'exec'), namespace)
        self.assertEqual(namespace['write_roles'](Path('/owned-fixture')), {'legacy_writer'})
        self.assertEqual(calls, [(Path('/owned-fixture/.getzilla/config/routing.json'), None)])
        namespace['load_json'] = lambda path, default: None
        self.assertEqual(namespace['write_roles'](Path('/owned-fixture')), {'legacy_default'})
