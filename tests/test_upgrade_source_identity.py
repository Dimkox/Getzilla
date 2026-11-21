"""NEW pure predicate/AST controls; no old fixture or updater body executes."""
import ast
import builtins
from contextlib import ExitStack
import os
from pathlib import Path
import socket
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla.component_state import matches_owned, mode_matches, owned_proof

# Bounded named public-source AST reads only, before the pure-data deny window.
TREES = {name: ast.parse((ROOT / name).read_bytes()) for name in (
    'scripts/getzilla_upgrade.py', 'tests/test_getzilla_upgrade.py',
    'tests/test_skill_archive.py', 'tests/test_adapter_removal.py')}


class UpgradeSourceIdentityTests(unittest.TestCase):
    def setUp(self):
        guard = ExitStack()
        self.addCleanup(guard.close)
        def deny(*args, **kwargs):
            raise AssertionError('pure fixture forbids I/O/process/network')
        for module, name in ((builtins, 'open'), (os, 'open'), (subprocess, 'Popen'),
                             (os, 'system'), (socket, 'socket')):
            guard.enter_context(patch.object(module, name, side_effect=deny))

    def test_identical_unowned_marker_mode_is_the_exact_ownership_trigger(self):
        choices = [node.test for node in ast.walk(TREES['scripts/getzilla_upgrade.py'])
            if isinstance(node, ast.If) and any(isinstance(child, ast.Raise)
            and isinstance(child.exc, ast.Call) and any(v.arg == 'reason'
            and isinstance(v.value, ast.Constant) and v.value.value == 'ownership'
            for v in child.exc.keywords) for child in node.body)]
        self.assertEqual(len(choices), 1)
        code = compile(ast.Expression(choices[0]), '<new-owned-mode-predicate>', 'eval')
        marker = b'NEW_OWNED_MARKER\n'
        for source_mode, incoming, expected in ((0o664, marker, True),
                                                (0o644, marker, False),
                                                (0o644, b'NEW_CHANGED_BYTES', True)):
            values = {'current': SimpleNamespace(content=marker, mode=0o644),
                      'content': incoming, 'entry': SimpleNamespace(mode=source_mode, path='.getzilla/runtime/.gitignore'),
                      'manifest': {'components': {}}, 'historical_match': False, 'initial_agents_block': False}
            actual = eval(code, {'__builtins__': {}, 'mode_matches': mode_matches,
                                'matches_owned': matches_owned, 'owned_proof': owned_proof}, values)
            self.assertIs(actual, expected)

    def check_calls(self, cls):
        for node in ast.walk(cls):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == 'upgrade' \
                    and node.func.attr in {'sync_project', 'planned_changes', 'load_installer'}:
                index = 1 if node.func.attr == 'planned_changes' else 0
                self.assertNotEqual(ast.unparse(node.args[index]), 'ROOT',
                                    'payload call bypasses its declared public/custom source fixture')

    def test_project_sync_payloads_use_the_existing_public_source_identity(self):
        cls = next(v for v in TREES['tests/test_getzilla_upgrade.py'].body
                   if isinstance(v, ast.ClassDef) and v.name == 'ProjectSyncTests')
        self.check_calls(cls)

    def test_archive_and_mode_helper_use_public_source_without_changing_program(self):
        cls = next(v for v in TREES['tests/test_skill_archive.py'].body
                   if isinstance(v, ast.ClassDef) and v.name == 'ArchiveUpgradeTests')
        self.check_calls(cls)
        self.assertTrue(any(isinstance(v, ast.Call) and isinstance(v.func, ast.Name)
                            and v.func.id == 'public_source_copy' for v in ast.walk(cls)))
        helper = next(v for v in TREES['tests/test_adapter_removal.py'].body
                      if isinstance(v, ast.FunctionDef) and v.name == '_assert_publication_modes')
        call = next(v for v in ast.walk(helper) if isinstance(v, ast.Call)
                    and isinstance(v.func, ast.Attribute) and ast.unparse(v.func) == 'subprocess.run')
        self.assertEqual(ast.unparse(call.args[0].elts[4]), 'str(source_home)')
        self.assertTrue(any(isinstance(v, ast.Call) and isinstance(v.func, ast.Name)
                            and v.func.id == 'public_source_copy' for v in ast.walk(helper)))
