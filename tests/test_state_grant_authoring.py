"""Grant writer separation keeps read demand and canonical mutable owners intact."""

from __future__ import annotations
import ast
import hashlib
import inspect
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import state


class StateGrantAuthoringTests(unittest.TestCase):
    def test_writer_leaf_uses_canonical_state_owners_and_public_signatures(self):
        from getzilla import grant_authoring

        self.assertIs(grant_authoring.state, state)
        self.assertIs(grant_authoring.state.GrantExtensionError, state.GrantExtensionError)
        for name in ("add_approval", "extend_protected_path_approval", "_extend_protected_path_approval"):
            self.assertEqual(inspect.signature(getattr(state, name)), inspect.signature(getattr(grant_authoring, name)))
        self.assertTrue(hasattr(grant_authoring.add_approval, "__wrapped__"))
        self.assertTrue(hasattr(grant_authoring._extend_protected_path_approval, "__wrapped__"))

    def test_fresh_read_only_import_does_not_load_authoring(self):
        program = (
            "import sys;sys.path.insert(0,sys.argv[1]);from getzilla import state;"
            "assert callable(state.get_active_route);assert callable(state.get_active_change);"
            "assert callable(state.update_route);assert 'getzilla.grant_authoring' not in sys.modules"
        )
        result = subprocess.run([sys.executable, "-B", "-c", program, str(ROOT / ".getzilla")], cwd=ROOT, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_leaf_first_import_has_no_partial_initialization_cycle(self):
        program = (
            "import sys;sys.path.insert(0,sys.argv[1]);from getzilla import grant_authoring;from getzilla import state;"
            "assert grant_authoring.state is state;assert callable(grant_authoring.add_approval)"
        )
        result = subprocess.run([sys.executable, "-B", "-c", program, str(ROOT / ".getzilla")], cwd=ROOT, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_each_ordinary_reader_projection_excludes_writer_import(self):
        from getzilla.architecture_fitness import _queue_export_slice

        tree = ast.parse((ROOT / ".getzilla/getzilla/state.py").read_text())
        for export in ("get_active_route", "get_active_change", "update_route"):
            with self.subTest(export=export):
                selected = _queue_export_slice(tree, frozenset({export}))
                imports = [node.module for node in ast.walk(selected) if isinstance(node, ast.ImportFrom)]
                self.assertNotIn("grant_authoring", imports)

    def test_source_binding_hashes_the_actual_writer_leaf(self):
        from getzilla.verification_policy_source import implementation_source_binding

        result = implementation_source_binding()
        self.assertEqual(
            result["grant_authoring.py"],
            hashlib.sha256((ROOT / ".getzilla/getzilla/grant_authoring.py").read_bytes()).hexdigest(),
        )
