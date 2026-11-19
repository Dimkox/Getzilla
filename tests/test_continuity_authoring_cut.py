"""Structural source-budget cut; existing continuity suites own behavioral contracts."""
from __future__ import annotations

import ast
import hashlib
import inspect
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'.getzilla'))
WRITERS=('normalize_route','_changed','_passive','_union_assessment','submit','_rejection',
         '_sync_gate_projection','attach_package','_request_schema','_resolution','ack_scope','update_intent','finish_task')


class ContinuityAuthoringCutTests(unittest.TestCase):
    def test_readonly_owner_is_smaller_and_reader_projections_exclude_authoring(self):
        path=ROOT/'.getzilla/getzilla/continuity.py'
        self.assertLessEqual(path.stat().st_size,34*1024,'continuity still charges writer bodies to readers')
        from getzilla.architecture_fitness import _queue_export_slice
        tree=ast.parse(path.read_text())
        for reader in ('validate_route','package_documents','context_binding','scope_gaps','receipt_context_current','assert_finishable'):
            with self.subTest(reader=reader):
                selected=_queue_export_slice(tree,frozenset({reader}))
                imports=[alias.name for node in ast.walk(selected) if isinstance(node,(ast.Import,ast.ImportFrom)) for alias in node.names]
                self.assertNotIn('continuity_authoring',imports)
        program="import sys;from getzilla import continuity;assert callable(continuity.validate_route);assert 'getzilla.continuity_authoring' not in sys.modules"
        env=dict(os.environ,PYTHONPATH=str(ROOT/'.getzilla'),PYTHONDONTWRITEBYTECODE='1')
        result=subprocess.run([sys.executable,'-B','-c',program],env=env,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_leaf_first_import_retains_canonical_mutable_state_and_public_signatures(self):
        from getzilla import continuity,state
        from getzilla import continuity_authoring as authoring
        self.assertIs(authoring.continuity,continuity)
        self.assertIs(authoring.continuity.state,state)
        for name in WRITERS:
            self.assertEqual(inspect.signature(getattr(continuity,name)),inspect.signature(getattr(authoring,name)),name)
        for name in ('normalize_route','submit','attach_package','ack_scope','finish_task'):
            self.assertTrue(hasattr(getattr(continuity,name),'__wrapped__'))
        self.assertFalse(hasattr(authoring.submit,'__wrapped__'),'lock decorator duplicated in leaf')
        program="from getzilla import continuity_authoring as a;from getzilla import continuity as c;assert a.continuity is c;assert callable(a.submit)"
        env=dict(os.environ,PYTHONPATH=str(ROOT/'.getzilla'),PYTHONDONTWRITEBYTECODE='1')
        result=subprocess.run([sys.executable,'-B','-c',program],env=env,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_policy_source_binding_hashes_actual_new_authoring_source(self):
        from getzilla.verification_policy_source import implementation_source_binding
        binding=implementation_source_binding()
        expected=hashlib.sha256((ROOT/'.getzilla/getzilla/continuity_authoring.py').read_bytes()).hexdigest()
        self.assertEqual(binding['continuity_authoring.py'],expected)
