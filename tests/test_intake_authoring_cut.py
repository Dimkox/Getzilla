"""Structural ownership controls; unchanged intake behavior remains in its original suites."""
import inspect
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'.getzilla'))


class IntakeAuthoringCutTests(unittest.TestCase):
    def test_readonly_owner_is_bounded_and_does_not_import_authoring_for_protocol_validation(self):
        source=ROOT/'.getzilla/getzilla/intake_publication.py'
        self.assertLessEqual(source.stat().st_size,18*1024,'writer implementation still loads in the readonly source owner')
        code="""import sys
from getzilla import intake_publication as p
assert 'getzilla.intake_authoring' not in sys.modules
p.validate_protocol_metadata({'version':1,'required':True,'generation':0,'committed':None,'pending':None})
assert 'getzilla.intake_authoring' not in sys.modules
"""
        environment=dict(__import__('os').environ,PYTHONPATH=str(ROOT/'.getzilla'),PYTHONDONTWRITEBYTECODE='1')
        result=subprocess.run([sys.executable,'-c',code],env=environment,capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_public_signatures_and_canonical_state_error_and_json_owners_remain(self):
        from getzilla import intake_publication as p,state,requirements_intake,workflow_artifacts
        self.assertIs(p.state,state)
        self.assertIs(p.IntakeError,requirements_intake.IntakeError)
        self.assertIs(p.canonical_json,workflow_artifacts.canonical_json)
        self.assertIs(p._strict_json,workflow_artifacts._strict_json)
        self.assertEqual(str(inspect.signature(p.prepare_intake)), '(root, intent, expected_cut_digest, expected_state_digest)')
        self.assertEqual(str(inspect.signature(p.recover_intake)), '(root, publication_id)')
        self.assertEqual(str(inspect.signature(p.decide_intake)), '(root, *, decision, event_id, expected_cut_digest, expected_state_digest, expected_draft_digest, expected_source_digest)')
        self.assertTrue(hasattr(p.recover_intake,'__wrapped__'))
        self.assertTrue(hasattr(p.decide_intake,'__wrapped__'))
