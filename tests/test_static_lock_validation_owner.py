import ast
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]

class StaticLockOwnerTests(unittest.TestCase):
 def test_core_mirror_is_exact_canonical_pure_validator(self):
  canonical=ROOT/'trust-ci/lock_profile_validation.py'
  self.assertEqual(canonical.read_bytes(),(ROOT/'.getzilla/getzilla/lock_profile_validation.py').read_bytes())
  tree=ast.parse(canonical.read_text())
  self.assertFalse(any(isinstance(node,(ast.Import,ast.ImportFrom)) and 'subprocess' in ast.unparse(node) for node in ast.walk(tree)))
  self.assertFalse(any(isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id in {'exec','eval','compile'} for node in ast.walk(tree)))
 def test_ci_namespace_no_longer_executes_or_compiles_script_bytes(self):
  tree=ast.parse((ROOT/'.getzilla/getzilla/security_python_target.py').read_text())
  self.assertFalse(any(isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id in {'exec','eval','compile'} for node in ast.walk(tree)))
  self.assertFalse(any(isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr in {'exec_module','load_module','get_code'} for node in ast.walk(tree)))
 def test_regeneration_check_refuses_stale_mirror_without_writing(self):
  result=subprocess.run([sys.executable,str(ROOT/'scripts/getzilla_sync_lock_validation.py'),'--check'],capture_output=True,text=True)
  self.assertEqual(result.returncode,0,result.stderr)
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory)
   for relative in ['scripts/getzilla_sync_lock_validation.py','trust-ci/lock_profile_validation.py','.getzilla/getzilla/lock_profile_validation.py']:
    destination=root/relative
    destination.parent.mkdir(parents=True,exist_ok=True)
    destination.write_bytes((ROOT/relative).read_bytes())
   mirror=root/'.getzilla/getzilla/lock_profile_validation.py'
   mirror.write_bytes(mirror.read_bytes()+b'\n# stale\n')
   before=mirror.read_bytes()
   result=subprocess.run([sys.executable,str(root/'scripts/getzilla_sync_lock_validation.py'),'--check'],capture_output=True,text=True)
   self.assertNotEqual(result.returncode,0)
   self.assertEqual(mirror.read_bytes(),before)
