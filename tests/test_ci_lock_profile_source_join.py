import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'.getzilla'))
from getzilla import security_python_target as target

class CurrentCIProfileTests(unittest.TestCase):
 def test_all_actual_frozen_recipe_profiles_are_joined(self):
  for recipe,profile in [('Dockerfile.api','runtime'),('Dockerfile.worker','runtime'),('Dockerfile.test','test'),('runner.Dockerfile','runner')]:
   with self.subTest(recipe=recipe):
    context=target.ci_install_context(ROOT,'trust-ci/'+recipe)
    self.assertIsNotNone(context)
    primary='trust-ci/requirements-'+profile+'.txt'
    self.assertEqual(context['requirements'],primary)
    self.assertEqual(context['graph'],[primary])
    self.assertEqual(context['install_requirements'],{primary:hashlib.sha256((ROOT/primary).read_bytes()).hexdigest()})
    for path in ['trust-ci/uv.lock','trust-ci/pyproject.toml','trust-ci/lock_profiles.py','trust-ci/lock-profiles.json']:
     self.assertEqual(context['source_inputs'][path],hashlib.sha256((ROOT/path).read_bytes()).hexdigest())
 def test_source_lock_profile_and_validator_tamper_refuse(self):
  names=['Dockerfile.api','pyproject.toml','README.md','uv.lock','lock_profiles.py','lock-profiles.json','requirements-runtime.txt','requirements-test.txt','requirements-runner.txt']
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);(root/'trust-ci').mkdir()
   for name in names:shutil.copyfile(ROOT/'trust-ci'/name,root/'trust-ci'/name)
   self.assertIsNotNone(target.ci_install_context(root,'trust-ci/Dockerfile.api'))
   for name in ['uv.lock','lock-profiles.json','requirements-runtime.txt','requirements-test.txt','requirements-runner.txt','pyproject.toml','lock_profiles.py']:
    path=root/'trust-ci'/name;original=path.read_bytes();path.write_bytes(original+b' tampered')
    with self.subTest(name=name):self.assertIsNone(target.ci_install_context(root,'trust-ci/Dockerfile.api'))
    path.write_bytes(original)
   path=root/'trust-ci/Dockerfile.api';path.write_text(path.read_text().replace('--no-deps -r','-r'))
   self.assertIsNone(target.ci_install_context(root,'trust-ci/Dockerfile.api'))

 def test_self_consistent_binding_cannot_hide_wrong_locked_project_version(self):
  names=['Dockerfile.api','pyproject.toml','README.md','uv.lock','lock_profiles.py','lock-profiles.json','requirements-runtime.txt','requirements-test.txt','requirements-runner.txt']
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);(root/'trust-ci').mkdir()
   for name in names:shutil.copyfile(ROOT/'trust-ci'/name,root/'trust-ci'/name)
   lock=root/'trust-ci/uv.lock';before=lock.read_text()
   changed=before.replace('name = "adaptive-trust-ci"\nversion = "2.1.0"','name = "adaptive-trust-ci"\nversion = "2.1.1"',1)
   self.assertNotEqual(changed,before);lock.write_text(changed)
   binding=root/'trust-ci/lock-profiles.json';value=json.loads(binding.read_text())
   value['inputs']['uv.lock']=hashlib.sha256(lock.read_bytes()).hexdigest();binding.write_text(json.dumps(value))
   self.assertIsNone(target.ci_install_context(root,'trust-ci/Dockerfile.api'))
