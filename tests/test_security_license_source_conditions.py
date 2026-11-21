import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'.getzilla'))
from getzilla import security_license_source_conditions as conditions

class SourceConditionsTests(unittest.TestCase):
 def test_actual_original_bytes_and_scope_are_required(self):
  fixture=json.loads((ROOT/'tests/fixtures/security-license-source-conditions.json').read_text())
  for profile in conditions.PROFILES:
   files={p:fixture['files'][sha]['text'].encode() for p,sha in profile['files'].items()}
   result=conditions.retained_conditions(profile['artifact_sha256'],profile['component_id'],files)
   self.assertIsNotNone(result)
   self.assertIs(result['qualifies_complete_component'],False)
   self.assertEqual(result['policy_scope'],'selected-isolated-internal-linux-ci-only')
   self.assertIsNone(conditions.retained_conditions('0'*64,profile['component_id'],files))
   self.assertIsNone(conditions.retained_conditions(profile['artifact_sha256'],'other',files))
   path=next(iter(files))
   files[path]+=b' changed'
   self.assertIsNone(conditions.retained_conditions(profile['artifact_sha256'],profile['component_id'],files))
 def test_fixture_original_file_hashes(self):
  fixture=json.loads((ROOT/'tests/fixtures/security-license-source-conditions.json').read_text())
  for sha,row in fixture['files'].items():
      self.assertEqual(hashlib.sha256(row['text'].encode()).hexdigest(),sha)

 def test_actual_copyleft_source_evidence_does_not_require_global_permission(self):
  from getzilla import security_go_tool_inputs as go, security_licenses as licenses
  from getzilla.security_artifacts import ArtifactError
  fixture=json.loads((ROOT/'tests/fixtures/security-license-internal-family-conditions.json').read_text())
  profile=fixture['profiles'][0]
  terms={name:fixture['texts'][sha]['text'].encode() for name,sha in profile['terms'].items()}
  component,_=go.component_from_terms(profile['component_id'],terms)
  self.assertIn('MPL-2.0',component['expression'])
  with self.assertRaises(ArtifactError):
      licenses._select_expression(component['expression'],list(licenses.ALLOWED))

 def test_blueoak_scope_binds_action_archive_original_npm_and_selected_use(self):
  from getzilla import security_license_family_conditions as family,security_licenses as licenses
  from getzilla.security_artifacts import ArtifactError
  fixture=json.loads((ROOT/'tests/fixtures/security-license-source-conditions.json').read_text())
  for profile in conditions.ACTION_PROFILES:
   record=dict(kind='action',sha256=profile['artifact_sha256'],subject=dict(reference=profile['action_reference']),origin=dict(kind='github-action-source/v1'))
   component={k:profile[k] for k in ('source_artifact_sha256','source_url','name','version','expression')}
   component.update(id=profile['component_id'],files=[dict(path=p,sha256=sha,bytes=len(fixture['files'][sha]['text'].encode())) for p,sha in profile['terms'].items()],license_paths=list(profile['terms']),notice_paths=[])
   allowed=family.allowed_for(record,component,list(licenses.ALLOWED),selected_internal=True)
   self.assertIn('BlueOak-1.0.0',allowed)
   chosen,ids=licenses._select_expression(component['expression'],allowed)
   bodies={p:fixture['files'][sha]['text'].encode() for p,sha in profile['terms'].items()}
   licenses._license_evidence(bodies,component,ids,chosen)
   with self.assertRaises(ArtifactError):
       licenses._select_expression(component['expression'],list(licenses.ALLOWED))
   self.assertNotIn('BlueOak-1.0.0',family.allowed_for(record,component,list(licenses.ALLOWED),selected_internal=False))
   changed=copy.deepcopy(record)
   changed['sha256']='0'*64
   self.assertNotIn('BlueOak-1.0.0',family.allowed_for(changed,component,list(licenses.ALLOWED),selected_internal=True))
   changed=copy.deepcopy(component)
   changed['source_artifact_sha256']='0'*64
   self.assertNotIn('BlueOak-1.0.0',family.allowed_for(record,changed,list(licenses.ALLOWED),selected_internal=True))

 def test_opengrep_root_source_condition_keeps_unknown_binary_frontier(self):
  from getzilla import security_release_tool_inputs as release
  fixture=json.loads((ROOT/'tests/fixtures/security-license-source-conditions.json').read_text())
  profile=next(r for r in conditions.PROFILES if r['component_id'].startswith('release-source:'))
  raw=fixture['files'][profile['files']['source/LICENSE']]['text'].encode()
  result=release.component_frontier({'opengrep.bin':dict(sha256='a'*64,size=4)},{},dict(license=raw,opam=b'license: "LGPL-2.1-only"'))
  self.assertFalse(result['complete'])
  self.assertEqual(result['components'][0]['id'],profile['component_id'])
  self.assertFalse(result['components'][0]['source_conditions']['qualifies_complete_component'])
  self.assertEqual(len(result['gaps']),3)
  changed=release.component_frontier({}, {},dict(license=raw+b' changed',opam=b'license: "LGPL-2.1-only"'))
  self.assertEqual(changed['components'],[])
