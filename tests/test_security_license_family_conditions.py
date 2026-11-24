from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'.getzilla'))
from getzilla import security_license_family_conditions as conditions
from getzilla import security_licenses as licenses
from getzilla.security_artifacts import ArtifactError

class FamilyConditionsTests(unittest.TestCase):
    def fixture(self):
        fixture=json.loads((ROOT/'tests/fixtures/security-license-internal-family-conditions.json').read_text())
        profile=fixture['profiles'][0]
        prefix='go-terms/'+hashlib.sha256(profile['component_id'].encode()).hexdigest()+'/'
        files={prefix+name:fixture['texts'][sha]['text'].encode() for name,sha in profile['terms'].items()}
        component=dict(id=profile['component_id'],expression=profile['expression'],requires=[],
            files=[dict(path=p,sha256=hashlib.sha256(b).hexdigest(),bytes=len(b)) for p,b in files.items()],
            license_paths=list(files),notice_paths=[])
        self.source_modules=[dict(module=profile['component_id'].removeprefix('go-module:'),h1=profile['source_h1'])]
        record=dict(kind='tool',sha256=profile['artifact_sha256'],origin=dict(kind='go-checker-release/v1'))
        return record,component,files

    def test_exact_selected_component_terms(self):
        record,component,files=self.fixture()
        allowed=conditions.allowed_for(record,component,list(licenses.ALLOWED),selected_internal=True,source_modules=self.source_modules)
        chosen,ids=licenses._select_expression(component['expression'],allowed)
        terms,_=licenses._license_evidence(files,component,ids,chosen)
        self.assertTrue(terms)
        self.assertIn('MPL-2.0',chosen)

    def test_source_scope_and_legal_mutations_do_not_get_permission(self):
        record,component,_=self.fixture()
        mutations=[('sha256','0'*64),('kind','image'),('origin',dict(kind='release-source/v1'))]
        for key,value in mutations:
            changed=copy.deepcopy(record)
            changed[key]=value
            self.assertEqual(conditions.allowed_for(changed,component,list(licenses.ALLOWED),selected_internal=True,source_modules=self.source_modules),list(licenses.ALLOWED))
        for key,value in [('id','other'),('expression','MPL-2.0'),('license_paths',[])]:
            changed=copy.deepcopy(component)
            changed[key]=value
            self.assertEqual(conditions.allowed_for(record,changed,list(licenses.ALLOWED),selected_internal=True,source_modules=self.source_modules),list(licenses.ALLOWED))
        changed=copy.deepcopy(component)
        changed['files'][0]['sha256']='0'*64
        self.assertEqual(conditions.allowed_for(record,changed,list(licenses.ALLOWED),selected_internal=True,source_modules=self.source_modules),list(licenses.ALLOWED))

    def test_raw_future_and_redistribution_stay_denied(self):
        record,component,_=self.fixture()
        allowed=conditions.allowed_for(record,component,list(licenses.ALLOWED),selected_internal=False)
        with self.assertRaises(ArtifactError):
            licenses._select_expression(component['expression'],allowed)
        self.assertEqual(len(licenses.ALLOWED),6)
        with self.assertRaises(ArtifactError):
            licenses._select_expression('X11',list(licenses.ALLOWED))
        self.assertEqual(licenses._select_expression('X11',['X11'])[0],['X11'])
        self.assertEqual(conditions.allowed_for(record,component,list(licenses.ALLOWED),selected_internal=True),list(licenses.ALLOWED))
        changed=copy.deepcopy(self.source_modules)
        changed[0]['h1']='h1:other'
        self.assertEqual(conditions.allowed_for(record,component,list(licenses.ALLOWED),selected_internal=True,source_modules=changed),list(licenses.ALLOWED))

    def test_every_fixture_matches_exact_recognition_and_profile(self):
        from getzilla.security_license_texts import recognized_license, recognized_license_bundle
        fixture=json.loads((ROOT/'tests/fixtures/security-license-internal-family-conditions.json').read_text())
        for sha,item in fixture['texts'].items():
            self.assertEqual(hashlib.sha256(item['text'].encode()).hexdigest(),sha)
            single=recognized_license(item['text'])
            identified=(single,) if single else recognized_license_bundle(item['text'])
            self.assertEqual(identified,tuple(item['identifiers']))
            self.assertIsNone(recognized_license_bundle(item['text']+' changed'))

    def test_go_finding_replays_live_compact_proof_and_rejects_changed_terms(self):
        import tempfile
        from unittest.mock import patch
        from tests.test_security_go_tool_inputs import qualified_fixture
        from getzilla import security_artifacts, security_tools, security_go_tool_inputs as go
        from getzilla.security_license_families import finding_consistent
        with tempfile.TemporaryDirectory() as directory:
            checker, artifacts, record, specs=qualified_fixture(directory)
            with patch.object(go,'PIN_SPECS',specs),patch.object(security_tools,'TRUSTED_ROOT',checker):
                evidence=security_artifacts.family_evidence(artifacts,record)
                selected,terms,notices=[],[],[]
                for component in evidence['components']:
                    chosen,ids=licenses._select_expression(component['expression'],list(licenses.ALLOWED))
                    owned={item['path'] for item in component['files']}
                    files={p:b for p,b in evidence['files'].items() if p in owned}
                    full,attribution=licenses._license_evidence(files,component,ids,chosen)
                    selected.extend(chosen)
                    terms.extend(full)
                    notices.extend(attribution)
                finding=dict(kind='tool',reference=record['subject']['reference'],status='pass',
                    selected_expression=' AND '.join(sorted(set(selected))),distribution='internal',
                    **evidence['binding'],family_record=record,
                    component_inventory_json=(artifacts/record['components']['path']).read_text(),
                    license_files=terms,notice_files=notices,
                    obligations='internal use; exact source/component/license evidence retained')
                self.assertTrue(finding_consistent(finding,list(licenses.ALLOWED),licenses._select_expression))
                from unittest import mock
                with mock.patch.dict(go._VERIFIED_FAMILIES, {}, clear=True):
                    self.assertFalse(finding_consistent(finding,list(licenses.ALLOWED),licenses._select_expression))
                changed=copy.deepcopy(finding)
                changed['license_files'][0]['sha256']='0'*64
                self.assertFalse(finding_consistent(changed,list(licenses.ALLOWED),licenses._select_expression))
                proof=artifacts/record['components']['path']
                proof.write_bytes(proof.read_bytes()+b' ')
                self.assertFalse(finding_consistent(finding,list(licenses.ALLOWED),licenses._select_expression))
