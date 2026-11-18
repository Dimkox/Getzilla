"""Exact retained legal profiles do not expand the automatic SPDX vocabulary."""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import security_licenses as licenses


class PointedPolicyTests(unittest.TestCase):
    def test_optional_closed_exceptions_are_digest_bound(self):
        policy = dict(schema_version=1, project_repository='github.com/Dimkox/Getzilla',
            auto_allow=list(licenses.ALLOWED), usage_distribution={}, dependency_exceptions=[])
        parsed = licenses._policy(policy)
        self.assertEqual(parsed['dependency_exceptions'], [])
        self.assertNotEqual(parsed['digest'], licenses._policy({k:v for k,v in policy.items() if k!='dependency_exceptions'})['digest'])

    def test_no_automatic_exception_identifiers(self):
        for expression in ('MIT-0','PSF-2.0'):
            with self.subTest(expression=expression), self.assertRaises(ValueError):
                licenses._select_expression(expression,list(licenses.ALLOWED))

class PointedConditionsTests(unittest.TestCase):
    def fixture(self, name='typing-extensions'):
        f=json.loads((ROOT/'tests/fixtures/security-license-exceptions.json').read_text())[name]
        dep=dict(ecosystem='PyPI',name=f['name'],version=f['version'],manifest='requirements.txt',usage='runtime',extras=[])
        scope=dict(manifest_sha256='a'*64,profile='python:cpython:3.12:linux-x86_64',abi='cpython-312-x86_64-linux-gnu',delivery_kind='source-use')
        if name=='cffi-cp313':scope.update(profile='python:cpython:3.13:linux-x86_64',abi='cpython-313-x86_64-linux-gnu')
        record=dict(ecosystem='PyPI',name=f['name'],version=f['version'],filename=f['filename'],sha256=f['sha256'],origin={'artifact_url':'https://files.pythonhosted.org/packages/aa/'+f['filename']})
        subject={**{k:dep[k] for k in ('ecosystem','name','version','manifest','usage')},**scope,
            'distribution':'internal','artifact_sha256':f['sha256'],'filename':f['filename'],'artifact_url':record['origin']['artifact_url']}
        entry=dict(subject=subject,condition_profile=('cffi-2.1.1-cp313-mit0-inline-mit-v1' if name=='cffi-cp313' else 'cffi-2.1.1-mit0-inline-mit-v1') if f['name']=='cffi' else 'typing-extensions-4.16.0-history-unchanged-v1')
        files={p:b.encode() for p,b in f['files'].items()}
        term=next(p for p in files if p.endswith('/LICENSE'))
        meta=dict(expression='MIT-0' if f['name']=='cffi' else 'PSF-2.0',license_paths=[term],dynamic=[],classifiers=[])
        return entry,dep,record,files,meta,scope

    def verify(self, values):
        from getzilla.security_license_exceptions import verify_exception
        entry,dep,record,files,meta,scope=values
        policy={'dependency_exceptions':[entry]}
        return verify_exception(policy,dep,record,files,meta,'internal',scope)

    def test_exact_real_full_terms_and_member_pass(self):
        for name in ('cffi','cffi-cp313','typing-extensions'):
            with self.subTest(name=name):
                result=self.verify(self.fixture(name))
                self.assertEqual(result['detail']['code'],'policy-exception-conditions-verified')
                self.assertEqual(len(result['required_retention']),2)
                self.assertEqual(result['detail']['expression'],'MIT-0' if name.startswith('cffi') else 'PSF-2.0')

    def test_each_actual_term_or_source_member_change_fails(self):
        for name in ('cffi','cffi-cp313','typing-extensions'):
            values=self.fixture(name)
            for path in values[3]:
                altered=copy.deepcopy(values);altered[3][path]+=b'\nAdditional restriction'
                with self.subTest(name=name,path=path),self.assertRaises(ValueError):
                    self.verify(altered)

    def test_exact_subject_and_live_scope_replay_fails(self):
        values=self.fixture()
        for where,key,value in ((1,'usage','build'),(1,'manifest','other.txt'),(2,'sha256','b'*64),
                (2,'filename','other.whl'),(5,'manifest_sha256','b'*64),(5,'abi','other'),
                (5,'profile','other'),(5,'delivery_kind','installed-package')):
            altered=copy.deepcopy(values);altered[where][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.verify(altered)

    def test_policy_rejects_duplicates_and_unreviewed_profiles(self):
        from getzilla.security_license_exceptions import validate_exceptions
        entry=self.fixture()[0]
        for entries in ([entry,entry],[dict(entry,satisfied=True)],
                [dict(entry,condition_profile='certifi-mpl2')],
                [dict(entry,subject=dict(entry['subject'],artifact_id='a'*64))]):
            with self.subTest(entries=entries),self.assertRaises(ValueError):validate_exceptions(entries)

    def test_full_terms_cannot_be_replaced_by_label(self):
        values=self.fixture();term=next(p for p in values[3] if p.endswith('/LICENSE'));values[3][term]=b'PSF-2.0'
        with self.assertRaises(ValueError):self.verify(values)

class ExceptionDispatchTests(unittest.TestCase):
    def test_unobserved_target_cannot_use_exception(self):
        from getzilla.security_license_exceptions import scope_for
        values=PointedConditionsTests().fixture()
        with self.assertRaises(ValueError):scope_for(values[1],None,None)

    def test_exact_profile_detail_has_separate_consistency_check(self):
        from getzilla.security_license_exceptions import detail_consistent
        case=PointedConditionsTests();values=case.fixture();proved=case.verify(values)
        finding=dict(expression='PSF-2.0',selected_expression='PSF-2.0',ecosystem='PyPI',package='typing-extensions',version='4.16.0',
            manifest='requirements.txt',distribution='internal',artifact_sha256=values[2]['sha256'],
            origin=values[2]['origin'],license_files=proved['license_files'],notice_files=proved['notice_files'],policy_exception=proved['detail'])
        self.assertTrue(detail_consistent(finding))
        for key in ('exception_sha256','requirements_sha256'):
            altered=copy.deepcopy(finding);altered['policy_exception'][key]='0'*64
            self.assertFalse(detail_consistent(altered))
        altered=copy.deepcopy(finding);altered['license_files'][0]['sha256']='0'*64
        self.assertFalse(detail_consistent(altered))

class RealWheelDispatchTests(unittest.TestCase):
    def test_current_observed_target_and_source_with_real_typing_wheel(self):
        import base64
        import tempfile
        from datetime import datetime, timezone
        from getzilla import security_python_target as target
        from tests.test_security_licenses import artifact, inventory, manifest, POLICY
        f=json.loads((ROOT/'tests/fixtures/security-license-exceptions.json').read_text())['typing-extensions']
        payload=base64.b64decode(f['wheel_base64'])
        now=datetime(2026,11,18,tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'source';source.mkdir();artifacts=root/'artifacts';artifacts.mkdir()
            dep=dict(ecosystem='PyPI',name='typing-extensions',version='4.16.0',manifest='requirements.txt',usage='runtime',extras=[],distribution='internal')
            (source/'requirements.txt').write_text('typing-extensions==4.16.0 --hash=sha256:'+f['sha256']+'\n')
            inv=inventory(dep,manifests=[dict(path='requirements.txt',sha256=hashlib.sha256((source/'requirements.txt').read_bytes()).hexdigest())])
            facts=target.observe_target()
            binding=dict(target=facts,source=dict(head_sha='a'*40,tree_sha='b'*40,checker_sha='c'*40,checker_tree_sha='d'*40,
                candidate_clean=True,checker_clean=True,same_project=True),run=dict(provider='github-actions',repository='owned/project',run_id='42',run_attempt='1',head_sha='a'*40),
                inventory_sha256=inv['digest'],profile_sha256='e'*64,source_pins=target.source_pins(source,inv,facts))
            record=artifact(artifacts,dep,payload,filename=f['filename']);record['context']=target.artifact_context(dep)
            from getzilla.security_artifacts import archive_files
            record['python_target']=target.wheel_observation(f['filename'],archive_files(payload,f['filename']),binding,dependency=dep)
            from getzilla.security_license_exceptions import scope_for
            scope=scope_for(dep,binding,record['python_target'])
            entry=PointedConditionsTests().fixture()[0]
            entry['subject'].update(scope);entry['subject']['manifest_sha256']=hashlib.sha256((source/'requirements.txt').read_bytes()).hexdigest()
            entry['subject']['artifact_url']=record['origin']['artifact_url']
            policy=dict(POLICY,dependency_exceptions=[entry])
            manifest(artifacts,inv,[record],acquired=now)
            result=licenses.evaluate_artifacts(inv,artifacts,policy,now=now,target_binding=binding)
            self.assertEqual(result['status'],'pass',result['gaps'])
            self.assertEqual(result['assurance'],'artifact-integrity-only')
            self.assertIn('original_diagnostic',result['details'][0]['policy_exception'])
            from getzilla import security_cli
            self.assertTrue(security_cli._findings_consistent('security-licenses',dict(findings=result['details']),now))
            for changed in ('missing-policy','wrong-manifest','wrong-target','wrong-url','wrong-distribution','old-run'):
                candidate=copy.deepcopy(policy);live=copy.deepcopy(binding)
                if changed=='missing-policy':candidate.pop('dependency_exceptions')
                if changed=='wrong-manifest':candidate['dependency_exceptions'][0]['subject']['manifest_sha256']='0'*64
                if changed=='wrong-target':candidate['dependency_exceptions'][0]['subject']['abi']='other'
                if changed=='wrong-url':candidate['dependency_exceptions'][0]['subject']['artifact_url']='https://files.pythonhosted.org/packages/other/'+f['filename']
                if changed=='wrong-distribution':candidate['dependency_exceptions'][0]['subject']['distribution']='redistributed'
                if changed=='old-run':live['run']['run_attempt']='2'
                with self.subTest(changed=changed):
                    rejected=licenses.evaluate_artifacts(inv,artifacts,candidate,now=now,target_binding=live)
                    self.assertEqual(rejected['status'],'fail')
                    self.assertFalse(rejected['details'])

class FactoryExceptionDispatchTests(unittest.TestCase):
    def test_real_typing_wheel_factory_composition_and_parent_replay(self):
        import base64
        import io
        import tempfile
        import zipfile
        from datetime import datetime, timezone
        from getzilla import security_factory_inputs as factory, security_python_target as target
        from getzilla.security_artifacts import archive_inventory,artifact_identity
        from tests.test_security_licenses import artifact,manifest,POLICY
        f=json.loads((ROOT/'tests/fixtures/security-license-exceptions.json').read_text())['typing-extensions']
        payload=base64.b64decode(f['wheel_base64']);now=datetime(2026,11,18,tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);output=root/'factory-output';output.mkdir()
            app={'app/getzilla_factory/__init__.py':b'owned current source fixture'}
            profile=json.loads((ROOT/licenses.POLICY_PATH).read_text())['factory_offline_profile']
            original=dict(ecosystem='PyPI',name='typing-extensions',version='4.16.0',manifest='factory/uv.lock',usage='runtime',extras=[],
                artifact_filename=f['filename'],artifact_sha256=f['sha256'],artifact_source='https://files.pythonhosted.org/packages/aa/bb/'+f['filename'],
                distribution='redistributed',delivery_kind='factory-offline-archive',source_use_sha256=['3'*64])
            declaration=dict(schema_version=1,profile=factory.PROFILE,policy_profile=profile,inventory_sha256='a'*64,product_version='0.1.0',
                dependencies=[original],app_members_sha256=factory.digest({k:dict(size=len(v),sha256=hashlib.sha256(v).hexdigest()) for k,v in app.items()}))
            binding=dict(target=target.observe_target(),source=dict(head_sha='a'*40,tree_sha='b'*40,checker_sha='c'*40,checker_tree_sha='d'*40,
                candidate_clean=True,checker_clean=True,same_project=True),run=dict(provider='github-actions',repository='owned/project',run_id='42',run_attempt='1',head_sha='a'*40),
                inventory_sha256='a'*64,profile_sha256='e'*64,factory_inputs=declaration)
            environment={**factory.MARKERS,'python_full_version':'3.12.3'}
            inv=factory.output_inventory(declaration,binding,environment);dep=inv['dependencies'][0]
            record=artifact(output,dep,payload,filename=f['filename']);record['context']=target.artifact_context(dep)
            manifest(output,inv,[record],acquired=now)
            envelope=dict(schema_version=1,declaration_sha256=factory.digest(declaration),source=binding['source'],run=binding['run'],
                environment=environment,builder_sha256=profile['builder_sha256'],helper_sha256=hashlib.sha256((ROOT/'factory/runtime/setup_manager.py').read_bytes()).hexdigest())
            (output/'factory-input.json').write_text(json.dumps(envelope))
            entries=dict(app)
            with zipfile.ZipFile(io.BytesIO(payload)) as wheel:
                entries.update({'site-packages/'+name:wheel.read(name) for name in wheel.namelist()})
            def write_delivery(entries):
                archive=output/'factory-output.zip'
                with zipfile.ZipFile(archive,'w') as writer:
                    for path,raw in entries.items():writer.writestr(path,raw)
                members=archive_inventory(archive.read_bytes(),archive.name)
                detached=output/'factory-output.manifest.json'
                detached.write_text(json.dumps(dict(schema_version='factory-release/v1',profile='factory-python',product_version='0.1.0',
                    files=[dict(path=k,**v,mode=0o644) for k,v in members.items()])))
                ah=hashlib.sha256(archive.read_bytes()).hexdigest();mh=hashlib.sha256(detached.read_bytes()).hexdigest()
                (output/'factory-output.sha256').write_text(f'{ah}  {archive.name}\n{mh}  {detached.name}\n')
                catalog=json.loads((output/'manifest.json').read_text())
                catalog['deliveries']=[dict(context=dep['delivery_context'],kind='factory-offline-archive',profile=factory.PROFILE,path=archive.name,sha256=ah,
                    manifest_path=detached.name,manifest_sha256=mh,sidecar_path='factory-output.sha256',components=[dict(artifact_id=artifact_identity(record),prefix='site-packages/')])]
                (output/'manifest.json').write_text(json.dumps(catalog))
            write_delivery(entries)
            entry=PointedConditionsTests().fixture()[0]
            entry['subject'].update(manifest='factory/uv.lock',manifest_sha256=profile['lock_sha256'],usage='runtime',distribution='redistributed',
                delivery_kind='factory-offline-archive',profile=factory.PROFILE,abi='cp312-cp312-manylinux_2_17_x86_64',artifact_url=record['origin']['artifact_url'])
            policy=dict(POLICY,factory_offline_profile=profile,dependency_exceptions=[entry])
            result=licenses.evaluate_artifacts(inv,output,policy,now=now,_factory_parent_binding=binding)
            self.assertEqual(result['status'],'pass',result['gaps'])
            self.assertIn('site-packages/typing_extensions.py',result['details'][0]['delivery']['retained_members'])
            # Output-only JSON cannot discharge the parent source/run/target checks.
            bare=licenses.evaluate_artifacts(inv,output,policy,now=now)
            self.assertEqual(bare['status'],'fail')
            for field in ('source','run'):
                altered=copy.deepcopy(binding)
                if field=='source':altered['source']['head_sha']='f'*40
                else:altered['run']['run_attempt']='2'
                with self.subTest(replay=field):
                    rejected=licenses.evaluate_artifacts(inv,output,policy,now=now,_factory_parent_binding=altered)
                    self.assertEqual(rejected['status'],'fail')
            altered_entries=dict(entries);altered_entries['site-packages/typing_extensions.py']+=b'\n# modified'
            write_delivery(altered_entries)
            rejected=licenses.evaluate_artifacts(inv,output,policy,now=now,_factory_parent_binding=binding)
            self.assertEqual(rejected['status'],'fail')
            self.assertTrue(any(g['code']=='license-obligation-missing' for g in rejected['gaps']))

class CIExceptionCustodyTests(unittest.TestCase):
    from tests.test_ci_image_license_inputs import CIImageTargetBindingTests as _Fixture
    setUp=_Fixture.setUp

    def test_actual_cffi_and_typing_require_extra_final_members(self):
        import base64
        import tempfile
        from datetime import datetime,timezone
        from unittest.mock import patch
        from getzilla import security_ci_inputs as ci,security_python_target as target
        from getzilla.security_artifacts import archive_files
        from tests.test_security_licenses import artifact,manifest,wheel,POLICY
        consumer=self.uses['consumers'][0]
        allfixtures=json.loads((ROOT/'tests/fixtures/security-license-exceptions.json').read_text())
        deps=[];payloads=[];profiles=[]
        for name in ('cffi-cp313','typing-extensions'):
            f=allfixtures[name];dep=dict(ecosystem='PyPI',name=f['name'],version=f['version'],manifest='trust-ci/requirements.txt',usage='runtime-and-development',extras=[])
            deps.append(dep);payloads.append((f['filename'],base64.b64decode(f['wheel_base64'])))
            profiles.append(PointedConditionsTests().fixture(name)[0])
        deps.append(dict(deps[0],name='pycparser',version='3.0'))
        payloads.append(('pycparser-3.0-py3-none-any.whl',wheel(name='pycparser',version='3.0',extra_files={'pycparser-3.0.dist-info/WHEEL':'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n'})))
        consumer['dependencies']=deps
        tags=['cp313-cp313-manylinux2014_x86_64','cp313-cp313-manylinux_2_17_x86_64','py3-none-any']
        consumer['target'].update(python_version='3.13.18',abi='cpython-313-x86_64-linux-gnu')
        consumer['target']['marker_environment'].update(python_version='3.13',python_full_version='3.13.18')
        consumer['supported_tags']=tags
        consumer['target'].update(tags_sha256=target.digest(tags),tag_count=len(tags))
        consumer['source_pins']={target.digest(target._subject(dep)):dict(context_sha256=target._context_key(dep),manifest_sha256='2'*64,
            hashes=[hashlib.sha256(payload).hexdigest()],files=[],marker_active=True) for dep,(_,payload) in zip(deps,payloads)}
        self.uses['subjects']={target.digest(target._subject(dep)):[0] for dep in deps}
        inv,binding=ci.scope(self.parent,0)
        now=datetime(2026,11,18,tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            artifacts=Path(directory);records=[];actual={};prefix=consumer['site_packages'][0]+'/'
            for dep,(filename,payload) in zip(inv['dependencies'],payloads):
                record=artifact(artifacts,dep,payload,filename=filename);record['context']=target.artifact_context(dep)
                files=archive_files(payload,filename)
                record['python_target']=target.wheel_observation(filename,files,binding,dependency=dep)
                records.append(record)
                # Model the held image member reader. It returns actual requested
                # installed bytes; the verifier must request source/inline notice.
                import io,zipfile
                with zipfile.ZipFile(io.BytesIO(payload)) as z:
                    actual.update({prefix+name:z.read(name) for name in z.namelist()})
            for entry,dep,record in zip(profiles,inv['dependencies'],records):
                from getzilla.security_license_exceptions import scope_for
                entry['subject'].update(scope_for(dep,binding,record['python_target']),manifest=dep['manifest'],usage=dep['usage'],artifact_url=record['origin']['artifact_url'])
            policy=dict(POLICY,dependency_exceptions=profiles)
            manifest(artifacts,inv,records,acquired=now)
            def held_members(_uses,_source,_run,_index,requested):
                return {path:actual[path] for path in requested if path in actual}
            with patch('getzilla.security_image_producer.ci_member_evidence',side_effect=held_members):
                result=licenses.evaluate_artifacts(inv,artifacts,policy,now=now,target_binding=binding)
                self.assertEqual(result['status'],'pass',result['gaps'])
                for path in ('cffi/_cffi_gen_src.py','typing_extensions.py'):
                    body=actual.pop(prefix+path)
                    with self.subTest(path=path):
                        rejected=licenses.evaluate_artifacts(inv,artifacts,policy,now=now,target_binding=binding)
                        self.assertEqual(rejected['status'],'fail')
                        self.assertTrue(any(g['code']=='artifact-target-use-unobserved' for g in rejected['gaps']))
                    actual[prefix+path]=body

class FamilyFindingConsistencyTests(unittest.TestCase):
    def test_actual_action_tool_image_family_forms_and_swapped_binding(self):
        import tempfile
        from tests import test_public_security_inputs as fixtures
        from getzilla import security_cli
        for fixture in (fixtures.action_fixture,fixtures.release_fixture,fixtures.image_fixture):
            with self.subTest(fixture=fixture.__name__),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);inv,record,_=fixture(root)
                result=licenses.evaluate_artifacts(inv,root,fixtures.POLICY,now=fixtures.NOW)
                self.assertEqual(result['status'],'pass',result['gaps'])
                finding=result['details'][0]
                self.assertTrue(security_cli._findings_consistent('security-licenses',dict(findings=[finding]),fixtures.NOW))
                for change in ('missing-record','artifact-sha','subject','context','proof','components'):
                    altered=copy.deepcopy(finding)
                    if change=='missing-record':altered.pop('family_record',None)
                    if change=='artifact-sha':altered['artifact_sha256']='0'*64
                    if change=='subject':altered['subject']['reference']='other/source@'+'f'*40
                    if change=='context':altered['context']['manifest']='other.yml'
                    if change=='proof':altered['proofs'][-1]['sha256']='0'*64
                    if change=='components':altered['component_inventory_json']='{}'
                    with self.subTest(change=change):
                        self.assertFalse(security_cli._findings_consistent('security-licenses',dict(findings=[altered]),fixtures.NOW))


if __name__ == '__main__':
    unittest.main()
