"""Owned tiny wheels and fixed-origin bytes; no network, subprocess or package execution."""
from contextlib import ExitStack, contextmanager, redirect_stdout
from datetime import datetime, timezone
import copy
import hashlib
import io
import inspect
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'.getzilla'))
from getzilla import security_license_acquisition as acquisition, security_artifacts as artifacts
from getzilla import security_licenses as licenses, security_cli as cli
from getzilla import security_image_producer as producer, expanded_security as expanded

NOW = datetime(2026, 11, 18, tzinfo=timezone.utc)
MIT = json.loads((ROOT/'tests/fixtures/security-license-texts.json').read_bytes())['MIT']['text'].encode()


class PythonArtifactTargetTests(unittest.TestCase):
    def setUp(self):
        effects = ExitStack()
        self.addCleanup(effects.close)
        for name in ('socket.socket', 'socket.getaddrinfo', 'subprocess.Popen', 'subprocess.run'):
            effects.enter_context(mock.patch(name, side_effect=AssertionError('outside effects denied')))
        temporary = tempfile.TemporaryDirectory(dir=ROOT/'.getzilla/runtime')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def target(self):
        self.assertIn('target_binding',inspect.signature(acquisition.acquire_pypi).parameters,'missing real observed Python target input')
        from getzilla import security_python_target as target
        return target

    def fixture(self, *, tag='cp313-cp313-manylinux_2_17_x86_64', wheel_tag=None, requires_python=None, dynamic=None):
        filename = 'owned-1.0-'+tag+'.whl'
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.writestr('owned-1.0.dist-info/METADATA', 'Metadata-Version: 2.4\nName: owned\nVersion: 1.0\nLicense-Expression: MIT\nLicense-File: LICENSE\n'+('Requires-Python: '+requires_python+'\n' if requires_python else '')+('Dynamic: '+dynamic+'\n' if dynamic else '')+'\n')
            archive.writestr('owned-1.0.dist-info/WHEEL', 'Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: '+(wheel_tag or tag)+'\n\n')
            archive.writestr('owned-1.0.dist-info/licenses/LICENSE', MIT)
        payload = stream.getvalue()
        sha = hashlib.sha256(payload).hexdigest()
        url = 'https://files.pythonhosted.org/packages/owned/'+filename
        item = dict(filename=filename, digests={'sha256': sha}, url=url, yanked=False, packagetype='bdist_wheel')
        index = dict(info=dict(name='owned',version='1.0'), urls=[item])
        dep = dict(ecosystem='PyPI', name='owned',version='1.0',manifest='requirements.txt',usage='build-ci',extras=[])
        return dep, index, payload

    def facts(self):
        target = self.target()
        tags = ('cp313-cp313-manylinux_2_17_x86_64', 'py3-none-any')
        descriptor = dict(schema_version=1, implementation='cpython', python_version='3.13.1',
            platform='linux-x86_64', abi='cpython-313-x86_64-linux-gnu',
            tags_sha256=target.digest(list(tags)), tag_count=len(tags),
            marker_environment={'python_version':'3.13','python_full_version':'3.13.1','sys_platform':'linux'})
        return descriptor, tags

    def binding(self, inventory):
        target = self.target()
        descriptor, _ = self.facts()
        profile = dict(source=dict(head_sha='a'*40,tree_sha='b'*40,checker_sha='c'*40,checker_tree_sha='d'*40,
            candidate_clean=True,checker_clean=True,same_project=True),
            run=dict(provider='github-actions',repository='owned/project',run_id='42',run_attempt='1',head_sha='a'*40),
            inventory_sha256=inventory['digest'],profile_sha256='e'*64,python_target=descriptor)
        return target.binding(profile)

    def test_real_current_target_is_observed_and_substituted_descriptor_refuses(self):
        target = self.target()
        observed = target.observe_target()
        self.assertEqual(target.validate_target(observed), observed)
        for key in ('python_version','platform','abi','tags_sha256'):
            bad = copy.deepcopy(observed)
            bad[key] = 'unknown' if key != 'tags_sha256' else '0'*64
            with self.assertRaises(artifacts.ArtifactError):
                target.validate_target(bad)

    def test_native_wheel_requires_real_target_and_exact_catalog_observation(self):
        target = self.target()
        dep, index, payload = self.fixture()
        inventory = dict(complete=True,gaps=[],digest='a'*64,dependencies=[dep],tools=[],images=[])
        with self.assertRaises(artifacts.ArtifactError):
            acquisition._select(index,dep)
        descriptor, tags = self.facts()
        with mock.patch.object(target,'_facts',return_value=(descriptor,tags)):
            binding = self.binding(inventory)
            def fetch(url, *, maximum):
                body = json.dumps(index).encode() if url == artifacts.pypi_index_url('owned','1.0') else payload
                self.assertLessEqual(len(body),maximum)
                return body
            bundle = acquisition.acquire_pypi([dep], self.root, inventory_digest=inventory['digest'],
                now=NOW, fetch=fetch, target_binding=binding)
            record = bundle['records'][0]
            self.assertEqual(record['python_target']['binding_sha256'],target.digest(binding))
            self.assertEqual(record['filename'],index['urls'][0]['filename'])
            policy = dict(schema_version=1,project_repository='github.com/owned/project',auto_allow=['MIT'],usage_distribution={'build-ci':'internal'})
            report = licenses.evaluate_artifacts(inventory,self.root,policy,now=NOW,target_binding=binding)
            self.assertEqual(report['status'],'pass',report)
            self.assertEqual(report['details'][0]['context']['python_target_sha256'],target.digest(descriptor))
            self.assertEqual(licenses.evaluate_artifacts(inventory,self.root,policy,now=NOW)['status'],'fail')
            licenses.artifact_catalog_source(inventory,self.root,policy,now=NOW,target_binding=binding)
            for field in ('source','run','inventory_sha256','profile_sha256'):
                bad = copy.deepcopy(binding)
                if field == 'source':
                    bad[field]['head_sha']='f'*40
                elif field == 'run':
                    bad[field]['run_attempt']='2'
                else:
                    bad[field]='f'*64
                self.assertEqual(licenses.evaluate_artifacts(inventory,self.root,policy,now=NOW,target_binding=bad)['status'],'fail')
            altered = copy.deepcopy(record)
            altered['python_target']['wheel_tags']=['py3-none-any']
            self.assertNotEqual(artifacts.artifact_identity(altered),artifacts.artifact_identity(record))
            with self.assertRaises(artifacts.ArtifactError):
                target.verify_record(altered,payload,binding)

    def test_abi_platform_internal_wheel_and_ambiguous_selection_refuse(self):
        target = self.target()
        descriptor,tags = self.facts()
        with mock.patch.object(target,'_facts',return_value=(descriptor,tags)):
            for tag in ('cp312-cp312-manylinux_2_17_x86_64','cp313-cp313-win_amd64'):
                dep,index,payload = self.fixture(tag=tag)
                with self.assertRaises(artifacts.ArtifactError):
                    target.select_dependency(index,dep,self.binding(dict(digest='a'*64)))
            dep,index,payload = self.fixture(wheel_tag='cp312-cp312-manylinux_2_17_x86_64')
            with self.assertRaises(artifacts.ArtifactError):
                acquisition.acquire_pypi([dep],self.root,inventory_digest='a'*64,now=NOW,
                    fetch=lambda url,**options: json.dumps(index).encode() if url.endswith('/json') else payload,
                    target_binding=self.binding(dict(digest='a'*64)))
            self.assertFalse((self.root/'manifest.json').exists())
            index['urls'].append(dict(index['urls'][0]))
            with self.assertRaises(artifacts.ArtifactError):
                target.select_dependency(index,dep,self.binding(dict(digest='a'*64)))

    def test_profile_binds_current_target_without_rewriting_source_inventory(self):
        target = self.target()
        descriptor,tags = self.facts()
        source=dict(head_sha='a'*40,tree_sha='b'*40,checker_sha='c'*40,checker_tree_sha='d'*40,
            candidate_clean=True,checker_clean=True,same_project=False)
        inventory=dict(complete=True,gaps=[],digest='a'*64,dependencies=[],tools=[],images=[])
        original=copy.deepcopy(inventory)
        roots=dict(database='/owned/db',artifacts='/owned/artifacts',tools='/owned/tools')
        run=dict(provider='github-actions',repository='owned/project',run_id='42',run_attempt='1',head_sha='a'*40)
        with mock.patch.object(target,'_facts',return_value=(descriptor,tags)):
            profile=cli.input_profile(source,inventory,roots,run,'b'*64,now=NOW,package_target=descriptor)
            self.assertEqual(profile['python_target'],descriptor)
            cli.validate_input_profile(profile,source,inventory,roots,run,'b'*64,now=NOW)
            wrong=copy.deepcopy(descriptor)
            wrong['abi']='different'
            with mock.patch.object(target,'_facts',return_value=(wrong,tags)),self.assertRaises(artifacts.ArtifactError):
                cli.validate_input_profile(profile,source,inventory,roots,run,'b'*64,now=NOW)
        self.assertEqual(inventory,original)

    def test_native_pipeline_and_callback_keep_the_same_expected_target(self):
        target=self.target()
        descriptor,tags=self.facts()
        request=dict(root=str(self.root/'source'),database=str(self.root/'db'),artifacts=str(self.root/'artifacts'),
            tools=str(self.root/'tools'),profile=str(self.root/'profile'),preparation=str(self.root/'preparation'),
            report=str(self.root/'report'),run={})
        @contextmanager
        def produce(*arguments):
            yield {},{}
        with mock.patch.object(target,'_facts',return_value=(descriptor,tags)), \
                mock.patch.object(producer,'produce',produce), \
                mock.patch.object(producer,'_pipeline_tools',return_value=self.root/'tools'), \
                mock.patch.object(cli,'source_binding',return_value={}), \
                mock.patch.object(cli,'validate_selection_authority'), \
                mock.patch.object(cli,'prepare_inputs',side_effect=[{}, {'status':'prepared'}]) as prepare, \
                mock.patch.object(cli,'evaluate',return_value={'status':'fail'}) as evaluate, \
                mock.patch.object(cli,'_atomic'), redirect_stdout(io.StringIO()):
            producer._pipeline(request,self.root,object())
            self.assertEqual([call.kwargs['package_target'] for call in prepare.call_args_list],[descriptor,descriptor])
            self.assertEqual(evaluate.call_args.kwargs['package_target'],descriptor)
            expected=self.binding(dict(digest='a'*64))
            profile=dict(source=expected['source'],run=expected['run'],inventory_sha256=expected['inventory_sha256'],
                profile_sha256=expected['profile_sha256'],python_target=descriptor)
            self.assertEqual(expanded._license_target({'GETZILLA_SECURITY_INPUT_PROFILE':json.dumps(profile)}),{'target_binding':expected})

    def test_current_target_cannot_clear_declared_factory_offline_delivery(self):
        target=self.target()
        descriptor,tags=self.facts()
        dep,index,payload=self.fixture()
        dep['manifest']='factory/uv.lock'
        inventory=dict(complete=True,gaps=[],digest='a'*64,dependencies=[dep],tools=[],images=[])
        policy=dict(schema_version=1,project_repository='github.com/Dimkox/Getzilla',auto_allow=['MIT'],
            usage_distribution={'build-ci':'internal'},factory_offline_profile=dict(
                profile='ubuntu-24.04-x86_64-cpython312',distribution='redistributed',
                lock_sha256='a'*64,wheel_inventory_sha256='b'*64,builder_sha256='c'*64))
        with mock.patch.object(target,'_facts',return_value=(descriptor,tags)):
            expected=self.binding(inventory)
            acquisition.acquire_pypi([dep],self.root,inventory_digest='a'*64,now=NOW,target_binding=expected,
                fetch=lambda url,**options: json.dumps(index).encode() if url.endswith('/json') else payload)
            report=licenses.evaluate_artifacts(inventory,self.root,policy,now=NOW,target_binding=expected)
        self.assertEqual(report['status'],'fail')
        self.assertIn('artifact-target-scope-unobserved',{gap['code'] for gap in report['gaps']})

    def test_existing_universal_default_and_unknown_use_scope_stay_strict(self):
        self.target()
        dep,index,payload=self.fixture(tag='py3-none-any')
        inventory=dict(complete=True,gaps=[],digest='a'*64,dependencies=[dep],tools=[],images=[])
        acquisition.acquire_pypi([dep],self.root,inventory_digest='a'*64,now=NOW,
            fetch=lambda url,**options: json.dumps(index).encode() if url.endswith('/json') else payload)
        policy=dict(schema_version=1,project_repository='github.com/owned/project',auto_allow=['MIT'],usage_distribution={'build-ci':'internal'})
        self.assertEqual(licenses.evaluate_artifacts(inventory,self.root,policy,now=NOW)['status'],'pass')
        policy['usage_distribution']={}
        refused=licenses.evaluate_artifacts(inventory,self.root,policy,now=NOW)
        self.assertEqual(refused['status'],'fail')
        self.assertIn('license-scope-unknown',{gap['code'] for gap in refused['gaps']})

    def test_python_version_constraints_cannot_borrow_compatible_filename_tags(self):
        target=self.target()
        descriptor,tags=self.facts()
        dep,index,payload=self.fixture(requires_python='>=3.14')
        with mock.patch.object(target,'_facts',return_value=(descriptor,tags)):
            expected=self.binding(dict(digest='a'*64))
            with self.assertRaises(artifacts.ArtifactError):
                acquisition.acquire_pypi([dep],self.root,inventory_digest='a'*64,now=NOW,target_binding=expected,
                    fetch=lambda url,**options: json.dumps(index).encode() if url.endswith('/json') else payload)
            index['urls'][0]['requires_python']='>=3.14'
            with self.assertRaises(artifacts.ArtifactError):
                target.select_dependency(index,dep,expected)

    def test_source_hash_pins_fence_current_target_and_rehashed_registry(self):
        target=self.target()
        self.assertTrue(callable(getattr(target,'source_pins',None)))
        descriptor,tags=self.facts()
        dep,index,payload=self.fixture()
        source=self.root/'requirements.txt'
        source.write_text('owned==1.0 --hash=sha256:'+'0'*64+'\n')
        inventory=dict(digest='a'*64,dependencies=[dep],manifests=[dict(path='requirements.txt',
            sha256=hashlib.sha256(source.read_bytes()).hexdigest())])
        with mock.patch.object(target,'_facts',return_value=(descriptor,tags)):
            expected=self.binding(inventory)
            expected['source_pins']=target.source_pins(self.root,inventory,descriptor)
            with self.assertRaises(artifacts.ArtifactError):
                target.select_dependency(index,dep,expected)
            source.write_text('owned==1.0 --hash=sha256:'+index['urls'][0]['digests']['sha256']+'\n')
            inventory['manifests'][0]['sha256']=hashlib.sha256(source.read_bytes()).hexdigest()
            expected['source_pins']=target.source_pins(self.root,inventory,descriptor)
            selected=target.select_dependency(index,dep,expected)
            self.assertEqual(selected['artifact_sha256'],index['urls'][0]['digests']['sha256'])
            self.assertEqual(acquisition._select(index,selected)['filename'],index['urls'][0]['filename'])
            bad=copy.deepcopy(index)
            bad['urls'][0]['digests']['sha256']='f'*64
            with self.assertRaises(artifacts.ArtifactError):
                target.select_dependency(bad,dep,expected)
            source.write_text('owned==1.0 --hash=sha256:'+'f'*64+'\n')
            with self.assertRaises(artifacts.ArtifactError):
                target.source_pins(self.root,inventory,descriptor)

    def test_actual_httpx_equality_wildcard_keeps_exact_covered_version(self):
        try:
            matched=licenses._satisfies('1.0.9','==1.*','PyPI')
        except (artifacts.ArtifactError,licenses.VulnerabilityError):
            self.fail('actual httpx Requires-Dist httpcore==1.* needs PEP440 support')
        self.assertTrue(matched)
        self.assertFalse(licenses._satisfies('2.0.0','==1.*','PyPI'))
        self.assertFalse(licenses._satisfies('1.0.9','!=1.*','PyPI'))
        with self.assertRaises(artifacts.ArtifactError):
            licenses._satisfies('1.0.9','1.^','PyPI')

    def test_actual_pydantic_marker_uses_only_explicit_target_and_selected_extras(self):
        marker="(python_version >= '3.9' and platform_system == 'Windows') and extra == 'timezone'"
        dep=dict(ecosystem='PyPI',extras=['timezone'])
        try:
            active=licenses._marker_required(marker,dep,dict(python_version='3.12',platform_system='Linux'))
        except artifacts.ArtifactError:
            self.fail('actual pydantic compound PEP508 marker needs bounded resolver support')
        self.assertFalse(active)
        self.assertTrue(licenses._marker_required(marker,dep,dict(python_version='3.12',platform_system='Windows')))
        self.assertFalse(licenses._marker_required(marker,dict(ecosystem='PyPI',extras=[]),dict(python_version='3.12',platform_system='Windows')))
        with self.assertRaises(artifacts.ArtifactError):
            licenses._marker_required(marker,dep,dict(python_version='3.12'))
        with self.assertRaises(artifacts.ArtifactError):
            licenses._marker_required("unknown_target == 'private'",dep,{})

    def test_verified_final_wheel_dynamic_retains_concrete_metadata_and_source_refusal(self):
        dep,index,payload=self.fixture(tag='py3-none-any',dynamic='license-file')
        inv=dict(complete=True,gaps=[],digest='a'*64,dependencies=[dep],tools=[],images=[])
        acquisition.acquire_pypi([dep],self.root,inventory_digest='a'*64,now=NOW,
            fetch=lambda url,**options: json.dumps(index).encode() if url.endswith('/json') else payload)
        policy=dict(schema_version=1,project_repository='github.com/owned/project',auto_allow=['MIT'],usage_distribution={'build-ci':'internal'})
        self.assertEqual(licenses.evaluate_artifacts(inv,self.root,policy,now=NOW)['status'],'pass')
        files=artifacts.archive_files(payload,index['urls'][0]['filename'])
        metadata=artifacts.package_metadata(files,'PyPI',index['urls'][0]['filename'])
        self.assertEqual(metadata['dynamic'],['license-file'],'do not erase Dynamic from adapter output')
        with self.assertRaises(artifacts.ArtifactError):
            licenses._license_evidence(files,dict(metadata,final_wheel=True),{'MIT'},['MIT'])
        for forbidden in ('Name','Version','Metadata-Version','private-field', 'License,Name'):
            bad=dict(metadata,dynamic=[forbidden])
            with self.subTest(field=forbidden), self.assertRaises(artifacts.ArtifactError):
                licenses._license_evidence(files,bad,{'MIT'},['MIT'],final_wheel=True)
        sdist_files={'owned-1.0/PKG-INFO':files['owned-1.0.dist-info/METADATA'],'owned-1.0/LICENSE':MIT}
        source=artifacts.package_metadata(sdist_files,'PyPI','owned-1.0.tar.gz')
        with self.assertRaises(artifacts.ArtifactError):
            licenses._license_evidence(sdist_files,source,{'MIT'},['MIT'])
