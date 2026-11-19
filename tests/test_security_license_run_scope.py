"""Owned native-run applicability fixtures; never provider or runtime qualification."""

import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".getzilla"))
from getzilla import security_licenses as licenses, security_cli as cli, security_image_producer as producer
from getzilla import security_image_backend as native, security_python_target as target
from tests.test_security_licenses import artifact, wheel, manifest, inventory, dependency, POLICY

NOW = datetime(2026, 11, 18, 21, 0, tzinfo=timezone.utc)


class SelectedRunLicenseTests(unittest.TestCase):
    def test_checker_licence_gaps_cannot_reuse_previous_private_bindings(self):
        _, _, _, inv, source, run, binding = self.fixture()
        key = 'checker-tool:trivy:' + 'a' * 64
        context = self.live(inv, source, run, binding,
                            checker_tool_conditions={key: {'kind': 'checker-tool'}})
        context.state['license_checker_tools'] = {'stale': 'old proof'}
        output = {'status': 'fail', 'gaps': [{'code': 'go-native-unresolved'}], 'details': []}
        with mock.patch('getzilla.security_go_tool_inputs.checker_inventory', return_value={}) as inventory_of, \
                mock.patch.object(licenses, 'evaluate_artifacts', return_value=output) as evaluate, \
                mock.patch('getzilla.security_go_tool_inputs.qualified_tool_bindings') as qualify:
            result = context.checker_inputs(self.root, POLICY, now=NOW)
        self.assertEqual(result, output)
        self.assertNotIn('license_checker_tools', context.state)
        self.assertNotIn(key, context.passed)
        self.assertIn(output['gaps'][0], context.gaps)
        inventory_of.assert_called_once()
        evaluate.assert_called_once_with({}, self.root / 'checker-tools', POLICY, now=NOW)
        qualify.assert_not_called()

    def test_checker_licence_credit_needs_exact_independent_pair_binding(self):
        _, _, _, inv, source, run, binding = self.fixture()
        conditions = {'checker-tool:' + role + ':' + str(i) * 64: {'kind': 'checker-tool', 'role': role}
                      for i, role in enumerate(('trivy', 'buildkit'), 1)}
        context = self.live(inv, source, run, binding, checker_tool_conditions=conditions)
        output = {'status': 'pass', 'gaps': [], 'details': [
            {'kind': 'tool', 'family_record': {'owned_id': str(i) * 64}} for i in (1, 2)]}
        exact = {key: {'source_pins': value, 'family_artifact_id': str(i) * 64}
                 for i, (key, value) in enumerate(conditions.items(), 1)}
        with mock.patch('getzilla.security_go_tool_inputs.checker_inventory', return_value={}), \
                mock.patch.object(licenses, 'evaluate_artifacts', return_value=output), \
                mock.patch('getzilla.security_go_tool_inputs.qualified_tool_bindings', return_value=exact) as qualify, \
                mock.patch('getzilla.security_artifacts.artifact_identity', side_effect=lambda record: record['owned_id']):
            self.assertEqual(context.checker_inputs(self.root, POLICY, now=NOW), output)
            self.assertEqual(set(context.passed), set(conditions))
            qualify.assert_called_once()
            context.begin()
            qualify.return_value = {next(iter(exact)): exact[next(iter(exact))]}
            with self.assertRaises(licenses.ArtifactError):
                context.checker_inputs(self.root, POLICY, now=NOW)
        self.assertNotIn('license_checker_tools', context.state)
        self.assertFalse(context.passed)

    def test_selected_checker_source_preparation_retains_gaps_outside_raw_inventory(self):
        _, _, _, inv, source, run, binding = self.fixture()
        required = {'checker-tool:trivy:' + 'a' * 64: {'kind': 'checker-tool'}}
        context = self.live(inv, source, run, binding, checker_tool_conditions=required)
        report = {'records': [{'kind': 'tool', 'reference': 'checker-only-fixture'}],
                  'gaps': [{'code': 'go-source-missing'}]}
        original = copy.deepcopy(inv)
        with mock.patch('getzilla.security_go_tool_producer.prepare_tools', return_value=report) as prepare:
            records, preparation = cli._prepare_families(
                inv, self.root, self.root / 'tools', None, now=NOW, run_context=context)
        prepare.assert_called_once_with(cli.TRUSTED_ROOT, self.root, inventory_digest=inv['digest'], now=NOW)
        self.assertEqual(records, [])
        self.assertEqual(preparation['providers'], [{'kind': 'go-checker-tools-v1', 'report': report}])
        self.assertEqual(inv, original)

    def test_no_selected_checker_use_does_not_fetch_checker_sources(self):
        _, _, _, inv, source, run, binding = self.fixture()
        context = self.live(inv, source, run, binding)
        with mock.patch('getzilla.security_go_tool_producer.prepare_tools') as prepare:
            for scope in (None, context):
                cli._prepare_families(inv, self.root, self.root / 'tools', None, now=NOW, run_context=scope)
        prepare.assert_not_called()

    def test_family_provider_join_keeps_full_inventory_records_and_one_budget_owner(self):
        inventory=dict(digest='a'*64,tools=[dict(kind='github-action'),dict(kind='release-tool')])
        old=dict(kind='image')
        action_record=dict(kind='action')
        actions=dict(records=[action_record],source_inventory=inventory,bound_bytes=123,record_bytes=45)
        release=dict(records=[],frontiers=[dict(path='owned')],bound_bytes=67)
        with mock.patch('getzilla.security_release_tool_inputs.prepare',return_value=release) as raw, \
                mock.patch('getzilla.security_action_inputs.prepare_actions',return_value=actions) as node:
            records,providers=cli._prepare_families(inventory,self.root,self.root/'tools',[old],now=NOW)
        self.assertEqual(records,[old,action_record])
        raw.assert_called_once_with(inventory,self.root,self.root/'tools',now=NOW)
        node.assert_called_once_with(inventory,self.root,now=NOW)
        self.assertEqual(providers,dict(schema_version=1,providers=[
            dict(kind='opengrep-release-v1',frontiers=release['frontiers']),
            dict(kind='github-action-source-v1',report=actions)]))
        error=licenses.ArtifactError('artifact-action-origin','PRIVATE_MARKER')
        with mock.patch('getzilla.security_action_inputs.prepare_actions',side_effect=error),self.assertRaises(licenses.ArtifactError):
            cli._prepare_families(dict(tools=[dict(kind='github-action')]),self.root,self.root/'tools',None,now=NOW)
        self.assertEqual(cli._preparation_fault(error),dict(stage='action-source',error_kind='artifact',
            error_code='artifact-action-origin',errno=None))

    def test_checker_provisioned_tools_stay_mandatory_with_an_explicit_runtime_tcb(self):
        module=self.module()
        paths={'.getzilla/getzilla/security_acquisition.py':"TRIVY_VERSION='1.2.3'\nTRIVY_ARCHIVE_SHA256='"+'a'*64+"'\n",
            '.getzilla/getzilla/security_image_provision.py':"VERSION='4.5.6'\nARCHIVE_SHA256='"+'b'*64+"'\n"}
        for path,text in paths.items():
            named=self.root/path
            named.parent.mkdir(parents=True,exist_ok=True)
            named.write_text(text,encoding='utf-8')
        tools=module.checker_tools(self.root)
        self.assertEqual(set(tools),{'checker-tool:trivy:'+'a'*64,'checker-tool:buildkit:'+'b'*64})
        host,future,inactive,inv,source,run,binding=self.fixture()
        context=self.live(inv,source,run,binding,checker_tool_conditions=tools)
        self.catalog(host,inv,binding)
        result=licenses.evaluate_artifacts(inv,self.root,POLICY,now=NOW,target_binding=binding,run_context=context)
        self.assertEqual(result['selected_run']['status'],'fail-for-selected-run')
        self.assertEqual(sum(gap['code']=='required-checker-tool-unverified' for gap in result['selected_run']['gaps']),2)
        self.assertTrue(result['selected_run']['tcb_assumptions'])
        joined=dict(status='pass',gaps=[],details=[dict(kind='tool',family_record=dict(owned_id='1'*64)),
            dict(kind='tool',family_record=dict(owned_id='2'*64))])
        with self.assertRaises(Exception):
            context._checker_output(joined)
        bindings={key:dict(source_pins=value,family_artifact_id=str(index)*64)
            for index,(key,value) in enumerate(tools.items(),1)}
        context.state['license_checker_tools']=bindings
        with mock.patch('getzilla.security_artifacts.artifact_identity',side_effect=lambda record:record['owned_id']):
            context._checker_output(joined)
            partial=copy.deepcopy(joined)
            partial['details'].pop()
            with self.assertRaises(Exception):
                context._checker_output(partial)
            wrong=copy.deepcopy(bindings)
            first=next(iter(wrong))
            wrong[first]['source_pins']['archive_sha256']='f'*64
            context.state['license_checker_tools']=wrong
            with self.assertRaises(Exception):
                context._checker_output(joined)
        context.state['license_checker_tools']=bindings
        named=self.root/'.getzilla/getzilla/security_image_provision.py'
        named.write_text(paths['.getzilla/getzilla/security_image_provision.py']+"VERSION='4.5.7'\n",encoding='utf-8')
        with self.assertRaises(Exception):
            module.checker_tools(self.root)

    def test_aggregate_reobserves_a_self_consistent_smaller_manifest_scope(self):
        from getzilla import ci_admission as admission
        checker='c'*40
        policy=json.dumps(POLICY).encode()
        path=self.root/'.getzilla/config/license-policy.json'
        path.parent.mkdir(parents=True)
        path.write_bytes(policy)
        directory=self.root/'saved'
        directory.mkdir()
        (directory/'security-run-inputs.json').write_text('{}',encoding='utf-8')
        observed=dict(claim=dict(required_ids=['one','two']),conditions={'one':{'kind':'host'},'two':{'kind':'family'}})
        record=dict(checker=dict(head=checker,tree='d'*40,selected_ref=checker,selection='operator-variable'),
            files=[dict(path='security-run-inputs.json')],scope_expectation=copy.deepcopy(observed))
        def git(_root,*args):
            values={('rev-parse',checker+'^{commit}'):checker,('rev-parse',checker+'^{tree}'):'d'*40,
                ('cat-file','-s',checker+':.getzilla/config/license-policy.json'):str(len(policy)),
                ('rev-parse','HEAD'):'a'*40,('rev-parse','HEAD^{tree}'):'b'*40,('status','--porcelain'):''}
            return values[args]
        environment=dict(GETZILLA_OPERATOR_CHECKER=checker,GITHUB_REPOSITORY='Dimkox/Getzilla',
            GITHUB_RUN_ID='42',GITHUB_RUN_ATTEMPT='1',GITHUB_SHA='a'*40,GITHUB_EVENT_NAME='pull_request')
        with mock.patch.object(admission,'_git',side_effect=git), \
                mock.patch.object(admission.subprocess,'run',return_value=mock.Mock(stdout=policy)), \
                mock.patch.dict(admission.os.environ,environment), \
                mock.patch('getzilla.security_license_scope.declaration_expectation',return_value=observed) as reobserve:
            result=admission._reobserve_scope(self.root,directory,record,'42','1')
            self.assertIs(type(result),admission._ScopeExpectation)
            self.assertEqual(reobserve.call_args.args[3]['checker_sha'],checker)
            subset=copy.deepcopy(record)
            subset['scope_expectation']['claim']['required_ids']=['one']
            subset['scope_expectation']['conditions'].pop('two')
            with self.assertRaises(ValueError):
                admission._reobserve_scope(self.root,directory,subset,'42','1')
            altered=copy.deepcopy(record)
            altered['checker']['head']='0'*40
            with self.assertRaises(ValueError):
                admission._reobserve_scope(self.root,directory,altered,'42','1')

    def test_build_requirement_ids_do_not_depend_on_a_caller_consumer_subset(self):
        host,future,inactive,inv,source,run,binding=self.fixture()
        dep=dependency(name='setuptools',manifest='trust-ci/pyproject.toml',usage='build')
        inv['dependencies'].append(dep)
        inv['builds']=[dict(dockerfile='trust-ci/Dockerfile.test',build_sha256='9'*64)]
        binding['source_pins'][target.digest(target._subject(dep))]={
            **binding['source_pins'][target.digest(target._subject(host))],
            'context_sha256':target._context_key(dep)}
        binding['ci_uses']={'consumers':[]}
        required,_,_=self.module().requirements(inv,binding)
        self.assertIn('ci-install:'+'9'*64,required)
        self.assertIn('build-input:'+'9'*64+':'+target.digest(target._subject(dep)),required)

    def test_envelope_reobserves_source_profile_and_cannot_choose_subset(self):
        module=self.module()
        host,future,inactive,inv,source,run,binding=self.fixture()
        graphs=target.closure_graphs(self.root,inv)
        profile=cli.input_profile(source,inv,{key:str(self.root/key) for key in ('database','artifacts','tools')},
            run,'f'*64,now=NOW,package_target=binding['target'],package_pins=binding['source_pins'],package_graphs=graphs)
        inputs=dict(schema_version=1,profile=profile,inventory=inv,selection=None,catalog=None)
        with mock.patch('getzilla.security_inventory.declared_inventory',return_value=inv), \
                mock.patch('getzilla.security_cli._policy_digest',return_value='f'*64), \
                mock.patch('getzilla.security_licenses.load_policy',return_value=POLICY), \
                mock.patch.object(module,'checker_tools',return_value={}):
            expected=module.declaration_expectation(self.root,self.root,inputs,source,run,now=NOW,scratch=self.root)
            self.assertEqual(expected['claim']['required_ids'],['host:'+target.digest(target._subject(host))])
            for variant in ('inventory','pins','source','profile'):
                altered=copy.deepcopy(inputs)
                if variant=='inventory':
                    altered['inventory']['dependencies'].pop()
                elif variant=='pins':
                    altered['profile']['python_source_pins'][target.digest(target._subject(host))]['marker_active']=False
                elif variant=='source':
                    altered['profile']['source']['head_sha']='0'*40
                else:
                    altered['profile']['profile_sha256']='0'*64
                with self.subTest(variant=variant),self.assertRaises(Exception):
                    module.declaration_expectation(self.root,self.root,altered,source,run,now=NOW,scratch=self.root)
            (self.root/host['manifest']).write_text('example==2.0.0\n',encoding='utf-8')
            with self.assertRaises(Exception):
                module.declaration_expectation(self.root,self.root,inputs,source,run,now=NOW,scratch=self.root)

    def test_preparation_uses_sealed_current_run_not_global_future_coverage(self):
        from getzilla.expanded_security import CHECK_FAMILIES

        host, future, inactive, inv, source, run, binding = self.fixture()
        context = self.live(inv, source, run, binding)
        self.catalog(host, inv, binding)
        result = licenses.evaluate_artifacts(
            inv, self.root, POLICY, now=NOW, target_binding=binding, run_context=context
        )
        profile = dict(
            profile_sha256=binding["profile_sha256"],
            source=source,
            inventory_sha256=inv["digest"],
            policy_sha256="f" * 64,
            observed_counts=dict(dependencies=3, tools=0, images=0),
            required_sources={key: [] for key in CHECK_FAMILIES},
        )
        obligations = [
            dict(
                check_id=key,
                applicability="required" if key == "security-inventory" else "not_applicable",
                evidence=dict(inventory_sha256=inv["digest"], policy_sha256="f" * 64, complete=True),
                data_sources=[],
            )
            for key in CHECK_FAMILIES
        ]
        prepared = cli.preparation_result(profile, source, source, obligations, [], result, now=NOW)
        self.assertEqual(prepared["status"], "prepared", prepared["gaps"])
        self.assertIs(prepared["overall_coverage_complete"], False)
        self.assertEqual(prepared["preparation_scope"], "selected-native-security-run")
        forged = copy.deepcopy(result)
        forged["selected_run"]["conditions"] = []
        refused = cli.preparation_result(profile, source, source, obligations, [], forged, now=NOW)
        self.assertEqual(refused["status"], "unavailable")
        for field in ("gaps", "raw_coverage"):
            with self.subTest(field=field):
                forged = copy.deepcopy(result)
                forged[field] = [] if field == "gaps" else {"complete": True}
                refused = cli.preparation_result(profile, source, source, obligations, [], forged, now=NOW)
                self.assertEqual(refused["status"], "unavailable")

    def test_finalizer_names_scoped_pass_and_keeps_raw_global_incomplete(self):
        from tests.test_security_cli import SecurityCliTests

        host, future, inactive, inv, source, run, binding = self.fixture()
        context = self.live(inv, source, run, binding)
        self.catalog(host, inv, binding)
        result = licenses.evaluate_artifacts(
            inv, self.root, POLICY, now=NOW, target_binding=binding, run_context=context
        )
        _source, checks = SecurityCliTests().report()
        for check in checks:
            detail = check["details"][0]
            detail["inventory_sha256"] = inv["digest"]
            for proof in detail["data_sources"]:
                proof["acquisition"]["last_verified_sync_utc"] = NOW.isoformat()
                proof["acquisition"]["source_published_at"] = NOW.isoformat()
        detail = next(check["details"][0] for check in checks if check["name"] == "security-licenses")
        detail.update(
            findings=result["selected_run"]["details"],
            selected_run=result["selected_run"],
            raw_coverage=result["raw_coverage"],
            raw_license_diagnostics=result["gaps"],
        )
        report = cli.finalize_report(source, source, checks, inv["digest"], "f" * 64, now=NOW)
        self.assertEqual(report["status"], "pass-for-selected-run", report["qualification_gaps"])
        self.assertIs(report["overall_coverage_complete"], False)
        from getzilla.ci_admission import _selected_scope,_security,_ScopeExpectation,_SCOPE_SEAL
        record=dict(report=report,run_id=run['run_id'],attempt=run['run_attempt'],
            scope_expectation=_ScopeExpectation(dict(claim=context.claim,conditions=context.required),_SCOPE_SEAL),
            checker=dict(head=source['checker_sha'],tree=source['checker_tree_sha'],selected_ref=source['checker_sha'],
                selection='operator-variable',boundary='separate-checkout'))
        self.assertTrue(_selected_scope(record,NOW))
        self.assertEqual(_security(record,source['head_sha'],source['tree_sha'],NOW),[])
        globalized=copy.deepcopy(record)
        globalized['report']['status']='pass'
        self.assertTrue(_security(globalized,source['head_sha'],source['tree_sha'],NOW))
        for field in ('conditions','profile_sha256','source'):
            with self.subTest(admission=field):
                altered=copy.deepcopy(record)
                altered['report']['acceptance_scope'][field]=[] if field=='conditions' else '0'*64 if field=='profile_sha256' else {}
                self.assertFalse(_selected_scope(altered,NOW))
        missing=copy.deepcopy(record)
        missing.pop('scope_expectation')
        self.assertFalse(_selected_scope(missing,NOW))
        imported=copy.deepcopy(record)
        imported['scope_expectation']=dict(imported['scope_expectation'])
        self.assertFalse(_selected_scope(imported,NOW))
        missing=copy.deepcopy(record)
        missing['scope_expectation']['conditions']={}
        missing['scope_expectation']['claim']['required_ids']=[]
        self.assertFalse(_selected_scope(missing,NOW))
        detail["selected_run"]["status"] = "pass"
        self.assertNotEqual(
            cli.finalize_report(source, source, checks, inv["digest"], "f" * 64, now=NOW)["status"],
            "pass-for-selected-run",
        )

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=ROOT / ".getzilla/runtime")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def module(self):
        self.assertIsNotNone(
            importlib.util.find_spec("getzilla.security_license_scope"),
            "missing privately bound selected-run license applicability",
        )
        from getzilla import security_license_scope

        return security_license_scope

    def test_exact_backend_credit_needs_sealed_live_installed_terms_and_preserves_other_gaps(self):
        from tests.test_ci_image_license_inputs import CIImageTargetBindingTests
        from getzilla import security_ci_inputs as ci
        fixture = CIImageTargetBindingTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        project, (installed, binding) = fixture.backend_context()
        consumer = fixture.uses['consumers'][0]
        build = dict(dockerfile=consumer['recipe'], build_sha256=consumer['build_sha256'])
        inv = inventory(*consumer['dependencies'], builds=[build])
        inv['digest'] = fixture.parent['inventory_sha256']
        parent = dict(fixture.parent, source_pins=consumer['source_pins'])
        context = self.live(inv, fixture.source, fixture.run, parent)
        context.state['ci_uses'] = fixture.uses
        wheel = 'setuptools-84.1.0.dist-info/WHEEL'
        license_path = 'setuptools-84.1.0.dist-info/licenses/LICENSE'
        detail = dict(ecosystem='PyPI', package='setuptools', version='84.1.0',
            manifest='trust-ci/pyproject.toml', context=dict(usage='build'), status='pass', distribution='internal',
            artifact_sha256='9' * 64, license_files=[dict(path=license_path)], notice_files=[],
            delivery=dict(image=consumer['image'], members={'site/'+wheel:'1'*64, 'site/'+license_path:'2'*64}))
        output = dict(status='pass', gaps=[], inventory_digest=installed['digest'], policy_digest='b'*64, details=[detail])
        key = 'build-input:'+consumer['build_sha256']+':'+target.digest(target._subject(project))
        self.assertIn(key, context.required)
        with self.assertRaises(ValueError):
            context.build_inputs(binding, output)
        ci.seal_evaluation(binding, output, _entry=ci._EVALUATION_ENTRY)
        context.build_inputs(binding, output)
        self.assertEqual(set(context.passed), {key})
        self.assertIn('ci-install:'+consumer['build_sha256'], set(context.required)-context.passed.keys())
        for failure in ('restored-json', 'wrong-wheel', 'wrong-image', 'missing-term-custody'):
            context.passed.clear()
            changed = copy.deepcopy(output)
            if failure == 'wrong-wheel':
                changed['details'][0]['artifact_sha256'] = 'f'*64
            elif failure == 'wrong-image':
                changed['details'][0]['delivery']['image'] = 'other@sha256:'+'f'*64
            elif failure == 'missing-term-custody':
                changed['details'][0]['delivery']['members'].pop('site/'+license_path)
            if failure != 'restored-json':
                ci.seal_evaluation(binding, changed, _entry=ci._EVALUATION_ENTRY)
            with self.subTest(failure=failure), self.assertRaises(ValueError):
                context.build_inputs(binding, changed)
            self.assertEqual(context.passed, {})

    def fixture(self):
        host = dependency(manifest=".getzilla/config/python-quality-requirements.txt", usage="build-ci")
        future = dependency(name="future", manifest="future/requirements.txt", usage="runtime")
        future.pop("distribution")
        inactive = dependency(name="inactive", manifest=host["manifest"], usage="build-ci")
        inv = inventory(host, future, inactive, builds=[])
        declarations = {
            host["manifest"]: 'example==1.0.0\ninactive==1.0.0; python_version < "0"\n',
            future["manifest"]: "future==1.0.0\n",
        }
        inv["manifests"] = []
        for name, text in declarations.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8", newline="\n")
            inv["manifests"].append(dict(path=name, sha256=hashlib.sha256(text.encode()).hexdigest()))
        inv["digest"] = target.digest({k: v for k, v in inv.items() if k != "digest"})
        source = dict(
            head_sha="a" * 40,
            tree_sha="b" * 40,
            checker_sha="c" * 40,
            checker_tree_sha="d" * 40,
            candidate_clean=True,
            checker_clean=True,
            same_project=True,
        )
        run = dict(
            provider="github-actions", repository="owned/project", run_id="42", run_attempt="1", head_sha="a" * 40
        )
        observed = target.observe_target()
        pins = target.source_pins(self.root, inv, observed)
        binding = dict(
            target=observed,
            source=source,
            run=run,
            inventory_sha256=inv["digest"],
            profile_sha256="e" * 64,
            source_pins=pins,
        )
        return host, future, inactive, inv, source, run, binding

    def test_activation_reobserves_source_pins_and_needs_private_native_entry(self):
        module = self.module()
        host, future, inactive, inv, source, run, binding = self.fixture()
        guard = object()
        state = dict(source=source, run=run, native_guard=guard, root=self.root, declared_inventory=inv)
        profile = dict(
            python_target=binding["target"],
            python_source_pins=binding["source_pins"],
            source=source,
            run=run,
            inventory_sha256=inv["digest"],
        )
        profile["profile_sha256"] = target.digest(profile)
        with mock.patch.object(producer, "_LIVE", state), mock.patch.object(native, "_GUARD", guard):
            with self.assertRaises(Exception):
                module.activate(self.root, profile)
            module.activate(self.root, profile, _entry=producer._LICENSE_ENTRY)
            self.assertIsNotNone(module.current(self.root, inv, target.binding(profile)))
            wrong = copy.deepcopy(profile)
            wrong["python_source_pins"][target.digest(target._subject(inactive))]["marker_active"] = True
            wrong["profile_sha256"] = target.digest({k: v for k, v in wrong.items() if k != "profile_sha256"})
            with self.assertRaises(Exception):
                module.activate(self.root, wrong, _entry=producer._LICENSE_ENTRY)

    def live(self, inv, source, run, binding,*,checker_tool_conditions=None):
        module = self.module()
        guard = object()
        state = dict(
            source=source,
            run=run,
            builds={},
            build_inputs=[],
            native_guard=guard,
            root=self.root,
            declared_inventory=copy.deepcopy(inv),
            license_entry=producer._LICENSE_ENTRY,
            license_binding=copy.deepcopy(binding),
            license_profile=dict(profile_sha256=binding["profile_sha256"], source=source),
            license_checker_declarations=dict(checker_tool_conditions or {}),
        )
        effects = mock.patch.multiple(producer, _LIVE=state)
        effects.start()
        self.addCleanup(effects.stop)
        effect = mock.patch.object(native, "_GUARD", guard)
        effect.start()
        self.addCleanup(effect.stop)
        return module.current(self.root, inv, binding)

    def catalog(self, host, inv, binding):
        payload = wheel(
            extra_files={
                "example-1.0.0.dist-info/WHEEL": "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n"
            }
        )
        record = artifact(self.root, host, payload)
        record["context"] = target.artifact_context(host)
        record["python_target"] = target.wheel_observation(
            record["filename"], target.archive_files(payload, record["filename"]), binding, dependency=host
        )
        manifest(self.root, inv, [record], acquired=NOW)

    def test_default_global_result_remains_incomplete_and_json_cannot_select_run(self):
        module = self.module()
        host, future, inactive, inv, source, run, binding = self.fixture()
        self.catalog(host, inv, binding)
        with mock.patch.object(producer, "_LIVE", None):
            self.assertIsNone(module.current(self.root, inv, binding))
            result = licenses.evaluate_artifacts(inv, self.root, POLICY, now=NOW, target_binding=binding)
        self.assertEqual(result["status"], "fail")
        self.assertNotIn("selected_run", result)
        with self.assertRaises(Exception):
            licenses.evaluate_artifacts(
                inv, self.root, POLICY, now=NOW, target_binding=binding, run_context={"status": "pass"}
            )

    def test_selected_run_keeps_future_inactive_diagnostics_but_requires_actual_host(self):
        host, future, inactive, inv, source, run, binding = self.fixture()
        context = self.live(inv, source, run, binding)
        self.catalog(host, inv, binding)
        original = copy.deepcopy(inv)
        result = licenses.evaluate_artifacts(
            inv, self.root, POLICY, now=NOW, target_binding=binding, run_context=context
        )
        self.assertEqual(result["status"], "overall-incomplete")
        self.assertEqual(result["raw_coverage"]["status"], "fail")
        self.assertFalse(result["selected_run"]["overall_coverage_complete"])
        self.assertEqual(result["selected_run"]["status"], "pass-for-selected-run", result["selected_run"]["gaps"])
        self.assertTrue(result["gaps"])
        self.assertEqual(inv, original)
        self.assertEqual(context.acquisition_dependencies(), [host])
        self.assertTrue(self.module().validate_result(result["selected_run"]))
        changed = copy.deepcopy(result["selected_run"])
        changed["context_sha256"] = "0" * 64
        self.assertFalse(self.module().validate_result(changed))
        (self.root / "manifest.json").unlink()
        failed = licenses.evaluate_artifacts(
            inv, self.root, POLICY, now=NOW, target_binding=binding, run_context=context
        )
        self.assertEqual(failed["selected_run"]["status"], "fail-for-selected-run")
        self.assertFalse(self.module().validate_result(result["selected_run"]))

    def test_missing_actual_family_and_unobserved_build_consumer_stay_mandatory(self):
        host, future, inactive, inv, source, run, binding = self.fixture()
        subject = dict(
            kind="github-action",
            reference="owned/action@" + "f" * 40,
            manifest=".github/workflows/owned.yml",
            line=1,
            source_sha256="2" * 64,
            usage="build-ci",
        )
        inv["tools"] = [subject]
        row = dict(build_sha256="3" * 64, dockerfile="trust-ci/runner.Dockerfile", recipe_sha256="4" * 64)
        inv["builds"] = [row]
        context = self.live(inv, source, run, binding)
        self.catalog(host, inv, binding)
        result = licenses.evaluate_artifacts(
            inv, self.root, POLICY, now=NOW, target_binding=binding, run_context=context
        )
        self.assertEqual(result["selected_run"]["status"], "fail-for-selected-run")
        self.assertTrue(any("family" in gap["code"] or "tool" in gap["code"] for gap in result["selected_run"]["gaps"]))
        self.assertTrue(any("consumer" in gap["code"] for gap in result["selected_run"]["gaps"]))

    def test_changed_guard_source_inventory_or_profile_cannot_reuse_scope(self):
        host, future, inactive, inv, source, run, binding = self.fixture()
        context = self.live(inv, source, run, binding)
        for variant in ("guard", "inventory", "profile"):
            with self.subTest(variant=variant):
                if variant == "guard":
                    with mock.patch.object(native, "_GUARD", object()), self.assertRaises(Exception):
                        context.validate(inv, binding)
                elif variant == "inventory":
                    changed = copy.deepcopy(inv)
                    changed["dependencies"].pop()
                    with self.assertRaises(Exception):
                        context.validate(changed, binding)
                else:
                    changed = copy.deepcopy(binding)
                    changed["profile_sha256"] = "0" * 64
                    with self.assertRaises(Exception):
                        context.validate(inv, changed)
