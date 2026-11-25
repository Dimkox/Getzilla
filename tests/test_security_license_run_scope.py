"""Owned native-run applicability fixtures; never provider or runtime qualification."""

import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".getzilla"))
from getzilla import security_image_authority as image_authority
from getzilla import security_licenses as licenses, security_cli as cli, security_image_producer as producer
from getzilla import security_python_target as target
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
                mock.patch('getzilla.expanded_security._policy_digest',return_value='f'*64), \
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
        with mock.patch.object(image_authority, "_LIVE", state), mock.patch.object(image_authority, "_GUARD", guard):
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
        effects = mock.patch.multiple(image_authority, _LIVE=state)
        effects.start()
        self.addCleanup(effects.stop)
        effect = mock.patch.object(image_authority, "_GUARD", guard)
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
        with mock.patch.object(image_authority, "_LIVE", None):
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
                    with mock.patch.object(image_authority, "_GUARD", object()), self.assertRaises(Exception):
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
