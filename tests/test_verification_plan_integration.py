"""Owned contract controls; only opted-in tiny projects execute native runners."""
from __future__ import annotations

import copy
import contextlib
from datetime import datetime, timezone
import inspect
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from getzilla import verification


class OwnedReceiptFixtureTests(unittest.TestCase):
    """The shared fixture proves current contracts without borrowing real inputs."""

    def reporter(self):
        from tests import _support
        reporter = getattr(_support, 'owned_verification_report', None)
        self.assertTrue(callable(reporter), 'missing source-bound owned report fixture')
        return reporter

    def prepare(self, root):
        from getzilla import state
        from getzilla.continuity import submit
        from getzilla.change import start_change
        from tests._support import prepare_review_source, synchronize_fixture_scope
        state.bind_session('owned-receipt')
        submit(root, 'Fix owned report boundary', 'owned-receipt')
        state.update_route(root, delivery_lane='full')
        start_change(root)
        synchronize_fixture_scope(root)
        prepare_review_source(root)

    def test_owned_project_declares_an_empty_security_world_before_initial_commit(self):
        from tests._support import project_copy
        self.assertIn('verification_fixture', inspect.signature(project_copy).parameters)
        from getzilla.security_inventory import collect_inventory
        with project_copy(git=True, verification_fixture=True) as root:
            inventory = collect_inventory(root)
            self.assertTrue(inventory['complete'], inventory['gaps'])
            self.assertEqual([inventory[key] for key in ('dependencies', 'images', 'tools')], [[], [], []])
            self.assertEqual([path.name for path in (root / '.getzilla/templates').iterdir()], ['change'])
            self.assertTrue((root / '.getzilla/owned-verification-fixture.json').is_file())

    def test_current_report_and_receipt_bind_then_reject_a_same_tree_new_head(self):
        reporter = self.reporter()
        from tests._support import project_copy, observed_context
        from getzilla import receipts, state
        from getzilla.verification_plan import report_gaps
        import subprocess
        with project_copy(git=True, verification_fixture=True) as root:
            self.prepare(root)
            report = reporter(root)
            self.assertEqual(report['check_status'], 'pass', report['checks'])
            self.assertEqual(report_gaps(root, report), [])
            receipts.write_receipt(root, 'verification', 'pass', details=report, expected_context=observed_context(root))
            self.assertEqual(receipts.get_receipt(root, state.get_active_route(root)['route_id'], 'verification')['details'], report)
            subprocess.run(['git', 'commit', '--allow-empty', '-qm', 'new owned head'], cwd=root, check=True)
            self.assertTrue(report_gaps(root, report))

    def test_real_validation_refuses_missing_duplicate_unplanned_and_forged_security_results(self):
        reporter = self.reporter()
        from tests._support import project_copy
        from getzilla.verification_plan import report_gaps
        with project_copy(git=True, verification_fixture=True) as root:
            self.prepare(root)
            original = reporter(root)
            self.assertEqual(report_gaps(root, original), [])
            variants = []
            missing = copy.deepcopy(original)
            missing.pop('required_plan')
            variants.append(missing)
            forged_plan = copy.deepcopy(original)
            forged_plan['required_plan']['digest'] = 'f' * 64
            variants.append(forged_plan)
            for field in ('source', 'context'):
                stale = copy.deepcopy(original)
                stale['required_plan']['binding'][field] = {'owned_stale': True}
                variants.append(stale)
            duplicate = copy.deepcopy(original)
            duplicate['checks'].append(copy.deepcopy(duplicate['checks'][0]))
            variants.append(duplicate)
            unplanned = copy.deepcopy(original)
            unplanned['checks'].append({'name': 'invented-producer', 'status': 'pass', 'summary': 'not owned', 'details': []})
            variants.append(unplanned)
            absent = copy.deepcopy(original)
            absent['checks'] = [row for row in absent['checks'] if row['name'] != 'security-inventory']
            variants.append(absent)
            for field in ('family', 'inventory_sha256', 'policy_sha256', 'data_sources'):
                forged = copy.deepcopy(original)
                row = next(row for row in forged['checks'] if row['name'] == 'security-inventory')
                detail = next(detail for detail in row['details'] if detail.get('kind') == 'security-result')
                detail[field] = [{'unavailable': True}] if field == 'data_sources' else 'forged'
                variants.append(forged)
            for variant in variants:
                with self.subTest(variant=len(variant['checks'])):
                    self.assertTrue(report_gaps(root, variant))

    def test_historical_status_only_storage_remains_readable_but_unqualified(self):
        self.reporter()
        from tests._support import project_copy, observed_context
        from getzilla import receipts, state
        from getzilla.verification_plan import report_gaps
        with project_copy(git=True, verification_fixture=True) as root:
            self.prepare(root)
            historical = {'captured': 'historical fixture bytes\n' * 3000}
            receipts.write_receipt(root, 'verification', 'pass', details=historical, expected_context=observed_context(root))
            actual = receipts.get_receipt(root, state.get_active_route(root)['route_id'], 'verification')
            self.assertEqual(actual['details'], historical)
            self.assertTrue(report_gaps(root, actual['details']))

    def test_owned_provider_failure_cannot_be_replaced_with_all_pass_results(self):
        reporter = self.reporter()
        from tests._support import project_copy
        from getzilla.verification_plan import report_gaps
        import subprocess
        with project_copy(git=True, verification_fixture=True) as root:
            (root / 'broken.py').write_text('def broken(:\n')
            subprocess.run(['git', 'add', 'broken.py'], cwd=root, check=True)
            subprocess.run(['git', 'commit', '-qm', 'owned syntax refusal'], cwd=root, check=True)
            self.prepare(root)
            report = reporter(root)
            self.assertEqual(report['check_status'], 'fail')
            self.assertTrue(any(row['name'] == 'ruff' and row['status'] == 'fail' for row in report['checks']))
            self.assertTrue(report_gaps(root, report))

    def test_added_declared_dependency_restores_required_security_sources(self):
        reporter = self.reporter()
        from tests._support import project_copy
        import subprocess
        with project_copy(git=True, verification_fixture=True) as root:
            (root / 'requirements.txt').write_text('owned-fixture-package==1.0.0\n')
            subprocess.run(['git', 'add', 'requirements.txt'], cwd=root, check=True)
            subprocess.run(['git', 'commit', '-qm', 'declared owned dependency'], cwd=root, check=True)
            self.prepare(root)
            report = reporter(root)
            plan = report['required_plan']
            security = {row['check_id']: row for row in plan['obligations'] if row['check_id'].startswith('security-')
                        or row['check_id'] == 'known-vulnerabilities'}
            self.assertEqual(security['known-vulnerabilities']['applicability'], 'required')
            self.assertEqual(security['security-licenses']['evidence']['dependency_count'], 1)
            self.assertTrue(security['known-vulnerabilities']['data_sources'][0]['unavailable'])
            self.assertEqual(report['check_status'], 'fail')

    def test_owned_provider_scope_restores_environment_and_callbacks_after_failure(self):
        import os
        from tests._support import owned_verification_providers, project_copy
        keys = ('GETZILLA_SECURITY_DB', 'GETZILLA_OSV_DB', 'GETZILLA_OSV_ONLINE',
                'GETZILLA_SECURITY_TOOLS', 'GETZILLA_SECURITY_ARTIFACTS', 'GETZILLA_TEST_WORKERS')
        outer = {key: 'owned-outer-selector' for key in keys}
        original_ruff, original_bandit = verification._ruff, verification._bandit
        with mock.patch.dict(os.environ, outer):
            with self.assertRaisesRegex(RuntimeError, 'owned interruption'):
                with project_copy(git=True, verification_fixture=True) as root:
                    with owned_verification_providers(root):
                        self.assertEqual(os.environ['GETZILLA_TEST_WORKERS'], '1')
                        self.assertEqual(os.environ['GETZILLA_OSV_ONLINE'], '0')
                        for key in keys:
                            if key not in ('GETZILLA_TEST_WORKERS', 'GETZILLA_OSV_ONLINE'):
                                self.assertTrue(Path(os.environ[key]).is_relative_to(root))
                        raise RuntimeError('owned interruption')
            self.assertEqual({key: os.environ[key] for key in keys}, outer)
        self.assertIs(verification._ruff, original_ruff)
        self.assertIs(verification._bandit, original_bandit)


class RequiredDispatchTests(unittest.TestCase):
    def test_forged_optionality_cannot_borrow_current_policy_binding(self):
        from getzilla.verification_plan import bind_result, build_required_plan, obligation, digest
        with mock.patch('getzilla.verification_plan.policy_binding', return_value={'digest': 'a' * 64}):
            current = build_required_plan(Path('.'), mode='fast', context={}, source={}, inventory={}, risk={},
                selection={}, extra_obligations=[obligation('owned')])
        forged = copy.deepcopy(current)
        forged['obligations'][0].update(applicability='not_applicable', evidence={'kind': 'forged-source-exclusion'})
        forged['digest'] = digest({key: value for key, value in forged.items() if key != 'digest'})
        result = verification.CheckResult('owned', 'skip', 'forged optionality')
        bind_result(forged, result)
        with mock.patch('getzilla.verification_plan.current_required_plan', return_value=current):
            gate = verification._required_quality_gate(Path('.'), 'fast', [], [result], forged)
        self.assertEqual(gate.status, 'fail')

    def test_proved_optional_security_does_not_block_independent_dispatch(self):
        from getzilla.verification_plan import bind_result, build_required_plan, obligation
        from getzilla.quality_gates import evaluate_quality_gate
        with mock.patch('getzilla.verification_plan.policy_binding', return_value={'digest': 'a' * 64}):
            plan = build_required_plan(Path('.'), mode='pr', context={}, source={}, inventory={}, risk={}, selection={},
                extra_obligations=[obligation('owned-optional', required=False, evidence={'kind': 'complete-empty-source'}),
                                   obligation('owned-later')])
        results, observed = [], []
        dispatcher = verification._CheckDispatch(results, 'pr', required_plan=plan)
        dispatcher.run('owned-optional', lambda: verification.CheckResult('owned-optional', 'skip', 'complete source contains no applicable objects'))
        dispatcher.run('owned-later', lambda: observed.append('ran') or verification.CheckResult('owned-later', 'pass', 'closed'))
        self.assertEqual(observed, ['ran'])
        for result in results:
            bind_result(plan, result)
        gate = evaluate_quality_gate(mode='pr', checks=results, required_plan=plan, current_binding=plan['binding'],
            now_utc=datetime(2026,11,9,tzinfo=timezone.utc), data_source_validator=lambda *a, **kw: True)
        # This minimal unit omits mandatory PR checks, but its proved optional result is not a skip refusal.
        self.assertFalse(any(row['path'] == 'owned-optional' for row in gate.details))
        refused = verification._CheckDispatch([], 'pr', required_plan=plan)
        refused.run('owned-later', lambda: verification.CheckResult('owned-later', 'skip', 'same wording cannot waive required work'))
        self.assertEqual(refused.blocked_by, 'owned-later')

    def test_no_python_inputs_has_explicit_applicability_record(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(verification, '_ruff', return_value=verification.CheckResult('ruff', 'pass', 'unit')), \
             mock.patch.object(verification, '_bandit', return_value=verification.CheckResult('bandit', 'pass', 'unit')):
            result = verification._python_checks(Path(directory), 'fast', None, [], required_plan={'digest': 'a' * 64})
        selected = [row for row in result if row.name == 'python-unittest']
        self.assertEqual([(row.status, row.summary) for row in selected], [('skip', 'no native Python discovery inputs')])

    def test_native_compiler_keeps_factory_marker_and_sandbox_exclusion_without_running(self):
        from getzilla import verification_plan as api
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'factory/tests').mkdir(parents=True)
            (root / 'factory/pyproject.toml').write_text('[project]\nname="owned"\n')
            (root / 'factory/tests/run_disposable_exit.py').write_text('# inert public declaration\n')
            with contextlib.ExitStack() as patches:
                patches.enter_context(mock.patch.dict('os.environ', {'GETZILLA_VERIFY_CAPABILITY': 'repository-sandbox'}, clear=True))
                for module, name, value in ((api, 'tree_fingerprint', 'a' * 64),
                        (verification, '_existing_quality_paths', []), (verification, 'python_check_selection', (True, True)),
                        (verification, '_semgrep_config', None), (verification, '_trivy_config_present', False)):
                    patches.enter_context(mock.patch.object(module, name, return_value=value))
                patches.enter_context(mock.patch('getzilla.stacks.planned_stack_checks', return_value=[]))
                rows = api._native_obligations(root, 'pr', {}, {}, files=[], profiles=['base'], bases=[], documents=None)
            named = {row['check_id']: row for row in rows}
        self.assertEqual(named['factory-unit']['applicability'], 'required')
        self.assertEqual(named['factory-postgres-exit']['applicability'], 'not_applicable')
        self.assertEqual(named['factory-postgres-exit']['evidence']['reason'],
                         'repository-sandbox has no nested-container/database capability')
        self.assertIn('pytest', named)
        self.assertEqual(named['coverage']['applicability'], 'not_applicable')

    def test_focused_contract_uses_source_owned_driver_with_original_bound(self):
        self.assertIn('required_plan', inspect.signature(verification._focused_landing_contract).parameters)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'test_owned.py'
            path.write_text('import unittest\nclass Owned(unittest.TestCase):\n def test_owned(self): pass\n')
            value = {'name': 'criterion-tests', 'status': 'pass', 'summary': 'owned', 'details': []}
            with mock.patch('getzilla.criterion_tests.run_required_tests', return_value=value) as driver:
                result = verification._focused_landing_contract(root, {'focused_tests': ['test_owned.py']}, required_plan={})
            driver.assert_called_once_with(root, ['test_owned.py'], timeout=300)
            self.assertEqual((result.name, result.status), ('static-seo-landing-contract', 'pass'))

    def test_explicit_frontend_missing_manifest_remains_a_named_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            result = verification._node(Path(directory), 'pr', required_plan={'digest': 'a' * 64})
        self.assertEqual([(row.name, row.status) for row in result], [('package-json', 'fail')])

    def test_final_gate_rederives_current_plan_and_refuses_changed_binding(self):
        self.assertTrue(callable(getattr(verification, '_required_quality_gate', None)))
        from getzilla.verification_plan import bind_result, build_required_plan, obligation
        with mock.patch('getzilla.verification_plan.policy_binding', return_value={'digest': 'a' * 64}):
            plan = build_required_plan(Path('.'), mode='fast', context={}, source={}, inventory={}, risk={},
                                       selection={}, extra_obligations=[obligation('owned')])
        result = verification.CheckResult('owned', 'pass', 'closed')
        bind_result(plan, result)
        with mock.patch('getzilla.verification_plan.current_required_plan', return_value=plan) as current:
            gate = verification._required_quality_gate(Path('.'), 'fast', [], [result], plan)
        self.assertEqual(gate.status, 'pass')
        current.assert_called_once()
        changed = copy.deepcopy(plan)
        changed['binding']['source'] = {'head': 'different'}
        with mock.patch('getzilla.verification_plan.current_required_plan', return_value=changed):
            self.assertEqual(verification._required_quality_gate(Path('.'), 'fast', [], [result], plan).status, 'fail')

    def test_nested_required_refusal_prevents_later_callback(self):
        self.assertIn('required_plan', inspect.signature(verification._CheckDispatch).parameters)
        plan = {'digest': 'a' * 64, 'obligations': []}
        results, called = [], []
        dispatch = verification._CheckDispatch(results, 'pr', required_plan=plan)
        self.assertIs(dispatch.required_plan, plan)
        dispatch.run('required-first', lambda: verification.CheckResult('required-first', 'fail', 'owned refusal'))
        dispatch.run('later', lambda: called.append('ran'))
        self.assertEqual(called, [])
        self.assertEqual([item.name for item in results], ['required-first', 'later'])
        self.assertEqual(results[1].details[0]['execution'], 'not_executed')

    def test_python_same_plan_reaches_core_and_applicable_exit_after_pytest(self):
        self.assertIn('required_plan', inspect.signature(verification._python_checks).parameters)
        with tempfile.TemporaryDirectory(prefix='owned-python-plan-') as directory:
            root = Path(directory)
            (root / 'tests').mkdir()
            (root / 'pyproject.toml').write_text('[project]\nname="public-fixture"\n')
            (root / 'tests/test_public.py').write_text('def test_public():\n    assert True\n')
            (root / 'factory/tests').mkdir(parents=True)
            (root / 'factory/tests/run_disposable_exit.py').write_text('# inert; never executed\n')
            plan, received, commands = {'digest': 'a' * 64}, [], []
            def core(_root, _mode, _pytest, **options):
                received.append(options.get('required_plan'))
                return [verification.CheckResult('pytest', 'pass', 'closed unit'),
                        verification.CheckResult('coverage', 'skip', 'pytest runner owns tests; measure unittest trees only')]
            def command(_root, name, argv, timeout, **options):
                commands.append(name)
                return verification.CheckResult(name, 'pass', 'closed callback')
            with mock.patch.object(verification, 'command_exists', return_value=True), \
                 mock.patch.object(verification, '_ruff', return_value=verification.CheckResult('ruff', 'pass', 'unit')), \
                 mock.patch.object(verification, '_bandit', return_value=verification.CheckResult('bandit', 'pass', 'unit')), \
                 mock.patch.object(verification, '_core_python_checks', side_effect=core), \
                 mock.patch.object(verification, '_command_check', side_effect=command):
                result = verification._python_checks(root, 'pr', None, [], required_plan=plan)
            self.assertEqual(received, [plan])
            self.assertEqual(commands, ['factory-postgres-exit'])
            self.assertEqual(result[-1].name, 'factory-postgres-exit')

    def test_shared_selectors_compile_without_commands_or_installation(self):
        self.assertTrue(callable(getattr(verification, 'python_check_selection', None)))
        self.assertTrue(callable(getattr(verification, 'node_check_selection', None)))
        self.assertTrue(callable(getattr(verification, 'composer_check_selection', None)))
        with tempfile.TemporaryDirectory(prefix='owned-selector-plan-') as directory:
            root = Path(directory)
            (root / 'tests').mkdir()
            (root / 'tests/test_public.py').write_text('# source only\n')
            (root / 'package.json').write_text(json.dumps({'scripts': {'test': 'public-test', 'build': 'public-build'}}))
            (root / 'package-lock.json').write_text('{}')
            (root / 'composer.json').write_text('{}')
            (root / 'vendor/bin').mkdir(parents=True)
            (root / 'vendor/bin/phpunit').write_text('# inert\n')
            with mock.patch.object(verification, '_command_check', side_effect=AssertionError('command forbidden')), \
                 mock.patch.object(verification, '_node_toolchain', side_effect=AssertionError('install forbidden')):
                self.assertEqual(verification.python_check_selection(root), (False, True))
                selected = verification.node_check_selection(root, 'pr')
                self.assertIn('npm-test', selected[3])
                self.assertIn('npm-build', selected[3])
                self.assertEqual([item[0] for item in verification.composer_check_selection(root)], ['phpunit'])


class NativeSecurityProjectionTests(unittest.TestCase):
    def test_native_projection_retains_205_structured_findings_and_all_source_proof(self):
        self.assertTrue(callable(getattr(verification, 'known_vulnerability_check', None)))
        findings = [{'id': 'PUBLIC-' + str(n), 'package': 'owned', 'version': '1', 'manifest': 'public.lock'}
                    for n in range(205)]
        detail = {'kind': 'security-result', 'schema_version': 1, 'family': 'vulnerabilities',
                  'outcome': 'finding', 'findings': findings, 'accepted': [{'id': 'PUBLIC-ACCEPTED'}],
                  'gaps': [{'code': 'owned-gap'}], 'data_sources': [{'source_id': 'owned-proof'}],
                  'inventory_sha256': 'a' * 64, 'policy_sha256': 'b' * 64}
        value = {'name': 'known-vulnerabilities', 'status': 'fail', 'summary': '205 owned findings', 'details': [detail]}
        with mock.patch.object(verification, 'known_vulnerability_check', return_value=copy.deepcopy(value)) as producer:
            result = verification._known_vulnerabilities(Path('.'))
        producer.assert_called_once()
        structured = [row for row in result.details if row.get('kind') == 'security-result']
        self.assertEqual(structured, [detail])
        self.assertEqual(len([row for row in result.details if 'message' in row]), 200)
        self.assertEqual(result.status, 'fail')

    def test_seven_family_binding_rejects_wrong_missing_and_duplicate_family(self):
        from getzilla.verification_plan import (SECURITY_FAMILIES, bind_result, build_required_plan,
                                              obligation, plan_gaps)
        # Policy/source reader is injected only for this pure contract fixture.
        with mock.patch('getzilla.verification_plan.policy_binding', return_value={'digest': 'a' * 64}):
            plan = build_required_plan(Path('.'), mode='fast', context={}, source={}, inventory={}, risk={}, selection={},
                                       extra_obligations=[obligation(name) for name in SECURITY_FAMILIES])
        results = []
        for name, family in SECURITY_FAMILIES.items():
            value = {'name': name, 'status': 'pass', 'details': [{'kind': 'security-result', 'schema_version': 1,
                     'family': family, 'outcome': 'pass', 'data_sources': []}]}
            bind_result(plan, value)
            results.append(value)
        kwargs = {'current_binding': plan['binding'], 'now_utc': datetime(2026, 11, 9, tzinfo=timezone.utc),
                  'data_source_validator': lambda source, **options: True}
        self.assertEqual(plan_gaps(plan, results, **kwargs), [])
        for modified in (results[:-1], [*results, results[0]]):
            self.assertTrue(plan_gaps(plan, modified, **kwargs))
        wrong = copy.deepcopy(results)
        wrong[0]['details'][0]['family'] = 'wrong-family'
        self.assertTrue(plan_gaps(plan, wrong, **kwargs))
