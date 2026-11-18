"""New pure stack planning controls; no tool installation or command execution."""

from __future__ import annotations
import json
import sys
from datetime import datetime, timezone
from getzilla import verification_plan
from getzilla.verification import _command_check
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from getzilla import stacks
from getzilla import stack_runners
from getzilla.stack_toolchains import Toolchain, Blocker
from getzilla.verification import CheckResult


class StackPlanTests(unittest.TestCase):
    def test_all_registered_plans_match_closed_actual_runner_results(self):
        cases = [
            ('rust', 'Cargo.toml', {'Cargo.lock': ''},
             {'toolchain:rust', 'cargo-fmt', 'cargo-clippy', 'cargo-build', 'cargo-test'}),
            ('go', 'go.mod', {}, {'toolchain:go', 'gofmt', 'go-vet', 'go-build', 'go-test'}),
            ('dotnet', 'owned.csproj', {'packages.lock.json': '{}'},
             {'toolchain:dotnet', 'dotnet-restore', 'dotnet-build', 'dotnet-test', 'dotnet-format', 'nuget-vulnerabilities'}),
            ('java', 'pom.xml', {'gradle.lockfile': '', 'mvnw': '', 'mvnw.cmd': ''},
             {'toolchain:java', 'maven-build'}),
            ('powershell', 'owned.Tests.ps1', {}, {'toolchain:powershell', 'psscriptanalyzer', 'pester'}),
        ]
        for identifier, marker, extra, expected in cases:
            with self.subTest(stack=identifier), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for name, value in {marker: '', **extra}.items():
                    (root / name).write_text(value)
                spec = {'default_version': '1', 'source': {'modules': {
                    'PSScriptAnalyzer': {'version': '1'}, 'Pester': {'version': '1'}}}}
                stack = stacks.Stack(identifier, (marker,), (), toolchain=spec)
                def command(_root, name, *args, **options):
                    return CheckResult(name, 'pass', 'closed callback')
                with mock.patch.object(stacks, 'tree_files', return_value=[marker, *extra]), \
                     mock.patch.object(stack_runners, 'powershell_interpreter', return_value='/owned/pwsh'):
                    rows = stacks.planned_stack_checks(root, 'pr', [marker], registry={identifier: stack})
                    self.assertEqual({row['check_id'] for row in rows}, expected)
                    observed, _ = stacks.stack_checks(root, 'pr', [marker], make=CheckResult, command=command,
                        registry={identifier: stack}, files=[marker], required_plan={'obligations': rows},
                        ensure=lambda *_: Toolchain(identifier, '1', root, ()))
                    self.assertEqual({row.name for row in observed}, expected)
                    self.assertTrue(all(row.status == 'pass' for row in observed))
                    blocked, _ = stacks.stack_checks(root, 'pr', [marker], make=CheckResult, command=command,
                        registry={identifier: stack}, files=[marker], required_plan={'obligations': rows},
                        ensure=lambda *_: Blocker('OWNED_UNAVAILABLE', 'closed fixture refusal'))
                    self.assertEqual({row.name for row in blocked}, expected)
                    self.assertTrue(all(row.status == 'fail' for row in blocked))

    def test_registry_planner_is_read_only_and_bound_to_actual_runner(self):
        self.assertTrue(callable(getattr(stacks, 'planned_stack_checks', None)))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'Cargo.toml').write_text('[package]\nname="owned"\n')
            stack = stacks.Stack('rust', ('Cargo.toml',), ('.rs',), toolchain={'version': '1'})
            with mock.patch.object(stacks, 'tree_files', return_value=['Cargo.toml']), \
                 mock.patch.object(stacks, 'default_ensure', side_effect=AssertionError('install forbidden')):
                plan = stacks.planned_stack_checks(root, 'pr', ['Cargo.toml'], registry={'rust': stack})
                self.assertEqual({row['check_id'] for row in plan},
                    {'toolchain:rust', 'cargo-lockfile', 'cargo-fmt', 'cargo-clippy', 'cargo-build', 'cargo-test'})
                self.assertTrue(all(row['applicability'] == 'required' for row in plan))
                replacement = mock.Mock(side_effect=AssertionError('mismatched runner must not execute'))
                with mock.patch.dict(stacks.RUNNERS, {'rust': replacement}), \
                     self.assertRaisesRegex(ValueError, 'required-plan-incomplete'):
                    stacks.planned_stack_checks(root, 'pr', ['Cargo.toml'], registry={'rust': stack})
                replacement.assert_not_called()

    def test_actual_missing_stack_results_cannot_silently_disappear(self):
        self.assertIn('required_plan', __import__('inspect').signature(stacks.stack_checks).parameters)
        stack = stacks.Stack('owned', ('owned.build',), ('.owned',), toolchain={'version': '1'})
        plan = {'obligations': [{'check_id': 'owned-test', 'applicability': 'required'}]}
        def runner(context):
            return []
        with mock.patch.dict(stacks.PLANNERS, {'owned': (runner, lambda context: ['owned-test'])}):
            results, metadata = stacks.stack_checks(Path('.'), 'pr', ['owned.build'], make=CheckResult,
                command=lambda *a, **kw: self.fail('command forbidden'), registry={'owned': stack},
                runners={'owned': runner}, files=['owned.build'], required_plan=plan)
        self.assertEqual([(row.name, row.status) for row in results], [('owned-test', 'fail')])
        self.assertEqual(metadata['checked'], ['owned'])

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)


    def write(self, name, text=''):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')


    def planner(self):
        self.assertTrue(hasattr(stacks, 'planned_stack_checks'),
                        'stack runners have no source-derived planned-check contract')
        return stacks.planned_stack_checks


    def test_rust_multi_project_plan_precedes_tools_and_untouched_is_explicit(self):
        self.write('a/Cargo.toml', '[package]\nname="a"\n')
        self.write('a/Cargo.lock')
        self.write('a/src/lib.rs')
        self.write('b/Cargo.toml', '[package]\nname="b"\n')
        self.write('b/src/lib.rs')
        planned = self.planner()(self.root, 'pr', ['a/src/lib.rs'])
        self.assertEqual({item['check_id'] for item in planned},
                         {'toolchain:rust', 'cargo-fmt:a', 'cargo-clippy:a', 'cargo-build:a', 'cargo-test:a'})
        untouched = self.planner()(self.root, 'pr', ['README.md'])
        self.assertEqual([(item['check_id'], item['applicability']) for item in untouched],
                         [('stack:rust', 'not_applicable')])
        self.assertEqual(untouched[0]['evidence']['touched'], [])


    def test_unknown_dynamic_adapter_is_plan_incomplete_before_it_runs(self):
        self.write('pay.cbl')
        def uncontracted(_context):
            self.fail('an adapter without a declared check contract must not run')
        registry = {'cobol': stacks.Stack('cobol', ('*.cbl',), ('.cbl',))}
        with self.assertRaisesRegex(ValueError, 'plan-incomplete'):
            self.planner()(self.root, 'pr', ['pay.cbl'], registry=registry,
                           runners={'cobol': uncontracted})
        checks, _ = stacks.stack_checks(self.root, 'pr', ['pay.cbl'], make=CheckResult,
            command=_command_check, registry=registry, runners={'cobol': uncontracted})
        self.assertEqual([(check.name, check.status) for check in checks], [('stack:cobol', 'fail')])


    def test_registered_adapter_cannot_omit_a_planned_check_after_an_actual_pass(self):
        self.write('pay.cbl')
        self.write('check.py', 'print("actual first check")\n')
        def runner(context):
            return [context.command(context.root, 'cobol-first', [sys.executable, 'check.py'], 30)]
        def plan(_context):
            return [{'check_id': name, 'applicability': 'required', 'reason': 'project check', 'evidence': {}}
                    for name in ('cobol-first', 'cobol-second')]
        registry = {'cobol': stacks.Stack('cobol', ('*.cbl',), ('.cbl',))}
        self.planner()
        checks, _ = stacks.stack_checks(self.root, 'pr', ['pay.cbl'], make=CheckResult,
            command=_command_check, registry=registry, runners={'cobol': runner},
            planners={'cobol': (runner, plan)})
        self.assertEqual([(check.name, check.status) for check in checks],
                         [('cobol-first', 'pass'), ('cobol-second', 'fail')])
        self.assertIn('actual first check', checks[0].stdout)
        self.assertEqual(checks[1].details[0]['code'], 'stack-check-not-run')


    def test_java_mode_and_powershell_test_applicability_use_source_selectors(self):
        self.write('pom.xml', '<project/>')
        self.write('mvnw', '#!/bin/sh\n')
        self.write('tools/Build.ps1', 'Write-Output 1')
        self.write('tools/Build.Tests.ps1', 'Describe test {}')
        fast = self.planner()(self.root, 'fast', ['pom.xml', 'tools/Build.ps1'])
        by_name = {item['check_id']: item for item in fast}
        self.assertEqual(by_name['java']['applicability'], 'not_applicable')
        self.assertNotIn('pester', by_name)
        full = self.planner()(self.root, 'pr', ['pom.xml', 'tools/Build.ps1'])
        self.assertEqual({item['check_id'] for item in full},
                         {'toolchain:java', 'maven-dependencies', 'maven-build',
                          'toolchain:powershell', 'psscriptanalyzer', 'pester'})


    def test_native_consumer_node_composer_and_pilot_obligations_cannot_disappear(self):
        self.write('package.json', json.dumps({'scripts': {'lint': 'eslint .', 'test': 'node test.js', 'build': 'tsc'}}))
        self.write('pnpm-lock.yaml', 'lockfileVersion: 9.0\n')
        self.write('tsconfig.json', '{}')
        self.write('composer.json', '{}')
        self.write('vendor/bin/phpunit')
        self.write('pilot/tests/test_example.py', 'import unittest\n')
        names = {item['check_id'] for item in verification_plan._native_obligations(
            self.root, 'pr', {'quality_profiles': ['php']}, {})}
        self.assertTrue({'pnpm-install', 'pnpm-lint', 'pnpm-test', 'pnpm-build', 'tsc',
                         'composer-validate', 'phpunit', 'pilot-unittest', 'php-lint'} <= names, names)


    def test_node_only_plan_records_python_not_applicable_and_qg_uses_that_proof(self):
        from getzilla.quality_gates import evaluate_quality_gate
        self.write('package.json', '{"scripts":{"test":"node test.js"}}')
        self.write('package-lock.json', '{}')
        self.write('tests/test_checkout.js', 'console.log("checkout")\n')
        obligations = verification_plan._native_obligations(self.root, 'pr', {}, {})
        # This unit checks native applicability; the P03 seven-family producer has its own integration coverage.
        obligations = [item for item in obligations if item['check_id'] != 'known-vulnerabilities']
        by_name = {item['check_id']: item for item in obligations}
        self.assertIn('python-unittest', by_name, 'missing Python inputs need an explicit source-derived declaration')
        self.assertEqual(by_name['python-unittest']['applicability'], 'not_applicable')
        self.assertEqual(by_name['ruff']['applicability'], 'not_applicable')
        self.assertEqual(by_name['bandit']['applicability'], 'not_applicable')
        from getzilla.util import tree_fingerprint
        plan = verification_plan.build_required_plan(self.root, mode='pr', context={},
            source={'fingerprint': tree_fingerprint(self.root)}, inventory={}, risk={},
            selection={'requested_profiles': None}, extra_obligations=obligations)
        checks = []
        for item in obligations:
            check = {'name': item['check_id'], 'status': 'skip' if item['applicability'] == 'not_applicable' else 'pass',
                     'summary': 'structural fixture', 'details': []}
            verification_plan.bind_result(plan, check)
            checks.append(check)
        queried_sources = []
        def reject_unexpected_source(*args, **_kwargs):
            queried_sources.append(args)
            raise AssertionError('native applicability fixture has no external data sources')
        decision = evaluate_quality_gate(mode='pr', checks=checks, required_plan=plan,
            current_binding=plan['binding'], now_utc=datetime(2026, 11, 3, tzinfo=timezone.utc),
            data_source_validator=reject_unexpected_source)
        self.assertEqual(queried_sources, [])
        self.assertEqual(decision.status, 'pass', decision.details)



class CollectedStackRepairTests(unittest.TestCase):
    def test_unavailable_obligation_cannot_credit_a_forged_fallback_pass(self):
        from datetime import datetime, timezone
        from getzilla import verification_plan as api, quality_gates
        stack = stacks.Stack('owned', ('owned.build',), ())
        def unknown(context):
            self.fail('unadmitted runner callback')
        with mock.patch.dict(stacks.RUNNERS, {'owned': unknown}), mock.patch.dict(stacks.PLANNERS, {}, clear=True):
            rows = stacks.planned_stack_checks(Path('.'), 'fast', ['owned.build'], registry={'owned': stack}, files=['owned.build'])
        self.assertEqual([row['check_id'] for row in rows], ['stack:owned'])
        with mock.patch.object(api, 'policy_binding', return_value={'digest': 'a' * 64}):
            plan = api.build_required_plan(Path('.'), mode='fast', context={}, source={}, inventory={}, risk={}, selection={},
                extra_obligations=[api.obligation(row['check_id'], evidence=row['evidence']) for row in rows])
        result = CheckResult('stack:owned', 'pass', 'unproved fallback assertion')
        api.bind_result(plan, result)
        decision = quality_gates.evaluate_quality_gate(mode='fast', checks=[result], required_plan=plan,
            current_binding=plan['binding'], now_utc=datetime(2026,11,9,tzinfo=timezone.utc),
            data_source_validator=lambda *args, **options: True)
        self.assertEqual(decision.status, 'fail')

    def observe(self, *, unknown=False, missing=False):
        from datetime import datetime, timezone
        from getzilla import verification_plan as api, quality_gates
        calls = []
        def known(context):
            calls.append('known')
            return [CheckResult('owned-required', 'pass', 'owned callback')]
        def replacement(context):
            calls.append('unknown')
            return [CheckResult('stack:owned', 'pass', 'unproved callback')]
        def forbidden(*args, **options):
            self.fail('unadmitted ensure/command callback')
        stack = stacks.Stack('owned', ('owned.build',), (), toolchain={'default_version': '1'})
        runner = replacement if unknown else known
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'owned.build').write_text('# inert public marker\n')
            with mock.patch.dict(stacks.RUNNERS, {'owned': runner}), \
                 mock.patch.dict(stacks.PLANNERS, {} if missing else {'owned': (known, lambda context: ['owned-required'])}, clear=missing):
                if unknown or missing:
                    with self.assertRaisesRegex(ValueError, 'required-plan-incomplete'):
                        stacks.planned_stack_checks(root, 'fast', ['owned.build'], registry={'owned': stack}, files=['owned.build'])
                    self.assertEqual(calls, [], 'unadmitted pair must not execute')
                    return calls, None, None
                rows = stacks.planned_stack_checks(root, 'fast', ['owned.build'], registry={'owned': stack}, files=['owned.build'])
                result, _ = stacks.stack_checks(root, 'fast', ['owned.build'], make=CheckResult, command=forbidden,
                    ensure=forbidden, registry={'owned': stack}, files=['owned.build'], required_plan={'obligations': rows})
                with mock.patch.object(api, 'policy_binding', return_value={'digest': 'a' * 64}):
                    plan = api.build_required_plan(root, mode='fast', context={}, source={}, inventory={}, risk={}, selection={},
                        extra_obligations=[api.obligation(row['check_id'], required=row['applicability']=='required', evidence=row['evidence']) for row in rows])
                for item in result:
                    api.bind_result(plan, item)
                decision = quality_gates.evaluate_quality_gate(mode='fast', checks=result, required_plan=plan,
                    current_binding=plan['binding'], now_utc=datetime(2026,11,9,tzinfo=timezone.utc),
                    data_source_validator=lambda *args, **options: True)
        return calls, result, decision

    def test_exact_registered_pair_runs_its_proved_result(self):
        calls, result, decision = self.observe()
        self.assertEqual(calls, ['known'])
        self.assertEqual([(row.name,row.status) for row in result], [('owned-required','pass')])
        self.assertEqual(decision.status, 'pass')

    def test_missing_or_mismatched_pair_never_executes_or_qualifies(self):
        for missing in (False, True):
            with self.subTest(missing=missing):
                calls, result, decision = self.observe(unknown=True, missing=missing)
                self.assertEqual(calls, [])
                self.assertIsNone(result, 'no runner result may be manufactured after plan refusal')
                self.assertIsNone(decision, 'no quality decision may credit an unavailable plan')


ROOT = Path(__file__).resolve().parents[1]
