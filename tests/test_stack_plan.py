"""The required plan must know consumer checks before any toolchain or runner executes."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import stacks, verification_plan  # noqa: E402
from getzilla.verification import CheckResult, _command_check  # noqa: E402


class StackPlanTests(unittest.TestCase):
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
                         {'cargo-fmt:a', 'cargo-clippy:a', 'cargo-build:a', 'cargo-test:a'})
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
                         {'maven-dependencies', 'maven-build', 'psscriptanalyzer', 'pester'})

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
        plan = verification_plan.build_required_plan(self.root, mode='pr', context=None,
            source={}, inventory={}, risk={}, selection={}, extra_obligations=obligations)
        checks = []
        for item in obligations:
            check = {'name': item['check_id'], 'status': 'skip' if item['applicability'] == 'not_applicable' else 'pass',
                     'summary': 'structural fixture', 'details': []}
            verification_plan.bind_result(plan, check)
            checks.append(check)
        decision = evaluate_quality_gate(mode='pr', checks=checks, required_plan=plan,
            current_binding=plan['binding'], now_utc=datetime(2026, 11, 3, tzinfo=timezone.utc))
        self.assertEqual(decision.status, 'pass', decision.details)


if __name__ == '__main__':
    unittest.main()
