"""New pure stack planning controls; no tool installation or command execution."""
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
                with mock.patch.dict(stacks.RUNNERS, {'rust': lambda context: []}):
                    refused = stacks.planned_stack_checks(root, 'pr', ['Cargo.toml'], registry={'rust': stack})
                self.assertEqual([row['check_id'] for row in refused], ['stack:rust'])
                self.assertEqual(refused[0]['applicability'], 'required')

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
