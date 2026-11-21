from __future__ import annotations

import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.language_quality.adapters import swift
from getzilla.language_quality.models import AdapterRequest, ToolOutput


class SwiftAdapterTests(unittest.TestCase):
    def request(self, tool: str = 'swiftlint', **changes) -> AdapterRequest:
        request = AdapterRequest(
            tool_id=tool, driver='cli', launcher=('/tools/' + tool,),
            scope='changed', files=('Sources/My File.swift',),
        )
        return replace(request, **changes)

    def output(self, code: int = 0, data=None, stderr: str = '') -> ToolOutput:
        return ToolOutput(code, json.dumps([] if data is None else data), stderr)

    def lint_violation(self) -> dict:
        return dict(file='/workspace/Sources/App.swift', line=4, character=2,
                    severity='Error', type='Force Cast', rule_id='force_cast',
                    reason='Avoid forced casts.')

    def format_violation(self) -> dict:
        return {'file': '/workspace/Sources/App.swift', 'line': 4,
                'rule_id': 'indent', 'reason': 'Use consistent indentation.'}

    def test_both_tools_support_changed_and_full_scopes(self) -> None:
        for tool in ('swiftlint', 'swiftformat'):
            with self.subTest(tool=tool):
                cap = swift.capabilities(tool, 'cli')
                self.assertTrue(cap.incremental)
                self.assertTrue(cap.full)

    def test_rejects_unknown_tool_and_driver(self) -> None:
        for tool, driver in (('swift-format', 'cli'), ('swiftlint', 'gradle')):
            with self.subTest(tool=tool, driver=driver):
                with self.assertRaises(ValueError):
                    swift.capabilities(tool, driver)

    def test_swiftlint_plans_read_only_json_without_cache(self) -> None:
        argv = swift.build_argv(self.request(config_path='.swiftlint.yml'))
        self.assertEqual(argv[:2], ('/tools/swiftlint', 'lint'))
        for flag in ('--strict', '--force-exclude', '--no-cache'):
            self.assertIn(flag, argv)
        self.assertEqual(argv[argv.index('--reporter') + 1], 'json')
        self.assertEqual(argv[argv.index('--config') + 1], './.swiftlint.yml')
        self.assertEqual(argv[-1], './Sources/My File.swift')
        for flag in ('--fix', '--autocorrect', '--format', '--write-baseline'):
            self.assertNotIn(flag, argv)

    def test_swiftformat_plans_read_only_json_without_cache(self) -> None:
        argv = swift.build_argv(self.request('swiftformat', config_path='.swiftformat'))
        self.assertEqual(argv[0], '/tools/swiftformat')
        self.assertIn('--lint', argv)
        self.assertEqual(argv[argv.index('--cache') + 1], 'ignore')
        self.assertEqual(argv[argv.index('--reporter') + 1], 'json')
        self.assertEqual(argv[argv.index('--config') + 1], './.swiftformat')
        self.assertEqual(argv[-1], './Sources/My File.swift')
        for flag in ('--lenient', '--output', '--report', '--infer-options'):
            self.assertNotIn(flag, argv)

    def test_full_scope_has_explicit_package_target(self) -> None:
        for tool in ('swiftlint', 'swiftformat'):
            with self.subTest(tool=tool):
                self.assertEqual(swift.build_argv(self.request(tool, scope='full', files=()))[-1], '.')

    def test_leading_dash_filename_is_a_path_not_an_option(self) -> None:
        for tool in ('swiftlint', 'swiftformat'):
            with self.subTest(tool=tool):
                self.assertEqual(swift.build_argv(self.request(tool, files=('--fix.swift',)))[-1], './--fix.swift')

    def test_rejects_empty_changed_scope_unsafe_paths_and_non_swift_files(self) -> None:
        paths = ((), ('../App.swift',), ('/etc/App.swift',), ('Sources/../App.swift',),
                 ('App.swift\n--fix',), ('App.swift\x00',), ('App\\Other.swift',),
                 ('./App.swift',), ('Sources//App.swift',), ('Package.json',), ('.',))
        for tool in ('swiftlint', 'swiftformat'):
            for files in paths:
                with self.subTest(tool=tool, files=files):
                    with self.assertRaises(ValueError):
                        swift.build_argv(self.request(tool, files=files))

    def test_rejects_unsafe_config_task_and_empty_launcher(self) -> None:
        for changes in ({'config_path': '../config'}, {'config_path': '/config'},
                        {'config_path': ''}, {'task': 'format'}, {'launcher': ()},
                        {'launcher': ('/tools/swiftlint\x00',)}, {'scope': 'unknown'}):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    swift.build_argv(self.request(**changes))

    def test_empty_json_with_success_is_pass(self) -> None:
        for tool in ('swiftlint', 'swiftformat'):
            with self.subTest(tool=tool):
                result = swift.normalize(self.request(tool), self.output())
                self.assertEqual(result.status, 'PASS')
                self.assertEqual(result.diagnostics, ())

    def test_swiftlint_violation_preserves_diagnostic(self) -> None:
        result = swift.normalize(self.request(), self.output(2, [self.lint_violation()]))
        self.assertEqual(result.status, 'FAIL')
        diagnostic, = result.diagnostics
        self.assertEqual((diagnostic.severity, diagnostic.code, diagnostic.line, diagnostic.column),
                         ('error', 'force_cast', 4, 2))
        self.assertEqual(diagnostic.path, '/workspace/Sources/App.swift')

    def test_swiftformat_violation_preserves_diagnostic(self) -> None:
        result = swift.normalize(self.request('swiftformat'), self.output(1, [self.format_violation()]))
        self.assertEqual(result.status, 'FAIL')
        diagnostic, = result.diagnostics
        self.assertEqual((diagnostic.severity, diagnostic.code, diagnostic.line, diagnostic.column),
                         ('warning', 'indent', 4, None))

    def test_diagnostics_with_zero_exit_cannot_become_pass(self) -> None:
        for tool, violation in (('swiftlint', self.lint_violation()), ('swiftformat', self.format_violation())):
            with self.subTest(tool=tool):
                self.assertEqual(swift.normalize(self.request(tool), self.output(0, [violation])).status, 'FAIL')

    def test_lint_exit_without_diagnostics_is_error(self) -> None:
        for tool, code in (('swiftlint', 2), ('swiftformat', 1)):
            with self.subTest(tool=tool):
                self.assertEqual(swift.normalize(self.request(tool), self.output(code)).status, 'ERROR')

    def test_unknown_exit_and_compiler_error_are_not_lint_failure(self) -> None:
        for tool, code in (('swiftlint', 1), ('swiftlint', 70), ('swiftformat', 2),
                           ('swiftformat', 70), ('swiftformat', -9)):
            with self.subTest(tool=tool, code=code):
                output = self.output(code, [self.format_violation()], 'error: compiler failed')
                self.assertEqual(swift.normalize(self.request(tool), output).status, 'ERROR')

    def test_malformed_json_and_schema_are_errors(self) -> None:
        invalid = ('', 'not json', '{}', 'null', '[false]', '[{}]', '[] trailing')
        for tool in ('swiftlint', 'swiftformat'):
            for stdout in invalid:
                with self.subTest(tool=tool, stdout=stdout):
                    self.assertEqual(swift.normalize(self.request(tool), ToolOutput(0, stdout, '')).status, 'ERROR')

    def test_invalid_diagnostic_values_are_errors(self) -> None:
        for tool, base in (('swiftlint', self.lint_violation()), ('swiftformat', self.format_violation())):
            for changes in ({'line': True}, {'line': -1}, {'line': '4'}, {'file': 42},
                            {'rule_id': ''}, {'reason': False}, {'file': 'App.swift\x00'}):
                with self.subTest(tool=tool, changes=changes):
                    record = dict(base, **changes)
                    self.assertEqual(swift.normalize(self.request(tool), self.output(0, [record])).status, 'ERROR')

    def test_swiftlint_unknown_severity_and_boolean_character_are_errors(self) -> None:
        for changes in ({'severity': 'fatal'}, {'character': True}):
            record = dict(self.lint_violation(), **changes)
            self.assertEqual(swift.normalize(self.request(), self.output(2, [record])).status, 'ERROR')

    def test_swiftlint_threshold_diagnostic_can_have_no_file(self) -> None:
        record = dict(self.lint_violation(), file=None, line=0, character=0, rule_id='warning_threshold')
        result = swift.normalize(self.request(), self.output(2, [record]))
        self.assertEqual(result.status, 'FAIL')
        self.assertIsNone(result.diagnostics[0].path)
        self.assertIsNone(result.diagnostics[0].line)
        self.assertIsNone(result.diagnostics[0].column)

    def test_duplicate_json_fields_are_not_silently_accepted(self) -> None:
        record = json.dumps(self.format_violation()).replace('"line": 4', '"line": 4, "line": 0')
        result = swift.normalize(self.request('swiftformat'), ToolOutput(0, '[' + record + ']', ''))
        self.assertEqual(result.status, 'ERROR')

    def test_malformed_request_sequences_cannot_produce_a_pass(self) -> None:
        for changes in ({'launcher': '/tools/swiftlint'},
                        {'scope': 'full', 'files': 'App.swift'}):
            with self.subTest(changes=changes):
                result = swift.normalize(self.request(**changes), self.output())
                self.assertEqual(result.status, 'ERROR')

    def test_output_bounds_and_nonstandard_json_fail_closed(self) -> None:
        reports = (' ' * 1_048_577, '[' + ','.join(['{}'] * 10_001) + ']',
                   '[NaN]', '[' * 2_000 + ']' * 2_000)
        for stdout in reports:
            with self.subTest(size=len(stdout)):
                result = swift.normalize(self.request(), ToolOutput(0, stdout, ''))
                self.assertEqual(result.status, 'ERROR')

    def test_boolean_and_string_exit_codes_are_errors(self) -> None:
        for code in (False, True, '0', None):
            with self.subTest(code=code):
                self.assertEqual(swift.normalize(self.request(), self.output(code)).status, 'ERROR')


if __name__ == '__main__':
    unittest.main()
