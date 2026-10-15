from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.language_quality.adapters import dart
from getzilla.language_quality.models import AdapterRequest, ToolOutput


class DartAdapterTests(unittest.TestCase):
    def request(self, tool_id='dart_analyzer', driver='dart', **changes):
        request = AdapterRequest(tool_id=tool_id, driver=driver,
                                 launcher=(f'/sdk/bin/{driver}',),
                                 scope='full', files=())
        return replace(request, **changes)

    def output(self, returncode=0, stdout='', stderr=''):
        return ToolOutput(returncode=returncode, stdout=stdout, stderr=stderr)

    def test_analyzer_requires_full_package_scope_for_both_drivers(self):
        for driver in ('dart', 'flutter'):
            with self.subTest(driver=driver):
                self.assertFalse(dart.capabilities('dart_analyzer', driver).incremental)
                self.assertTrue(dart.capabilities('dart_analyzer', driver).full)
                with self.assertRaises(ValueError):
                    dart.build_argv(self.request(driver=driver, scope='changed',
                                                 files=('lib/a.dart',)))

    def test_dart_command_runs_once_with_machine_output(self):
        self.assertEqual(dart.build_argv(self.request()), (
            '/sdk/bin/dart', '--suppress-analytics', 'analyze',
            '--format=machine', '--fatal-infos', '--fatal-warnings', '.',
        ))

    def test_flutter_command_cannot_restore_packages_or_write_reports(self):
        self.assertEqual(dart.build_argv(self.request(driver='flutter')), (
            '/sdk/bin/flutter', '--suppress-analytics', '--no-color', '--no-wrap',
            '--no-version-check', 'analyze',
            '--no-pub', '--no-preamble', '--fatal-infos', '--fatal-warnings', '.',
        ))

    def test_formatter_uses_read_only_check_and_literal_file_arguments(self):
        request = self.request('dart_format', scope='changed',
                               files=('lib/a file.dart', '-odd.dart'))
        self.assertTrue(dart.capabilities('dart_format', 'dart').incremental)
        self.assertEqual(dart.build_argv(request), (
            '/sdk/bin/dart', '--suppress-analytics', 'format', '--output=none',
            '--set-exit-if-changed', '--show=changed', '--summary=line',
            './lib/a file.dart', './-odd.dart',
        ))
        self.assertEqual(dart.build_argv(self.request('dart_format'))[-1], '.')

    def test_unknown_tools_drivers_and_flutter_format_are_rejected(self):
        for tool, driver in (('other', 'dart'), ('dart_analyzer', 'shell'),
                             ('dart_format', 'flutter')):
            with self.subTest(tool=tool, driver=driver):
                with self.assertRaises(ValueError):
                    dart.capabilities(tool, driver)
                with self.assertRaises(ValueError):
                    dart.build_argv(self.request(tool, driver))

    def test_invalid_requests_cannot_add_commands_or_leave_package(self):
        invalid = [
            {'launcher': ()}, {'launcher': ('dart\nformat',)},
            {'launcher': ('dart', '')}, {'task': 'pub get'}, {'scope': 'unknown'},
            {'config_path': 'custom.yaml'}, {'config_path': '../analysis_options.yaml'},
            {'files': ('../a.dart',)}, {'files': ('/a.dart',)},
            {'files': ('C:/a.dart',)}, {'files': ('lib\\a.dart',)},
            {'files': ('a//b.dart',)}, {'files': ('./a.dart',)},
            {'files': ('a\x00.dart',)}, {'files': ('a\n.dart',)},
            {'files': ('a.dart', 'a.dart')}, {'files': ('pubspec.yaml',)},
        ]
        for changes in invalid:
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    dart.build_argv(self.request('dart_format', **changes))
        with self.assertRaises(ValueError):
            dart.build_argv(self.request('dart_format', scope='changed'))
        dart.build_argv(self.request(config_path='analysis_options.yaml'))

    def test_empty_machine_output_is_success_only_for_zero_exit(self):
        self.assertEqual(dart.normalize(self.request(), self.output()).status, 'PASS')
        for code in (1, 2, 3, 4, 64, -9):
            with self.subTest(code=code):
                self.assertEqual(dart.normalize(self.request(), self.output(code)).status,
                                 'ERROR')

    def test_machine_diagnostics_preserve_escaped_pipes_and_backslashes(self):
        text = (r'ERROR|COMPILE_TIME_ERROR|UNDEFINED_NAME|/workspace/lib/a\|b.dart|2|7|3|'
                r'Unknown a\|b and c\\d\nsecond line' + '\n')
        result = dart.normalize(self.request(), self.output(3, text))
        self.assertEqual(result.status, 'FAIL')
        diagnostic, = result.diagnostics
        self.assertEqual((diagnostic.severity, diagnostic.code),
                         ('error', 'UNDEFINED_NAME'))
        self.assertEqual((diagnostic.path, diagnostic.line, diagnostic.column),
                         ('/workspace/lib/a|b.dart', 2, 7))
        self.assertEqual(diagnostic.message, 'Unknown a|b and c\\d\nsecond line')

    def test_machine_warning_and_info_exit_codes_are_checked(self):
        for severity, code in (('WARNING', 2), ('INFO', 1)):
            text = f'{severity}|LINT|RULE|lib/a.dart|1|1|0|Message\n'
            with self.subTest(severity=severity):
                result = dart.normalize(self.request(), self.output(code, text))
                self.assertEqual(result.status, 'FAIL')
                self.assertEqual(result.diagnostics[0].severity, severity.lower())
                self.assertEqual(dart.normalize(self.request(), self.output(0, text)).status,
                                 'ERROR')

    def test_machine_highest_severity_controls_expected_exit_code(self):
        text = ('INFO|LINT|A|lib/a.dart|1|1|1|Info\n'
                'ERROR|COMPILE_TIME_ERROR|B|lib/b.dart|2|1|1|Error\n')
        self.assertEqual(dart.normalize(self.request(), self.output(3, text)).status, 'FAIL')
        self.assertEqual(dart.normalize(self.request(), self.output(1, text)).status, 'ERROR')

    def test_malformed_machine_output_never_passes(self):
        texts = ('No issues found!', '{}', 'ERROR|broken',
                 'ERROR|LINT|CODE|lib/a.dart|0|1|1|Message',
                 'ERROR|LINT|CODE|lib/a.dart|1|1|-1|Message',
                 'OTHER|LINT|CODE|lib/a.dart|1|1|1|Message',
                 r'ERROR|LINT|CODE|lib/a.dart|1|1|1|bad\q',
                 'ERROR|LINT|CODE|lib/a.dart|1|1|1|Message|extra')
        for text in texts:
            with self.subTest(text=text):
                self.assertEqual(dart.normalize(self.request(), self.output(0, text)).status,
                                 'ERROR')

    def test_machine_stderr_and_server_crash_remain_errors(self):
        self.assertEqual(dart.normalize(self.request(), self.output(
            stderr='The analysis server shut down unexpectedly.')).status, 'ERROR')
        text = 'ERROR|LINT|CODE|lib/a.dart|1|1|1|Message'
        self.assertEqual(dart.normalize(self.request(), self.output(4, text)).status, 'ERROR')

    def test_invalid_package_configuration_is_an_execution_error(self):
        machine = 'ERROR|COMPILE_TIME_ERROR|INVALID_YAML|/workspace/analysis_options.yaml|1|1|1|Invalid YAML'
        self.assertEqual(dart.normalize(self.request(), self.output(3, machine)).status, 'ERROR')
        flutter = 'error • Invalid package • pubspec.yaml:1:1 • invalid_dependency\n'
        self.assertEqual(dart.normalize(self.request(driver='flutter'), self.output(
            1, flutter, '1 issue found. (ran in 0.2s)')).status, 'ERROR')

    def test_flutter_success_requires_complete_known_summary(self):
        request = self.request(driver='flutter')
        result = dart.normalize(request, self.output(stdout='No issues found! (ran in 0.2s)\n'))
        self.assertEqual(result.status, 'PASS')
        for text in ('', 'No issues found!', 'Nothing to analyze.',
                     'No issues found! (ran in 0.2s)\nUnknown output'):
            with self.subTest(text=text):
                self.assertEqual(dart.normalize(request, self.output(stdout=text)).status,
                                 'ERROR')

    def test_flutter_diagnostic_and_stderr_summary_are_normalized(self):
        result = dart.normalize(self.request(driver='flutter'), self.output(
            1, '  error • Undefined name • lib/main.dart:3:5 • undefined_identifier\n',
            '1 issue found. (ran in 0.2s)\n'))
        self.assertEqual(result.status, 'FAIL')
        diagnostic, = result.diagnostics
        self.assertEqual((diagnostic.path, diagnostic.line, diagnostic.column),
                         ('lib/main.dart', 3, 5))
        self.assertEqual(diagnostic.code, 'undefined_identifier')

    def test_flutter_windows_separator_is_supported(self):
        result = dart.normalize(self.request(driver='flutter'), self.output(
            1, '   info - Use const - lib\\main.dart:1:2 - prefer_const_constructors\n',
            '1 issue found. (ran in 0.1s)'))
        self.assertEqual(result.status, 'FAIL')
        self.assertEqual(result.diagnostics[0].severity, 'info')

    def test_flutter_summary_count_and_returncode_must_match(self):
        request = self.request(driver='flutter')
        diagnostic = 'warning • Message • lib/a.dart:1:1 • unused_local_variable\n'
        outputs = (
            self.output(0, diagnostic, '1 issue found. (ran in 0.2s)'),
            self.output(1, diagnostic, '2 issues found. (ran in 0.2s)'),
            self.output(1, diagnostic), self.output(1, 'No issues found! (ran in 0.2s)'),
            self.output(0, 'No issues found! (ran in 0.2s)', 'Server error occurred'),
            self.output(0, 'No issues found! (ran in 0.2s)\nNo issues found! (ran in 0.2s)'),
        )
        for output in outputs:
            with self.subTest(output=output):
                self.assertEqual(dart.normalize(request, output).status, 'ERROR')

    def test_formatter_clean_summary_is_success(self):
        result = dart.normalize(self.request('dart_format'), self.output(
            stdout='Formatted 2 files (0 changed) in 0.02 seconds.\n'))
        self.assertEqual(result.status, 'PASS')

    def test_formatter_reports_changed_files_without_rewriting_them(self):
        result = dart.normalize(self.request('dart_format'), self.output(
            1, 'Changed lib/a.dart\nFormatted 2 files (1 changed) in 0.02 seconds.\n'))
        self.assertEqual(result.status, 'FAIL')
        self.assertEqual(result.diagnostics[0].path, 'lib/a.dart')

    def test_formatter_missing_or_inconsistent_output_is_error(self):
        outputs = (
            self.output(), self.output(1), self.output(65, stderr='Could not format'),
            self.output(stdout='Formatted no files in 0.02 seconds.'),
            self.output(stdout='Formatted 1 file (1 changed) in 0.02 seconds.'),
            self.output(1, 'Changed a.dart\nFormatted 1 file (0 changed) in 0.02 seconds.'),
            self.output(1, 'Formatted a.dart\nFormatted 1 file (1 changed) in 0.02 seconds.'),
            self.output(stdout='Formatted 1 file (0 changed) in 0.02 seconds.', stderr='Warning'),
            self.output(1, 'Changed a.dart\nChanged a.dart\nFormatted 2 files (2 changed) in 0.02 seconds.'),
        )
        for output in outputs:
            with self.subTest(output=output):
                self.assertEqual(dart.normalize(self.request('dart_format'), output).status,
                                 'ERROR')

    def test_normalization_rejects_invalid_request_or_output_types(self):
        result = dart.normalize(self.request(scope='changed'), self.output())
        self.assertEqual(result.status, 'ERROR')
        for output in (self.output(True), self.output(0, None), self.output(0, '', None)):
            with self.subTest(output=output):
                self.assertEqual(dart.normalize(self.request(), output).status, 'ERROR')


if __name__ == '__main__':
    unittest.main()
