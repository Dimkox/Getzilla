"""Controlled upstream report shapes must never turn missing evidence into a pass."""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import verification_tool_reports as reports


PLAYWRIGHT = {
    'config': {'rootDir': '/project'},
    'suites': [{
        'title': 'checkout.spec.ts', 'file': 'checkout.spec.ts', 'line': 0, 'column': 0,
        'specs': [], 'suites': [{
            'title': 'checkout', 'file': 'checkout.spec.ts', 'line': 3, 'column': 1,
            'specs': [{
                'title': 'accepts a card', 'ok': True, 'tags': [], 'id': 'opaque-id',
                'file': 'checkout.spec.ts', 'line': 5, 'column': 1,
                'tests': [{
                    'timeout': 30000, 'annotations': [], 'expectedStatus': 'passed',
                    'projectId': 'chromium', 'projectName': 'chromium',
                    'results': [{
                        'workerIndex': 0, 'parallelIndex': 0, 'status': 'passed',
                        'duration': 11, 'errors': [], 'stdout': [], 'stderr': [],
                        'retry': 0, 'startTime': '2026-10-31T00:00:00.000Z',
                        'attachments': [],
                    }],
                    'status': 'expected',
                }],
            }],
        }],
    }],
    'errors': [],
    'stats': {'startTime': '2026-10-31T00:00:00.000Z', 'duration': 30,
              'expected': 1, 'skipped': 0, 'unexpected': 0, 'flaky': 0},
}

SCHEMATHESIS = {
    'schemathesis_version': '4.32.7', 'exit_code': 0, 'complete': True,
    'stop_reason': 'completed',
    'operations': {'total': 3, 'selected': 2, 'tested': 2, 'errored': 0, 'skipped': 0},
    'test_cases': {'generated': 12, 'without_checks': 0, 'errored': 0},
    'failures': [], 'errors': [], 'warnings': {},
}

MUTMUT = {
    'killed': 2, 'survived': 0, 'total': 2, 'no_tests': 0, 'skipped': 0,
    'suspicious': 0, 'timeout': 0, 'check_was_interrupted_by_user': 0, 'segfault': 0,
}

STRYKER = {
    'schemaVersion': '2', 'thresholds': {'high': 80, 'low': 60},
    'files': {'src/checkout.ts': {
        'language': 'typescript', 'source': 'const price = quantity * unitPrice;',
        'mutants': [{
            'id': '0', 'mutatorName': 'ArithmeticOperator', 'replacement': '/',
            'location': {'start': {'line': 1, 'column': 15},
                         'end': {'line': 1, 'column': 35}},
            'status': 'Killed', 'killedBy': ['checkout-test'],
        }],
    }},
}


class ReportTests(unittest.TestCase):
    def parse(self, format_name, value):
        return reports.parse_report(format_name, json.dumps(value))

    def test_junit_nested_totals_count_cases_once(self):
        result = reports.parse_report('junit', '''
            <testsuites tests="2" failures="0" errors="0" skipped="0">
              <testsuite tests="2"><testsuite tests="1"><testcase
                classname="checkout.Card" name="accepts"/></testsuite>
                <testcase name="server starts"/></testsuite>
            </testsuites>''')
        self.assertEqual(result['kind'], 'tests')
        self.assertEqual(result['status'], 'pass')
        self.assertEqual(result['counts']['total'], 2)
        self.assertEqual(result['tests'], [
            {'id': 'checkout.Card::accepts', 'status': 'pass'},
            {'id': 'server starts', 'status': 'pass'},
        ])
        self.assertEqual(result['reason_codes'], [])

    def test_junit_failures_errors_skips_and_xfail_do_not_pass(self):
        for child, status in [('<failure/>', 'fail'), ('<error/>', 'fail'),
                              ('<skipped/>', 'skip'),
                              ('<skipped type="pytest.xfail"/>', 'skip')]:
            with self.subTest(child=child):
                result = reports.parse_report(
                    'junit', '<testsuite><testcase name="case">' + child
                    + '</testcase></testsuite>')
                self.assertEqual(result['status'], 'fail')
                self.assertEqual(result['tests'][0]['status'], status)
                self.assertTrue(result['reason_codes'])

    def test_junit_empty_and_disabled_runs_do_not_pass(self):
        for content in ['<testsuites/>', '<testsuite tests="0"/>',
                        '<testsuite><testcase name="a" status="notrun"/></testsuite>']:
            with self.subTest(content=content):
                self.assertEqual(reports.parse_report('junit', content)['status'], 'fail')

    def test_junit_aggregate_claims_must_match_cases_at_each_level(self):
        for attrs in ['tests="2"', 'failures="1"', 'errors="1"', 'skipped="1"',
                      'tests="-1"', 'tests="true"', 'tests="1.0"']:
            with self.subTest(attrs=attrs):
                with self.assertRaises(reports.ReportError):
                    reports.parse_report('junit', '<testsuites><testsuite ' + attrs
                                         + '><testcase name="a"/></testsuite></testsuites>')

    def test_junit_duplicate_and_colliding_ids_are_ambiguous(self):
        for cases in [
            '<testcase name="a"/><testcase name="a"/>',
            '<testcase classname="a" name="b"/><testcase name="a::b"/>',
        ]:
            with self.subTest(cases=cases):
                with self.assertRaises(reports.ReportError):
                    reports.parse_report('junit', '<testsuite>' + cases + '</testsuite>')

    def test_junit_refuses_dtd_entities_and_bad_structure(self):
        for content in [
            '<!DOCTYPE testsuite [<!ENTITY x "case">]><testsuite/>',
            '<!DOCTYPE testsuite SYSTEM "file:///private"><testsuite/>',
            '<anything><testcase name="a"/></anything>',
            '<testsuite><testcase/></testsuite>',
            '<testsuite><testcase name=" "/></testsuite>',
            '<testsuite><unknown><testcase name="a"/></unknown></testsuite>',
            '<testsuite><testcase name="a"><unknown/></testcase></testsuite>',
            '<testsuite><testcase name="a"><failure/><skipped/></testcase></testsuite>',
            '<testsuite><testcase name="a" status="mystery"/></testsuite>',
            '<testsuite>',
        ]:
            with self.subTest(content=content):
                with self.assertRaises(reports.ReportError):
                    reports.parse_report('junit', content)

    def test_junit_metadata_cannot_hide_outcomes_or_entity_declarations(self):
        for metadata in ['<properties><testcase name="hidden"><failure/></testcase></properties>',
                         '<system-out><failure/></system-out>',
                         '<properties><property name="x"><error/></property></properties>']:
            with self.subTest(metadata=metadata):
                with self.assertRaises(reports.ReportError):
                    reports.parse_report('junit', '<testsuite><testcase name="a"/>'
                                         + metadata + '</testsuite>')
        declaration = '<!DOCTYPE testsuite [<!ENTITY x "case">]><testsuite/>'
        nul_encoded = declaration.encode('utf-16-le').decode('utf-8')
        with self.assertRaises(reports.ReportError):
            reports.parse_report('junit', nul_encoded)

    def test_playwright_pass_uses_file_suite_spec_and_project_identity(self):
        result = self.parse('playwright-json', PLAYWRIGHT)
        self.assertEqual(result['kind'], 'tests')
        self.assertEqual(result['status'], 'pass')
        self.assertEqual(result['counts']['total'], 1)
        self.assertEqual(result['tests'], [{
            'id': 'checkout.spec.ts::checkout::accepts a card [chromium]', 'status': 'pass',
        }])

    def test_playwright_multiple_projects_are_distinct(self):
        value = copy.deepcopy(PLAYWRIGHT)
        spec = value['suites'][0]['suites'][0]['specs'][0]
        other = copy.deepcopy(spec['tests'][0])
        other['projectName'] = 'webkit'
        spec['tests'].append(other)
        value['stats']['expected'] = 2
        result = self.parse('playwright-json', value)
        self.assertEqual(result['status'], 'pass')
        self.assertEqual([item['id'] for item in result['tests']], [
            'checkout.spec.ts::checkout::accepts a card [chromium]',
            'checkout.spec.ts::checkout::accepts a card [webkit]',
        ])

    def test_playwright_top_level_specs_omit_empty_project_suffix(self):
        value = copy.deepcopy(PLAYWRIGHT)
        spec = value['suites'][0]['suites'][0]['specs'][0]
        spec['tests'][0]['projectName'] = ''
        value['suites'][0]['specs'] = [spec]
        value['suites'][0]['suites'] = []
        result = self.parse('playwright-json', value)
        self.assertEqual(result['tests'][0]['id'], 'checkout.spec.ts::accepts a card')

    def test_playwright_expected_failure_is_not_a_pass(self):
        value = copy.deepcopy(PLAYWRIGHT)
        test = value['suites'][0]['suites'][0]['specs'][0]['tests'][0]
        test['expectedStatus'] = 'failed'
        test['results'][0]['status'] = 'failed'
        result = self.parse('playwright-json', value)
        self.assertEqual(result['status'], 'fail')
        self.assertEqual(result['tests'][0]['status'], 'fail')

    def test_playwright_skipped_flaky_unexpected_and_interrupted_fail(self):
        for outcome, actual, expected in [('skipped', 'skipped', 'skipped'),
                                          ('flaky', 'passed', 'passed'),
                                          ('unexpected', 'failed', 'passed'),
                                          ('unexpected', 'interrupted', 'passed')]:
            with self.subTest(outcome=outcome, actual=actual):
                value = copy.deepcopy(PLAYWRIGHT)
                test = value['suites'][0]['suites'][0]['specs'][0]['tests'][0]
                test['status'], test['expectedStatus'] = outcome, expected
                test['results'][0]['status'] = actual
                if outcome == 'flaky':
                    test['results'].insert(0, {'status': 'failed', 'retry': 0})
                value['stats']['expected'] = 0
                value['stats'][outcome] = 1
                result = self.parse('playwright-json', value)
                self.assertEqual(result['status'], 'fail')
                self.assertNotEqual(result['tests'][0]['status'], 'pass')

    def test_playwright_each_attempt_and_global_errors_matter(self):
        for change in ('retry', 'global-error', 'result-error', 'no-results'):
            with self.subTest(change=change):
                value = copy.deepcopy(PLAYWRIGHT)
                test = value['suites'][0]['suites'][0]['specs'][0]['tests'][0]
                if change == 'retry':
                    test['results'].insert(0, {'status': 'failed'})
                elif change == 'global-error':
                    value['errors'] = [{'message': 'teardown failed'}]
                elif change == 'result-error':
                    test['results'][0]['errors'] = [{'message': 'error'}]
                else:
                    test['results'] = []
                result = self.parse('playwright-json', value)
                self.assertEqual(result['status'], 'fail')

    def test_playwright_stats_are_checked_against_real_test_outcomes(self):
        for counts in [
            {'expected': 9, 'skipped': 0, 'unexpected': 0, 'flaky': 0},
            {'expected': 0, 'skipped': 1, 'unexpected': 0, 'flaky': 0},
            {'expected': True, 'skipped': 0, 'unexpected': 0, 'flaky': 0},
            {'expected': -1, 'skipped': 0, 'unexpected': 0, 'flaky': 0},
            {'expected': 1},
        ]:
            with self.subTest(counts=counts):
                value = copy.deepcopy(PLAYWRIGHT)
                value['stats'] = counts
                with self.assertRaises(reports.ReportError):
                    self.parse('playwright-json', value)

    def test_playwright_stats_are_optional_but_real_cases_are_required(self):
        value = copy.deepcopy(PLAYWRIGHT)
        del value['stats']
        self.assertEqual(self.parse('playwright-json', value)['status'], 'pass')
        value['suites'] = []
        self.assertEqual(self.parse('playwright-json', value)['status'], 'fail')

    def test_playwright_duplicate_ids_and_invalid_structures_are_rejected(self):
        for change in ('duplicate', 'suites', 'tests', 'empty-spec', 'expected', 'outcome', 'result'):
            with self.subTest(change=change):
                value = copy.deepcopy(PLAYWRIGHT)
                spec = value['suites'][0]['suites'][0]['specs'][0]
                test = spec['tests'][0]
                if change == 'duplicate':
                    spec['tests'].append(copy.deepcopy(test))
                elif change == 'suites':
                    value['suites'] = {}
                elif change == 'tests':
                    spec['tests'] = 'test'
                elif change == 'empty-spec':
                    spec['tests'] = []
                    del value['stats']
                elif change == 'expected':
                    del test['expectedStatus']
                elif change == 'outcome':
                    test['status'] = 'pass'
                else:
                    test['results'][0]['status'] = 'success'
                with self.assertRaises(reports.ReportError):
                    self.parse('playwright-json', value)

    def test_schemathesis_completed_checks_are_aggregate_api_evidence(self):
        result = self.parse('schemathesis-json', SCHEMATHESIS)
        self.assertEqual(result['kind'], 'api')
        self.assertEqual(result['status'], 'pass')
        self.assertEqual(result['tests'], [])
        self.assertEqual(result['counts']['operations_tested'], 2)
        self.assertEqual(result['counts']['test_cases_generated'], 12)
        self.assertEqual(result['reason_codes'], [])

    def test_schemathesis_complete_does_not_hide_an_early_stop(self):
        for field, replacement in [('complete', False), ('stop_reason', 'interrupted'),
                                   ('exit_code', 130), ('failures', [{'operation': 'GET /'}]),
                                   ('errors', [{'message': 'schema error'}])]:
            with self.subTest(field=field):
                value = copy.deepcopy(SCHEMATHESIS)
                value[field] = replacement
                self.assertEqual(self.parse('schemathesis-json', value)['status'], 'fail')

    def test_schemathesis_no_checked_cases_or_unexecuted_operations_fail(self):
        for change in ('empty', 'no-checks', 'skipped', 'errored', 'case-error'):
            with self.subTest(change=change):
                value = copy.deepcopy(SCHEMATHESIS)
                if change == 'empty':
                    value['operations'] = dict(total=0, selected=0, tested=0, errored=0, skipped=0)
                    value['test_cases'] = dict(generated=0, without_checks=0, errored=0)
                elif change == 'no-checks':
                    value['test_cases']['without_checks'] = 12
                elif change == 'skipped':
                    value['operations'].update(tested=1, skipped=1)
                elif change == 'errored':
                    value['operations'].update(tested=1, errored=1)
                elif change == 'case-error':
                    value['test_cases']['errored'] = 1
                self.assertEqual(self.parse('schemathesis-json', value)['status'], 'fail')

    def test_schemathesis_required_fields_and_counter_relationships_are_checked(self):
        for change in ('missing', 'bool', 'negative', 'too-many-selected', 'too-many-tested',
                       'too-many-without-checks', 'too-many-case-errors', 'unaccounted',
                       'complete', 'failures'):
            with self.subTest(change=change):
                value = copy.deepcopy(SCHEMATHESIS)
                if change == 'missing':
                    del value['operations']['tested']
                elif change == 'bool':
                    value['operations']['tested'] = True
                elif change == 'negative':
                    value['operations']['tested'] = -1
                elif change == 'too-many-selected':
                    value['operations']['selected'] = 4
                elif change == 'too-many-tested':
                    value['operations']['tested'] = 3
                elif change == 'too-many-without-checks':
                    value['test_cases']['without_checks'] = 13
                elif change == 'too-many-case-errors':
                    value['test_cases']['errored'] = 13
                elif change == 'unaccounted':
                    value['operations']['tested'] = 1
                elif change == 'complete':
                    value['complete'] = 'true'
                else:
                    value['failures'] = {}
                with self.assertRaises(reports.ReportError):
                    self.parse('schemathesis-json', value)

    def test_schemathesis_case_counters_are_disjoint_and_extra_counts_are_retained(self):
        value = copy.deepcopy(SCHEMATHESIS)
        value['test_cases'].update(with_failures=0, unique_failures=0)
        result = self.parse('schemathesis-json', value)
        self.assertEqual(result['counts'].get('test_cases_with_failures'), 0)
        self.assertEqual(result['counts'].get('test_cases_unique_failures'), 0)
        for fields in [dict(without_checks=7, errored=6),
                       dict(with_failures=7, without_checks=6),
                       dict(with_failures=True), dict(unique_failures=-1)]:
            with self.subTest(fields=fields):
                broken = copy.deepcopy(value)
                broken['test_cases'].update(fields)
                with self.assertRaises(reports.ReportError):
                    self.parse('schemathesis-json', broken)
        value['test_cases'].update(with_failures=1, unique_failures=20)
        self.assertEqual(self.parse('schemathesis-json', value)['status'], 'fail')

    def test_aggregate_formats_cannot_exceed_the_case_budget(self):
        with self.assertRaises(reports.ReportError):
            self.parse('mutmut-json', dict(MUTMUT, total=10001, killed=10001))
        value = copy.deepcopy(SCHEMATHESIS)
        value['test_cases']['generated'] = 10001
        with self.assertRaises(reports.ReportError):
            self.parse('schemathesis-json', value)

    def test_mutmut_requires_every_mutation_to_be_killed(self):
        result = self.parse('mutmut-json', MUTMUT)
        self.assertEqual(result['kind'], 'mutations')
        self.assertEqual(result['status'], 'pass')
        self.assertEqual(result['counts']['killed'], 2)
        self.assertEqual(result['tests'], [])
        for field in ['survived', 'no_tests', 'skipped', 'suspicious', 'timeout',
                      'check_was_interrupted_by_user', 'segfault']:
            with self.subTest(field=field):
                value = dict(MUTMUT, killed=1)
                value[field] = 1
                result = self.parse('mutmut-json', value)
                self.assertEqual(result['status'], 'fail')
                self.assertEqual(result['counts'][field], 1)

    def test_mutmut_zero_and_unexported_status_residue_fail(self):
        for value in [dict(MUTMUT, total=0, killed=0), dict(MUTMUT, total=3)]:
            with self.subTest(value=value):
                result = self.parse('mutmut-json', value)
                self.assertEqual(result['status'], 'fail')
                self.assertTrue(result['reason_codes'])
        self.assertEqual(self.parse('mutmut-json', dict(MUTMUT, total=3))
                         ['counts']['unaccounted'], 1)

    def test_mutmut_malformed_or_overcounted_stats_are_rejected(self):
        for change in ('missing', 'bool', 'negative', 'float', 'string', 'overcount'):
            with self.subTest(change=change):
                value = dict(MUTMUT)
                if change == 'missing':
                    del value['skipped']
                else:
                    value['killed'] = {'bool': True, 'negative': -1, 'float': 2.0,
                                       'string': '2', 'overcount': 3}[change]
                with self.assertRaises(reports.ReportError):
                    self.parse('mutmut-json', value)

    def test_stryker_killed_mutants_have_file_qualified_ids(self):
        result = self.parse('stryker-json', STRYKER)
        self.assertEqual(result['status'], 'pass')
        self.assertEqual(result['kind'], 'mutations')
        self.assertEqual(result['counts']['killed'], 1)
        self.assertEqual(result['tests'], [{'id': 'src/checkout.ts::0', 'status': 'pass'}])

    def test_stryker_all_non_killed_viable_statuses_fail(self):
        for status in ('Survived', 'NoCoverage', 'Timeout', 'RuntimeError', 'Pending', 'Ignored'):
            with self.subTest(status=status):
                value = copy.deepcopy(STRYKER)
                value['files']['src/checkout.ts']['mutants'][0]['status'] = status
                result = self.parse('stryker-json', value)
                self.assertEqual(result['status'], 'fail')
                self.assertNotEqual(result['tests'][0]['status'], 'pass')
                self.assertTrue(result['reason_codes'])

    def test_stryker_compile_errors_are_excluded_but_not_positive_evidence(self):
        value = copy.deepcopy(STRYKER)
        mutants = value['files']['src/checkout.ts']['mutants']
        mutants.append(dict(mutants[0], id='1', status='CompileError'))
        result = self.parse('stryker-json', value)
        self.assertEqual(result['status'], 'pass')
        self.assertEqual(result['counts']['total'], 2)
        self.assertEqual(result['counts']['viable'], 1)
        self.assertEqual(result['counts']['compile_errors'], 1)
        self.assertEqual(result['tests'][1]['status'], 'skip')
        mutants.pop(0)
        self.assertEqual(self.parse('stryker-json', value)['status'], 'fail')
        value['files'] = {}
        self.assertEqual(self.parse('stryker-json', value)['status'], 'fail')

    def test_stryker_duplicate_ids_are_scoped_to_the_exact_file(self):
        value = copy.deepcopy(STRYKER)
        value['files']['src/other.ts'] = copy.deepcopy(value['files']['src/checkout.ts'])
        self.assertEqual(self.parse('stryker-json', value)['status'], 'pass')
        mutants = value['files']['src/checkout.ts']['mutants']
        mutants.append(copy.deepcopy(mutants[0]))
        with self.assertRaises(reports.ReportError):
            self.parse('stryker-json', value)

    def test_stryker_malformed_structure_and_status_fail_closed(self):
        for change in ('files', 'mutants', 'id', 'status', 'absolute', 'parent'):
            with self.subTest(change=change):
                value = copy.deepcopy(STRYKER)
                if change == 'files':
                    value['files'] = []
                elif change == 'mutants':
                    value['files']['src/checkout.ts']['mutants'] = {}
                elif change == 'id':
                    value['files']['src/checkout.ts']['mutants'][0]['id'] = 0
                elif change == 'status':
                    value['files']['src/checkout.ts']['mutants'][0]['status'] = 'Passed'
                else:
                    path = '/absolute.ts' if change == 'absolute' else '../outside.ts'
                    value['files'] = {path: value['files']['src/checkout.ts']}
                with self.assertRaises(reports.ReportError):
                    self.parse('stryker-json', value)

    def test_all_parsers_bound_individual_cases(self):
        junit = '<testsuite>' + ''.join('<testcase name="t%d"/>' % i for i in range(10001))
        with self.assertRaises(reports.ReportError):
            reports.parse_report('junit', junit + '</testsuite>')
        playwright = copy.deepcopy(PLAYWRIGHT)
        spec = playwright['suites'][0]['suites'][0]['specs'][0]
        spec['tests'] = [dict(spec['tests'][0], projectName=str(i)) for i in range(10001)]
        del playwright['stats']
        with self.assertRaises(reports.ReportError):
            self.parse('playwright-json', playwright)
        stryker = copy.deepcopy(STRYKER)
        mutants = stryker['files']['src/checkout.ts']['mutants']
        stryker['files']['src/checkout.ts']['mutants'] = [
            dict(mutants[0], id=str(i)) for i in range(10001)]
        with self.assertRaises(reports.ReportError):
            self.parse('stryker-json', stryker)

    def test_duplicate_json_keys_nonfinite_numbers_and_bad_roots_are_rejected(self):
        for format_name in ('playwright-json', 'schemathesis-json', 'mutmut-json', 'stryker-json'):
            for content in ('{"files":{},"files":{}}', '{"nested":{"x":1,"x":2}}',
                            '{"value":NaN}', '{"value":Infinity}', '[]', 'null', '{'):
                with self.subTest(format=format_name, content=content):
                    with self.assertRaises(reports.ReportError):
                        reports.parse_report(format_name, content)

    def test_unknown_format_and_errors_do_not_echo_unbounded_report_content(self):
        report_payload = 'private-report-content-' * 1000
        for format_name, content in [('unknown', report_payload), ('junit', report_payload),
                                     ('mutmut-json', '{"' + report_payload + '":')]:
            with self.subTest(format=format_name):
                with self.assertRaises(reports.ReportError) as caught:
                    reports.parse_report(format_name, content)
                self.assertLess(len(str(caught.exception)), 200)
                self.assertNotIn('private-report-content', str(caught.exception))

    def test_criteria_require_all_exact_ids_to_pass(self):
        report = reports.parse_report('junit', '''<testsuite>
            <testcase classname="A" name="test_ok"/>
            <testcase classname="A" name="test_fail"><failure/></testcase>
            <testcase classname="A" name="test_skip"><skipped/></testcase>
        </testsuite>''')
        criteria = {'AC-1': ['A::test_ok'], 'INV-1': ['A::test_ok', 'A::test_fail'],
                    'FORBID-1': ['A::test_skip'], 'AC-2': ['test_ok', 'A::missing']}
        self.assertEqual(reports.evaluate_criteria(report, criteria), [
            {'id': 'AC-1', 'status': 'pass', 'tests': ['A::test_ok'], 'missing': []},
            {'id': 'INV-1', 'status': 'fail',
             'tests': ['A::test_ok', 'A::test_fail'], 'missing': []},
            {'id': 'FORBID-1', 'status': 'fail', 'tests': ['A::test_skip'], 'missing': []},
            {'id': 'AC-2', 'status': 'fail', 'tests': ['test_ok', 'A::missing'],
             'missing': ['test_ok', 'A::missing']},
        ])

    def test_criteria_ambiguity_empty_selection_and_aggregate_evidence_fail(self):
        ambiguous = {'tests': [{'id': 'a', 'status': 'pass'}, {'id': 'a', 'status': 'pass'}]}
        for report, requested in [(ambiguous, ['a']), ({'tests': []}, []),
                                  (self.parse('schemathesis-json', SCHEMATHESIS), ['GET /'])]:
            with self.subTest(requested=requested):
                result = reports.evaluate_criteria(report, {'AC-1': requested})
                self.assertEqual(result[0]['status'], 'fail')
        report = {'tests': [{'id': 'a', 'status': 'inconclusive'}]}
        self.assertEqual(reports.evaluate_criteria(report, {'AC-1': ['a']})[0]['status'], 'fail')


if __name__ == '__main__':
    unittest.main()
