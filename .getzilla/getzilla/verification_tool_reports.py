"""Bounded, fail-closed readers for optional verification tool reports.

Reports are observations, not proof of their source or freshness. The executor
must bind them to its own run before using these normalized results.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import PurePosixPath, PureWindowsPath
from xml.etree import ElementTree  # nosec B405


MAX_CASES = 10_000
MAX_DEPTH = 100
_CASE_STATUSES = {'pass', 'fail', 'skip', 'inconclusive'}
_MUTMUT_FIELDS = (
    'killed', 'survived', 'total', 'no_tests', 'skipped', 'suspicious', 'timeout',
    'check_was_interrupted_by_user', 'segfault',
)
_STRYKER_STATUSES = {
    'Killed': ('killed', 'pass'), 'Survived': ('survived', 'fail'),
    'NoCoverage': ('no_coverage', 'fail'), 'Timeout': ('timeout', 'inconclusive'),
    'CompileError': ('compile_errors', 'skip'), 'RuntimeError': ('runtime_errors', 'inconclusive'),
    'Pending': ('pending', 'inconclusive'), 'Ignored': ('ignored', 'skip'),
}


class ReportError(ValueError):
    """The report is malformed, ambiguous, inconsistent, or outside its bounds."""


def _object(value: object) -> dict:
    if not isinstance(value, dict):
        raise ReportError('Expected a report object')
    return value


def _array(value: object) -> list:
    if not isinstance(value, list):
        raise ReportError('Expected a report array')
    return value


def _string(value: object, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not empty and not value.strip()):
        raise ReportError('Expected a report string')
    return value


def _count(value: object) -> int:
    if type(value) is not int or value < 0:
        raise ReportError('Expected a nonnegative integer count')
    return value


def _counts(value: object, names: tuple[str, ...]) -> dict[str, int]:
    data = _object(value)
    return {name: _count(data.get(name)) for name in names}


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    data = {}
    for key, value in pairs:
        if key in data:
            raise ReportError('Duplicate JSON key')
        data[key] = value
    return data


def _reject_constant(_value: str) -> None:
    raise ReportError('Nonfinite JSON number')


def _add_case(tests: list[dict], seen: set[str], identity: str, status: str) -> None:
    if len(tests) >= MAX_CASES:
        raise ReportError('Report exceeds the case limit')
    if identity in seen:
        raise ReportError('Ambiguous duplicate case ID')
    seen.add(identity)
    tests.append({'id': identity, 'status': status})


def _result(kind: str, counts: dict[str, int], tests: list[dict], reasons: list[str]) -> dict:
    return {'kind': kind, 'status': 'fail' if reasons else 'pass', 'counts': counts,
            'tests': tests, 'reason_codes': list(dict.fromkeys(reasons))}


def _junit(content: str) -> dict:
    # ElementTree does not fetch external entities. Refuse declarations as well,
    # so internal entities cannot expand before the bounded case walk begins.
    if '\x00' in content or re.search(r'<!\s*(?:DOCTYPE|ENTITY)\b', content, flags=re.IGNORECASE):
        raise ReportError('XML declarations are not accepted')
    try:
        root = ElementTree.fromstring(content)  # nosec B314
    except (ElementTree.ParseError, ValueError):
        raise ReportError('Malformed JUnit XML') from None
    tests: list[dict] = []
    seen: set[str] = set()

    def metadata(node: ElementTree.Element) -> None:
        if node.tag == 'properties':
            if any(child.tag != 'property' or len(child) for child in node):
                raise ReportError('Invalid JUnit properties')
        elif len(node):
            raise ReportError('Invalid JUnit output or outcome structure')

    def case(node: ElementTree.Element) -> dict[str, int]:
        name = _string(node.get('name'))
        classname = _string(node.get('classname', ''), empty=True)
        identity = f'{classname}::{name}' if classname else name
        outcomes = set()
        for child in node:
            if child.tag in {'failure', 'error', 'skipped'}:
                outcomes.add(child.tag)
                metadata(child)
            elif child.tag not in {'properties', 'system-out', 'system-err'}:
                raise ReportError('Invalid JUnit testcase structure')
            else:
                metadata(child)
        if len(outcomes) > 1:
            raise ReportError('Conflicting JUnit testcase outcomes')
        declared = node.get('status', 'run')
        if declared in {'notrun', 'disabled', 'skipped'}:
            outcomes.add('skipped')
        elif declared in {'failed', 'failure', 'error'}:
            outcomes.add('error' if declared == 'error' else 'failure')
        elif declared not in {'run', 'passed', 'pass', 'success'}:
            raise ReportError('Unknown JUnit testcase status')
        if len(outcomes) > 1:
            raise ReportError('Conflicting JUnit testcase outcomes')
        status = 'skip' if 'skipped' in outcomes else 'fail' if outcomes else 'pass'
        _add_case(tests, seen, identity, status)
        return {'total': 1, 'passed': int(status == 'pass'),
                'failed': int('failure' in outcomes), 'errors': int('error' in outcomes),
                'skipped': int(status == 'skip')}

    def suite(node: ElementTree.Element, depth: int) -> dict[str, int]:
        if depth > MAX_DEPTH:
            raise ReportError('JUnit suite nesting exceeds the limit')
        if node.tag not in {'testsuite', 'testsuites'}:
            raise ReportError('Invalid JUnit root or suite')
        totals = dict.fromkeys(('total', 'passed', 'failed', 'errors', 'skipped'), 0)
        for child in node:
            if child.tag in {'testsuite', 'testsuites'}:
                subtotal = suite(child, depth + 1)
            elif child.tag == 'testcase' and node.tag == 'testsuite':
                subtotal = case(child)
            elif child.tag in {'properties', 'system-out', 'system-err'}:
                metadata(child)
                continue
            else:
                raise ReportError('Invalid JUnit suite structure')
            for key in totals:
                totals[key] += subtotal[key]
        # Check every wrapper against its own descendants; do not add wrapper
        # aggregate claims to the already counted leaf cases.
        for attribute, key in [('tests', 'total'), ('failures', 'failed'),
                               ('errors', 'errors'), ('skipped', 'skipped')]:
            if attribute in node.attrib:
                value = node.attrib[attribute]
                if not re.fullmatch(r'[0-9]+', value) or int(value) != totals[key]:
                    raise ReportError('Inconsistent JUnit aggregate count')
        return totals

    counts = suite(root, 0)
    reasons = ([] if counts['total'] else ['no_test_cases'])
    reasons += [key for key in ('failed', 'errors', 'skipped') if counts[key]]
    return _result('tests', counts, tests, reasons)


def _playwright(data: dict) -> dict:
    tests: list[dict] = []
    seen: set[str] = set()
    outcome_counts = dict.fromkeys(('expected', 'skipped', 'unexpected', 'flaky'), 0)
    errors = _array(data.get('errors'))
    for error in errors:
        _object(error)
    reasons = ['global_errors'] if errors else []
    result_statuses = {'passed', 'failed', 'timedOut', 'skipped', 'interrupted'}

    def test_case(value: object, identity: str) -> None:
        test = _object(value)
        expected = _string(test.get('expectedStatus'))
        outcome = _string(test.get('status'))
        if expected not in result_statuses or outcome not in outcome_counts:
            raise ReportError('Unknown Playwright test status')
        project = _string(test.get('projectName', ''), empty=True)
        if project:
            identity += f' [{project}]'
        attempts = _array(test.get('results'))
        if len(attempts) > MAX_CASES:
            raise ReportError('Report exceeds the attempt limit')
        actual = []
        has_errors = False
        for value in attempts:
            attempt = _object(value)
            status = _string(attempt.get('status'))
            if status not in result_statuses:
                raise ReportError('Unknown Playwright result status')
            actual.append(status)
            attempt_errors = _array(attempt.get('errors', []))
            for error in attempt_errors:
                _object(error)
            if 'error' in attempt and attempt['error'] is not None:
                _object(attempt['error'])
                has_errors = True
            has_errors |= bool(attempt_errors)
        passed = (expected == 'passed' and outcome == 'expected' and bool(actual)
                  and all(status == 'passed' for status in actual) and not has_errors)
        if passed:
            status = 'pass'
        elif outcome == 'skipped' or expected == 'skipped':
            status = 'skip'
        elif not actual or 'interrupted' in actual:
            status = 'inconclusive'
        else:
            status = 'fail'
        _add_case(tests, seen, identity, status)
        outcome_counts[outcome] += 1

    def suite(value: object, titles: list[str], file: str, depth: int) -> None:
        if depth > MAX_DEPTH:
            raise ReportError('Playwright suite nesting exceeds the limit')
        node = _object(value)
        title = _string(node.get('title'), empty=True)
        file = _string(node.get('file', file), empty=True)
        # The reporter's top-level suite is the file wrapper. Its title repeats
        # the file path; nested describe titles remain part of the exact ID.
        if title and not (depth == 0 and title == file):
            titles = [*titles, title]
        for value in _array(node.get('specs')):
            spec = _object(value)
            spec_title = _string(spec.get('title'))
            spec_file = _string(spec.get('file', file))
            if 'ok' in spec:
                if type(spec['ok']) is not bool:
                    raise ReportError('Invalid Playwright spec outcome')
                if not spec['ok']:
                    reasons.append('spec_not_ok')
            identity = '::'.join([spec_file, *titles, spec_title])
            spec_tests = _array(spec.get('tests'))
            if not spec_tests:
                raise ReportError('Playwright spec has no test cases')
            for test in spec_tests:
                test_case(test, identity)
        for child in _array(node.get('suites', [])):
            suite(child, titles, file, depth + 1)

    for value in _array(data.get('suites')):
        suite(value, [], '', 0)
    if 'stats' in data:
        claimed = _counts(data['stats'], tuple(outcome_counts))
        if claimed != outcome_counts:
            raise ReportError('Inconsistent Playwright aggregate counts')
    statuses = Counter(test['status'] for test in tests)
    counts = {'total': len(tests), 'passed': statuses['pass'], 'failed': statuses['fail'],
              'inconclusive': statuses['inconclusive'], 'errors': len(errors), **outcome_counts}
    if not tests:
        reasons.append('no_test_cases')
    if any(test['status'] != 'pass' for test in tests):
        reasons.append('test_not_passed')
    return _result('tests', counts, tests, reasons)


def _schemathesis(data: dict) -> dict:
    _string(data.get('schemathesis_version'))
    complete = data.get('complete')
    if type(complete) is not bool:
        raise ReportError('Invalid Schemathesis completion flag')
    exit_code = _count(data.get('exit_code'))
    stop_reason = _string(data.get('stop_reason'))
    operations = _counts(data.get('operations'), ('total', 'selected', 'tested', 'errored', 'skipped'))
    cases = _counts(data.get('test_cases'), ('generated', 'without_checks', 'errored'))
    for name in ('with_failures', 'unique_failures'):
        if name in data['test_cases']:
            cases[name] = _count(data['test_cases'][name])
    # Schemathesis 4.32.7 summary.py removes tested operations from the error set
    # and puts every remaining selected operation in skipped.
    if (operations['selected'] > operations['total']
            or sum(operations[key] for key in ('tested', 'errored', 'skipped'))
            != operations['selected']
            or cases['without_checks'] + cases['errored'] + cases.get('with_failures', 0)
            > cases['generated']):
        raise ReportError('Inconsistent Schemathesis aggregate counts')
    if operations['selected'] > MAX_CASES or cases['generated'] > MAX_CASES:
        raise ReportError('Report exceeds the case limit')
    failures, errors = _array(data.get('failures')), _array(data.get('errors'))
    for item in [*failures, *errors]:
        _object(item)
    if 'warnings' not in data or not isinstance(data['warnings'], (dict, list)):
        raise ReportError('Invalid Schemathesis warnings')
    counts = {**{f'operations_{key}': value for key, value in operations.items()},
              **{f'test_cases_{key}': value for key, value in cases.items()},
              'failures': len(failures), 'errors': len(errors), 'exit_code': exit_code}
    reasons = []
    if not complete or stop_reason != 'completed':
        reasons.append('incomplete_run')
    if exit_code:
        reasons.append('nonzero_exit')
    if not operations['tested'] or cases['generated'] <= cases['without_checks']:
        reasons.append('no_checked_cases')
    if operations['tested'] != operations['selected']:
        reasons.append('operations_not_tested')
    if operations['errored'] or cases['errored'] or errors:
        reasons.append('errors')
    if operations['skipped']:
        reasons.append('skipped')
    if failures or cases.get('with_failures') or cases.get('unique_failures'):
        reasons.append('failures')
    # The aggregate report exposes no per-test execution IDs. Inventing IDs from
    # operation names would let unproved acceptance criteria pass.
    return _result('api', counts, [], reasons)


def _mutmut(data: dict) -> dict:
    counts = _counts(data, _MUTMUT_FIELDS)
    if counts['total'] > MAX_CASES:
        raise ReportError('Report exceeds the case limit')
    accounted = sum(value for key, value in counts.items() if key != 'total')
    if accounted > counts['total']:
        raise ReportError('Inconsistent mutmut aggregate counts')
    # export-cicd-stats omits not_checked and caught_by_type_check, although
    # both contribute to total. The residue cannot be claimed as killed.
    counts['unaccounted'] = counts['total'] - accounted
    reasons = [] if counts['total'] else ['no_mutants']
    reasons += [key for key, value in counts.items() if key not in {'total', 'killed'} and value]
    return _result('mutations', counts, [], reasons)


def _stryker(data: dict) -> dict:
    tests: list[dict] = []
    seen: set[str] = set()
    counts = dict.fromkeys((value[0] for value in _STRYKER_STATUSES.values()), 0)
    for filename, value in _object(data.get('files')).items():
        _string(filename)
        path = PurePosixPath(filename)
        windows = PureWindowsPath(filename)
        if (path.is_absolute() or windows.drive or windows.root or '\\' in filename
                or any(part in {'', '.', '..'} for part in filename.split('/'))):
            raise ReportError('Stryker file must be a normalized relative path')
        file = _object(value)
        for value in _array(file.get('mutants')):
            mutant = _object(value)
            identity = filename + '::' + _string(mutant.get('id'))
            status = _string(mutant.get('status'))
            if status not in _STRYKER_STATUSES:
                raise ReportError('Unknown Stryker mutant status')
            counter, normalized = _STRYKER_STATUSES[status]
            _add_case(tests, seen, identity, normalized)
            counts[counter] += 1
    counts['total'] = len(tests)
    counts['viable'] = counts['total'] - counts['compile_errors']
    reasons = [] if counts['viable'] else ['no_viable_mutants']
    reasons += [key for key in counts
                if key not in {'total', 'viable', 'killed', 'compile_errors'} and counts[key]]
    return _result('mutations', counts, tests, reasons)


def parse_report(format: str, content: str) -> dict:
    """Parse supported reports; errors never include untrusted report content."""
    parsers = {'playwright-json': _playwright, 'schemathesis-json': _schemathesis,
               'mutmut-json': _mutmut, 'stryker-json': _stryker}
    if not isinstance(format, str) or format not in {'junit', *parsers}:
        raise ReportError('Unsupported report format')
    if not isinstance(content, str):
        raise ReportError('Report content must be text')
    try:
        if format == 'junit':
            return _junit(content)
        data = json.loads(content, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
        return parsers[format](_object(data))
    except ReportError:
        raise
    except (ValueError, RecursionError, OverflowError):
        raise ReportError('Malformed report or nesting limit exceeded') from None


def evaluate_criteria(report: dict, criteria: dict[str, list[str]]) -> list[dict]:
    """Require each requested exact ID to occur once and have a passing outcome."""
    observations: dict[str, list[str]] = {}
    tests = _array(_object(report).get('tests'))
    if len(tests) > MAX_CASES:
        raise ReportError('Report exceeds the case limit')
    for value in tests:
        test = _object(value)
        identity, status = _string(test.get('id')), _string(test.get('status'))
        if status not in _CASE_STATUSES:
            raise ReportError('Unknown normalized test status')
        observations.setdefault(identity, []).append(status)
    results = []
    for identity, value in _object(criteria).items():
        _string(identity)
        requested = [_string(item) for item in _array(value)]
        missing = [item for item in requested if item not in observations]
        passed = bool(requested) and all(observations.get(item) == ['pass'] for item in requested)
        results.append({'id': identity, 'status': 'pass' if passed else 'fail',
                        'tests': requested, 'missing': missing})
    return results
