"""Execute typed unittest references and retain invocation-owned case outcomes.

Uses the native bounded process runner. Local observations do not authenticate
candidate code; external CI remains the independent acceptance boundary.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

if __package__ in (None, ''):
    # Execute the installed verifier's driver even when the selected project is
    # a consumer or a source-only fixture without an embedded runtime package.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    __package__ = 'getzilla'

from .python_test_runner import _environment, execute
from .spec import _parse_canonical_json
from .verification_tool_workspace import checked_path, read_report, runtime_parent

MAX_REFERENCES = 2000
MAX_TESTS = 10000


def _target(root: Path, reference: str) -> str:
    if not isinstance(reference, str) or len(reference) > 512:
        raise ValueError('invalid typed test reference')
    parts = reference.split('::')
    path = parts[0]
    if (not re.fullmatch(r'(?:[A-Za-z_][A-Za-z0-9_]*/)*test_[A-Za-z0-9_]+\.py', path) or
            len(parts) > 3 or any(not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', part) for part in parts[1:])):
        raise ValueError('typed unittest evidence requires relative test_file.py[::Class[::test_method]]')
    if not checked_path(root, path).is_file():
        raise ValueError('typed test source is unavailable: ' + path)
    return '.'.join([path[:-3].replace('/', '.'), *parts[1:]])


def _cases(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _cases(item)
        else:
            yield item


class _ObservedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.observed = []
        self.outcomes = {}

    def startTest(self, test):
        super().startTest(test)
        self.observed.append(test.id())
        self.outcomes[test.id()] = 'inconclusive'

    def addSuccess(self, test):
        super().addSuccess(test)
        self.outcomes[test.id()] = 'pass'

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.outcomes[test.id()] = 'fail'

    def addError(self, test, err):
        super().addError(test, err)
        self.outcomes[test.id()] = 'fail'

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.outcomes[test.id()] = 'skip'

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        self.outcomes[test.id()] = 'fail'

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self.outcomes[test.id()] = 'fail'

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            self.outcomes[test.id()] = 'fail'


def _execute_references(root: Path, references: list[str]) -> dict:
    selections, cases, files = {}, {}, {}
    for reference in references:
        _target(root, reference)
        file_name, *selector = reference.split('::')
        path = root / file_name
        if file_name not in files:
            parent = path.parent
            package = True
            while parent != root:
                package = package and (parent / '__init__.py').is_file()
                parent = parent.parent
            # Native discovery verifies the imported file origin. With no package
            # initializer it uses the selected directory, not an unrelated tests package.
            loader = unittest.TestLoader()
            files[file_name] = list(_cases(loader.discover(str(path.parent), pattern=path.name,
                top_level_dir=str(root if package else path.parent))))
        loaded = files[file_name]
        if selector:
            loaded = [case for case in loaded if case.__class__.__name__ == selector[0] and
                      (len(selector) == 1 or case.id().endswith('.' + '.'.join(selector)))]
        identities = [item.id() for item in loaded]
        if len(identities) != len(set(identities)):
            raise ValueError('ambiguous repeated test identity in ' + reference)
        selections[reference] = identities
        for case in loaded:
            cases.setdefault(case.id(), case)
        if len(cases) > MAX_TESTS:
            raise ValueError('required test selection exceeds case bound')
    result = unittest.TextTestRunner(verbosity=2, resultclass=_ObservedResult).run(unittest.TestSuite(cases.values()))
    counts = Counter(result.observed)
    tests = [{'id': identity, 'status': status} for identity, status in sorted(result.outcomes.items())]
    verified = [reference for reference, identities in selections.items() if identities and
                all(counts[name] == 1 and result.outcomes.get(name) == 'pass' for name in identities)]
    return {'schema_version': 1, 'kind': 'criterion-test-execution', 'references': selections,
            'tests': tests, 'verified_references': sorted(verified),
            'status': 'pass' if references and len(verified) == len(references) and result.wasSuccessful() else 'fail'}


def run_required_tests(root: Path, references: list[str], *, timeout: int = 900) -> dict:
    detail = {'schema_version': 1, 'kind': 'criterion-test-execution', 'verified_references': [], 'tests': []}
    result = {'name': 'criterion-tests', 'status': 'fail', 'summary': 'required test execution incomplete',
              'details': [detail]}
    try:
        if (not isinstance(references, list) or not 0 < len(references) <= MAX_REFERENCES or
                type(timeout) is not int or not 1 <= timeout <= 900):
            raise ValueError('invalid required test selection or timeout')
        references = sorted(set(references))
        for reference in references:
            _target(root, reference)
        with tempfile.TemporaryDirectory(prefix='criterion-', dir=runtime_parent(root)) as directory:
            temporary = Path(directory)
            output = temporary / 'cases.json'
            command = [sys.executable, str(Path(__file__).resolve()), '--output', str(output)]
            for reference in references:
                command.extend(['--reference', reference])
            process = execute(command, root, _environment(root, temporary / '.coverage'), timeout=timeout)
            result.update(command=command, stdout=process.stdout[-12000:], stderr=process.stderr[-12000:])
            observed = _parse_canonical_json(read_report(output, temporary), output)
            if (not isinstance(observed, dict) or observed.get('schema_version') != 1 or
                    observed.get('kind') != 'criterion-test-execution' or
                    set(observed.get('references', {})) != set(references) or
                    not isinstance(observed.get('tests'), list) or len(observed['tests']) > MAX_TESTS):
                raise ValueError('required test report schema or selection mismatch')
            # Recompute coverage from case outcomes; do not consume a producer's aggregate PASS.
            observations = {}
            for item in observed['tests']:
                if not isinstance(item, dict) or set(item) != {'id', 'status'} or not isinstance(item['id'], str):
                    raise ValueError('invalid required test case')
                observations.setdefault(item['id'], []).append(item['status'])
            verified = []
            for reference, identifiers in observed['references'].items():
                if (not isinstance(identifiers, list) or not identifiers or len(identifiers) != len(set(identifiers)) or
                        any(observations.get(name) != ['pass'] for name in identifiers)):
                    continue
                verified.append(reference)
            completed = process.returncode == 0 and process.terminal_state == 'completed' and not process.cleanup_error
            observed['verified_references'] = sorted(verified) if completed else []
            result['details'] = [observed]
            result['status'] = 'pass' if completed and len(verified) == len(references) else 'fail'
            result['summary'] = f"{len(verified) if completed else 0}/{len(references)} required test references verified; {len(observations)} actual cases"
    except (OSError, ValueError, TypeError, KeyError, UnicodeError) as exc:
        result['summary'] = 'required test evidence unavailable: ' + str(exc)[:512]
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--reference', action='append', required=True)
    args = parser.parse_args()
    if not 0 < len(args.reference) <= MAX_REFERENCES:
        parser.error('required selection exceeds reference bound')
    observed = _execute_references(Path.cwd(), sorted(set(args.reference)))
    args.output.write_text(json.dumps(observed, ensure_ascii=True), encoding='utf-8')
    return 0 if observed['status'] == 'pass' else 1


if __name__ == '__main__':
    raise SystemExit(main())
