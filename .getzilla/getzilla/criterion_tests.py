"""Source-owned individual unittest evidence using the existing bounded native runner.

Local source identity is not test meaning, OS confinement or independent authority.
Only closed case identities/outcomes cross the driver; raw test/error output does not.
"""
from __future__ import annotations

import argparse
import ast
import contextlib
import hashlib
import importlib
import importlib.machinery
import importlib.util
import inspect
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import unittest

from .python_test_runner import _environment, execute
from .spec import _parse_canonical_json
from .verification_tool_workspace import (MAX_BYTES, MAX_FILE_BYTES, checked_path,
                                           read_report, runtime_parent)

MAX_REFERENCES = 2000
MAX_TESTS = 10000
_BOOTSTRAP = ("import sys;sys.path.insert(0,sys.argv.pop(1));"
              "from getzilla.criterion_tests import main;raise SystemExit(main())")


def _parts(reference):
    if not isinstance(reference, str) or len(reference) > 512:
        raise ValueError('invalid typed test reference')
    parts = reference.split('::')
    if (not re.fullmatch(r'(?:[A-Za-z_][A-Za-z0-9_]*/)*test_[A-Za-z0-9_]+\.py', parts[0])
            or len(parts) > 3 or any(not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', p) for p in parts[1:])):
        raise ValueError('unsupported typed unittest reference')
    return parts


def _target(root, reference):
    parts = _parts(reference)
    if not checked_path(root, parts[0]).is_file():
        raise ValueError('typed test source is unavailable')
    return '.'.join([parts[0][:-3].replace('/', '.'), *parts[1:]])


def _read_source(root, relative):
    path = checked_path(root, relative)
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE_BYTES:
            raise ValueError('typed source is not a bounded regular file')
        chunks, size = [], 0
        while True:
            block = os.read(fd, min(65536, MAX_FILE_BYTES + 1 - size))
            if not block:
                break
            chunks.append(block)
            size += len(block)
        def fields(s):
            return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_nlink,
                    s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        after = os.fstat(fd)
        if (fields(before) != fields(after) or fields(after) != fields(path.lstat())
                or size != before.st_size or size > MAX_FILE_BYTES):
            raise ValueError('typed source changed while reading')
        return b''.join(chunks)
    finally:
        os.close(fd)


def _source_ownership(root, references):
    ownership, contents, total = {}, {}, 0
    for reference in references:
        _target(root, reference)
        relative = _parts(reference)[0]
        if relative in ownership:
            continue
        content = _read_source(root, relative)
        total += len(content)
        if total > MAX_BYTES:
            raise ValueError('typed sources exceed existing workspace bound')
        tree = ast.parse(content)
        classes = {n.name: [m.name for m in n.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
                            and m.name.startswith('test')] for n in tree.body if isinstance(n, ast.ClassDef)}
        path = root / relative
        package = all((p / '__init__.py').is_file() for p in path.parents if p != root and p.is_relative_to(root))
        ownership[relative] = {'sha256': hashlib.sha256(content).hexdigest(),
            'module': relative[:-3].replace('/', '.') if package else path.stem, 'classes': classes,
            'functions': [n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                          and n.name.startswith('test')]}
        contents[relative] = content
    return ownership, contents


def _verified_references(report, references, ownership):
    if (not isinstance(report, dict) or report.get('schema_version') != 1
            or report.get('kind') != 'criterion-test-execution' or report.get('source') != ownership
            or not isinstance(report.get('references'), dict) or set(report['references']) != set(references)
            or not isinstance(report.get('tests'), list) or len(report['tests']) > MAX_TESTS):
        return []
    observations = {}
    for row in report['tests']:
        if (not isinstance(row, dict) or set(row) != {'id', 'status'} or not isinstance(row['id'], str)
                or len(row['id']) > 2048 or row['id'] in observations or row['status'] != 'pass'):
            return []
        observations[row['id']] = row['status']
    verified, selected = [], set()
    for reference in references:
        parts = _parts(reference)
        source = ownership.get(parts[0])
        if not isinstance(source, dict) or not isinstance(source.get('module'), str):
            return []
        declared = {source['module'] + '.' + cls + '.' + method
                    for cls, methods in source.get('classes', {}).items() for method in methods
                    if len(parts) == 1 or cls == parts[1]
                    if len(parts) < 3 or method == parts[2]}
        identifiers = report['references'][reference]
        if (not isinstance(identifiers, list) or not identifiers or any(not isinstance(x, str) for x in identifiers)
                or len(set(identifiers)) != len(identifiers) or set(identifiers) != declared
                or any(x not in observations for x in identifiers)):
            continue
        selected.update(identifiers)
        verified.append(reference)
    return sorted(verified) if selected == set(observations) else []


def _cases(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _cases(item)
        else:
            yield item


class _SnapshotLoader(importlib.machinery.SourceFileLoader):
    """Compile the exact held-source snapshot rather than accepting cached bytecode."""
    def __init__(self, name, path, content):
        super().__init__(name, path)
        self.content = content

    def get_code(self, fullname):
        return self.source_to_code(self.content, self.path)


class _Discard:
    def write(self, value):
        return len(value)

    def flush(self):
        pass


def _trusted_lifecycle(case):
    """Only the canonical unittest lifecycle can earn this driver's execution credit.

    Owned setUp/tearDown/test bodies remain ordinary test code, not confined code.
    Custom lifecycle adapters need a separate supported execution contract.
    """
    names = ('run', '__call__', '__getattribute__', '_callTestMethod', '_callSetUp',
             '_callTearDown', '_callCleanup', 'doCleanups')
    return all(inspect.getattr_static(case, name) is inspect.getattr_static(unittest.TestCase, name)
               for name in names)


class _ObservedResult(unittest.TestResult):
    def __init__(self, identities):
        super().__init__()
        self.identities, self.observed, self.outcomes = identities, [], {}

    def startTest(self, test):
        if not _trusted_lifecycle(test):
            raise ValueError('typed case lifecycle is unsupported or changed')
        super().startTest(test)
        name = self.identities[id(test)]
        self.observed.append(name)
        self.outcomes[name] = 'unknown'

    def addSuccess(self, test):
        name = self.identities[id(test)]
        if self.outcomes.get(name) == 'unknown':
            self.outcomes[name] = 'pass'

    def addFailure(self, test, err):
        self.outcomes[self.identities[id(test)]] = 'fail'
        self.failures.append((test, 'closed failure'))

    def addError(self, test, err):
        self.outcomes[self.identities[id(test)]] = 'fail'
        self.errors.append((test, 'closed error'))

    def addSkip(self, test, reason):
        self.outcomes[self.identities[id(test)]] = 'skip'

    def addExpectedFailure(self, test, err):
        self.addFailure(test, None)

    def addUnexpectedSuccess(self, test):
        self.addFailure(test, None)

    def addSubTest(self, test, subtest, err):
        if err is not None:
            self.addFailure(test, None)


def _execute_references(root, references):
    root = root.resolve()
    ownership, contents = _source_ownership(root, references)
    selections, cases, identities, loaded = {}, {}, {}, {}
    sys.path.insert(0, str(root))
    try:
        with contextlib.redirect_stdout(_Discard()), contextlib.redirect_stderr(_Discard()):
            for reference in references:
                relative, *selector = _parts(reference)
                source = ownership[relative]
                if relative not in loaded:
                    name = source['module']
                    if '.' in name:
                        parent = importlib.import_module(name.rsplit('.', 1)[0])
                        if not Path(parent.__file__).resolve().is_relative_to(root):
                            raise ValueError('typed source package is not owned')
                    path = (root / relative).resolve()
                    loader = _SnapshotLoader(name, str(path), contents[relative])
                    spec = importlib.util.spec_from_file_location(name, path, loader=loader)
                    if spec is None:
                        raise ValueError('typed source module is unavailable')
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[name] = module
                    loader.exec_module(module)
                    loaded[relative] = list(_cases(unittest.TestLoader().loadTestsFromModule(module)))
                chosen = [case for case in loaded[relative] if not selector or
                          type(case).__name__ == selector[0] and
                          (len(selector) == 1 or getattr(case, '_testMethodName', None) == selector[1])]
                selected = []
                for case in chosen:
                    if not _trusted_lifecycle(case):
                        raise ValueError('typed case lifecycle is unsupported')
                    cls, method = type(case), getattr(case, '_testMethodName', None)
                    if (cls.__module__ != source['module'] or method not in source['classes'].get(cls.__name__, [])
                            or not isinstance(case, unittest.TestCase)):
                        raise ValueError('typed case is imported or outside source ownership')
                    function = inspect.unwrap(inspect.getattr_static(cls, method))
                    if not inspect.isfunction(function) or Path(function.__code__.co_filename).resolve() != (root / relative).resolve():
                        raise ValueError('typed case implementation was substituted')
                    declaration = next((child for node in ast.parse(contents[relative]).body
                                        if isinstance(node, ast.ClassDef) and node.name == cls.__name__
                                        for child in node.body if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                                        and child.name == method), None)
                    first = min([declaration.lineno, *[n.lineno for n in declaration.decorator_list]]) if declaration else -1
                    if (declaration is None or not first <= function.__code__.co_firstlineno <= declaration.lineno
                            or function.__code__.co_qualname != cls.__qualname__ + '.' + method):
                        raise ValueError('typed case callable does not match the selected declaration')
                    name = source['module'] + '.' + cls.__name__ + '.' + method
                    if name in selected:
                        raise ValueError('duplicate selected identity')
                    selected.append(name)
                    cases.setdefault(name, case)
                    identities[id(cases[name])] = name
                selections[reference] = selected
                if len(cases) > MAX_TESTS:
                    raise ValueError('typed selection exceeds existing case bound')
            result = _ObservedResult(identities)
            unittest.TestSuite(cases.values()).run(result)
        if _source_ownership(root, references)[0] != ownership:
            raise ValueError('typed source changed during execution')
        tests = [{'id': name, 'status': status} for name, status in sorted(result.outcomes.items())]
        if len(result.observed) != len(set(result.observed)):
            tests.extend(tests[:1])
        report = {'schema_version': 1, 'kind': 'criterion-test-execution', 'source': ownership,
                  'references': selections, 'tests': tests}
        verified = _verified_references(report, references, ownership)
        return {**report, 'verified_references': verified,
                'status': 'pass' if len(verified) == len(references) and result.wasSuccessful() else 'fail'}
    finally:
        sys.path.remove(str(root))


def _driver_command(output, references):
    from .verification_plan import _module_source
    import getzilla
    engine = Path(getzilla.__file__).resolve().parents[1]
    identity = hashlib.sha256(_module_source(sys.modules[__name__])).hexdigest()
    command = [sys.executable, '-I', '-B', '-c', _BOOTSTRAP, str(engine), '--output', str(output),
               '--driver-sha256', identity]
    for reference in references:
        command.extend(['--reference', reference])
    return command


def run_required_tests(root, references, *, timeout=900):
    result = {'name': 'criterion-tests', 'status': 'fail', 'summary': 'required test evidence unavailable',
              'details': [{'schema_version': 1, 'kind': 'criterion-test-execution', 'verified_references': [], 'tests': []}]}
    try:
        if (not isinstance(references, list) or not 0 < len(references) <= MAX_REFERENCES
                or type(timeout) is not int or not 1 <= timeout <= 900):
            raise ValueError('invalid required test request')
        references = sorted(set(references))
        ownership, _contents = _source_ownership(root, references)
        with tempfile.TemporaryDirectory(prefix='criterion-', dir=runtime_parent(root)) as directory:
            temporary = Path(directory)
            output = temporary / 'cases.json'
            process = execute(_driver_command(output, references), root,
                              _environment(root, temporary / '.coverage'), timeout=timeout)
            observed = _parse_canonical_json(read_report(output, temporary), output)
            verified = _verified_references(observed, references, ownership)
            if _source_ownership(root, references)[0] != ownership:
                raise ValueError('typed source changed after execution')
            complete = process.returncode == 0 and process.terminal_state == 'completed' and not process.cleanup_error
            if complete and len(verified) == len(references):
                result['details'] = [{key: observed[key] for key in ('schema_version', 'kind', 'source', 'references', 'tests')}
                                     | {'verified_references': verified}]
                result.update(status='pass', summary=f'{len(verified)} source-owned test references verified')
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, ImportError):
        pass
    return result


def main():
    parser = argparse.ArgumentParser(description='Bounded source-owned criterion evidence')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--driver-sha256', required=True)
    parser.add_argument('--reference', action='append', default=[])
    args = parser.parse_args()
    try:
        from .verification_plan import _module_source
        if (not 0 < len(args.reference) <= MAX_REFERENCES
                or hashlib.sha256(_module_source(sys.modules[__name__])).hexdigest() != args.driver_sha256):
            return 2
        report = _execute_references(Path.cwd(), sorted(set(args.reference)))
        encoded = json.dumps(report, sort_keys=True, ensure_ascii=True).encode()
        if len(encoded) > MAX_FILE_BYTES:
            return 2
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as destination:
            destination.write(encoded)
        return 0 if report['status'] == 'pass' else 1
    except (OSError, ValueError, TypeError, ImportError, KeyError):
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
