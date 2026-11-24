"""Unittest instrumentation; journal ownership remains in verification_journal."""
from pathlib import Path
from types import FunctionType, MethodType
import unittest

from .verification_journal import (
    _exception_kind, _observe, bind_sink, case_identity, skip_classification,
    span, test_identity,
)


def case_location(test, root=None):
    try:
        method = getattr(test, getattr(test, '_testMethodName', ''), None)
        if isinstance(method, MethodType):
            method = method.__func__
        seen = set()
        for _ in range(8):
            if not isinstance(method, FunctionType) or id(method) in seen:
                return None
            seen.add(id(method))
            wrapped = method.__dict__.get('__wrapped__')
            if wrapped is None:
                break
            method = wrapped
        else:
            return None
        code = method.__code__
        if root is not None:
            path = Path(code.co_filename).relative_to(root).as_posix()
            if test_identity(path) is not None and test_identity(path)['path'] == path and 1 <= code.co_firstlineno <= 1000000:
                return (path, code.co_firstlineno)
    except Exception:
        return None  # Unsupported metadata cannot change the original skip outcome.
    return None


def unittest_runner(writer):
    """Use the standard runner once; observe its actual call boundaries only."""
    class Result(unittest.TextTestResult):
        def startTest(self, test):
            super().startTest(test)
            node = case_identity(test)
            _observe(writer, 'begin_test_phase', node, 'unknown')
            writer.emit('test', 'start', nodeid=node)
            originals = {}
            for name, stage in (('_callSetUp', 'setup'), ('_callTestMethod', 'call'), ('_callTearDown', 'teardown')):
                original = getattr(test, name)
                originals[name] = (name in test.__dict__, test.__dict__.get(name))
                def observed(*args, _original=original, _stage=stage, **kwargs):
                    _observe(writer, 'begin_test_phase', node, _stage)
                    try:
                        with bind_sink(writer, node), span(None, stage=_stage) as detail:
                            detail['outcome'] = 'pass'
                            return _original(*args, **kwargs)
                    except BaseException as error:
                        _observe(writer, 'note_exception', node, _stage, error)
                        raise
                setattr(test, name, observed)
            self._journal_originals = (test, originals)

        def stopTest(self, test):
            prior = getattr(self, '_journal_originals', None)
            if prior is not None and prior[0] is test:
                for name, (had, value) in prior[1].items():
                    if had:
                        setattr(test, name, value)
                    else:
                        test.__dict__.pop(name, None)
            super().stopTest(test)

        def addSuccess(self, test):
            writer.emit('test', 'end', nodeid=case_identity(test), outcome='pass')
            super().addSuccess(test)

        def addFailure(self, test, err):
            writer.emit('test', 'end', nodeid=case_identity(test), outcome='fail', error=err[1])
            super().addFailure(test, err)
            _observe(self, '_retain', test, err)

        def addError(self, test, err):
            writer.emit('test', 'end', nodeid=case_identity(test), outcome='error', error=err[1])
            super().addError(test, err)
            _observe(self, '_retain', test, err)

        def _retain(self, test, err=None, phase=None):
            started = getattr(self, '_journal_originals', (None,))[0] is test
            node = case_identity(test) if started else None
            _observe(writer, 'record_test_failure', node, phase if started else 'unknown', _exception_kind(err[1] if err else None))

        def addSkip(self, test, reason):
            writer.emit('test', 'end', nodeid=case_identity(test), outcome='skip', skip=skip_classification(reason), location=case_location(test, writer.source_root))
            super().addSkip(test, reason)

        def addExpectedFailure(self, test, err):
            writer.emit('test', 'end', nodeid=case_identity(test), outcome='expected-failure', error=err[1])
            super().addExpectedFailure(test, err)

        def addUnexpectedSuccess(self, test):
            writer.emit('test', 'end', nodeid=case_identity(test), outcome='unexpected-success')
            super().addUnexpectedSuccess(test)
            if self.unexpectedSuccesses and self.unexpectedSuccesses[-1] is test:
                _observe(self, '_retain', test, None, 'call')

        def addSubTest(self, test, subtest, err):
            writer.emit('call', 'unknown', nodeid=case_identity(test), outcome='pass' if err is None else 'fail',
                        error=None if err is None else err[1])
            super().addSubTest(test, subtest, err)
            if err is not None:
                _observe(self, '_retain', test, err, 'call')

    class Runner(unittest.TextTestRunner):
        resultclass = Result

        def run(self, test):
            writer.emit('collection', 'end')
            return super().run(test)
    return Runner
