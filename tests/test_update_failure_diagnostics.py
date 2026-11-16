"""NEW closed exception/data fixtures; no updater, installer or old tests run."""
from __future__ import annotations

import builtins
import ctypes
from contextlib import ExitStack
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import adapter_removal as producer
from getzilla import pytest_progress as progress
from getzilla import verification_failure_excerpt as excerpt
from getzilla import verification_progress_evidence as reader

CANARY = 'NEW_PRIVATE_UPDATE_VALUE_982'


class UpdateFailureDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.guard = ExitStack()
        self.addCleanup(self.guard.close)
        def deny(*args, **kwargs):
            raise AssertionError('outside-fixture I/O/process/native/network denied')
        for module, name in ((builtins, 'open'), (os, 'open'), (os, 'read'), (os, 'write'),
                             (subprocess, 'Popen'), (os, 'system'), (socket, 'socket'), (ctypes, 'CDLL')):
            self.guard.enter_context(patch.object(module, name, side_effect=deny))

    def helpers(self):
        self.assertTrue(callable(getattr(excerpt, 'update_exception_diagnostic', None)),
                        'real closed UpdateError diagnostic is absent')
        self.assertTrue(callable(getattr(excerpt, 'valid_update_diagnostic', None)))

    def actual(self, reason='dirty-target', phase='preflight'):
        try:
            raise producer.UpdateError(CANARY, reason=reason, phase=phase)
        except producer.UpdateError as error:
            return error

    def test_actual_type_closed_native_data_and_string_preserved(self):
        self.helpers()
        error = self.actual()
        self.assertIs(type(error), producer.UpdateError)
        self.assertEqual(str(error), CANARY)
        self.assertEqual(error.args, (CANARY,))
        value = excerpt.update_exception_diagnostic(error)
        self.assertTrue(excerpt.valid_update_diagnostic(value))
        self.assertEqual((value['reason'], value['phase'], value['via']),
                         ('dirty-target', 'preflight', 'direct'))
        self.assertNotIn(CANARY, json.dumps(value))
        error.__dict__['_update_diagnostic'] = ('checkout', 'checkout')
        self.assertEqual(excerpt.update_exception_diagnostic(error), value)
        with self.assertRaises(AttributeError):
            error._update_diagnostic = ('checkout', 'checkout')
        unknown = self.actual(reason=CANARY, phase=CANARY)
        self.assertEqual(excerpt.update_exception_diagnostic(unknown)['reason'], 'unknown')

    def test_only_actual_owned_module_type_not_names_or_markers(self):
        self.helpers()
        class UpdateError(RuntimeError):
            pass
        class Subclass(producer.UpdateError):
            pass
        for value in (UpdateError(CANARY), Subclass(CANARY), CANARY,
                      AssertionError('GETZILLA_UPDATE_DIAGNOSTIC dirty-target')):
            self.assertIsNone(excerpt.update_exception_diagnostic(value))
        real = self.actual()
        fake = SimpleNamespace(**producer.__dict__)
        with patch.dict(sys.modules, {'getzilla.adapter_removal': fake}):
            self.assertIsNone(excerpt.update_exception_diagnostic(real))
        copied_module = ModuleType(producer.__name__)
        copied_module.__dict__.update(producer.__dict__)
        with patch.dict(sys.modules, {'getzilla.adapter_removal': copied_module}):
            self.assertIsNone(excerpt.update_exception_diagnostic(real))
        invalid = dict(excerpt.update_exception_diagnostic(real), stdout=CANARY)
        self.assertFalse(excerpt.valid_update_diagnostic(invalid))
        self.assertFalse(excerpt.valid_update_diagnostic(dict(invalid, reason=CANARY)))

    def test_bounded_builtin_assertion_native_context_and_cause(self):
        self.helpers()
        cause = self.actual('target-index-mode', 'preflight')
        try:
            raise AssertionError(CANARY) from cause
        except AssertionError as error:
            value = excerpt.update_exception_diagnostic(error)
        self.assertEqual((value['reason'], value['via']), ('target-index-mode', 'cause'))
        try:
            try:
                raise self.actual('generated-policy', 'plan')
            except producer.UpdateError:
                raise AssertionError(CANARY)
        except AssertionError as error:
            value = excerpt.update_exception_diagnostic(error)
        self.assertEqual((value['reason'], value['via']), ('generated-policy', 'context'))
        loop = AssertionError(CANARY)
        loop.__context__ = loop
        self.assertIsNone(excerpt.update_exception_diagnostic(loop))
        class Subclass(AssertionError):
            pass
        sub = Subclass(CANARY)
        sub.__cause__ = cause
        self.assertIsNone(excerpt.update_exception_diagnostic(sub))

    def test_real_assert_raises_regex_context_survives_cleared_traceback(self):
        self.helpers()
        try:
            with unittest.TestCase().assertRaisesRegex(producer.UpdateError, '^unmatched$'):
                raise self.actual('generated-policy', 'plan')
        except AssertionError as error:
            self.assertIsNone(error.__context__.__traceback__)
            value = excerpt.update_exception_diagnostic(error)
        self.assertIsNotNone(value)
        self.assertEqual((value['reason'], value['via']), ('generated-policy', 'context'))

    def test_actual_worker_and_strict_data_reader_preserve_private_verdict(self):
        self.helpers()
        error = self.actual('missing-manifest', 'preflight')
        holder = SimpleNamespace(_pending_diagnostic=None, failure_disabled=False,
            failure_overflow=False, failure_sequence=0, failure_rows=0, _failure_append=lambda v: rows.append(v))
        rows = []
        node = 'tests/test_new_update_fixture.py::Owned::test_refusal'
        hook = progress._WorkerProgress.pytest_runtest_makereport(holder,
            SimpleNamespace(nodeid=node), SimpleNamespace(when='call', excinfo=SimpleNamespace(value=error)))
        next(hook)
        with self.assertRaises(StopIteration):
            next(hook)
        progress._WorkerProgress.pytest_runtest_logreport(holder,
            SimpleNamespace(failed=True, when='call', nodeid=node, sections=[CANARY], longrepr=CANARY))
        self.assertEqual(len(rows), 1)
        value = rows[0]['diagnostic']
        self.assertEqual(value['reason'], 'missing-manifest')
        self.assertTrue(progress._failure_diagnostic_valid(value))
        event = {k:v for k,v in rows[0].items() if k != 'kind'}
        observed = {'failure_events': {'version': 1, 'status': 'observed', 'workers': [
            {'worker': 0, 'sequence': 1, 'overflow': False, 'dropped': False,
             'partial_tail': False, 'events': [event]}]}}
        accepted = reader._progress_failure_rows(observed, 1)
        self.assertEqual(len(accepted), 1)
        rendered = reader._failure_progress_details(accepted, {progress._node_identity(node): node}, 1)
        self.assertEqual(rendered['events'][0]['diagnostic'], value)
        self.assertNotIn(CANARY, json.dumps(rendered))
        event['diagnostic'] = dict(value, path=CANARY)
        self.assertEqual(reader._progress_failure_rows(observed, 1), [])

    def test_first_strict_stream_reader_closed_data_and_rejection(self):
        self.helpers()
        value = excerpt.update_exception_diagnostic(self.actual('target-index-identity', 'preflight'))
        nonce = '8' * 32
        def parse(diagnostic):
            document = [dict(version=1, kind='core-failed-reports', nonce=nonce, worker=0),
                        dict(kind='failure', ordinal=1, phase='call',
                             path='tests/test_new_update_fixture.py', key='f' * 64, diagnostic=diagnostic)]
            content = b''.join(json.dumps(row).encode() + b'\n' for row in document)
            info = SimpleNamespace(st_dev=1, st_ino=2, st_size=len(content),
                                   st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_uid=os.getuid())
            class Stream(io.BytesIO):
                def fileno(self):
                    return 31337
            with patch.object(progress.fsx, 'lstat_at', return_value=info), \
                    patch.object(progress.fsx, 'open_at', return_value=31337), \
                    patch.object(os, 'fdopen', side_effect=lambda fd, mode: Stream(content)), \
                    patch.object(os, 'fstat', return_value=info):
                return progress._read_failure_prefix(object(), 0, nonce)
        self.assertEqual(parse(value)['events'][0]['diagnostic'], value)
        with self.assertRaises(ValueError):
            parse(dict(value, reason=CANARY))
        with self.assertRaises(ValueError):
            parse(dict(value, captured_stdout=CANARY))
        self.assertEqual((progress.MAX_FAILURE_BYTES, progress.MAX_FAILURE_EVENTS), (2048, 4))


if __name__ == '__main__':
    unittest.main()
