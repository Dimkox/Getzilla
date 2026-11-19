"""Ordinary/empty metadata checks; fixtures do not authenticate a native host."""
from __future__ import annotations

import hashlib
import importlib
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
EMPTY = hashlib.sha256(b'').hexdigest()


class NativeAccessTests(unittest.TestCase):
    def setUp(self):
        try:
            self.n = importlib.import_module('getzilla.native_access')
        except ModuleNotFoundError:
            self.fail('approved dependency-neutral native access boundary is missing')
        n = self.n
        self.now = 0.0
        self.enterContext(patch.object(n.time, 'monotonic', lambda: self.now))

        class EmptyHost(n.NativeAccessHost):
            def __init__(self):
                self.request, self.workflow, self.binding = object(), object(), object()
                self.revision = 1
                self.events = []
                self.after_read = lambda: None
                self.omit_lineage = False
                self.fail_admission = False

            def bind_native_request(self, request, workflow, deadline):
                if request is not self.request or workflow is not self.workflow:
                    raise n.NativeAccessError('native_access_denied')
                return self.binding

            def check_current(self, binding, deadline):
                if binding is not self.binding:
                    raise n.NativeAccessError('native_access_denied')
                return n.AuthorityStamp(self.revision, 'a' * 64, 'b' * 64)

            def load_authorized_cut(self, binding, query, deadline):
                self.events.append(('read', query.parameters))
                self.after_read()
                dep = n.SourceDependency(('public', 'project', 'fixture', 'local', 'empty'),
                                         'v1', EMPTY, EMPTY, 'identity/v1')
                return n.CapturedRead((n.SourceDocument(dep, b''),), object())

            def prepare_owned_response(self, binding, captured, computation, response, deadline):
                self.events.append(('prepare', computation, response))
                lineage = () if self.omit_lineage else tuple(d.dependency for d in captured.documents)
                return n.PreparedReadResponse(object(), lineage, EMPTY)

            def admit_response(self, binding, prepared, deadline):
                self.events.append(('admit',))
                if self.fail_admission:
                    raise RuntimeError('PUBLIC-ERROR-DETAIL-MUST-NOT-ECHO')
                return n.ExistingOperationDisposition('queued', 'existing:operation')

        self.host = EmptyHost()
        self.broker = n.NativeAccessBroker._compose(self.host)
        self.handle = self.broker.bind_native_request(self.host.request, self.host.workflow)
        self.query = n.RegisteredQuery('public-reader/v1', ('public-scope',), {})

    def capture(self):
        return self.broker.load_authorized_cut(self.handle, self.query, absolute_deadline=2.0)

    def prepare(self):
        return self.broker.prepare_owned_response(self.handle, 'public-computation/v1', self.capture(),
                                                   'registered-response', absolute_deadline=2.0)

    def test_missing_host_refuses_before_any_source_or_factory_import(self):
        broker = self.n.NativeAccessBroker()
        with self.assertRaisesRegex(self.n.NativeAccessError, '^native_access_unavailable$'):
            broker.bind_native_request({'session': 'claimed'}, {'uid': 1000})
        child = ('import sys;sys.path.insert(0,sys.argv[1]);from getzilla.native_access import NativeAccessBroker;'
                 'NativeAccessBroker();assert not any(n.startswith(("getzilla_factory","psycopg")) for n in sys.modules)')
        result = subprocess.run([sys.executable, '-B', '-c', child, str(ROOT / '.getzilla')],
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_handle_is_not_caller_constructible_serializable_or_foreign(self):
        import pickle
        with self.assertRaises(TypeError):
            self.n.NativeReadHandle()
        with self.assertRaises(TypeError):
            pickle.dumps(self.handle)
        for value in ({'session': 'claimed', 'role': 'worker'}, object(), object.__new__(self.n.NativeReadHandle)):
            with self.assertRaises(self.n.NativeAccessError):
                self.broker.load_authorized_cut(value, self.query, absolute_deadline=2.0)
        foreign = self.n.NativeAccessBroker._compose(self.host)
        with self.assertRaises(self.n.NativeAccessError):
            foreign.load_authorized_cut(self.handle, self.query, absolute_deadline=2.0)
        self.assertEqual(self.host.events, [])

    def test_query_captures_builtin_values_and_rejects_authority_fields(self):
        parameters = {'view': ['ordinary']}
        query = self.n.RegisteredQuery('public-reader/v1', ('public-scope',), parameters)
        parameters['view'].append('changed')
        first = query.parameters
        first['view'].append('changed-again')
        self.assertEqual(query.parameters, {'view': ['ordinary']})
        for wire in ({'reader_id': 'r', 'scope_ids': ['s'], 'parameters': {}, 'principal': 'claimed'},
                     {'reader_id': 'r', 'scope_ids': [], 'parameters': {}},
                     {'reader_id': 'r', 'scope_ids': ['s', 's'], 'parameters': {}}):
            with self.assertRaises(self.n.NativeAccessError):
                self.n.RegisteredQuery.from_dict(wire)
        with self.assertRaises(self.n.NativeAccessError):
            self.n.RegisteredQuery('r', ('s',), {'value': float('nan')})

    def test_read_is_owned_and_same_query_does_not_repeat_source_io(self):
        cut = self.capture()
        self.assertEqual(cut.documents[0].content, b'')
        self.assertFalse(cut.evidence_authority)
        self.assertIs(self.capture(), cut)
        self.assertEqual(self.host.events, [('read', {})])
        other = self.n.RegisteredQuery('public-reader/v1', ('other-scope',), {})
        with self.assertRaisesRegex(self.n.NativeAccessError, 'native_access_conflict'):
            self.broker.load_authorized_cut(self.handle, other, absolute_deadline=2.0)

    def test_change_during_read_never_returns_a_cut(self):
        self.host.after_read = lambda: setattr(self.host, 'revision', 2)
        with self.assertRaisesRegex(self.n.NativeAccessError, 'native_access_stale'):
            self.capture()

    def test_single_eight_mib_journal_keeps_identity_and_aggregate_limit(self):
        content = b' ' * (8 * 1048576)
        digest = hashlib.sha256(content).hexdigest()
        dep = self.n.SourceDependency(('public', 'project', 'fixture', 'local', 'journal'),
                                      'v1', digest, digest, 'identity/v1')
        document = self.n.SourceDocument(dep, content)
        with patch.object(self.host, 'load_authorized_cut',
                          return_value=self.n.CapturedRead((document,), object())):
            try:
                cut = self.capture()
            except self.n.NativeAccessError:
                self.fail('approved single eight-MiB journal must not be split or truncated')
        self.assertEqual(len(cut.documents), 1)
        self.assertIs(cut.documents[0], document)
        self.assertEqual(len(cut.documents[0].content), 8 * 1048576)
        extra_digest = hashlib.sha256(b' ').hexdigest()
        other = self.n.SourceDependency(('public', 'project', 'fixture', 'local', 'extra'),
                                        'v1', extra_digest, extra_digest, 'identity/v1')
        overflow = self.n.SourceDocument(other, b' ')
        with self.assertRaises(self.n.NativeAccessError):
            self.broker._documents(self.n.CapturedRead((document, overflow), object()))

    def test_one_absolute_deadline_is_not_reset_after_source_work(self):
        self.host.after_read = lambda: setattr(self, 'now', 2.0)
        with self.assertRaisesRegex(self.n.NativeAccessError, 'native_access_expired'):
            self.capture()
        self.now = 1.9
        with self.assertRaises(self.n.NativeAccessError):
            self.capture()

    def test_missing_or_changed_lineage_refuses_before_admission(self):
        self.host.omit_lineage = True
        with self.assertRaisesRegex(self.n.NativeAccessError, 'native_access_unavailable'):
            self.prepare()
        self.assertNotIn(('admit',), self.host.events)

    def test_same_preparation_is_single_use_and_target_cannot_change(self):
        prepared = self.prepare()
        self.assertIs(self.prepare(), prepared)
        with self.assertRaisesRegex(self.n.NativeAccessError, 'native_access_conflict'):
            self.broker.prepare_owned_response(self.handle, 'public-computation/v1', self.capture(),
                                               'other-response', absolute_deadline=2.0)
        result = self.broker.admit_response(self.handle, prepared)
        self.assertEqual((result.status, result.operation_id), ('queued', 'existing:operation'))
        with self.assertRaisesRegex(self.n.NativeAccessError, 'native_access_already_used'):
            self.broker.admit_response(self.handle, prepared)
        self.assertEqual(self.host.events.count(('admit',)), 1)

    def test_revocation_before_admission_does_not_call_consumer(self):
        prepared = self.prepare()
        self.host.revision = 2
        with self.assertRaisesRegex(self.n.NativeAccessError, 'native_access_stale'):
            self.broker.admit_response(self.handle, prepared)
        self.assertNotIn(('admit',), self.host.events)

    def test_admission_uncertainty_cannot_repeat_or_echo_native_error(self):
        prepared = self.prepare()
        self.host.fail_admission = True
        with self.assertRaisesRegex(self.n.NativeAccessError, '^native_access_outcome_unknown$'):
            self.broker.admit_response(self.handle, prepared)
        with self.assertRaisesRegex(self.n.NativeAccessError, '^native_access_already_used$'):
            self.broker.admit_response(self.handle, prepared)
        self.assertEqual(self.host.events.count(('admit',)), 1)

    def test_unqualified_resume_and_child_never_invent_new_authority(self):
        for operation in (lambda: self.broker.resume_native_request({'session': 'claimed'}, 'checkpoint'),
                          lambda: self.broker.delegate_native_request(self.handle, {'role': 'worker'})):
            with self.assertRaisesRegex(self.n.NativeAccessError, '^native_access_unavailable$'):
                operation()


if __name__ == '__main__':
    unittest.main()
