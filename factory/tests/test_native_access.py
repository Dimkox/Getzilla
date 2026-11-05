"""Public/empty bridge contracts; native auth/storage/transport are not qualified here."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
from pathlib import Path
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / '.getzilla'))
sys.path.insert(0, str(ROOT / 'factory/src'))
from getzilla.native_access import NativeAccessBroker, NativeAccessError, RegisteredQuery
from getzilla_factory.access_authority import AccessAuthority, AccessError, AccessSession
from getzilla_factory.access_release import AccessReleaseService, LocalSourceAdapter
from getzilla_factory.brokers import ProposalContext
from getzilla_factory.models import Actor, LeaseGrant, RunRole
from getzilla_factory.result_dispatch import UdsResultHandoffClient
from getzilla_factory.store import PostgresFactoryStore

EMPTY = hashlib.sha256(b'').hexdigest()
TASK = '00000000-0000-0000-0000-000000000001'
RUN = '00000000-0000-0000-0000-000000000002'
ATTEMPT = '00000000-0000-0000-0000-000000000003'
KEY = dict(zip(('tenant', 'project', 'provider', 'site', 'resource'),
               ('public', 'project', 'local', 'fixture', 'empty')))


class FactoryNativeAccessTests(unittest.TestCase):
    def setUp(self):
        try:
            self.n = importlib.import_module('getzilla_factory.native_access')
        except ModuleNotFoundError:
            self.fail('optional concrete Factory native access bridge is missing')
        self.events = []
        self.authority = object.__new__(AccessAuthority)
        self.authority._source = threading.RLock()
        self.snapshot = SimpleNamespace(revision=1, permission_digest='a' * 64)
        self.actor = Actor('worker', 'worker', frozenset({'task:execute', 'source:read', 'source:release'}),
                           frozenset({'repo'}))
        self.session = object.__new__(AccessSession)
        self.enterContext(patch.object(self.authority, 'actor', return_value=self.actor))
        self.enterContext(patch.object(self.authority, '_live', return_value=None))
        self.enterContext(patch.object(self.authority, '_credential_live', return_value=None))
        self.enterContext(patch.object(self.authority, '_current', side_effect=lambda session:
                                      (self.snapshot, {}, {'actor_id': 'worker'})))
        self.enterContext(patch.object(self.authority, 'release_binding', return_value=(1, 'a' * 64, 1, 'worker')))
        self.enterContext(patch.object(self.authority, 'authorize', return_value=True))
        self.store = PostgresFactoryStore('unopened-public-fixture')
        self.sources = LocalSourceAdapter([dict(key=KEY, version='v1', repository_id='repo',
            workspace_handle='workspace', relative_path='ordinary.txt', file='/not-read/empty', content_digest=EMPTY)])
        self.source_bytes = b''
        self.enterContext(patch('getzilla_factory.access_release._private', side_effect=lambda path, limit:
                               (self.source_bytes, ())))
        self.enterContext(patch.object(self.sources, '_read', side_effect=self.read_empty))
        client = object.__new__(UdsResultHandoffClient)
        client._transport, client._timeout = None, 1
        self.service = AccessReleaseService(self.store, self.authority, self.sources, {'registered-response': client})
        self.context = ProposalContext(TASK, RUN, 'worker', 7, 'b' * 64, 'reader', 'repo', 'workspace',
            ('ordinary.txt',), (), 1024, 1024, 1024, 0, 0, (), ('read_file',))
        self.grant = LeaseGrant(TASK, RUN, 'worker', RunRole.READER, 7,
                                 datetime.now(timezone.utc) + timedelta(minutes=1), 'c' * 64)
        self.workflow = self.n.FactoryTaskBinding(self.grant, 'b' * 64)
        self.enterContext(patch.object(self.store, '_transaction', side_effect=self.transaction))
        self.enterContext(patch.object(self.store, '_proposal_context', return_value=self.context))
        self.host = self.n.FactoryNativeAccessHost(self.service)
        self.broker = NativeAccessBroker._compose(self.host)
        self.handle = self.broker.bind_native_request(self.session, self.workflow)
        self.query = RegisteredQuery('factory.source-text/v1', (self.n.factory_source_scope(KEY),), {})

    def read_empty(self, key, context, authority, session, remaining):
        self.events.append('empty-read')
        self.assertEqual(key, tuple(KEY.values()))
        self.assertIs(context, self.context)
        # Keep the actual registered reader's path, current-rights and hash checks.
        # Only the private-file IO and native authorization are substituted by
        # this declared public/empty metadata fixture, never qualified authority.
        return LocalSourceAdapter._read(self.sources, key, context, authority, session, remaining)

    @contextmanager
    def transaction(self, **bounds):
        self.assertLessEqual(bounds['connect_timeout'], 2)
        class Cursor:
            def execute(inner, query, arguments):
                if 'access_task_fence_v1' not in query:
                    raise AssertionError('only existing task fence is expected in this metadata fixture')
            def fetchone(inner):
                return (ATTEMPT,)
        yield Cursor()

    def test_public_request_labels_cannot_bind_without_live_session_object(self):
        for request in ({'actor_id': 'worker', 'role': 'worker'}, 'session-selector', 1000):
            with self.assertRaises(NativeAccessError):
                self.broker.bind_native_request(request, self.workflow)
        self.assertEqual(self.events, [])

    def test_bridge_uses_registered_source_and_existing_current_task_context(self):
        cut = self.broker.load_authorized_cut(self.handle, self.query, absolute_deadline=self.deadline())
        self.assertEqual(cut.documents[0].content, b'')
        self.assertEqual(cut.documents[0].dependency.key, tuple(KEY.values()))
        self.assertGreaterEqual(self.events.count('empty-read'), 2)

    def deadline(self):
        import time
        return time.monotonic() + 2

    def test_caller_paths_or_unknown_scope_refuse_before_source_read(self):
        for query in (RegisteredQuery('factory.source-text/v1', ('unregistered',), {}),
                      RegisteredQuery('factory.source-text/v1', self.query.scope_ids, {'file': '/not-read/empty'})):
            with self.assertRaises(NativeAccessError):
                self.broker.load_authorized_cut(self.handle, query, absolute_deadline=self.deadline())
        self.assertEqual(self.events, [])

    def test_owned_preparation_keeps_capture_and_fresh_source_revalidation(self):
        cut = self.broker.load_authorized_cut(self.handle, self.query, absolute_deadline=self.deadline())
        prepared = self.broker.prepare_owned_response(self.handle, 'factory.source-text/v1', cut,
                                                      'registered-response', absolute_deadline=self.deadline())
        self.assertIsNotNone(prepared)
        self.assertGreaterEqual(self.events.count('empty-read'), 2)
        self.assertEqual(len(self.service._prepared), 1)
        item = next(iter(self.service._prepared.values()))
        self.assertEqual(item.lineage, ((tuple(KEY.values()), 'v1', EMPTY),))
        self.assertEqual(item.envelope.source_operation[:7], 'access:')

    def test_cached_read_refuses_changed_bytes_without_authority_revision(self):
        self.broker.load_authorized_cut(self.handle, self.query, absolute_deadline=self.deadline())
        self.source_bytes = b'changed-public-fixture'
        self.assertEqual(self.snapshot.revision, 1)
        with self.assertRaises(NativeAccessError):
            self.broker.load_authorized_cut(self.handle, self.query, absolute_deadline=self.deadline())
        self.assertEqual(self.service._prepared, {})

    def test_cached_preparation_refuses_changed_bytes_without_authority_revision(self):
        cut = self.broker.load_authorized_cut(self.handle, self.query, absolute_deadline=self.deadline())
        self.broker.prepare_owned_response(self.handle, 'factory.source-text/v1', cut,
                                          'registered-response', absolute_deadline=self.deadline())
        self.source_bytes = b'changed-public-fixture'
        with self.assertRaises(NativeAccessError):
            self.broker.prepare_owned_response(self.handle, 'factory.source-text/v1', cut,
                                               'registered-response', absolute_deadline=self.deadline())

    def test_cached_cut_refuses_changed_registered_source_version_and_transform(self):
        cut = self.broker.load_authorized_cut(self.handle, self.query, absolute_deadline=self.deadline())
        with patch.object(self.service, '_native_profile', return_value=(
                'factory.source-text/v1', 'identity/v1', 'changed-transform/v2')):
            with self.assertRaises(NativeAccessError):
                self.broker.prepare_owned_response(self.handle, 'factory.source-text/v1', cut,
                                                   'registered-response', absolute_deadline=self.deadline())

    def test_cached_read_refuses_changed_registered_source_version(self):
        self.broker.load_authorized_cut(self.handle, self.query, absolute_deadline=self.deadline())
        key = tuple(KEY.values())
        self.sources._sources[key] = replace(self.sources._sources[key], version='v2')
        with self.assertRaises(NativeAccessError):
            self.broker.load_authorized_cut(self.handle, self.query, absolute_deadline=self.deadline())

    def test_cached_read_refuses_current_reader_custody_failure(self):
        self.broker.load_authorized_cut(self.handle, self.query, absolute_deadline=self.deadline())
        with patch('getzilla_factory.access_release._private', side_effect=AccessError('source_unavailable')):
            with self.assertRaises(NativeAccessError):
                self.broker.load_authorized_cut(self.handle, self.query, absolute_deadline=self.deadline())

    def test_dispatch_revalidates_used_source_before_existing_claim(self):
        cut = self.broker.load_authorized_cut(self.handle, self.query, absolute_deadline=self.deadline())
        self.broker.prepare_owned_response(self.handle, 'factory.source-text/v1', cut,
                                          'registered-response', absolute_deadline=self.deadline())
        prepared = next(iter(self.service._prepared.values()))
        entry = self.service._queue._cut(prepared, None)
        self.service._queue._finish_commit(entry, 'd' * 64)
        before = self.events.count('empty-read')
        self.source_bytes = b'changed-public-fixture'
        self.assertEqual(self.service.run_once(), 0)
        self.assertGreater(self.events.count('empty-read'), before,
                           'native dispatch must revalidate the registered source before claiming')
        self.assertEqual(self.service.last_error, 'AccessError')

    def test_unregistered_computation_and_response_do_not_prepare(self):
        cut = self.broker.load_authorized_cut(self.handle, self.query, absolute_deadline=self.deadline())
        with self.assertRaises(NativeAccessError):
            self.broker.prepare_owned_response(self.handle, 'unimplemented-transform', cut,
                                               'registered-response', absolute_deadline=self.deadline())
        self.assertEqual(self.service._prepared, {})

    def test_old_handle_is_invalid_when_current_revision_changes(self):
        self.snapshot.revision = 2
        with self.assertRaisesRegex(NativeAccessError, 'native_access_stale'):
            self.broker.load_authorized_cut(self.handle, self.query, absolute_deadline=self.deadline())
        self.assertEqual(self.events, [])

    def test_registered_service_replacement_invalidates_the_binding(self):
        self.service._sources = object()
        with self.assertRaises(NativeAccessError):
            self.broker.load_authorized_cut(self.handle, self.query, absolute_deadline=self.deadline())
        self.assertEqual(self.events, [])

    def test_final_bridge_admission_uses_existing_release_once(self):
        cut = self.broker.load_authorized_cut(self.handle, self.query, absolute_deadline=self.deadline())
        reference = self.broker.prepare_owned_response(self.handle, 'factory.source-text/v1', cut,
                                                      'registered-response', absolute_deadline=self.deadline())
        calls = []
        def release(session, identifier):
            calls.append(identifier)
            self.assertIs(session, self.session)
            self.assertIn(identifier, self.service._prepared)
            return {'status': 'queued', 'operation_id': 'factory-result:existing'}
        with patch.object(self.service, 'release', side_effect=release):
            result = self.broker.admit_response(self.handle, reference)
            self.assertEqual(result.operation_id, 'factory-result:existing')
            with self.assertRaisesRegex(NativeAccessError, 'native_access_already_used'):
                self.broker.admit_response(self.handle, reference)
        self.assertEqual(len(calls), 1)

    def test_rebinding_same_existing_stage_does_not_mint_another_preparation(self):
        cut = self.broker.load_authorized_cut(self.handle, self.query, absolute_deadline=self.deadline())
        self.broker.prepare_owned_response(self.handle, 'factory.source-text/v1', cut,
                                          'registered-response', absolute_deadline=self.deadline())
        original = next(iter(self.service._prepared.values()))
        handle = self.broker.bind_native_request(self.session, self.workflow)
        repeated = self.broker.load_authorized_cut(handle, self.query, absolute_deadline=self.deadline())
        self.broker.prepare_owned_response(handle, 'factory.source-text/v1', repeated,
                                          'registered-response', absolute_deadline=self.deadline())
        self.assertEqual(len(self.service._prepared), 1,
                         'same checked task/run/attempt stage must retain one existing operation')
        current = next(iter(self.service._prepared.values()))
        self.assertEqual(current.identifier, original.identifier)
        self.assertEqual(current.envelope.record_digest, original.envelope.record_digest)
        self.assertEqual(current.deadline, original.deadline)

    def test_rebinding_with_another_target_conflicts_without_replacing_original(self):
        self.service._destinations['other-response'] = self.service._destinations['registered-response']
        broker = NativeAccessBroker._compose(self.n.FactoryNativeAccessHost(self.service))
        handle = broker.bind_native_request(self.session, self.workflow)
        cut = broker.load_authorized_cut(handle, self.query, absolute_deadline=self.deadline())
        broker.prepare_owned_response(handle, 'factory.source-text/v1', cut, 'registered-response',
                                      absolute_deadline=self.deadline())
        original = next(iter(self.service._prepared.values()))
        repeated = broker.bind_native_request(self.session, self.workflow)
        other = broker.load_authorized_cut(repeated, self.query, absolute_deadline=self.deadline())
        with self.assertRaises(NativeAccessError):
            broker.prepare_owned_response(repeated, 'factory.source-text/v1', other, 'other-response',
                                          absolute_deadline=self.deadline())
        self.assertEqual(len(self.service._prepared), 1)
        self.assertIs(next(iter(self.service._prepared.values())), original)


if __name__ == '__main__':
    unittest.main()
