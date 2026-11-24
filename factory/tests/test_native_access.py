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
        self.session = AccessSession(object(), object(), 'worker', 'fixture-principal', 'public', b'', 1)
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
        def release(session, identifier, *, absolute_deadline):
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

    def _prepare_with(self, broker, handle, deadline, destination='registered-response'):
        cut = broker.load_authorized_cut(handle, self.query, absolute_deadline=deadline)
        return broker.prepare_owned_response(handle, 'factory.source-text/v1', cut,
                                             destination, absolute_deadline=deadline)

    def test_tighter_rebound_deadline_reaches_actual_release_refresh(self):
        from getzilla_factory.access_release import _remaining_bounds
        now, observed = [100.0], []
        with patch('time.monotonic', side_effect=lambda: now[0]):
            broker = NativeAccessBroker._compose(self.host)
            self._prepare_with(broker, broker.bind_native_request(self.session, self.workflow), 102.0)
            original = next(iter(self.service._prepared.values()))
            now[0] = 100.1
            handle = broker.bind_native_request(self.session, self.workflow)
            reference = self._prepare_with(broker, handle, 100.3)
            def stop_at_refresh(prepared):
                now[0] = 100.4
                expired = False
                try:
                    _remaining_bounds(prepared.deadline)
                except AccessError:
                    expired = True
                observed.append((prepared.deadline, expired))
                raise AccessError('access_expired')  # End before any SQL admission.
            with patch.object(self.service, '_refresh_native_prepared', side_effect=stop_at_refresh):
                with self.assertRaises(NativeAccessError):
                    broker.admit_response(handle, reference)
            self.assertEqual(observed, [(100.3, True)],
                             'actual release must intersect original102 with caller100.3')
            self.assertEqual(original.deadline, 102.0)

    def test_expired_stable_stage_cannot_renew_deadline_or_target(self):
        self.service._destinations['other-response'] = self.service._destinations['registered-response']
        now = [100.0]
        with patch('time.monotonic', side_effect=lambda: now[0]):
            broker = NativeAccessBroker._compose(self.n.FactoryNativeAccessHost(self.service))
            self._prepare_with(broker, broker.bind_native_request(self.session, self.workflow), 102.0)
            original = next(iter(self.service._prepared.values()))
            now[0] = 102.1
            for target in ('registered-response', 'other-response'):
                handle = broker.bind_native_request(self.session, self.workflow)
                with self.assertRaises(NativeAccessError):
                    self._prepare_with(broker, handle, 104.1, target)
                self.assertIs(self.service._prepared[original.identifier], original)
                self.assertEqual(original.deadline, 102.0)
                self.assertEqual(original.destination, 'registered-response')

    def test_consumed_stable_stage_cannot_prepare_again_after_unknown_release(self):
        now = [100.0]
        with patch('time.monotonic', side_effect=lambda: now[0]):
            broker = NativeAccessBroker._compose(self.host)
            handle = broker.bind_native_request(self.session, self.workflow)
            reference = self._prepare_with(broker, handle, 102.0)
            with patch.object(self.service, '_refresh_native_prepared', side_effect=AccessError('source_unavailable')):
                with self.assertRaises(NativeAccessError):
                    broker.admit_response(handle, reference)
            repeated = broker.bind_native_request(self.session, self.workflow)
            with self.assertRaises(NativeAccessError):
                self._prepare_with(broker, repeated, 102.0)


    @contextmanager
    def _release_transaction(self, **bounds):
        self.assertLessEqual(bounds['connect_timeout'], 2)
        class Cursor:
            def execute(inner, query, arguments):
                inner.query = query
            def fetchone(inner):
                return (ATTEMPT if 'access_task_fence_v1' in inner.query else 'd' * 64,)
        yield Cursor()

    def test_tighter_deadline_is_retained_by_existing_pending_queue(self):
        now = [100.0]
        with patch('time.monotonic', side_effect=lambda: now[0]):
            broker = NativeAccessBroker._compose(self.host)
            self._prepare_with(broker, broker.bind_native_request(self.session, self.workflow), 102.0)
            handle = broker.bind_native_request(self.session, self.workflow)
            reference = self._prepare_with(broker, handle, 100.3)
            with patch.object(self.store, '_transaction', side_effect=self._release_transaction), \
                    patch.object(self.authority, '_queue_cut', side_effect=lambda prepared, queue, entry=None:
                                 queue._cut(prepared, entry)):
                result = broker.admit_response(handle, reference)
            self.assertEqual(result.status, 'queued')
            entry = next(iter(self.service._queue._entries.values()))
            self.assertEqual(entry.prepared.deadline, 100.3)
            self.assertEqual(entry.state, 'ready')
            self.assertTrue(next(iter(self.service._prepared.values())).consumed)
            with self.assertRaises(AccessError):
                self.service.release(self.session, entry.prepared.identifier)

    def test_dispatch_commit_past_tighter_deadline_refuses_before_transport(self):
        now, transports = [100.0], []
        with patch('time.monotonic', side_effect=lambda: now[0]):
            broker = NativeAccessBroker._compose(self.host)
            self._prepare_with(broker, broker.bind_native_request(self.session, self.workflow), 100.3)
            prepared = next(iter(self.service._prepared.values()))
            entry = self.service._queue._cut(prepared, None)
            self.service._queue._finish_commit(entry, 'd' * 64)
            @contextmanager
            def transaction(**bounds):
                with self._release_transaction(**bounds) as cursor:
                    yield cursor
                if entry.state == 'dispatch_admitted':
                    now[0] = 100.4  # Simulate delayed COMMIT, without SQL or actual transport.
            client = self.service._destinations['registered-response']
            with patch.object(self.store, '_transaction', side_effect=transaction), \
                    patch.object(self.authority, '_queue_cut', side_effect=lambda prepared, queue, entry=None:
                                 queue._cut(prepared, entry)), \
                    patch.object(client, 'dispatch', side_effect=lambda claim: transports.append(claim)):
                self.assertEqual(self.service.run_once(), 0)
            self.assertEqual(transports, [])
            self.assertEqual(self.service.last_error, 'AccessError')
            self.assertEqual(self.service._queue._entries, {})

    def test_expired_stage_capacity_refuses_instead_of_evicting_original_intents(self):
        now = [100.0]
        with patch('time.monotonic', side_effect=lambda: now[0]):
            broker = NativeAccessBroker._compose(self.host)
            self._prepare_with(broker, broker.bind_native_request(self.session, self.workflow), 102.0)
            original = next(iter(self.service._prepared.values()))
            # Fill the same existing cache with distinct ordinary workflow stages.
            # This is retention/capacity metadata, not new durable tasks or authority.
            for value in range(4, 19):
                grant = replace(self.grant, task_id=f'00000000-0000-0000-0000-{value:012d}')
                workflow = self.n.FactoryTaskBinding(grant, 'b' * 64)
                handle = broker.bind_native_request(self.session, workflow)
                self._prepare_with(broker, handle, 102.0)
                # Each independent workflow uses another bounded broker; the
                # existing service cache retains all previous stage intents.
                broker = NativeAccessBroker._compose(self.host)
            self.assertEqual(len(self.service._prepared), 16)
            now[0] = 102.1
            before = dict(self.service._prepared)
            grant = replace(self.grant, task_id='00000000-0000-0000-0000-000000000099')
            workflow = self.n.FactoryTaskBinding(grant, 'b' * 64)
            handle = broker.bind_native_request(self.session, workflow)
            with self.assertRaises(NativeAccessError):
                self._prepare_with(broker, handle, 104.1)
            self.assertEqual(self.service._prepared, before)
            self.assertIs(self.service._prepared[original.identifier], original)



class CommittedQueueWindowTests(unittest.TestCase):
    def pending(self, deadline=102.0):
        from getzilla_factory.access_release import _NativeQueue
        queue = _NativeQueue()
        prepared = SimpleNamespace(identifier='owned-pending', deadline=deadline,
                                   authority=(None, None, None, 'owned-scope'))
        with patch('getzilla_factory.access_release.time.monotonic', return_value=100.0):
            entry = queue._cut(prepared, None)
        return queue, entry

    def test_pending_commit_delay_does_not_consume_committed_dispatch_window(self):
        queue, entry = self.pending()
        with patch('getzilla_factory.access_release.time.monotonic', return_value=100.4):
            self.assertEqual(queue._ready(), ())
            queue._finish_commit(entry, 'd' * 64)
            self.assertEqual(queue._ready(), (entry,))
        self.assertAlmostEqual(entry.expires, 100.65)
        with patch('getzilla_factory.access_release.time.monotonic', return_value=100.5):
            with self.assertRaises(AccessError):
                queue._finish_commit(entry, 'd' * 64)
        self.assertAlmostEqual(entry.expires, 100.65)
        with patch('getzilla_factory.access_release.time.monotonic', return_value=100.66):
            self.assertEqual(queue._ready(), ())
            with self.assertRaises(AccessError):
                queue._cut(entry.prepared, entry)

    def test_committed_window_never_renews_original_capture_deadline(self):
        queue, entry = self.pending(deadline=100.5)
        with patch('getzilla_factory.access_release.time.monotonic', return_value=100.4):
            queue._finish_commit(entry, 'd' * 64)
        self.assertEqual(entry.expires, 100.5)
        self.assertEqual(entry.prepared.deadline, 100.5)

    def test_expired_pending_capture_cannot_become_ready(self):
        queue, entry = self.pending(deadline=100.5)
        with patch('getzilla_factory.access_release.time.monotonic', return_value=100.5):
            with self.assertRaises(AccessError):
                queue._finish_commit(entry, 'd' * 64)
        self.assertEqual(entry.state, 'pending')
        self.assertFalse(queue.wakeup.is_set())


if __name__ == '__main__':
    unittest.main()
