"""Actual owned PostgreSQL/outbox and authenticated UDS retrieval delivery."""
import hashlib
import json
import unittest
from contextlib import contextmanager

from factory.tests import test_access_release_postgres as access_fixture
from factory.tests.test_postgres_integration import DATABASE_URL
from getzilla.native_access import NativeAccessBroker, NativeAccessError, RegisteredQuery
from getzilla_factory.access_release import AccessReleaseService, LocalSourceAdapter
from getzilla_factory.native_access import FactoryNativeAccessHost, FactoryTaskBinding


@contextmanager
def transaction_after_commit(store, matching, action):
    from unittest.mock import patch
    original = store._transaction
    @contextmanager
    def observed(**bounds):
        found = False
        with original(**bounds) as cursor:
            class Cursor:
                def execute(self, query, *args, **kwargs):
                    nonlocal found
                    found = found or matching in query
                    return cursor.execute(query, *args, **kwargs)
                def __getattr__(self, name):
                    return getattr(cursor, name)
            yield Cursor()
        if found:
            action()
    with patch.object(store, '_transaction', side_effect=observed):
        yield


@unittest.skipUnless(DATABASE_URL, 'owned disposable PostgreSQL is required')
class RetrievalAccessPostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        access_fixture.AccessReleasePostgresTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        access_fixture.AccessReleasePostgresTests.tearDownClass()

    setUp = access_fixture.AccessReleasePostgresTests.setUp
    revoke = access_fixture.AccessReleasePostgresTests.revoke

    def composition(self, client=None, *, profile='factory.local-retrieval162/v1', receiver=None):
        raw = b'def choose_key(value):\n    return "OWNED_AUTHORIZED_RESULT"\n'
        self.source.write_bytes(raw)
        self.source.chmod(0o600)
        source = LocalSourceAdapter([dict(key=self.key('a'), version='v1',
            repository_id=self.task.repository_id, workspace_handle=self.execution.workspace_handle,
            relative_path='factory/src/owned.py', file=str(self.source),
            content_digest=hashlib.sha256(raw).hexdigest(), classification='internal')])
        service = AccessReleaseService(self.fixture.store, self.auth.access_authority, source,
            {'private-a': self.client if client is None else client}, retrieval_profile=profile)
        self.addCleanup(service.close)
        if receiver is not None:
            receiver.attach(service, 'private-a')
        broker = NativeAccessBroker._compose(FactoryNativeAccessHost(service))
        session = self.auth.access_session('Bearer synthetic-owned-credential-worker', 'source:read')
        handle = broker.bind_native_request(session,
            FactoryTaskBinding(self.execution.lease, self.execution.packet_digest))
        query = RegisteredQuery('factory.retrieval162/v1', ('current-destination',),
            {'query': 'choose_key', 'destination_id': 'private-a', 'token_budget': 2048})
        import time
        cut = broker.load_authorized_cut(handle, query, absolute_deadline=time.monotonic() + 2)
        reference = broker.prepare_owned_response(handle, 'factory.retrieval162/v1', cut,
            'private-a', absolute_deadline=time.monotonic() + 2)
        return service, broker, handle, reference

    def owned_composition(self, *, profile='factory.local-retrieval162/v1'):
        from getzilla_factory.retrieval_receiver import OwnedRetrievalReceiver
        from getzilla_factory.result_dispatch import UdsResultHandoffClient
        path = self.source.parent / 'retention.sock'
        try:
            receiver = OwnedRetrievalReceiver(path, 'synthetic-owned-retention-credential',
                retention_profile=profile)
        except TypeError:
            if profile != 'factory.local-retrieval162/v1':
                self.fail('explicit ephemeral capture-lifetime profile is missing')
            receiver = OwnedRetrievalReceiver(path, 'synthetic-owned-retention-credential')
        receiver.start()
        self.addCleanup(receiver.close)
        client = UdsResultHandoffClient(path, 'synthetic-owned-retention-credential', timeout_seconds=.5)
        return receiver, client, self.composition(client, profile=profile,
            receiver=None if profile == 'factory.local-retrieval162/v1' else receiver)

    def operator(self):
        return self.auth.access_session('Bearer synthetic-owned-credential-operator', 'factory:access-admin')

    def test_exact_cited_context_uses_actual_existing_outbox_and_one_real_uds_delivery(self):
        service, broker, handle, reference = self.composition()
        retained = next(iter(service._prepared.values()))
        expected = retained.envelope.sanitized_payload
        result = broker.admit_response(handle, reference)
        self.assertEqual(result.status, 'queued')
        self.assertEqual(self.received, [])
        self.assertEqual(service.run_once(), 1)
        self.assertEqual(len(self.received), 1)
        delivered = self.received[0][1]['result_envelope']['sanitized_payload']
        self.assertEqual(delivered, expected)
        self.assertIn('OWNED_AUTHORIZED_RESULT', json.loads(delivered)['context'])
        self.assertEqual(json.loads(delivered)['citations'][0]['path'], 'factory/src/owned.py')
        self.assertIsNone(getattr(next(iter(service._prepared.values())), 'envelope', None))
        self.assertEqual(service.run_once(), 0)
        with self.assertRaises(NativeAccessError):
            broker.admit_response(handle, reference)
        self.assertEqual(len(self.received), 1)

    def test_actual_group_revocation_after_commit_prevents_real_uds_delivery(self):
        service, broker, handle, reference = self.composition()
        broker.admit_response(handle, reference)
        self.revoke()
        self.assertEqual(service.run_once(), 0)
        self.assertEqual(self.received, [])
        self.assertEqual(service._queue._entries, {})
        self.assertIsNone(getattr(next(iter(service._prepared.values())), 'envelope', None))

    def test_actual_source_deletion_before_release_prevents_database_admission(self):
        service, broker, handle, reference = self.composition()
        self.revoke(deleted=True)
        with self.assertRaises(NativeAccessError):
            broker.admit_response(handle, reference)
        self.assertEqual(service.run_once(), 0)
        self.assertEqual(self.received, [])
        broker.discard(handle)
        self.assertIsNone(getattr(next(iter(service._prepared.values())), 'envelope', None))

    def test_current_operator_retires_actual_local_result_payload_with_explicit_projection(self):
        service, broker, handle, reference = self.composition()
        prepared = next(iter(service._prepared.values()))
        envelope = prepared.envelope.record_digest
        broker.admit_response(handle, reference)
        operator = self.auth.access_session('Bearer synthetic-owned-credential-operator', 'factory:access-admin')
        try:
            outcome = service.retire_retrieval(operator, envelope, reason='source_deleted')
        except AttributeError:
            self.fail('current access owner has no durable retrieval retirement')
        self.assertTrue(outcome['local_retired'])
        # The old fixture receiver does not implement retirement. A generic
        # delivery response must never masquerade as a deletion receipt.
        self.assertEqual(outcome['recipient'], 'unknown')
        with self.fixture.store._transaction() as cursor:
            cursor.execute('SELECT envelope->>\'contract\',payload_retired_at IS NOT NULL, '
                'envelope ? \'sanitized_payload\', envelope_digest, source_digest '
                'FROM factory.result_sources_v1 WHERE envelope_digest=%s', (envelope,))
            kind, retired, has_text, original, source = cursor.fetchone()
        self.assertEqual(kind, 'factory-retired-result/v1')
        self.assertTrue(retired)
        self.assertFalse(has_text)
        self.assertEqual(original.strip(), envelope)
        self.assertEqual(source.strip(), prepared.envelope.source_digest)
        self.assertEqual(service.run_once(), 0)

    def test_owned_receiver_and_every_local_holder_drop_delivered_derivatives(self):
        receiver, _client, (service, broker, handle, reference) = self.owned_composition()
        prepared = next(iter(service._prepared.values()))
        cut = broker._requests[handle].cut
        binding = broker._requests[handle].binding
        receiver.arm(service, prepared.identifier)
        broker.admit_response(handle, reference)
        self.assertEqual(service.run_once(), 1)
        self.assertIn(b'OWNED_AUTHORIZED_RESULT', receiver._payload)
        self.revoke(deleted=True)
        outcome = service.retire_retrieval(self.operator(), prepared.envelope.record_digest, reason='source_deleted')
        self.assertEqual(outcome['recipient'], 'confirmed')
        self.assertTrue(outcome['local_retired'])
        self.assertTrue(outcome['ephemeral_retired'])
        self.assertIsNone(receiver._payload)
        self.assertTrue(receiver._retired)
        self.assertEqual(broker._requests, {})
        self.assertEqual(cut.documents, ())
        self.assertIsNone(binding.captured)
        self.assertEqual(service._queue._entries, {})
        self.assertIsNone(getattr(next(iter(service._prepared.values())), 'envelope', None))
        with self.fixture.store._transaction() as cursor:
            cursor.execute('SELECT s.envelope::text,o.access_binding::text,o.retirement_state '
                'FROM factory.result_sources_v1 s JOIN factory.next_model_request_outbox_v1 o '
                'USING(envelope_digest) WHERE s.envelope_digest=%s', (prepared.envelope.record_digest,))
            stored, lineage, state = cursor.fetchone()
        for sentinel in ('OWNED_AUTHORIZED_RESULT', 'factory/src/owned.py', 'same-id'):
            self.assertNotIn(sentinel, stored)
            self.assertNotIn(sentinel, lineage)
        self.assertEqual(state, 'confirmed')

    def test_retirement_ack_blocks_late_original_handoff_after_an_earlier_claim(self):
        from getzilla_factory.result_dispatch import DispatchClaim
        receiver, client, (service, broker, handle, reference) = self.owned_composition()
        prepared = next(iter(service._prepared.values()))
        receiver.arm(service, prepared.identifier)
        queued = broker.admit_response(handle, reference)
        request = queued.operation_id.removeprefix('factory-result:')
        record = prepared.envelope
        late = DispatchClaim(request, queued.operation_id, record.record_digest, record.repository_id,
            record.task_id, record.run_id, record.fence, record.packet_digest, record.attempt_id,
            'e' * 64, 'factory-protected-dispatcher', 'claimed', record.to_dict())
        outcome = service.retire_retrieval(self.operator(), record.record_digest, reason='operator_retire')
        self.assertEqual(outcome['recipient'], 'confirmed')
        self.assertNotEqual(client.dispatch(late).state, 'delivered')
        self.assertIsNone(receiver._payload)
        self.assertEqual(service.run_once(), 0)

    def test_worker_and_foreign_project_operator_cannot_retire_owned_result(self):
        import copy
        from getzilla_factory.access_authority import AccessError
        service, broker, handle, reference = self.composition()
        prepared = next(iter(service._prepared.values()))
        broker.admit_response(handle, reference)
        worker = self.auth.access_session('Bearer synthetic-owned-credential-worker', 'source:read')
        with self.assertRaises(AccessError):
            service.retire_retrieval(worker, prepared.envelope.record_digest, reason='operator_retire')
        operator = self.operator()
        update = copy.deepcopy(self.policy)
        update['revision'] = 2
        next(item for item in update['actors'] if item['actor_id'] == 'operator')['projects'] = []
        self.auth.access_authority.update(operator, 1, update)
        with self.assertRaises(AccessError):
            service.retire_retrieval(operator, prepared.envelope.record_digest, reason='operator_retire')
        with self.fixture.store._transaction() as cursor:
            cursor.execute('SELECT payload_retired_at IS NULL FROM factory.result_sources_v1 '
                'WHERE envelope_digest=%s', (prepared.envelope.record_digest,))
            self.assertTrue(cursor.fetchone()[0])

    def test_lost_receiver_reply_stays_unknown_without_repost_then_read_only_observation_confirms(self):
        from unittest.mock import patch
        receiver, _client, (service, broker, handle, reference) = self.owned_composition()
        prepared = next(iter(service._prepared.values()))
        receiver.arm(service, prepared.identifier)
        broker.admit_response(handle, reference)
        actual = receiver._retirement
        calls = []
        def lost_reply(body, deadline):
            calls.append(1)
            actual(body, deadline)
            raise TimeoutError('synthetic lost reply')
        with patch.object(receiver, '_retirement', side_effect=lost_reply):
            first = service.retire_retrieval(self.operator(), prepared.envelope.record_digest, reason='source_deleted')
            self.assertTrue(first['local_retired'])
            self.assertEqual(first['recipient'], 'unknown')
            with self.fixture.store._transaction() as cursor:
                cursor.execute('SELECT retirement_deadline,retirement_claim FROM factory.next_model_request_outbox_v1 '
                    'WHERE envelope_digest=%s', (prepared.envelope.record_digest,))
                original = cursor.fetchone()
            duplicate = service.retire_retrieval(self.operator(), prepared.envelope.record_digest, reason='source_deleted')
            self.assertEqual(duplicate['recipient'], 'unknown')
            self.assertEqual(calls, [1])
            with self.fixture.store._transaction() as cursor:
                cursor.execute('SELECT retirement_deadline,retirement_claim FROM factory.next_model_request_outbox_v1 '
                    'WHERE envelope_digest=%s', (prepared.envelope.record_digest,))
                self.assertEqual(cursor.fetchone(), original)
        observed = service.observe_retrieval_retirement(self.operator(), prepared.envelope.record_digest)
        self.assertEqual(observed['recipient'], 'confirmed')
        self.assertIsNone(receiver._payload)

    def test_retirement_commit_lost_never_posts_or_falsely_claims_recipient_erasure(self):
        from unittest.mock import patch
        from getzilla_factory.store import StoreUnavailable
        receiver, _client, (service, broker, handle, reference) = self.owned_composition()
        prepared = next(iter(service._prepared.values()))
        receiver.arm(service, prepared.identifier)
        broker.admit_response(handle, reference)
        self.assertEqual(service.run_once(), 1)
        def lost():
            raise StoreUnavailable('synthetic lost acknowledgement')
        with patch.object(receiver, '_retirement', wraps=receiver._retirement) as posts:
            with transaction_after_commit(service._store, 'factory.retire_access_result_v1', lost):
                outcome = service.retire_retrieval(self.operator(), prepared.envelope.record_digest, reason='source_deleted')
            self.assertIsNone(outcome['local_retired'])
            self.assertEqual(outcome['recipient'], 'unknown')
            self.assertEqual(posts.call_count, 0)
            observed = service.observe_retrieval_retirement(self.operator(), prepared.envelope.record_digest)
            self.assertTrue(observed['local_retired'])
            self.assertEqual(observed['recipient'], 'unknown')
            duplicate = service.retire_retrieval(self.operator(), prepared.envelope.record_digest, reason='source_deleted')
            self.assertEqual(duplicate['recipient'], 'unknown')
            self.assertEqual(posts.call_count, 0)
            self.assertIsNotNone(receiver._payload, 'unknown is not a deletion receipt')

    def test_original_admission_commit_lost_can_retire_without_repeating_original_effect(self):
        from getzilla_factory.store import StoreUnavailable
        receiver, _client, (service, broker, handle, reference) = self.owned_composition()
        prepared = next(iter(service._prepared.values()))
        receiver.arm(service, prepared.identifier)
        def lost():
            raise StoreUnavailable('synthetic lost acknowledgement')
        with transaction_after_commit(service._store, 'factory.stage_access_release_v1', lost):
            with self.assertRaises(NativeAccessError):
                broker.admit_response(handle, reference)
        outcome = service.retire_retrieval(self.operator(), prepared.envelope.record_digest, reason='operator_retire')
        self.assertTrue(outcome['local_retired'])
        self.assertEqual(outcome['recipient'], 'confirmed')
        self.assertIsNone(receiver._payload)
        self.assertEqual(service.run_once(), 0)

    def test_operator_revocation_between_commit_and_send_prevents_retirement_transport(self):
        import copy
        from unittest.mock import patch
        receiver, _client, (service, broker, handle, reference) = self.owned_composition()
        prepared = next(iter(service._prepared.values()))
        receiver.arm(service, prepared.identifier)
        broker.admit_response(handle, reference)
        operator = self.operator()
        def revoke_operator():
            changed = copy.deepcopy(self.policy)
            changed['revision'] = 2
            record = next(item for item in changed['actors'] if item['actor_id'] == 'operator')
            record['scopes'].remove('factory:access-admin')
            self.auth.access_authority.update(operator, 1, changed)
        with patch.object(receiver, '_retirement', wraps=receiver._retirement) as posts:
            with transaction_after_commit(service._store, 'factory.retire_access_result_v1', revoke_operator):
                outcome = service.retire_retrieval(operator, prepared.envelope.record_digest, reason='operator_retire')
            self.assertTrue(outcome['local_retired'])
            self.assertEqual(outcome['recipient'], 'unknown')
            self.assertEqual(posts.call_count, 0)

    def test_retired_source_and_provenance_cannot_restore_payload_or_dispatch(self):
        import psycopg
        from getzilla_factory.contracts import canonical_json
        receiver, _client, (service, broker, handle, reference) = self.owned_composition()
        prepared = next(iter(service._prepared.values()))
        receiver.arm(service, prepared.identifier)
        broker.admit_response(handle, reference)
        outcome = service.retire_retrieval(self.operator(), prepared.envelope.record_digest, reason='operator_retire')
        self.assertTrue(outcome['local_retired'])
        for statement, parameters in (
            ('UPDATE factory.result_sources_v1 SET envelope=%s::jsonb WHERE envelope_digest=%s',
             (canonical_json(prepared.envelope.to_dict()).decode(), prepared.envelope.record_digest)),
            ('UPDATE factory.result_sources_v1 SET payload_retired_at=NULL,retired_projection_sha256=NULL,'
             'payload_retirement_reason=NULL WHERE envelope_digest=%s', (prepared.envelope.record_digest,)),
            ('UPDATE factory.result_sources_v1 SET access_grade=\'ordinary\' WHERE envelope_digest=%s',
             (prepared.envelope.record_digest,)),
            ('UPDATE factory.next_model_request_outbox_v1 SET access_phase=\'sending\' WHERE envelope_digest=%s',
             (prepared.envelope.record_digest,)),
            ('UPDATE factory.next_model_request_outbox_v1 SET retirement_claim=NULL WHERE envelope_digest=%s',
             (prepared.envelope.record_digest,))):
            with self.subTest(statement=statement), self.assertRaises(psycopg.Error):
                with psycopg.connect(DATABASE_URL) as connection:
                    connection.execute(statement, parameters)
        self.assertEqual(service.run_once(), 0)
        self.assertIsNone(receiver._payload)

    def test_receiver_restart_denies_delayed_frames_and_old_result_rearming(self):
        from getzilla_factory.access_authority import AccessError
        from getzilla_factory.retrieval_receiver import OwnedRetrievalReceiver
        from getzilla_factory.result_dispatch import UdsResultHandoffClient
        import httpx
        receiver, client, (service, broker, handle, reference) = self.owned_composition()
        prepared = next(iter(service._prepared.values()))
        receiver.arm(service, prepared.identifier)
        queued = broker.admit_response(handle, reference)
        outcome = service.retire_retrieval(self.operator(), prepared.envelope.record_digest, reason='operator_retire')
        self.assertEqual(outcome['recipient'], 'confirmed')
        receiver.close()
        replacement = OwnedRetrievalReceiver(client._socket_path, 'synthetic-owned-retention-credential')
        replacement.start()
        self.addCleanup(replacement.close)
        body = {'contract': 'adaptive-factory.native-result-handoff/v1', 'operation_id': queued.operation_id,
            'request_digest': queued.operation_id.removeprefix('factory-result:'),
            'envelope_digest': prepared.envelope.record_digest,
            **{key: getattr(prepared.envelope, key) for key in (
                'repository_id', 'task_id', 'run_id', 'fence', 'packet_digest', 'attempt_id')},
            'result_envelope': prepared.envelope.to_dict()}
        with httpx.Client(transport=httpx.HTTPTransport(uds=str(client._socket_path)),
                base_url='http://owned', trust_env=False) as transport:
            response = transport.post('/v1/native-result-handoffs', json=body, headers={
                'Authorization': 'Bearer synthetic-owned-retention-credential',
                'Idempotency-Key': queued.operation_id, 'X-Operation-ID': queued.operation_id})
        self.assertEqual(response.status_code, 403)
        new_client = UdsResultHandoffClient(client._socket_path, 'synthetic-owned-retention-credential', timeout_seconds=.5)
        new_service, _broker, _handle, _reference = self.composition(new_client)
        recreated = next(iter(new_service._prepared.values()))
        self.assertEqual(recreated.envelope.record_digest, prepared.envelope.record_digest)
        with self.assertRaises(AccessError):
            replacement.arm(new_service, recreated.identifier)
        self.assertIsNone(replacement._payload)

    def test_retirement_cancels_busy_source_capture_without_repopulating_owned_holders(self):
        from concurrent.futures import ThreadPoolExecutor
        import threading
        import time
        from unittest.mock import patch
        from getzilla_factory import access_release
        receiver, _client, (service, broker, handle, reference) = self.owned_composition()
        prepared = next(iter(service._prepared.values()))
        receiver.arm(service, prepared.identifier)
        broker.admit_response(handle, reference)
        self.assertEqual(service.run_once(), 1)
        session = self.auth.access_session('Bearer synthetic-owned-credential-worker', 'source:read')
        busy_handle = broker.bind_native_request(session,
            FactoryTaskBinding(self.execution.lease, self.execution.packet_digest))
        query = RegisteredQuery('factory.retrieval162/v1', ('current-destination',),
            {'query': 'choose_key', 'destination_id': 'private-a', 'token_budget': 2048})
        entered, release = threading.Event(), threading.Event()
        original = access_release._private
        def paused(path, limit):
            if threading.current_thread().name.startswith('retirement-busy'):
                entered.set()
                if not release.wait(1):
                    raise TimeoutError('synthetic source pause')
            return original(path, limit)
        with patch('getzilla_factory.access_release._private', side_effect=paused), \
                ThreadPoolExecutor(max_workers=1, thread_name_prefix='retirement-busy') as pool:
            pending = pool.submit(broker.load_authorized_cut, busy_handle, query,
                absolute_deadline=time.monotonic() + 2)
            self.assertTrue(entered.wait(.8))
            try:
                outcome = service.retire_retrieval(self.operator(), prepared.envelope.record_digest, reason='operator_retire')
                self.assertTrue(outcome['local_retired'])
                self.assertFalse(outcome['ephemeral_retired'])
                self.assertEqual(outcome['recipient'], 'confirmed')
            finally:
                release.set()
            with self.assertRaises(NativeAccessError):
                pending.result(timeout=1)
        self.assertEqual(broker._requests, {})
        self.assertIsNone(receiver._payload)
        observed = service.observe_retrieval_retirement(self.operator(), prepared.envelope.record_digest)
        self.assertTrue(observed['ephemeral_retired'])

    def test_explicit_ephemeral_profile_expires_receiver_and_holders_with_paused_service_then_reconciles(self):
        import time
        from getzilla_factory.access_release import AccessReleaseService
        profile = 'factory.ephemeral-retrieval162/v1'
        receiver, client, (service, broker, handle, reference) = self.owned_composition(profile=profile)
        prepared = next(iter(service._prepared.values()))
        cut = broker._requests[handle].cut
        broker.admit_response(handle, reference)
        entry = next(iter(service._queue._entries.values()))
        remaining = entry.expires - time.monotonic()
        self.assertEqual(service.run_once(), 1, f'{service.last_error}; queue_remaining={remaining:.4f}')
        self.assertIn(b'OWNED_AUTHORIZED_RESULT', receiver._payload)
        with self.fixture.store._transaction() as cursor:
            cursor.execute('SELECT retrieval_capture_at,retrieval_retire_after FROM '
                'factory.next_model_request_outbox_v1 WHERE envelope_digest=%s', (prepared.envelope.record_digest,))
            original_clock = cursor.fetchone()
        time.sleep(max(0, prepared.deadline - time.monotonic()) + .08)
        self.assertIsNone(receiver._payload)
        self.assertEqual(cut.documents, ())
        self.assertEqual(broker._requests, {})
        with self.fixture.store._transaction() as cursor:
            cursor.execute('SELECT payload_retired_at IS NULL FROM factory.result_sources_v1 '
                'WHERE envelope_digest=%s', (prepared.envelope.record_digest,))
            self.assertTrue(cursor.fetchone()[0], 'paused service is not a claimed database erasure')
        restarted = AccessReleaseService(self.fixture.store, self.auth.access_authority, service._sources,
            {'private-a': client}, retrieval_profile=profile)
        self.addCleanup(restarted.close)
        receiver.attach(restarted, 'private-a')
        restarted.run_once()
        with self.fixture.store._transaction() as cursor:
            cursor.execute('SELECT s.payload_retired_at IS NOT NULL,o.retirement_state,'
                'o.retrieval_capture_at,o.retrieval_retire_after FROM factory.result_sources_v1 s '
                'JOIN factory.next_model_request_outbox_v1 o USING(envelope_digest) WHERE s.envelope_digest=%s',
                (prepared.envelope.record_digest,))
            local, state, captured_at, due = cursor.fetchone()
        self.assertTrue(local)
        self.assertEqual(state, 'confirmed')
        self.assertEqual((captured_at, due), original_clock)

    def test_ephemeral_profile_without_actual_attached_owner_refuses_before_private_source_read(self):
        from unittest.mock import patch
        from getzilla_factory.access_release import AccessReleaseService
        profile = 'factory.ephemeral-retrieval162/v1'
        service = AccessReleaseService(self.fixture.store, self.auth.access_authority, self.access._sources,
            {'private-a': self.client}, retrieval_profile=profile)
        host = FactoryNativeAccessHost(service)
        broker = NativeAccessBroker._compose(host)
        session = self.auth.access_session('Bearer synthetic-owned-credential-worker', 'source:read')
        with patch('getzilla_factory.access_release._private', side_effect=AssertionError('unexpected source read')):
            with self.assertRaises(NativeAccessError):
                broker.bind_native_request(session, FactoryTaskBinding(self.execution.lease, self.execution.packet_digest))

    def test_ephemeral_future_wall_clock_mapping_denies_admission_without_renewal(self):
        import time
        from unittest.mock import patch
        real_wall = time.time()
        with patch('getzilla_factory.retrieval_receiver.time.time', return_value=real_wall + 1000000):
            receiver, _client, (service, broker, handle, reference) = self.owned_composition(
                profile='factory.ephemeral-retrieval162/v1')
        prepared = next(iter(service._prepared.values()))
        with self.assertRaises(NativeAccessError):
            broker.admit_response(handle, reference)
        with self.fixture.store._transaction() as cursor:
            cursor.execute('SELECT count(*) FROM factory.result_sources_v1 WHERE envelope_digest=%s',
                (prepared.envelope.record_digest,))
            self.assertEqual(cursor.fetchone()[0], 0)
        self.assertIsNone(receiver.context)

    def test_ephemeral_capture_due_denies_release_and_cannot_be_extended_in_database(self):
        import time
        import psycopg
        receiver, _client, (service, broker, handle, reference) = self.owned_composition(
            profile='factory.ephemeral-retrieval162/v1')
        prepared = next(iter(service._prepared.values()))
        broker.admit_response(handle, reference)
        with self.fixture.store._transaction() as cursor:
            cursor.execute('SELECT retrieval_retire_after FROM factory.next_model_request_outbox_v1 '
                'WHERE envelope_digest=%s', (prepared.envelope.record_digest,))
            due = cursor.fetchone()[0]
        with self.assertRaises(psycopg.Error), psycopg.connect(DATABASE_URL) as connection:
            connection.execute('UPDATE factory.next_model_request_outbox_v1 '
                'SET retrieval_retire_after=retrieval_retire_after+interval \'2 seconds\' WHERE envelope_digest=%s',
                (prepared.envelope.record_digest,))
        time.sleep(max(0, prepared.deadline - time.monotonic()) + .06)
        self.assertEqual(service.run_once(), 0)
        self.assertIsNone(receiver.context)
        with self.fixture.store._transaction() as cursor:
            cursor.execute('SELECT retrieval_retire_after FROM factory.next_model_request_outbox_v1 '
                'WHERE envelope_digest=%s', (prepared.envelope.record_digest,))
            self.assertEqual(cursor.fetchone()[0], due)
        with self.assertRaises(NativeAccessError):
            broker.admit_response(handle, reference)

    def test_real_operator_retirement_api_rejects_worker_and_closed_schema_then_retires(self):
        from fastapi.testclient import TestClient
        from getzilla_factory.api import create_app
        receiver, _client, (service, broker, handle, reference) = self.owned_composition()
        prepared = next(iter(service._prepared.values()))
        receiver.arm(service, prepared.identifier)
        broker.admit_response(handle, reference)
        body = {'envelope_digest': prepared.envelope.record_digest, 'reason': 'source_deleted'}
        with TestClient(create_app(self.fixture.service, self.auth, access_service=service)) as http:
            denied = http.post('/v1/access/result-retirement', json=body,
                headers={'Authorization': 'Bearer synthetic-owned-credential-worker'})
            self.assertEqual(denied.status_code, 403)
            headers = {'Authorization': 'Bearer synthetic-owned-credential-operator'}
            malformed = http.post('/v1/access/result-retirement', json=body | {'reason': []}, headers=headers)
            self.assertEqual(malformed.status_code, 422)
            duplicate = http.post('/v1/access/result-retirement', content='{"reason":"source_deleted",'
                '"reason":"operator_retire","envelope_digest":"' + prepared.envelope.record_digest + '"}',
                headers=headers | {'Content-Type': 'application/json'})
            self.assertEqual(duplicate.status_code, 422)
            retired = http.post('/v1/access/result-retirement', json=body, headers=headers)
            self.assertEqual(retired.status_code, 200, retired.text)
            self.assertTrue(retired.json()['local_retired'])
            self.assertEqual(retired.json()['recipient'], 'confirmed')
            observed = http.get('/v1/access/result-retirement/' + prepared.envelope.record_digest, headers=headers)
            self.assertEqual(observed.status_code, 200)
            self.assertEqual(observed.json()['recipient'], 'confirmed')
        self.assertIsNone(receiver._payload)

    def test_ephemeral_lost_expiry_commit_converges_by_observation_without_retirement_repost(self):
        import time
        from unittest.mock import patch
        from getzilla_factory.store import StoreUnavailable
        receiver, _client, (service, broker, handle, reference) = self.owned_composition(
            profile='factory.ephemeral-retrieval162/v1')
        prepared = next(iter(service._prepared.values()))
        broker.admit_response(handle, reference)
        self.assertEqual(service.run_once(), 1)
        time.sleep(max(0, prepared.deadline - time.monotonic()) + .06)
        self.assertIsNone(receiver.context)
        def lost():
            raise StoreUnavailable('synthetic lost expiry acknowledgement')
        with patch.object(receiver, '_retirement', wraps=receiver._retirement) as posts:
            with transaction_after_commit(service._store, 'factory.expire_access_result_v1', lost):
                service.run_once()
            self.assertEqual(posts.call_count, 0)
            with self.fixture.store._transaction() as cursor:
                cursor.execute('SELECT retirement_state FROM factory.next_model_request_outbox_v1 '
                    'WHERE envelope_digest=%s', (prepared.envelope.record_digest,))
                self.assertEqual(cursor.fetchone()[0], 'sending')
            time.sleep(.11)
            service.run_once()
            self.assertEqual(posts.call_count, 0)
        with self.fixture.store._transaction() as cursor:
            cursor.execute('SELECT retirement_state FROM factory.next_model_request_outbox_v1 '
                'WHERE envelope_digest=%s', (prepared.envelope.record_digest,))
            self.assertEqual(cursor.fetchone()[0], 'confirmed')
