"""Actual owned PostgreSQL/outbox and authenticated UDS retrieval delivery."""
import hashlib
import json
import unittest

from factory.tests import test_access_release_postgres as access_fixture
from factory.tests.test_postgres_integration import DATABASE_URL
from getzilla.native_access import NativeAccessBroker, NativeAccessError, RegisteredQuery
from getzilla_factory.access_release import AccessReleaseService, LocalSourceAdapter
from getzilla_factory.native_access import FactoryNativeAccessHost, FactoryTaskBinding


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

    def composition(self):
        raw = b'def choose_key(value):\n    return "OWNED_AUTHORIZED_RESULT"\n'
        self.source.write_bytes(raw)
        self.source.chmod(0o600)
        source = LocalSourceAdapter([dict(key=self.key('a'), version='v1',
            repository_id=self.task.repository_id, workspace_handle=self.execution.workspace_handle,
            relative_path='factory/src/owned.py', file=str(self.source),
            content_digest=hashlib.sha256(raw).hexdigest(), classification='internal')])
        service = AccessReleaseService(self.fixture.store, self.auth.access_authority, source,
            {'private-a': self.client}, retrieval_profile='factory.local-retrieval162/v1')
        self.addCleanup(service.close)
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
