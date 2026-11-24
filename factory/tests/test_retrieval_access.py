"""Native retrieval payload controls; base fixture substitutes auth and SQL.

These controls establish the real algorithm/retained-payload path, not native
authority or actual PostgreSQL/UDS qualification (covered separately).
"""
from dataclasses import replace
import hashlib
import json
import unittest
from unittest.mock import patch

from factory.tests import test_native_access as fixture
from getzilla.native_access import NativeAccessBroker, NativeAccessError, RegisteredQuery
from getzilla_factory.access_authority import AccessError
from getzilla_factory.access_release import AccessReleaseService

PROFILE = 'factory.local-retrieval162/v1'
QUERY = 'factory.retrieval162/v1'


class RetrievalAccessTests(unittest.TestCase):
    setUp = fixture.FactoryNativeAccessTests.setUp
    transaction = fixture.FactoryNativeAccessTests.transaction
    read_empty = fixture.FactoryNativeAccessTests.read_empty
    deadline = fixture.FactoryNativeAccessTests.deadline

    def enable(self, *, classification='internal'):
        self.source_bytes = b'def choose_key(value):\n    return value\n'
        key = tuple(fixture.KEY.values())
        self.sources._sources[key] = replace(self.sources._sources[key],
            relative_path='ordinary.py', digest=hashlib.sha256(self.source_bytes).hexdigest(),
            classification=classification)
        self.context = replace(self.context, allowed_paths=('ordinary.py',), max_output_bytes=32768)
        self.store._proposal_context.return_value = self.context
        self.snapshot.destinations = {'registered-response': {
            'tenant_id': 'public', 'project_id': 'project', 'repository_id': 'repo'}}
        try:
            self.service = AccessReleaseService(self.store, self.authority, self.sources,
                self.service._destinations, retrieval_profile=PROFILE)
        except TypeError:
            self.fail('existing native release owner has no opt-in retrieval composition')
        self.host = self.n.FactoryNativeAccessHost(self.service)
        self.broker = NativeAccessBroker._compose(self.host)
        self.handle = self.broker.bind_native_request(self.session, self.workflow)
        self.retrieval_query = RegisteredQuery(QUERY, ('current-destination',), {
            'query': 'choose_key', 'destination_id': 'registered-response', 'token_budget': 2048})

    def prepare_retrieval(self):
        cut = self.broker.load_authorized_cut(self.handle, self.retrieval_query,
            absolute_deadline=self.deadline())
        reference = self.broker.prepare_owned_response(self.handle, QUERY, cut,
            'registered-response', absolute_deadline=self.deadline())
        return cut, reference, next(iter(self.service._prepared.values()))

    def test_owned_source_is_ranked_cited_and_retained_in_existing_release_owner(self):
        self.enable()
        cut, reference, prepared = self.prepare_retrieval()
        payload = json.loads(prepared.envelope.sanitized_payload)
        self.assertIn('def choose_key', payload['context'])
        self.assertEqual(payload['citations'][0]['file_sha256'], hashlib.sha256(self.source_bytes).hexdigest())
        self.assertEqual(payload['citations'][0]['path'], 'ordinary.py')
        self.assertEqual(payload['components']['semantic'], 'unavailable')
        self.assertEqual(payload['measurement']['kind'], 'utf8_bytes_upper_bound_estimate')
        self.assertEqual(payload['measurement']['actual_units'], None)
        self.assertEqual(prepared.lineage[0][0], cut.documents[0].dependency.key)
        self.assertIsNotNone(reference)
        self.service._verify_native_payload(prepared)

    def test_query_cannot_select_source_ids_paths_classes_or_another_destination(self):
        self.enable()
        for parameters in ({'query': 'choose_key', 'file': 'ordinary.py'},
                           {'query': 'choose_key', 'source_ids': ['empty']},
                           {'query': 'choose_key', 'classification': 'public'},
                           {'query': 'choose_key', 'destination_id': 'foreign', 'token_budget': 2048}):
            with self.subTest(parameters=parameters):
                handle = self.broker.bind_native_request(self.session, self.workflow)
                with self.assertRaises(NativeAccessError):
                    self.broker.load_authorized_cut(handle, RegisteredQuery(QUERY,
                        ('current-destination',), parameters), absolute_deadline=self.deadline())
        self.assertEqual(self.events, [])

    def test_unknown_or_secret_class_is_not_read_or_ranked(self):
        for classification in ('unknown', 'secret', 'personal'):
            with self.subTest(classification=classification):
                self.enable(classification=classification)
                with self.assertRaises(NativeAccessError):
                    self.prepare_retrieval()
                self.assertEqual(self.events, [])

    def test_current_authz_denial_prevents_private_read(self):
        self.enable()
        with patch.object(self.authority, 'authorize', return_value=False):
            with self.assertRaises(NativeAccessError):
                self.prepare_retrieval()
        self.assertEqual(self.events, [])

    def test_fixed_projection_redacts_known_pii_and_secret_before_ranking_and_keeps_original_hash(self):
        self.enable()
        self.source_bytes = (b'def choose_key():\n    email = "fixture@example.test"\n'
            b'    password = "synthetic-private-sentinel"\n    return email\n')
        key = tuple(fixture.KEY.values())
        self.sources._sources[key] = replace(self.sources._sources[key],
            digest=hashlib.sha256(self.source_bytes).hexdigest())
        self.host = self.n.FactoryNativeAccessHost(self.service)
        self.broker = NativeAccessBroker._compose(self.host)
        self.handle = self.broker.bind_native_request(self.session, self.workflow)
        _, _, prepared = self.prepare_retrieval()
        wire = prepared.envelope.sanitized_payload
        self.assertNotIn('fixture@example.test', wire)
        self.assertNotIn('synthetic-private-sentinel', wire)
        citation = json.loads(wire)['citations'][0]
        self.assertEqual(citation['file_sha256'], hashlib.sha256(self.source_bytes).hexdigest())
        self.assertNotEqual(citation['chunk_sha256'], citation['transformed_sha256'])

    def test_destination_and_retained_query_cannot_be_rebound_after_capture(self):
        self.enable()
        cut = self.broker.load_authorized_cut(self.handle, self.retrieval_query,
            absolute_deadline=self.deadline())
        with self.assertRaises(NativeAccessError):
            self.broker.prepare_owned_response(self.handle, QUERY, cut, 'foreign',
                absolute_deadline=self.deadline())
        self.assertEqual(self.service._prepared, {})

    def test_final_payload_recomputation_rejects_mutated_citation_or_text(self):
        self.enable()
        _, _, prepared = self.prepare_retrieval()
        value = prepared.envelope.to_dict()
        value['sanitized_payload'] = '{"context":"substituted"}'
        from getzilla_factory.contracts import canonical_digest
        value['sanitized_payload_digest'] = canonical_digest(value['sanitized_payload'])
        altered = replace(prepared, envelope=type(prepared.envelope).from_dict(value))
        with self.assertRaises(AccessError):
            self.service._verify_native_payload(altered)

    def test_discard_drops_owned_derivatives_and_cancels_queued_delivery(self):
        self.enable()
        _, _, prepared = self.prepare_retrieval()
        binding = self.broker._requests[self.handle].binding
        entry = self.service._queue._cut(prepared, None)
        self.service._queue._finish_commit(entry, 'd' * 64)
        try:
            self.broker.discard(self.handle)
        except AttributeError:
            self.fail('native broker has no explicit owned-derivative disposal')
        self.assertEqual(self.broker._requests, {})
        self.assertIsNone(binding.captured)
        self.assertEqual(self.service._queue._entries, {})
        retained = self.service._prepared[prepared.identifier]
        self.assertTrue(retained.consumed)
        for attribute in ('envelope', 'native_payload', 'native_capture', 'session'):
            self.assertIsNone(getattr(retained, attribute, None))
        with self.assertRaises(NativeAccessError):
            self.broker.load_authorized_cut(self.handle, self.retrieval_query,
                absolute_deadline=self.deadline())

    def test_dispatcher_tick_retires_expired_derivatives_without_transport(self):
        self.enable()
        _, _, prepared = self.prepare_retrieval()
        self.service._prepared[prepared.identifier] = replace(prepared, deadline=0)
        self.assertEqual(self.service.run_once(), 0)
        retained = self.service._prepared[prepared.identifier]
        self.assertIsNone(getattr(retained, 'envelope', None))
