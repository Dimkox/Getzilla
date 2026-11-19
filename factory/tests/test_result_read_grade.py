"""Ordinary DTO/serialization contracts only; no HTTP or private-payload probes."""
from contextlib import contextmanager
import json
import unittest
from unittest.mock import patch

from getzilla_factory.models import Actor
from getzilla_factory.result_contracts import ResultEnvelopeV2
from getzilla_factory.service import FactoryService, ResultAdmissionUnavailable
from getzilla_factory.store import PostgresFactoryStore, StoreError
from factory.tests.test_result_admission_api import envelope


class ResultReadGradeTests(unittest.TestCase):
    def read(self, row):
        class Cursor:
            def execute(self, *_args):
                pass
            def fetchone(self):
                return row
        @contextmanager
        def transaction(**_kwargs):
            yield Cursor()
        store = PostgresFactoryStore('synthetic-unused-unit-fixture')
        wire = row[0]
        digest = ResultEnvelopeV2.from_dict(wire).record_digest
        with patch.object(store, '_transaction', transaction):
            return store.result_envelope(wire['repository_id'], wire['task_id'], digest)

    def test_protected_persistent_grade_is_refused_before_payload_dto_construction(self):
        wire = envelope()  # Ordinary public unit string only, never source/private bytes.
        record = ResultEnvelopeV2.from_dict(wire)
        class Cursor:
            def execute(self, *_args):
                pass
            def fetchone(self):
                return wire, 'protected', False
        @contextmanager
        def transaction(**_kwargs):
            yield Cursor()
        store = PostgresFactoryStore('synthetic-unused-unit-fixture')
        with patch.object(store, '_transaction', transaction), \
                patch.object(ResultEnvelopeV2, 'from_dict', side_effect=AssertionError('payload DTO construction')):
            with self.assertRaisesRegex(StoreError, '^protected result unavailable$'):
                store.result_envelope(wire['repository_id'], wire['task_id'], record.record_digest)

    def test_missing_unknown_or_conflicting_grade_never_defaults_to_ordinary(self):
        for grade, binding in ((None, False), ('unknown', False), ('ordinary', True), ('protected', False)):
            with self.subTest(grade=grade, binding=binding), self.assertRaises(StoreError):
                self.read((envelope(), grade, binding))

    def test_protected_producer_marker_is_not_an_ordinary_record_even_if_metadata_is_missing(self):
        for changes in ({'policy_version': 'access-local-text/v1'}, {'source_operation': 'access:unit-contract'}):
            with self.subTest(changes=changes), self.assertRaises(StoreError):
                self.read((envelope(**changes), 'ordinary', False))

    def test_ordinary_legacy_dto_and_serialization_are_unchanged(self):
        wire = envelope()
        result = self.read((wire, 'ordinary', False))
        self.assertEqual(result.to_dict(), wire)
        self.assertEqual(json.loads(json.dumps(result.to_dict())), wire)

    def test_service_contract_rejects_protected_markers_before_legacy_serialization(self):
        record = ResultEnvelopeV2.from_dict(envelope(policy_version='access-local-text/v1'))
        class Store:
            def result_envelope(self, *_args):
                return record
        actor = Actor('ordinary-unit-reader', 'client', frozenset({'task:read'}), frozenset({record.repository_id}))
        with self.assertRaises(ResultAdmissionUnavailable):
            FactoryService(Store()).get_result_envelope(record.task_id, record.record_digest,
                repository_id=record.repository_id, actor=actor)
