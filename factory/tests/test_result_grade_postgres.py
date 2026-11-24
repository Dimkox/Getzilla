"""Ordinary SQL provenance/integrity fixtures; no HTTP or private source payloads."""
import unittest
import uuid

from getzilla_factory.result_contracts import ResultEnvelopeV2
from factory.tests import test_execution_persistence_postgres as fixtures
from factory.tests.test_postgres_integration import DATABASE_URL, WORKER
from factory.tests.test_result_admission_api import envelope


@unittest.skipUnless(DATABASE_URL, 'owned disposable PostgreSQL required')
class ResultGradePostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.ExecutionPersistencePostgresTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        fixtures.ExecutionPersistencePostgresTests.tearDownClass()

    def setUp(self):
        self.fixture = fixtures.ExecutionPersistencePostgresTests('runTest')
        self.fixture.setUp()
        self.task, self.execution = self.fixture.claim_execution('ordinary-grade-contract', capabilities=['text'])

    def admit(self, protected=False):
        lease = self.execution.lease
        with self.fixture.store._transaction() as cursor:
            cursor.execute('SELECT attempt_id FROM factory.attempts WHERE run_id=%s', (lease.run_id,))
            attempt = str(cursor.fetchone()[0])
        value = envelope(repository_id=self.task.repository_id, task_id=lease.task_id, run_id=lease.run_id,
            fence=lease.fence, packet_digest=lease.packet_digest, attempt_id=attempt,
            source_operation=('access:' if protected else 'ordinary:') + uuid.uuid4().hex,
            policy_version='access-local-text/v1' if protected else 'result-sanitizer/1')
        # The existing envelope helper's payload is the ordinary public string 'safe'.
        record = ResultEnvelopeV2.from_dict(value)
        self.fixture.store.admit_result(record, actor=WORKER, idempotency_key=uuid.uuid4().hex * 2,
                                        correlation_id='ordinary-grade-unit')
        return record

    def test_source_grade_is_stamped_at_insert_and_is_immutable(self):
        import psycopg
        ordinary, protected = self.admit(), self.admit(True)
        with psycopg.connect(DATABASE_URL) as connection:
            grades = dict(connection.execute('SELECT trim(envelope_digest),access_grade FROM factory.result_sources_v1').fetchall())
        self.assertEqual(grades[ordinary.record_digest], 'ordinary')
        self.assertEqual(grades[protected.record_digest], 'protected')
        with self.assertRaisesRegex(psycopg.errors.RaiseException, 'immutable result source'):
            with psycopg.connect(DATABASE_URL) as connection:
                connection.execute("UPDATE factory.result_sources_v1 SET access_grade='ordinary' WHERE envelope_digest=%s",
                                   (protected.record_digest,))
        read = self.fixture.store.result_envelope(ordinary.repository_id, ordinary.task_id, ordinary.record_digest)
        self.assertEqual(read.to_dict(), ordinary.to_dict())

    def insert_outbox(self, record, phase):
        import psycopg
        digest = uuid.uuid4().hex * 2
        with psycopg.connect(DATABASE_URL) as connection:
            connection.execute('INSERT INTO factory.next_model_request_outbox_v1 '
                '(request_digest,envelope_digest,task_id,run_id,attempt_id,repository_id,fence,packet_digest,'
                'dispatch_phase,operation_id,observation_deadline) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'
                "clock_timestamp()+interval '2 seconds')",
                (digest, record.record_digest, record.task_id, record.run_id, record.attempt_id,
                 record.repository_id, record.fence, record.packet_digest, phase, 'factory-result:' + digest))
        return digest

    def test_missing_or_pruned_outbox_does_not_erase_source_grade(self):
        import psycopg
        record = self.admit(True)
        with psycopg.connect(DATABASE_URL) as connection:
            self.assertEqual(connection.execute('SELECT access_grade FROM factory.result_sources_v1 '
                'WHERE envelope_digest=%s', (record.record_digest,)).fetchone(), ('protected',))
        digest = self.insert_outbox(record, 'blocked')
        with psycopg.connect(DATABASE_URL) as connection:
            self.assertEqual(connection.execute('SELECT source_grade FROM factory.next_model_request_outbox_v1 '
                'WHERE request_digest=%s', (digest,)).fetchone(), ('protected',))
            connection.execute('DELETE FROM factory.next_model_request_outbox_v1 WHERE request_digest=%s', (digest,))
            self.assertEqual(connection.execute('SELECT access_grade FROM factory.result_sources_v1 '
                'WHERE envelope_digest=%s', (record.record_digest,)).fetchone(), ('protected',))

    def test_source_grade_blocks_ordinary_dispatch_even_without_access_binding(self):
        import psycopg
        record = self.admit(True)
        with self.assertRaises(psycopg.errors.CheckViolation):
            self.insert_outbox(record, 'pending')
        digest = self.insert_outbox(record, 'blocked')
        with psycopg.connect(DATABASE_URL) as connection:
            self.assertEqual(connection.execute('SELECT factory.claim_model_requests_v1(%s,%s,%s)',
                ('ordinary-unit-dispatcher', 1, 5)).fetchone()[0], [])
        with self.assertRaisesRegex(psycopg.errors.RaiseException, 'immutable result provenance'):
            with psycopg.connect(DATABASE_URL) as connection:
                connection.execute("UPDATE factory.next_model_request_outbox_v1 SET source_grade='ordinary' WHERE request_digest=%s",
                                   (digest,))

    def test_grade_trigger_functions_do_not_add_runtime_write_privileges(self):
        with self.fixture.store._transaction() as cursor:
            for function in ('stamp_result_access_grade_v1()', 'stamp_outbox_access_grade_v1()'):
                cursor.execute('SELECT has_function_privilege(current_user,%s,%s)', ('factory.' + function, 'EXECUTE'))
                self.assertFalse(cursor.fetchone()[0])
            for table, column in (('result_sources_v1', 'access_grade'), ('next_model_request_outbox_v1', 'source_grade')):
                cursor.execute('SELECT has_column_privilege(current_user,%s,%s,%s)', ('factory.'+table, column, 'UPDATE'))
                self.assertFalse(cursor.fetchone()[0])
