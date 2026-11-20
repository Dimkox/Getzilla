"""Real schema-025 upgrade controls in the caller-bound disposable PostgreSQL."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import os
import secrets
import time
import unittest
from unittest.mock import patch
import uuid

from getzilla_factory.migrations import PostgresMigrator, discover_migrations


DATABASE_URL = os.environ.get('FACTORY_TEST_DATABASE_URL')


@unittest.skipUnless(DATABASE_URL, 'requires explicitly bound disposable PostgreSQL')
class FactoryStopMigrationTests(unittest.TestCase):
    def setUp(self):
        import psycopg
        self.psycopg = psycopg
        from factory.tests.run_disposable_exit import _binding_matches
        self.assertTrue(_binding_matches(
            os.environ['FACTORY_TEST_POSTGRES_CONTAINER_ID'], os.environ['FACTORY_TEST_POSTGRES_CONTAINER'],
            os.environ['FACTORY_TEST_POSTGRES_NONCE'], require_running=True))
        with psycopg.connect(DATABASE_URL) as connection:
            connection.execute('DROP SCHEMA IF EXISTS factory CASCADE')
        old = tuple(item for item in discover_migrations() if item.version <= 25)
        self.assertEqual([item.version for item in old], list(range(1, 26)))
        with patch('getzilla_factory.migrations.discover_migrations', return_value=old):
            PostgresMigrator(DATABASE_URL).apply()

    def upgrade(self):
        available = discover_migrations()
        self.assertEqual([item.version for item in available], list(range(1, 31)))
        self.assertEqual([item.version for item in PostgresMigrator(DATABASE_URL).apply()], list(range(26, 31)))
        self.assertEqual(PostgresMigrator(DATABASE_URL).apply(), ())

    def insert(self, connection, scope, enabled, key, *, created=None):
        identifier = uuid.uuid4()
        connection.execute(
            'INSERT INTO factory.kill_switches(switch_id,scope_key,enabled,actor_id,reason,idempotency_key,created_at) '
            'VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(idempotency_key) DO NOTHING',
            (identifier, scope, enabled, 'fixture-operator', 'fixture-stop', key,
             created or datetime.now(timezone.utc)))
        return identifier

    def test_upgrade_preserves_historical_head_and_adds_revision_without_new_store(self):
        with self.psycopg.connect(DATABASE_URL) as connection:
            self.insert(connection, 'global', True, '1' * 64, created=datetime(2020, 1, 1, tzinfo=timezone.utc))
            latest = self.insert(connection, 'global', False, '2' * 64,
                                 created=datetime(2021, 1, 1, tzinfo=timezone.utc))
        self.upgrade()
        with self.psycopg.connect(DATABASE_URL) as connection:
            rows = connection.execute('SELECT revision FROM factory.kill_switches ORDER BY revision').fetchall()
            self.assertEqual(rows, [(1,), (2,)])
            self.assertEqual(connection.execute(
                'SELECT switch_id,enabled,revision FROM factory.kill_switch_heads WHERE scope_key=%s',
                ('global',)).fetchone(), (latest, False, 2))
            self.assertEqual(connection.execute(
                "SELECT count(*) FROM information_schema.tables WHERE table_schema='factory' "
                "AND table_name LIKE '%kill%'").fetchone()[0], 2)

    def test_runtime_insert_revision_is_serialized_and_head_ignores_clock_rollback(self):
        self.upgrade()
        first = self.psycopg.connect(DATABASE_URL)
        self.addCleanup(first.close)
        first.execute('SET LOCAL ROLE factory_runtime')
        self.insert(first, 'global', False, '3' * 64, created=datetime(2030, 1, 1, tzinfo=timezone.utc))
        def second():
            with self.psycopg.connect(DATABASE_URL) as connection:
                connection.execute('SET LOCAL ROLE factory_runtime')
                self.insert(connection, 'global', True, '4' * 64,
                            created=datetime(2000, 1, 1, tzinfo=timezone.utc))
        with ThreadPoolExecutor(max_workers=1) as executor:
            later = executor.submit(second)
            time.sleep(.1)
            self.assertFalse(later.done(), 'same-scope insertion bypassed the revision lock')
            first.commit()
            later.result(timeout=5)
        with self.psycopg.connect(DATABASE_URL) as connection:
            history = connection.execute(
                'SELECT enabled,revision FROM factory.kill_switches ORDER BY revision').fetchall()
            self.assertEqual([item[0] for item in history], [False, True])
            self.assertGreater(history[1][1], history[0][1])
            self.assertEqual(connection.execute(
                'SELECT enabled,revision FROM factory.kill_switch_heads WHERE scope_key=%s',
                ('global',)).fetchone(), (True, history[1][1]))
            self.assertEqual(connection.execute(
                'SELECT active_kills FROM factory.metric_counters WHERE singleton').fetchone()[0], 1)
            from getzilla_factory.store import PostgresFactoryStore
            with connection.cursor() as cursor:
                self.assertTrue(PostgresFactoryStore(DATABASE_URL)._is_killed(cursor, ('fixture',)),
                                'the actual claim consumer ignored the monotone stop revision')

    def test_conflicting_replay_does_not_change_head_or_enable_runtime_authority(self):
        self.upgrade()
        with self.psycopg.connect(DATABASE_URL) as connection:
            connection.execute('SET LOCAL ROLE factory_runtime')
            self.insert(connection, 'repository:fixture', True, '5' * 64)
        with self.psycopg.connect(DATABASE_URL) as connection:
            before = connection.execute(
                'SELECT switch_id,enabled,revision FROM factory.kill_switch_heads').fetchall()
            connection.execute('SET LOCAL ROLE factory_runtime')
            self.insert(connection, 'repository:fixture', False, '5' * 64)
        with self.psycopg.connect(DATABASE_URL) as connection:
            self.assertEqual(connection.execute(
                'SELECT switch_id,enabled,revision FROM factory.kill_switch_heads').fetchall(), before)
            self.assertFalse(connection.execute(
                "SELECT has_table_privilege('factory_runtime','factory.kill_switch_heads','SELECT')").fetchone()[0])
            self.assertFalse(connection.execute(
                "SELECT has_function_privilege('factory_runtime','factory.assign_kill_revision()','EXECUTE')").fetchone()[0])
            self.assertFalse(connection.execute(
                "SELECT has_sequence_privilege('factory_runtime','factory.kill_switch_revision_seq','USAGE')").fetchone()[0])

    def test_actual_factory_operator_service_keeps_idempotency_and_scope_authority(self):
        from psycopg.conninfo import conninfo_to_dict, make_conninfo
        from getzilla_factory.admin import provision_runtime_login
        from getzilla_factory.models import Actor
        from getzilla_factory.service import AuthorizationError, FactoryService
        from getzilla_factory.store import PostgresFactoryStore, StoreError
        self.upgrade()
        login = 'stop_fixture_runtime'
        password = secrets.token_hex(24)
        provision_runtime_login(DATABASE_URL, login, password)
        def remove_fixture_login():
            with self.psycopg.connect(DATABASE_URL) as connection:
                connection.execute('DROP ROLE stop_fixture_runtime')
        self.addCleanup(remove_fixture_login)
        runtime_url = make_conninfo(**{**conninfo_to_dict(DATABASE_URL), 'user': login, 'password': password})
        service = FactoryService(PostgresFactoryStore(runtime_url))
        operator = Actor('fixture-operator', 'operator', frozenset({'factory:kill'}), frozenset({'*'}))
        arguments = dict(scope_key='global', enabled=True, reason='fixture-stop', idempotency_key='6' * 64,
                         actor=operator, now=datetime.now(timezone.utc))
        self.assertTrue(service.set_kill(**arguments))
        with self.psycopg.connect(DATABASE_URL) as connection:
            before = connection.execute('SELECT switch_id,enabled,revision FROM factory.kill_switch_heads').fetchall()
        self.assertTrue(service.set_kill(**arguments))
        with self.assertRaises(StoreError):
            service.set_kill(**{**arguments, 'enabled': False})
        outsider = Actor('fixture-client', 'client', frozenset({'factory:kill'}), frozenset({'*'}))
        with self.assertRaises(AuthorizationError):
            service.set_kill(**{**arguments, 'actor': outsider, 'idempotency_key': '7' * 64})
        limited = Actor('fixture-limited', 'operator', frozenset({'factory:kill'}), frozenset({'other-repo'}))
        with self.assertRaises(AuthorizationError):
            service.set_kill(**{**arguments, 'actor': limited, 'idempotency_key': '8' * 64})
        with self.psycopg.connect(DATABASE_URL) as connection:
            self.assertEqual(connection.execute('SELECT count(*) FROM factory.kill_switches').fetchone()[0], 1)
            self.assertEqual(connection.execute(
                'SELECT switch_id,enabled,revision FROM factory.kill_switch_heads').fetchall(), before)


if __name__ == '__main__':
    unittest.main()
