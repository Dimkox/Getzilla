"""Separate, hash-bound SQLite history and PostgreSQL runtime catalogs."""
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from getzilla_factory.landing_sqlite.migrations import discover_migrations
from getzilla_factory.landing_sqlite_store import APPLICATION_ID, SCHEMA_VERSION, SQLiteLandingJobStore
from getzilla_factory.migrations import discover_migrations as postgres_migrations

ROOT = Path(__file__).resolve().parents[2]


class LandingSQLiteMigrationTests(unittest.TestCase):
    def test_runtime_uses_hash_bound_catalog_and_rejects_drift_or_unknown_sql(self):
        from getzilla_factory.landing_sqlite import migrations as catalog
        from getzilla_factory import landing_sqlite_store, paid_admission, shared_landing_contracts
        migrations = discover_migrations()
        self.assertEqual(paid_admission.SCHEMA, migrations[2].sql)
        self.assertEqual(shared_landing_contracts.CONTROL_SCHEMA, migrations[3].sql)
        self.assertEqual(landing_sqlite_store.MIGRATION_002_EXPAND, migrations[1].sql)
        self.assertEqual(landing_sqlite_store._SCHEMA, ''.join(item.sql for item in migrations))
        self.assertEqual(migrations[2].sha256, '243fa46a702cdd85d92fc3fd9e3b9d6b3465d99d70538c5f89c79c20a6f2427a')
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for item in migrations:
                (directory / item.name).write_text(item.sql)
            with patch.object(catalog, 'files', return_value=directory):
                self.assertEqual(catalog.discover_migrations(), migrations)
                target = directory / migrations[2].name
                target.write_text(migrations[2].sql + 'DROP TABLE paid_accounts;')
                with self.assertRaises(catalog.SQLiteMigrationError):
                    catalog.discover_migrations()
                target.write_text(migrations[2].sql)
                (directory / '005_unregistered.sql').write_text('SELECT 1;')
                with self.assertRaises(catalog.SQLiteMigrationError):
                    catalog.discover_migrations()

    def test_separate_contiguous_sqlite_and_postgres_catalogs(self):
        migrations = discover_migrations()
        self.assertEqual([item.version for item in migrations], [1, 2, 3, 4])
        self.assertEqual(SCHEMA_VERSION, migrations[-1].version)
        postgres = postgres_migrations()
        self.assertEqual([item.version for item in postgres], list(range(1, 31)))
        self.assertEqual(sorted(p.name for p in (ROOT / 'factory/src/getzilla_factory/resources').glob('*.sql')),
                         [item.name for item in postgres])

    def test_every_supported_prefix_upgrades_through_real_sqlite_runtime(self):
        migrations = discover_migrations()
        for version in (1, 2, 3, 4):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as temporary:
                state = Path(temporary) / 'state'
                state.mkdir(mode=0o700)
                database = state / 'landing.sqlite3'
                with sqlite3.connect(database) as connection:
                    for item in migrations[:version]:
                        connection.executescript(item.sql)
                    connection.execute(f'PRAGMA application_id={APPLICATION_ID}')
                    connection.execute(f'PRAGMA user_version={version}')
                database.chmod(0o600)
                store = SQLiteLandingJobStore(state, repository_root=ROOT)
                try:
                    self.assertEqual(store._connection.execute('PRAGMA user_version').fetchone(), (4,))
                    self.assertEqual(store._connection.execute('PRAGMA integrity_check').fetchone(), ('ok',))
                    self.assertEqual(store._connection.execute('PRAGMA foreign_key_check').fetchall(), [])
                finally:
                    store.close()
