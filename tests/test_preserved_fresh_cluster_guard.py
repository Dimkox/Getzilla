"""Fresh-cluster custody composition keeps preflight before schema mutation."""
import ast
import os
from pathlib import Path
import sys
from types import ModuleType
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]


class PreservedFreshClusterGuardTests(unittest.TestCase):
    def setup_function(self, migrations):
        source = ast.parse((ROOT / 'factory/tests/test_execution_persistence_postgres.py').read_bytes())
        declaration = next(n for n in source.body if isinstance(n, ast.ClassDef)
                           and n.name == 'FreshClusterArtifactAttestorMigrationTests')
        method = next(n for n in declaration.body if isinstance(n, ast.FunctionDef) and n.name == 'setUpClass')
        method.decorator_list = []
        namespace = {'os': os, 'FRESH_CLUSTER_DATABASE_URL': 'owned-fresh-dsn',
                     'discover_migrations': migrations}
        exec(compile(ast.Module(body=[method], type_ignores=[]), '<actual-fresh-setup>', 'exec'), namespace)
        return namespace['setUpClass']

    def test_owned_endpoint_refusal_precedes_migrations(self):
        from importlib import import_module
        probe = import_module('factory.tests.postgres_restart_probe')
        from unittest.mock import Mock
        migrations = Mock(side_effect=AssertionError('migration must not run'))
        setup = self.setup_function(migrations)
        environment = {'FACTORY_TEST_POSTGRES_JOURNAL': 'owned-journal',
                       'FACTORY_FRESH_POSTGRES_CONTAINER': 'gz-fresh',
                       'FACTORY_FRESH_POSTGRES_CONTAINER_ID': 'original-container',
                       'FACTORY_TEST_POSTGRES_NONCE': 'original-nonce'}
        with patch.dict(os.environ, environment, clear=True), \
                patch.dict(sys.modules, {'psycopg': ModuleType('psycopg')}), \
                patch.object(probe, '_assert_disposable_target', side_effect=ValueError('owned refusal')) as guard:
            with self.assertRaisesRegex(ValueError, 'owned refusal'):
                setup(object())
        migrations.assert_not_called()
        guard.assert_called_once_with('owned-fresh-dsn', 'gz-fresh', 'original-container', 'original-nonce')

    def test_missing_owned_binding_refuses_before_migrations(self):
        from unittest.mock import Mock
        migrations = Mock(side_effect=AssertionError('migration must not run'))
        setup = self.setup_function(migrations)
        with patch.dict(os.environ, {'FACTORY_TEST_POSTGRES_JOURNAL': 'owned-journal'}, clear=True), \
                patch.dict(sys.modules, {'psycopg': ModuleType('psycopg')}):
            with self.assertRaises(KeyError):
                setup(object())
        migrations.assert_not_called()
