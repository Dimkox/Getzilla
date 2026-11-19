"""Linux memory-model joins are not native Windows qualification."""
from datetime import datetime, timezone
import codecs
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

import getzilla
from getzilla import security_data as data, security_data_windows as windows, verification_policy_source
from getzilla import security_osv_diagnostics  # noqa: F401
from getzilla import security_osv_snapshot as snapshot, verification_plan
from tests.test_batch_composition_joins import _Registry, pure
from tests.test_osv_alias_decisions import archive, record
from tests.test_windows_snapshot_store import MemoryNative

NOW = datetime(2026, 11, 17, tzinfo=timezone.utc)
codecs.lookup('cp437')  # Load the stdlib ZIP codec before the pure I/O boundary.


class WindowsStoreJoinTests(unittest.TestCase):
    def test_native_backend_has_same_exact_owner_and_loaded_policy_binding(self):
        model = json.loads((Path(__file__).resolve().parents[1]/'architecture/system.yaml').read_bytes())
        content = [b'owned native interpreter one']
        with mock.patch.object(verification_plan, '_POLICY_PATHS', ()), \
                mock.patch.object(verification_policy_source.importlib, 'import_module',
                                  side_effect=lambda name, package: SimpleNamespace(filename=name.removeprefix('.')+'.py')), \
                mock.patch.object(verification_policy_source, '_module_source', side_effect=lambda module:
                    content[0] if module.filename=='security_data_windows.py' else module.filename.encode()), \
                mock.patch.object(getzilla, 'STACK_DIR', _Registry()), pure():
            owners = [n['id'] for n in model['nodes']
                      if '.getzilla/getzilla/security_data_windows.py' in n['repository_paths']]
            self.assertEqual(owners, ['NODE-SECURITY-SNAPSHOT-EVALUATOR'])
            before = verification_plan.policy_binding(Path('owned-native'))
            self.assertIn('security_data_windows.py', before['implementation'])
            content[0] = b'owned native interpreter changed'
            self.assertNotEqual(before['digest'], verification_plan.policy_binding(Path('owned-native'))['digest'])

    def test_factory_memory_backend_preserves_raw_alias_and_unknown_version_guards(self):
        native = MemoryNative()
        backend = windows.SnapshotStore
        database = Path('C:\\owned-join')
        acquisition = {'last_verified_sync_utc':NOW.isoformat(), 'retrieval_kind':'download'}
        opaque = ['provider,opaque', '', 'provider\x1b[31m']
        unrelated = {'id':'OSV-UNKNOWN', 'affected':[{'package':{'ecosystem':'PyPI','name':'other'}}]}
        dependency = snapshot.Dependency('PyPI', 'owned', '1.0.0', 'owned.lock')
        def publish(rows):
            payload = archive(rows)
            data.publish_snapshot(database, 'osv:PyPI', payload, acquisition=acquisition,
                                  coverage=data.osv_coverage(payload, 'PyPI'), now=NOW)
            found, _ = data.read_snapshot(database, 'osv:PyPI', now=NOW)
            self.assertEqual(found, payload)
        with mock.patch.object(data, 'os', SimpleNamespace(name='nt')), \
                mock.patch.object(data, '_SnapshotStore', side_effect=AssertionError('unexpected POSIX fallback')), \
                mock.patch.object(windows, 'SnapshotStore', side_effect=lambda path, create=False:
                    backend(path, create=create, _native=native)), pure():
            publish([unrelated, record(opaque+['CVE-2026-12345'])])
            findings = snapshot.query_offline([dependency], database, now=NOW)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].raw_aliases, opaque+['CVE-2026-12345'])
            self.assertEqual(findings[0].aliases, ['CVE-2026-12345'])
            publish([unrelated, record(['CVE-2026-12345', ' CVE-2026-12345 '])])
            with self.assertRaises(snapshot.VulnerabilityError):
                snapshot.query_offline([dependency], database, now=NOW)
            publish([{'id':'OSV-MATCHED-UNKNOWN', 'affected':[{'package':{'ecosystem':'PyPI','name':'owned'}}]}])
            with self.assertRaisesRegex(snapshot.VulnerabilityError, 'coverage is unknown'):
                snapshot.query_offline([dependency], database, now=NOW)
        self.assertEqual(native.handles, {})
