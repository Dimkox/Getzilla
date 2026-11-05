"""Public fixtures for the generic opt-in lifecycle; no native client is started."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]
from tests import test_optional_modules as fixtures
from getzilla.component_state import MANIFEST, read_state, ComponentTransaction
from getzilla.optional_modules import ModuleError, admit_module, manage_modules, module_status, rollback_modules, recover_modules
from getzilla.module_runtime import (ActivationRequestV1, plan_activation, commit_activation, quiesce_module,
    OwnedRuntimeV1, NativeProfileProofV1, QuiescenceProofV1)


class RuntimeModuleTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.OptionalModuleTests('test_lifecycle_installs_disabled_and_preserves_foreign_settings')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.make_runtime('1.0.0')
        self.fixture.run_module('install', {'runtime-addon': '1.0.0'})

    def make_runtime(self, version, features=None, entitlement=None):
        descriptor = {'schema_version': 1, 'module': 'runtime-addon', 'version': version,
                      'required_features': features or ['owned-runtime-v1', 'trusted-transport-v1'],
                      'native_profiles': ['fixture-owned-v1']}
        self.fixture.make_module('runtime-addon', version, permissions=['fixture.read'], entitlement=entitlement,
                                 files={'runtime.v1.json': (json.dumps(descriptor).encode(), False)})

    def request(self):
        record = read_state(self.root).manifest['components']['module:runtime-addon']['module']
        return ActivationRequestV1(project=str(self.root.absolute()), module='runtime-addon', version='1.0.0',
            manifest_sha256=record['manifest_sha256'], task_id='fixture-task', run_id='fixture-run',
            owner_id='fixture-owner', authority_epoch=0, context_digest='a' * 64,
            native_profile='fixture-owned-v1', scope_digest='b' * 64, operations=('fixture.read',))

    def test_runtime_install_is_disabled_and_old_enable_cannot_bypass_ports(self):
        record = module_status(self.root)['modules']['runtime-addon']
        self.assertEqual(record['schema_version'], 2)
        self.assertEqual(record['runtime']['state'], 'installed-disabled')
        self.assertIsNone(module_status(self.root)['workers'])
        before = (self.root / MANIFEST).read_bytes()
        with self.assertRaisesRegex(ModuleError, 'runtime_activation_required'):
            manage_modules(self.root, 'enable', {'runtime-addon': None}, grants=['fixture.read'])
        self.assertEqual((self.root / MANIFEST).read_bytes(), before)
        self.assertFalse(admit_module(self.root, 'runtime-addon')['allowed'])
        self.fixture.assert_user_settings()

    def test_default_ports_refuse_before_any_effect(self):
        before = (self.root / MANIFEST).read_bytes()
        with self.assertRaisesRegex(ModuleError, 'runtime_adapter_unavailable'):
            plan_activation(self.root, 'runtime-addon', self.request())
        self.assertEqual((self.root / MANIFEST).read_bytes(), before)
        self.assertFalse((self.root / '.getzilla/runtime/modules/pending.json').exists())
        self.fixture.assert_user_settings()

    def test_unknown_runtime_feature_refuses_install_without_publication(self):
        self.make_runtime('2.0.0', ['unrecognized-feature-v999'])
        before = (self.root / MANIFEST).read_bytes()
        with self.assertRaisesRegex(ModuleError, 'runtime_feature_unsupported'):
            self.fixture.run_module('update', {'runtime-addon': '2.0.0'})
        self.assertEqual((self.root / MANIFEST).read_bytes(), before)

    def test_passive_record_remains_v1_and_byte_stable_after_runtime_status(self):
        self.fixture.run_module('install', {'context': '1.0.0'})
        before = (self.root / MANIFEST).read_bytes()
        self.assertEqual(module_status(self.root)['modules']['context']['schema_version'], 1)
        self.assertEqual((self.root / MANIFEST).read_bytes(), before)

    def fixture_ports(self):
        """Trusted in-process fixture ports, never a qualified native adapter."""
        class Authority:
            def authorize_activation(self, request): return object()
            def validate_activation(self, request, handle): pass
        class Runtime:
            remaining = 0
            def prepare(self, request, generation, handle):
                return OwnedRuntimeV1('fixture-resource-owner', generation)
            def quiesce(self, owner, deadline):
                return QuiescenceProofV1(owner.owner_handle, owner.generation, self.remaining)
        class Native:
            def inspect_owned(self, request, owner, handle):
                return NativeProfileProofV1(request.digest(), owner.generation, owner.owner_handle)
        return {'native': Native(), 'runtime': Runtime(), 'authority': Authority()}

    def activate_fixture(self):
        ports = self.fixture_ports()
        plan = plan_activation(self.root, 'runtime-addon', self.request(), **ports)
        result = commit_activation(self.root, plan, **ports)
        self.assertEqual(result.state, 'enabled')
        return ports, plan

    def test_fixture_activation_is_bound_and_passive_admission_stays_unavailable(self):
        ports, plan = self.activate_fixture()
        metadata = module_status(self.root)['modules']['runtime-addon']
        self.assertEqual(metadata['runtime']['generation'], plan.generation)
        self.assertEqual(metadata['runtime']['request_digest'], self.request().digest())
        self.assertFalse(admit_module(self.root, 'runtime-addon')['allowed'])
        with self.assertRaisesRegex(ModuleError, 'runtime_quiescence_required'):
            self.fixture.run_module('uninstall', {'runtime-addon': None})
        with self.assertRaisesRegex(ModuleError, 'runtime_quiescence_required'):
            rollback_modules(self.root)
        self.fixture.assert_user_settings()

    def test_disable_denies_before_missing_port_and_never_claims_zero_workers(self):
        self.activate_fixture()
        report = manage_modules(self.root, 'disable', {'runtime-addon': None})
        self.assertEqual(report['status'], 'quiescing')
        self.assertIsNone(report['workers'])
        record = module_status(self.root)['modules']['runtime-addon']
        self.assertFalse(record['enabled'])
        self.assertEqual(record['grants'], [])
        self.assertEqual(record['runtime']['state'], 'quiescing')
        result = quiesce_module(self.root, 'runtime-addon')
        self.assertEqual(result.state, 'quiescing')
        self.assertIsNone(result.workers)
        self.assertEqual(result.reason, 'runtime_adapter_unavailable')

    def test_resource_proof_must_be_exact_and_zero_before_finishing(self):
        ports, plan = self.activate_fixture()
        ports['runtime'].remaining = 1
        with self.assertRaisesRegex(ModuleError, 'runtime_quiescence_unproven'):
            quiesce_module(self.root, 'runtime-addon', **ports)
        record = module_status(self.root)['modules']['runtime-addon']
        self.assertFalse(record['enabled'])
        self.assertEqual(record['runtime']['state'], 'quiescing')
        ports['runtime'].remaining = 0
        result = quiesce_module(self.root, 'runtime-addon', **ports)
        self.assertEqual(result.workers, 0)
        self.assertEqual(result.state, 'installed-disabled')
        self.assertIsNone(module_status(self.root)['modules']['runtime-addon']['runtime']['generation'])
        self.assertEqual(quiesce_module(self.root, 'runtime-addon', **ports).state, 'installed-disabled')
        self.assertEqual(rollback_modules(self.root)['status'], 'rolled_back')
        self.assertFalse(module_status(self.root)['modules']['runtime-addon']['enabled'])

    def test_history_full_still_allows_durable_disable(self):
        self.activate_fixture()
        history = self.root / '.getzilla/runtime/modules/history'
        for i in range(32):
            (history / f'{i:032x}.json').write_bytes(b'fixture history capacity only')
        report = manage_modules(self.root, 'disable', {'runtime-addon': None})
        self.assertEqual(report['status'], 'quiescing')
        self.assertFalse(module_status(self.root)['modules']['runtime-addon']['enabled'])

    def test_stale_plan_and_cross_project_request_publish_nothing(self):
        ports = self.fixture_ports()
        plan = plan_activation(self.root, 'runtime-addon', self.request(), **ports)
        self.fixture.run_module('install', {'context': '1.0.0'})
        before = (self.root / MANIFEST).read_bytes()
        with self.assertRaisesRegex(ModuleError, 'activation_plan_stale'):
            commit_activation(self.root, plan, **ports)
        self.assertEqual((self.root / MANIFEST).read_bytes(), before)
        from dataclasses import replace
        with self.assertRaisesRegex(ModuleError, 'activation_project_module_mismatch'):
            plan_activation(self.root, 'runtime-addon', replace(self.request(), project=str(self.root.parent)), **ports)

    def test_failed_runtime_publication_needs_actual_owner_quiescence_for_recovery(self):
        from unittest.mock import patch
        ports = self.fixture_ports()
        plan = plan_activation(self.root, 'runtime-addon', self.request(), **ports)
        write = ComponentTransaction.write
        def fail_history(transaction, path, *args, **kwargs):
            if path.startswith('.getzilla/runtime/modules/history/'):
                raise OSError('synthetic public fixture publication failure')
            return write(transaction, path, *args, **kwargs)
        with patch.object(ComponentTransaction, 'write', fail_history):
            with self.assertRaisesRegex(ModuleError, 'module_failed_recovery_required'):
                commit_activation(self.root, plan, **ports)
        pending = self.root / '.getzilla/runtime/modules/pending.json'
        before = pending.read_bytes()
        with self.assertRaises(ModuleError):
            recover_modules(self.root)
        self.assertEqual(pending.read_bytes(), before)
        ports['runtime'].remaining = 1
        with self.assertRaisesRegex(ModuleError, 'runtime_quiescence_unproven'):
            recover_modules(self.root, runtime=ports['runtime'])
        self.assertEqual(pending.read_bytes(), before)
        ports['runtime'].remaining = 0
        result = recover_modules(self.root, runtime=ports['runtime'])
        self.assertEqual(result['status'], 'recovered')
        self.assertFalse(pending.exists())
        metadata = module_status(self.root)['modules']['runtime-addon']
        self.assertFalse(metadata['enabled'])
        self.assertEqual(metadata['runtime']['state'], 'installed-disabled')
        self.assertEqual(metadata['grants'], [])
        self.assertEqual(recover_modules(self.root)['status'], 'nothing_to_recover')

    def test_update_and_rollback_never_restore_runtime_grants(self):
        ports, plan = self.activate_fixture()
        self.make_runtime('2.0.0')
        with self.assertRaisesRegex(ModuleError, 'runtime_quiescence_required'):
            self.fixture.run_module('update', {'runtime-addon': '2.0.0'})
        quiesce_module(self.root, 'runtime-addon', **ports)
        self.fixture.run_module('update', {'runtime-addon': '2.0.0'})
        self.assertFalse(module_status(self.root)['modules']['runtime-addon']['enabled'])
        rollback_modules(self.root)
        metadata = module_status(self.root)['modules']['runtime-addon']
        self.assertEqual(metadata['version'], '1.0.0')
        self.assertEqual(metadata['runtime']['state'], 'installed-disabled')
        self.assertEqual(metadata['grants'], [])
        self.assertIsNone(metadata['runtime']['generation'])

    def test_runtime_activation_does_not_bypass_licensed_entitlement(self):
        from dataclasses import replace
        self.make_runtime('2.0.0', entitlement='fixture.license')
        def verify(root, name, version, capability):
            return {'verified': True, 'project': str(root.absolute()), 'module': name,
                    'version': version, 'capability': capability}
        self.fixture.run_module('update', {'runtime-addon': '2.0.0'}, entitlement=verify)
        request = replace(self.request(), version='2.0.0')
        ports = self.fixture_ports()
        before = (self.root / MANIFEST).read_bytes()
        with self.assertRaisesRegex(ModuleError, 'entitlement_adapter_required'):
            plan_activation(self.root, 'runtime-addon', request, **ports)
        self.assertEqual((self.root / MANIFEST).read_bytes(), before)
        plan = plan_activation(self.root, 'runtime-addon', request, entitlement=verify, **ports)
        with self.assertRaisesRegex(ModuleError, 'entitlement_adapter_required'):
            commit_activation(self.root, plan, **ports)
        self.assertEqual(commit_activation(self.root, plan, entitlement=verify, **ports).state, 'enabled')


if __name__ == '__main__':
    unittest.main()
