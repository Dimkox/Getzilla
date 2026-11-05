"""The existing execution authority must be provisioned before any backend effect."""
from __future__ import annotations

import os
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch

from getzilla import continuity, execution, execution_store as store, policy, state
from tests.test_execution import CountingBackend, owned_route


class ExecutionStopTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        environment = patch.dict(os.environ, {'GETZILLA_SESSION_ID': 'owner'})
        environment.start()
        self.addCleanup(environment.stop)
        self.addCleanup(state.bind_session, None)
        owned_route(self.root, provision=False)
        self.caller = execution.trusted_caller(self.root)
        self.request = execution.SubmitRequest('first', {}, 30, label='contract-test')

    def test_unprovisioned_submit_refuses_before_backend_dispatch(self):
        backend = CountingBackend()
        with self.assertRaises(execution.ExecutionError) as error:
            execution.submit(self.root, self.caller, self.request, backend=backend)
        self.assertEqual(error.exception.code, 'execution_not_provisioned')
        self.assertEqual(backend.calls, 0)

    def test_explicit_provision_persists_store_before_arming_canonical_requirement(self):
        provision = getattr(execution, 'provision', None)
        self.assertIsNotNone(provision, 'explicit provisioning is unavailable')
        result = provision(self.root, self.caller)
        self.assertEqual(result['status'], 'provisioned')
        registry = store.load_registry(self.root)
        canonical = state.require_route_owner(self.root)
        self.assertEqual(registry['schema_version'], 2)
        self.assertEqual(canonical['execution_store_required'],
                         {'version': 1, 'generation': registry['generation']})
        backend = CountingBackend()
        view = execution.submit(self.root, self.caller, self.request, backend=backend)
        self.assertEqual(view['execution_status'], 'succeeded')
        self.assertEqual(backend.calls, 1)

    def test_missing_store_after_arming_is_never_recreated(self):
        execution.provision(self.root, self.caller)
        path = self.root / store.REGISTRY_PATH
        path.unlink()
        backend = CountingBackend()
        for operation in (lambda: execution.provision(self.root, self.caller),
                          lambda: execution.submit(self.root, self.caller, self.request, backend=backend)):
            with self.assertRaises((execution.ExecutionError, store.RegistryError)) as error:
                operation()
            self.assertEqual(error.exception.code, 'execution_store_unavailable')
            self.assertFalse(path.exists())
        self.assertEqual(backend.calls, 0)

    def test_missing_required_control_is_not_recreated_as_running(self):
        execution.provision(self.root, self.caller)
        path = self.root / store.REGISTRY_PATH
        value = json.loads(path.read_text())
        value['controls'] = {}
        path.write_text(json.dumps(value))  # Owned corruption fixture, not authority.
        with self.assertRaises(execution.ExecutionError) as error:
            execution.provision(self.root, self.caller)
        self.assertEqual(error.exception.code, 'execution_store_unavailable')
        self.assertEqual(store.load_registry(self.root)['controls'], {})

    def test_store_requirement_cannot_be_removed_or_set_by_route_update(self):
        with self.assertRaises(ValueError):
            state.update_route(self.root, execution_store_required={'version': 1, 'generation': '0' * 32})
        execution.provision(self.root, self.caller)
        with self.assertRaises(ValueError):
            state.update_route(self.root, execution_store_required=None)

    def test_interrupted_store_then_arm_can_resume_without_dispatch(self):
        with patch.object(state, 'arm_execution_store', side_effect=OSError('synthetic interrupted arm')):
            with self.assertRaises(OSError):
                execution.provision(self.root, self.caller)
        saved = store.load_registry(self.root)
        self.assertNotIn('execution_store_required', state.require_route_owner(self.root))
        backend = CountingBackend()
        with self.assertRaises(execution.ExecutionError):
            execution.submit(self.root, self.caller, self.request, backend=backend)
        resumed = execution.provision(self.root, self.caller)
        self.assertEqual(resumed['generation'], saved['generation'])
        self.assertEqual(backend.calls, 0)

    def test_generation_mismatch_refuses_provision_and_submit(self):
        execution.provision(self.root, self.caller)
        path = self.root / store.REGISTRY_PATH
        value = json.loads(path.read_text())
        value['generation'] = '0' * 32
        path.write_text(json.dumps(value))
        with self.assertRaises(execution.ExecutionError):
            execution.provision(self.root, self.caller)
        with self.assertRaises(execution.ExecutionError):
            execution.submit(self.root, self.caller, self.request, backend=CountingBackend())

    def test_stop_latches_before_any_new_submission_and_is_idempotent(self):
        execution.provision(self.root, self.caller)
        stopped = execution.stop(self.root, self.caller, reason='operator_stop')
        self.assertTrue(stopped['stopped'])
        self.assertEqual(stopped['control_revision'], 1)
        repeated = execution.stop(self.root, self.caller, reason='operator_stop')
        self.assertEqual(repeated['control_revision'], 1)
        backend = CountingBackend()
        with self.assertRaises(execution.ExecutionError) as error:
            execution.submit(self.root, self.caller, self.request, backend=backend)
        self.assertEqual(error.exception.code, 'execution_stopped')
        self.assertEqual(backend.calls, 0)
        self.assertEqual(store.load_registry(self.root)['records'], {})

    def test_stop_between_dispatch_and_consume_prevents_effect(self):
        execution.provision(self.root, self.caller)
        caller = self.caller
        class StopsBeforeConsume(CountingBackend):
            def dispatch(inner, root, admission, request):
                execution.stop(root, caller, reason='operator_stop')
                return super().dispatch(root, admission, request)
        backend = StopsBeforeConsume()
        result = execution.submit(self.root, self.caller, self.request, backend=backend)
        self.assertEqual(backend.calls, 0)
        self.assertEqual(result['dispatch_claim'], 'pending')
        self.assertTrue(execution.control_status(self.root, caller)['stopped'])

    def test_recovery_cannot_release_pending_attempt_from_previous_stop_revision(self):
        execution.provision(self.root, self.caller)
        caller = self.caller
        errors = []
        class RecoversBeforeConsume(CountingBackend):
            def dispatch(inner, root, admission, request):
                execution.stop(root, caller, reason='operator_stop')
                observed = execution.control_status(root, caller)
                try:
                    execution.recover(root, caller, expected_revision=observed['control_revision'],
                                      expected_source=observed['source_fingerprint'])
                except execution.ExecutionError as error:
                    errors.append(error.code)
                return super().dispatch(root, admission, request)
        backend = RecoversBeforeConsume()
        execution.submit(self.root, self.caller, self.request, backend=backend)
        self.assertEqual(errors, ['execution_cleanup_unconfirmed'])
        self.assertEqual(backend.calls, 0)

    def test_recovery_requires_exact_revision_source_and_no_uncertain_cleanup(self):
        execution.provision(self.root, self.caller)
        execution.stop(self.root, self.caller, reason='operator_stop')
        observed = execution.control_status(self.root, self.caller)
        for revision, source in ((0, observed['source_fingerprint']),
                                 (observed['control_revision'], '0' * 64)):
            with self.assertRaises(execution.ExecutionError):
                execution.recover(self.root, self.caller, expected_revision=revision, expected_source=source)
        recovered = execution.recover(self.root, self.caller, expected_revision=observed['control_revision'],
                                      expected_source=observed['source_fingerprint'])
        self.assertFalse(recovered['stopped'])
        self.assertEqual(recovered['control_revision'], 2)
        self.assertEqual(execution.submit(self.root, self.caller, self.request,
                                         backend=CountingBackend())['execution_status'], 'succeeded')

    def test_stopped_attempt_can_be_observed_and_cancelled_without_releasing_new_work(self):
        execution.provision(self.root, self.caller)
        backend = CountingBackend(complete=False)
        attempt = execution.submit(self.root, self.caller, self.request, backend=backend)
        execution.stop(self.root, self.caller)
        self.assertEqual(execution.get(self.root, self.caller, attempt['execution_id'])['execution_id'],
                         attempt['execution_id'])
        cancelled = execution.cancel(self.root, self.caller, attempt['execution_id'], backend=backend)
        self.assertEqual(cancelled['execution_status'], 'cancel_requested')
        self.assertEqual(cancelled['cleanup_status'], 'pending')
        self.assertEqual(backend.cancels, 1)
        observed = execution.control_status(self.root, self.caller)
        with self.assertRaises(execution.ExecutionError) as error:
            execution.recover(self.root, self.caller, expected_revision=observed['control_revision'],
                              expected_source=observed['source_fingerprint'])
        self.assertEqual(error.exception.code, 'execution_cleanup_unconfirmed')

    def test_stop_and_recovery_missing_required_store_do_not_recreate_it(self):
        execution.provision(self.root, self.caller)
        path = self.root / store.REGISTRY_PATH
        path.unlink()
        for operation in (lambda: execution.stop(self.root, self.caller),
                          lambda: execution.control_status(self.root, self.caller),
                          lambda: execution.recover(self.root, self.caller, expected_revision=0,
                                                    expected_source='0' * 64)):
            with self.assertRaises((execution.ExecutionError, store.RegistryError)):
                operation()
            self.assertFalse(path.exists())

    def test_stop_status_remains_available_when_source_observation_is_unavailable(self):
        execution.provision(self.root, self.caller)
        execution.stop(self.root, self.caller)
        with patch.object(execution, '_source', side_effect=execution.ExecutionError('source_inventory_unavailable')):
            observed = execution.control_status(self.root, self.caller)
        self.assertTrue(observed['stopped'])
        self.assertIsNone(observed['source_fingerprint'])
        self.assertEqual(observed['source_state'], 'unavailable')

    def test_armed_stop_gate_blocks_new_hook_work_but_preserves_observation(self):
        execution.provision(self.root, self.caller)
        edit = {'tool_name': 'Edit', 'tool_input': {'file_path': 'fixture.txt'}}
        self.assertTrue(policy.evaluate_pre_tool(self.root, edit)[0])
        execution.stop(self.root, self.caller)
        allowed, reason = policy.evaluate_pre_tool(self.root, edit)
        self.assertFalse(allowed)
        self.assertIn('execution_stopped', reason)
        self.assertTrue(policy.evaluate_pre_tool(self.root, {
            'tool_name': 'Read', 'tool_input': {'file_path': 'fixture.txt'}})[0])
        self.assertTrue(policy.evaluate_pre_tool(self.root, {
            'tool_name': 'Bash', 'tool_input': {'command': 'getzilla trust status --json'}})[0])
        self.assertTrue(policy.evaluate_pre_tool(self.root, {
            'tool_name': 'Bash', 'tool_input': {'command': 'getzilla trust stop --reason rollback --json'}})[0])
        self.assertFalse(policy.evaluate_pre_tool(self.root, {
            'tool_name': 'Bash', 'tool_input': {'command': 'getzilla trust status --json; echo extra'}})[0])
        self.assertFalse(policy.evaluate_pre_tool(self.root, {'tool_name': 'unknown_client_tool'})[0])

    def test_missing_armed_store_is_denied_before_hook_write_permit(self):
        execution.provision(self.root, self.caller)
        (self.root / store.REGISTRY_PATH).unlink()
        allowed, reason = policy.evaluate_pre_tool(self.root, {
            'tool_name': 'Edit', 'tool_input': {'file_path': 'fixture.txt'}})
        self.assertFalse(allowed)
        self.assertIn('execution_store_unavailable', reason)

    def test_missing_canonical_binding_cannot_downgrade_armed_task_to_unarmed(self):
        execution.provision(self.root, self.caller)
        canonical = self.root / '.getzilla/runtime/routes' / f'{self.caller.route_id}.json'
        canonical.unlink()
        allowed, reason = policy.evaluate_pre_tool(self.root, {
            'tool_name': 'Edit', 'tool_input': {'file_path': 'fixture.txt'}})
        self.assertFalse(allowed)
        self.assertIn('execution_store_unavailable', reason)

    def test_handoff_preserves_required_generation_and_stopped_control(self):
        execution.provision(self.root, self.caller)
        execution.stop(self.root, self.caller)
        before = state.require_route_owner(self.root)
        moved = continuity.submit(self.root, '', 'next-owner', continue_route=before['route_id'],
                                  expected_epoch=before['authority_epoch'], expected_revision=before['state_revision'],
                                  request_id='fixture-handoff')
        self.assertEqual(moved['execution_store_required'], before['execution_store_required'])
        current = execution.trusted_caller(self.root)
        self.assertTrue(execution.control_status(self.root, current)['stopped'])
        with self.assertRaises(execution.ExecutionError):
            execution.stop(self.root, self.caller)

    def test_recovery_source_binding_changes_with_unacknowledged_task_context(self):
        execution.provision(self.root, self.caller)
        execution.stop(self.root, self.caller)
        before = execution.control_status(self.root, self.caller)
        continuity.submit(self.root, 'Also correct a second typo.', 'owner')
        after = execution.control_status(self.root, self.caller)
        self.assertNotEqual(after['source_fingerprint'], before['source_fingerprint'])
        self.assertEqual(after['control_revision'], before['control_revision'])
        with self.assertRaises(execution.ExecutionError):
            execution.recover(self.root, self.caller, expected_revision=after['control_revision'],
                              expected_source=after['source_fingerprint'])

    def test_published_v2_schema_accepts_real_records_and_rejects_unknown_authority(self):
        import copy
        import jsonschema
        execution.provision(self.root, self.caller)
        execution.submit(self.root, self.caller, self.request, backend=CountingBackend())
        value = store.load_registry(self.root)
        schema_path = Path(__file__).resolve().parents[1] / 'schemas/execution-registry.v2.schema.json'
        schema = json.loads(schema_path.read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.validate(value, schema)
        invalid = copy.deepcopy(value)
        next(iter(invalid['records'].values()))['trusted_principal'] = 'self-labelled'
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(invalid, schema)
        invalid = copy.deepcopy(value)
        next(iter(invalid['controls'].values()))['stopped'] = 'false'
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(invalid, schema)


if __name__ == '__main__':
    unittest.main()


class ExecutionControlCliTests(unittest.TestCase):
    def test_real_cli_provisions_stops_and_recovers_only_its_fixture(self):
        session = '01a1a6ba-10e8-7bc1-81b1-684978be3580'
        script = Path(__file__).resolve().parents[1] / 'scripts/getzilla_trust.py'
        with tempfile.TemporaryDirectory() as name, patch.dict(os.environ, {'GETZILLA_SESSION_ID': session}):
            root = Path(name)
            owned_route(root, session=session, provision=False)
            self.addCleanup(state.bind_session, None)
            def invoke(*arguments):
                return subprocess.run([sys.executable, str(script), *arguments, '--json'], cwd=root,
                                      capture_output=True, text=True, timeout=15)
            provisioned = invoke('provision')
            self.assertEqual(provisioned.returncode, 0, provisioned.stdout)
            self.assertEqual(json.loads(provisioned.stdout)['status'], 'provisioned')
            stopped = invoke('stop')
            self.assertEqual(stopped.returncode, 0, stopped.stdout)
            self.assertTrue(json.loads(stopped.stdout)['stopped'])
            status = invoke('status')
            observed = json.loads(status.stdout)
            recovered = invoke('recover', '--expected-revision', str(observed['control_revision']),
                               '--expected-source', observed['source_fingerprint'])
            self.assertEqual(recovered.returncode, 0, recovered.stdout)
            self.assertFalse(json.loads(recovered.stdout)['stopped'])
