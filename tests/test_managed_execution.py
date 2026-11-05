"""Real local children in disposable workspaces; no provider or deployed state."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from getzilla import execution, execution_store as store, state
from tests.test_execution import owned_route


@unittest.skipUnless(hasattr(os, 'pidfd_open'), 'Linux owned pidfd launch is required')
class ManagedExecutionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir='/tmp')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        session = '01a1a6ba-10e8-7bc1-81b1-684978be3580'
        environment = patch.dict(os.environ, {'GETZILLA_SESSION_ID': session})
        environment.start()
        self.addCleanup(environment.stop)
        self.addCleanup(state.bind_session, None)
        config = self.root / '.getzilla/config'
        config.mkdir(parents=True)
        (config / 'policy.json').write_text('{}')
        (config / 'policy.json').chmod(0o644)
        owned_route(self.root, session=session)
        self.caller = execution.trusted_caller(self.root)

    def configure(self, program, arguments):
        binary = self.root / 'bin' / Path(program).name
        binary.parent.mkdir(mode=0o700, exist_ok=True)
        shutil.copyfile(program, binary)
        binary.chmod(0o755)
        self.config = {'schema_version': 1, 'tools': [{'id': 'python3', 'commands': [binary.name],
                       'managed': {'executable': str(binary),
                                   'sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                                   'argv': arguments}}]}
        (self.root / '.getzilla/config/toolchain.json').write_text(json.dumps(self.config))
        (self.root / '.getzilla/config/toolchain.json').chmod(0o644)
        return binary

    def run_tool(self, *, timeout=5):
        from getzilla.managed_execution import run
        return run(self.root, self.caller, tool_id='python3', intent_key='managed-fixture',
                   hard_timeout_seconds=timeout)

    def test_default_disabled_and_unpinned_tool_never_dispatches(self):
        from getzilla.managed_execution import run
        with self.assertRaises(execution.ExecutionError):
            run(self.root, self.caller, tool_id='python3', intent_key='disabled', hard_timeout_seconds=5)
        self.assertEqual(store.load_registry(self.root)['records'], {})

    def test_real_pinned_binary_completes_in_existing_attempt(self):
        self.configure('/usr/bin/true', [])
        result = self.run_tool()
        self.assertEqual(result['execution_status'], 'succeeded')
        self.assertEqual(result['cleanup_status'], 'confirmed')
        self.assertEqual(result['launch']['phase'], 'finished')
        self.assertEqual(len(store.load_registry(self.root)['records']), 1)

    def test_changed_executable_refuses_before_attempt_or_effect(self):
        binary = self.configure('/usr/bin/true', [])
        binary.write_bytes(b'compromised fixture, never executable')
        with self.assertRaises(execution.ExecutionError):
            self.run_tool()
        self.assertEqual(store.load_registry(self.root)['records'], {})

    def test_child_receives_only_explicit_environment(self):
        self.configure('/usr/bin/env', [])
        with patch.dict(os.environ, {'SYNTHETIC_PRIVATE_TEST_TOKEN': 'must-not-reach-child'}):
            result = self.run_tool()
        self.assertEqual(result['execution_status'], 'succeeded')
        output = result['output']['preview']
        self.assertNotIn('SYNTHETIC_PRIVATE_TEST_TOKEN', output)
        self.assertNotIn('must-not-reach-child', output)
        self.assertNotIn('GETZILLA_SESSION_ID', output)
        self.assertIn('LANG=C', output)

    def test_stop_before_gate_release_prevents_effect(self):
        marker = self.root / 'effect-marker'
        self.configure('/usr/bin/touch', [str(marker)])
        reached, release = threading.Event(), threading.Event()
        original = execution._register_managed
        def register(*arguments, **keywords):
            result = original(*arguments, **keywords)
            reached.set()
            if not release.wait(5):
                raise RuntimeError('test barrier timeout')
            return result
        results, failures = [], []
        def runner():
            try:
                results.append(self.run_tool())
            except Exception as error:
                failures.append(type(error).__name__)
        with patch.object(execution, '_register_managed', side_effect=register):
            worker = threading.Thread(target=runner)
            worker.start()
            try:
                self.assertTrue(reached.wait(5))
                self.assertFalse(marker.exists())
                execution.stop(self.root, self.caller)
            finally:
                release.set()
                worker.join(8)
        self.assertFalse(worker.is_alive())
        self.assertEqual(failures, [])
        self.assertFalse(marker.exists())
        self.assertEqual(results[0]['execution_status'], 'cancelled')
        self.assertEqual(results[0]['cleanup_status'], 'confirmed')

    def test_stop_interrupts_owned_running_group_and_confirms_cleanup(self):
        self.configure('/usr/bin/sleep', ['20'])
        results, failures = [], []
        def runner():
            try:
                results.append(self.run_tool(timeout=30))
            except Exception as error:
                failures.append(type(error).__name__)
        worker = threading.Thread(target=runner)
        worker.start()
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                with state.task_transition(self.root):
                    records = store.load_registry(self.root)['records'].values()
                if any((item.get('launch') or {}).get('phase') == 'released' for item in records):
                    break
                time.sleep(.01)
            else:
                self.fail('real child did not reach release: ' + str({
                    'failures': failures, 'results': [
                        (item['execution_status'], item['terminal_reason'], item['observation_status']) for item in results]}))
            stopped = execution.stop(self.root, self.caller)
            self.assertEqual(stopped['unconfirmed_attempts'], 1)
        finally:
            execution.stop(self.root, self.caller)
            worker.join(8)
        self.assertFalse(worker.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(results[0]['execution_status'], 'cancelled')
        self.assertEqual(results[0]['cleanup_status'], 'confirmed')
        self.assertEqual(execution.control_status(self.root, self.caller)['unconfirmed_attempts'], 0)

    def test_deadline_terminates_and_records_actual_cleanup(self):
        self.configure('/usr/bin/sleep', ['20'])
        result = self.run_tool(timeout=1)
        self.assertEqual(result['execution_status'], 'timed_out')
        self.assertEqual(result['cleanup_status'], 'confirmed')

    def test_real_cli_runs_one_existing_attempt_and_observes_it(self):
        self.configure('/usr/bin/true', [])
        script = Path(__file__).resolve().parents[1] / 'scripts/getzilla_trust.py'
        result = subprocess.run([sys.executable, str(script), 'run', '--tool', 'python3',
                                 '--intent', 'cli-fixture', '--timeout', '5', '--json'],
                                cwd=self.root, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout)
        view = json.loads(result.stdout)
        self.assertEqual(view['execution_status'], 'succeeded')
        observed = subprocess.run([sys.executable, str(script), 'get', view['execution_id'], '--json'],
                                  cwd=self.root, capture_output=True, text=True, timeout=15)
        self.assertEqual(observed.returncode, 0, observed.stdout)
        self.assertEqual(json.loads(observed.stdout)['execution_id'], view['execution_id'])
        self.assertEqual(len(store.load_registry(self.root)['records']), 1)

    def test_private_linked_fifo_and_writable_ancestry_refuse_before_binary_read(self):
        from getzilla import managed_execution
        for kind in ('private', 'hardlink', 'symlink', 'fifo', 'writable-parent'):
            with self.subTest(kind=kind):
                binary = self.configure('/usr/bin/true', [])
                if kind == 'private':
                    binary.chmod(0o600)
                elif kind == 'hardlink':
                    os.link(binary, binary.with_name('alias'))
                elif kind == 'symlink':
                    binary.unlink()
                    binary.symlink_to('/usr/bin/true')
                elif kind == 'fifo':
                    binary.unlink()
                    os.mkfifo(binary, 0o755)
                else:
                    binary.parent.chmod(0o775)
                inode = binary.lstat().st_ino
                original = os.read
                def never_read_private(descriptor, size):
                    self.assertNotEqual(os.fstat(descriptor).st_ino, inode, 'unqualified binary was read')
                    return original(descriptor, size)
                try:
                    with patch.object(managed_execution.os, 'read', side_effect=never_read_private):
                        with self.assertRaises(execution.ExecutionError):
                            self.run_tool()
                    self.assertEqual(store.load_registry(self.root)['records'], {})
                finally:
                    binary.parent.chmod(0o700)
                    binary.unlink()
                    alias = binary.with_name('alias')
                    if alias.exists():
                        alias.unlink()

    def test_output_drain_remains_bounded_and_does_not_starve_deadline(self):
        self.configure('/usr/bin/yes', ['synthetic-output'])
        started = time.monotonic()
        result = self.run_tool(timeout=1)
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(result['execution_status'], 'timed_out')
        self.assertLessEqual(len(result['output']['preview'].encode()), 4096)
        self.assertGreater(result['output']['dropped_bytes'], 0)
        self.assertLessEqual(len(json.dumps(result).encode()), 32768)

    def test_stop_before_late_handle_registration_prevents_effect(self):
        from getzilla import managed_execution
        marker = self.root / 'effect-marker'
        self.configure('/usr/bin/touch', [str(marker)])
        reached, resume = threading.Event(), threading.Event()
        original = managed_execution._spawn
        def spawn(*arguments):
            process = original(*arguments)
            reached.set()
            if not resume.wait(5):
                process.kill()
                process.wait()
                raise RuntimeError('test barrier timeout')
            return process
        results, failures = [], []
        def runner():
            try:
                results.append(self.run_tool())
            except Exception as error:
                failures.append(type(error).__name__)
        with patch.object(managed_execution, '_spawn', side_effect=spawn):
            worker = threading.Thread(target=runner)
            worker.start()
            try:
                self.assertTrue(reached.wait(5))
                execution.stop(self.root, self.caller)
                self.assertFalse(marker.exists())
            finally:
                resume.set()
                worker.join(8)
        self.assertFalse(worker.is_alive())
        self.assertEqual(failures, [])
        self.assertFalse(marker.exists())
        self.assertEqual(results[0]['execution_status'], 'cancelled')
        self.assertEqual(results[0]['cleanup_status'], 'confirmed')

    def test_config_change_after_registration_fences_release_and_never_replays(self):
        marker = self.root / 'effect-marker'
        self.configure('/usr/bin/touch', [str(marker)])
        original = execution._register_managed
        def change(*arguments):
            result = original(*arguments)
            self.config['tools'][0]['managed']['argv'] = [str(self.root / 'other-marker')]
            (self.root / '.getzilla/config/toolchain.json').write_text(json.dumps(self.config))
            return result
        with patch.object(execution, '_register_managed', side_effect=change):
            result = self.run_tool()
        self.assertFalse(marker.exists())
        self.assertFalse((self.root / 'other-marker').exists())
        self.assertEqual(result['execution_status'], 'failed')
        self.assertEqual(result['cleanup_status'], 'confirmed')
        repeated = self.run_tool()
        self.assertEqual(repeated['execution_id'], result['execution_id'])
        self.assertFalse((self.root / 'other-marker').exists())

    def test_registered_publication_lost_ack_kills_gated_child_without_second_spawn(self):
        from getzilla import managed_execution
        marker = self.root / 'effect-marker'
        self.configure('/usr/bin/touch', [str(marker)])
        original = store._publish
        def lose_ack(root, previous, value):
            result = original(root, previous, value)
            if any((item.get('launch') or {}).get('phase') == 'registered' for item in value['records'].values()):
                raise store.RegistryError('registry_persistence_unknown')
            return result
        with patch.object(store, '_publish', side_effect=lose_ack), \
                patch.object(managed_execution, '_spawn', wraps=managed_execution._spawn) as spawned:
            result = self.run_tool()
            repeated = self.run_tool()
        self.assertEqual(spawned.call_count, 1)
        self.assertEqual(repeated['execution_id'], result['execution_id'])
        self.assertFalse(marker.exists())
        self.assertEqual(result['cleanup_status'], 'confirmed')

    def test_missing_registry_during_active_wait_cleans_owned_child_without_recreation(self):
        from getzilla import managed_execution
        self.configure('/usr/bin/sleep', ['20'])
        original = execution._release_managed
        def remove(*arguments):
            result = original(*arguments)
            (self.root / store.REGISTRY_PATH).unlink()
            return result
        with patch.object(execution, '_release_managed', side_effect=remove), \
                patch.object(managed_execution, '_cleanup', wraps=managed_execution._cleanup) as cleanup:
            result = self.run_tool(timeout=30)
        self.assertFalse((self.root / store.REGISTRY_PATH).exists())
        self.assertEqual(cleanup.call_count, 1)
        self.assertIsNotNone(cleanup.call_args.args[0].returncode)
        self.assertEqual(result['execution_status'], 'orphaned')
        self.assertEqual(result['cleanup_status'], 'unconfirmed')

    def test_unrelated_directory_entry_does_not_change_executable_custody(self):
        from getzilla import managed_execution
        binary = self.configure('/usr/bin/true', [])
        inode, changed = binary.stat().st_ino, False
        original = os.read
        def harmless_entry(descriptor, size):
            nonlocal changed
            if not changed and os.fstat(descriptor).st_ino == inode:
                changed = True
                (binary.parent / 'unrelated-public-fixture').write_text('fixture')
            return original(descriptor, size)
        with patch.object(managed_execution.os, 'read', side_effect=harmless_entry):
            result = self.run_tool()
        self.assertTrue(changed)
        self.assertEqual(result['execution_status'], 'succeeded')

    def test_unacknowledged_context_does_not_bypass_native_scope_gate(self):
        from getzilla import continuity
        self.configure('/usr/bin/true', [])
        continuity.submit(self.root, 'Also correct a second typo.', state.current_session())
        with self.assertRaises(execution.ExecutionError):
            self.run_tool()
        self.assertEqual(store.load_registry(self.root)['records'], {})

    def test_initial_policy_snapshot_waits_for_existing_task_transition(self):
        from getzilla import managed_execution
        self.configure('/usr/bin/true', [])
        manifest_read, policy_called = threading.Event(), threading.Event()
        original_tool, original_policy = managed_execution._tool, managed_execution.policy.evaluate_pre_tool
        def tool(*arguments):
            result = original_tool(*arguments)
            manifest_read.set()
            return result
        def observe(*arguments, **keywords):
            policy_called.set()
            return original_policy(*arguments, **keywords)
        results, failures = [], []
        def runner():
            try:
                results.append(self.run_tool())
            except Exception as error:
                failures.append(type(error).__name__)
        with patch.object(managed_execution, '_tool', side_effect=tool), \
                patch.object(managed_execution.policy, 'evaluate_pre_tool', side_effect=observe):
            worker = threading.Thread(target=runner)
            try:
                with state.task_transition(self.root):
                    worker.start()
                    self.assertTrue(manifest_read.wait(5))
                    self.assertFalse(policy_called.wait(.1))
            finally:
                worker.join(8)
        self.assertFalse(worker.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(results[0]['execution_status'], 'succeeded')


if __name__ == '__main__':
    unittest.main()
