from __future__ import annotations

import json
import asyncio
import multiprocessing
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import model_continuation_state as journal
from tests.test_model_continuation import enabled_policy


@contextmanager
def _docker_root():
    directory = tempfile.mkdtemp(prefix='getzilla-native-test-')
    try:
        yield directory
    except BaseException:
        print('Test journal retained for resource reconciliation:', directory, file=sys.stderr)
        raise
    else:
        shutil.rmtree(directory)


def _start_then_exit(root, binding, pipe):
    from getzilla.codex_continuation import initialize, start_offline_container

    async def run():
        peer = await start_offline_container(Path(root), binding, 1, 1)
        await initialize(peer)
        pipe.send(peer._revision)
        os._exit(0)

    asyncio.run(run())


def _hold_operation(root, pipe):
    from getzilla import native_container
    with native_container._operation(Path(root)):
        pipe.send('locked')
        pipe.recv()


def _test_volumes(docker, nonce):
    from getzilla import controlled_fixture, native_container
    result = {}
    for name in native_container._volumes(nonce):
        value = json.loads(controlled_fixture._command([docker, 'volume', 'inspect', name]))
        assert len(value) == 1 and value[0]['Name'] == name
        assert value[0]['Labels']['getzilla.owner'] == nonce
        result[name] = value[0]
    return result


def _remove_test_volumes(docker, snapshots):
    from getzilla import controlled_fixture
    for name, before in snapshots.items():
        current = json.loads(controlled_fixture._command([docker, 'volume', 'inspect', name]))
        assert current == [before]
        users = controlled_fixture._command([docker, 'ps', '-a', '--no-trunc', '--filter', 'volume=' + name,
                                             '--format', '{{.ID}}'])
        assert not users
        controlled_fixture._command([docker, 'volume', 'rm', name])


class NativeContainerJournalTest(unittest.TestCase):
    def test_bounded_lock_contention_denies_then_allows_read(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(journal.time, 'time', return_value=1000):
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps(enabled_policy()), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a' * 64, 'b' * 64, 'c' * 64)
            journal.create_chain(root, binding, journal.Usage(1, '0.1'), journal.TaskBudget(2, 4, '1.5', 2000))
            locked, release = threading.Event(), threading.Event()

            def hold():
                with journal._store(root):
                    locked.set()
                    release.wait(5)

            thread = threading.Thread(target=hold)
            thread.start()
            try:
                self.assertTrue(locked.wait(2))
                with self.assertRaisesRegex(journal.JournalError, 'lock_busy'):
                    journal.inspect_chain(root, binding)
            finally:
                release.set()
                thread.join(5)
            self.assertFalse(thread.is_alive())
            first = journal.inspect_chain(root, binding)
            self.assertEqual(journal.inspect_chain(root, binding), first)
            self.assertEqual(first['revision'], 1)

    def test_identity_is_recorded_before_start_and_recovered_without_dispatch(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(journal.time, 'time', return_value=1000):
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps(enabled_policy()), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a' * 64, 'b' * 64, 'c' * 64)
            journal.create_chain(root, binding, journal.Usage(1, '0.1'), journal.TaskBudget(2, 4, '1.5', 2000))
            claim = journal.claim_native_start(root, binding, 1, 1, 'f' * 32)
            result = journal.record_native_container(root, binding, 1, claim['revision'], 'd' * 64, 'e' * 64, 'f' * 32)
            self.assertEqual(result['state'], 'container_recorded')
            self.assertFalse(result['dispatch_permitted'])
            recovered = journal.inspect_native_container(root, binding, result['revision'], 1)
            self.assertEqual(recovered['container_id'], 'd' * 64)
            self.assertEqual(recovered['image_id'], 'e' * 64)
            self.assertEqual(recovered['owner_nonce'], 'f' * 32)
            self.assertFalse(recovered['dispatch_permitted'])
            self.assertEqual(journal.record_native_container(root, binding, 1, claim['revision'], 'd' * 64, 'e' * 64, 'f' * 32), result)
            self.assertNotEqual(journal.record_native_container(root, binding, 1, claim['revision'], '1' * 64, 'e' * 64, 'f' * 32), result)

    def test_durable_start_intent_is_single_claim_before_resources(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(journal.time, 'time', return_value=1000):
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps(enabled_policy()), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a' * 64, 'b' * 64, 'c' * 64)
            journal.create_chain(root, binding, journal.Usage(1, '0.1'), journal.TaskBudget(2, 4, '1.5', 2000))
            claimed = journal.claim_native_start(root, binding, 1, 1, 'f' * 32)
            self.assertTrue(claimed['claimed'])
            self.assertFalse(claimed['dispatch_permitted'])
            duplicate = journal.claim_native_start(root, binding, 1, claimed['revision'], 'e' * 32)
            self.assertFalse(duplicate['claimed'])
            self.assertEqual(journal.inspect_native_intent(root, binding, 1)['owner_nonce'], 'f' * 32)

    def test_concurrent_native_start_has_one_durable_claim(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(journal.time, 'time', return_value=1000):
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps(enabled_policy()), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a' * 64, 'b' * 64, 'c' * 64)
            journal.create_chain(root, binding, journal.Usage(1, '0.1'), journal.TaskBudget(2, 4, '1.5', 2000))
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda nonce: journal.claim_native_start(root, binding, 1, 1, nonce), ['d' * 32, 'e' * 32]))
            self.assertEqual(sum(result['claimed'] for result in results), 1)
            self.assertTrue(all(not result['dispatch_permitted'] for result in results))

    def test_failed_start_cannot_create_resources_again(self):
        from getzilla import native_container
        from getzilla.codex_continuation import ProtocolError
        import hashlib
        with tempfile.TemporaryDirectory() as directory, patch.object(journal.time, 'time', return_value=1000):
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps(enabled_policy()), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a' * 64, 'b' * 64, 'c' * 64)
            journal.create_chain(root, binding, journal.Usage(1, '0.1'), journal.TaskBudget(2, 4, '1.5', 2000))
            executable = root / 'fake-codex'
            executable.write_bytes(b'native-test-input')
            digest = hashlib.sha256(executable.read_bytes()).hexdigest()
            with patch.object(native_container, '_docker', return_value='/usr/bin/docker'), \
                 patch.object(native_container.shutil, 'which', return_value=str(executable)), \
                 patch.object(native_container.fixture, 'CODEX_SHA256', digest), \
                 patch.object(native_container, '_build', side_effect=RuntimeError('interrupted')) as build:
                with self.assertRaisesRegex(RuntimeError, 'interrupted'):
                    asyncio.run(native_container.start(root, binding, 1, 1))
                with self.assertRaisesRegex(ProtocolError, 'journal_denied'):
                    asyncio.run(native_container.start(root, binding, 1, 1))
                self.assertEqual(build.call_count, 1)
            self.assertEqual(journal.inspect_native_intent(root, binding, 1)['revision'], 2)

    def test_cleanup_cannot_race_active_allocator(self):
        from getzilla import native_container
        from getzilla.codex_continuation import ProtocolError
        import hashlib
        with tempfile.TemporaryDirectory() as directory, patch.object(journal.time, 'time', return_value=1000):
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps(enabled_policy()), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a' * 64, 'b' * 64, 'c' * 64)
            journal.create_chain(root, binding, journal.Usage(1, '0.1'), journal.TaskBudget(2, 4, '1.5', 2000))
            executable = root / 'fake-codex'
            executable.write_bytes(b'native-test-input')
            entered, release = threading.Event(), threading.Event()

            def paused_build(*args):
                entered.set()
                release.wait(5)
                raise RuntimeError('interrupted')

            def run():
                try:
                    asyncio.run(native_container.start(root, binding, 1, 1))
                except RuntimeError:
                    pass

            with patch.object(native_container, '_docker', return_value='/usr/bin/docker'), \
                 patch.object(native_container.shutil, 'which', return_value=str(executable)), \
                 patch.object(native_container.fixture, 'CODEX_SHA256', hashlib.sha256(executable.read_bytes()).hexdigest()), \
                 patch.object(native_container, '_build', side_effect=paused_build), \
                 patch.object(native_container.fixture, '_command', return_value=''):
                thread = threading.Thread(target=run)
                thread.start()
                try:
                    self.assertTrue(entered.wait(3))
                    with self.assertRaisesRegex(ProtocolError, 'native_busy'):
                        native_container.cleanup(root, binding, 1, 2)
                finally:
                    release.set()
                    thread.join(5)

    def test_operation_lock_survives_process_contention_and_releases_after_crash(self):
        from getzilla import native_container
        from getzilla.codex_continuation import ProtocolError
        with tempfile.TemporaryDirectory() as directory, patch.object(journal.time, 'time', return_value=1000):
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps(enabled_policy()), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a' * 64, 'b' * 64, 'c' * 64)
            journal.create_chain(root, binding, journal.Usage(1, '0.1'), journal.TaskBudget(2, 4, '1.5', 2000))
            claim = journal.claim_native_start(root, binding, 1, 1, 'f' * 32)
            context = multiprocessing.get_context('spawn')
            parent, child = context.Pipe()
            process = context.Process(target=_hold_operation, args=(str(root), child))
            process.start()
            try:
                self.assertTrue(parent.poll(10))
                self.assertEqual(parent.recv(), 'locked')
                with self.assertRaisesRegex(ProtocolError, 'native_busy'):
                    native_container.cleanup(root, binding, 1, claim['revision'])
            finally:
                process.terminate()
                process.join(10)
            with patch.object(native_container, '_docker', return_value='/usr/bin/docker'), \
                 patch.object(native_container.fixture, '_command', return_value='') as command:
                with self.assertRaisesRegex(ProtocolError, 'operation_unknown'):
                    native_container.cleanup(root, binding, 1, claim['revision'])
                command.assert_not_called()
            state = journal.inspect_chain(root, binding)
            self.assertNotIn('cleanup_1', state['events'])

    def test_cleanup_removes_only_recorded_image_identity(self):
        from getzilla import native_container
        with tempfile.TemporaryDirectory() as directory, patch.object(journal.time, 'time', return_value=1000):
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps(enabled_policy()), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a' * 64, 'b' * 64, 'c' * 64)
            journal.create_chain(root, binding, journal.Usage(1, '0.1'), journal.TaskBudget(2, 4, '1.5', 2000))
            claim = journal.claim_native_start(root, binding, 1, 1, 'f' * 32)
            identity = journal.record_native_container(root, binding, 1, claim['revision'], 'd' * 64, 'e' * 64, 'f' * 32)
            started = journal.record_native_phase(root, binding, 1, identity['revision'], 'd' * 64, 'started')
            owned, foreign = 'sha256:' + 'e' * 64, 'sha256:' + '1' * 64
            removed = []

            def command(args, timeout=60):
                if args[1:3] == ['image', 'ls']:
                    return owned + '\n' + foreign
                if args[1:3] == ['image', 'inspect']:
                    return json.dumps([{'Id': owned, 'Config': {'Labels': {'getzilla.owner': 'f' * 32}}}])
                if args[1:3] == ['image', 'rm']:
                    removed.append(args[3])
                return ''

            with patch.object(native_container, '_docker', return_value='/usr/bin/docker'), \
                 patch.object(native_container.fixture, '_command', side_effect=command):
                native_container.cleanup(root, binding, 1, started['revision'])
            self.assertEqual(removed, [owned])

    def test_cleanup_refuses_unrecorded_helper_identity(self):
        from getzilla import native_container
        from getzilla.codex_continuation import ProtocolError
        with tempfile.TemporaryDirectory() as directory, patch.object(journal.time, 'time', return_value=1000):
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps(enabled_policy()), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a' * 64, 'b' * 64, 'c' * 64)
            journal.create_chain(root, binding, journal.Usage(1, '0.1'), journal.TaskBudget(2, 4, '1.5', 2000))
            claim = journal.claim_native_start(root, binding, 1, 1, 'f' * 32)
            identity = journal.record_native_container(root, binding, 1, claim['revision'], 'd' * 64, 'e' * 64, 'f' * 32)
            started = journal.record_native_phase(root, binding, 1, identity['revision'], 'd' * 64, 'started')
            calls = []

            def command(args, timeout=60):
                calls.append(args)
                return '1' * 64 if args[1:3] == ['ps', '-a'] else ''

            with patch.object(native_container, '_docker', return_value='/usr/bin/docker'), \
                 patch.object(native_container.fixture, '_command', side_effect=command):
                with self.assertRaisesRegex(ProtocolError, 'resource_identity_unknown'):
                    native_container.cleanup(root, binding, 1, started['revision'])
            self.assertFalse(any(args[1:3] == ['rm', '-f'] for args in calls))

    def test_interrupted_checkpoint_is_never_replayed_or_cleaned(self):
        from getzilla import native_container
        from getzilla.codex_continuation import ProtocolError
        with tempfile.TemporaryDirectory() as directory, patch.object(journal.time, 'time', return_value=1000):
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps(enabled_policy()), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a' * 64, 'b' * 64, 'c' * 64)
            journal.create_chain(root, binding, journal.Usage(1, '0.1'), journal.TaskBudget(2, 4, '1.5', 2000))
            claim = journal.claim_native_start(root, binding, 1, 1, 'f' * 32)
            identity = journal.record_native_container(root, binding, 1, claim['revision'], 'd' * 64, 'e' * 64, 'f' * 32)
            started = journal.record_native_phase(root, binding, 1, identity['revision'], 'd' * 64, 'started')
            pending = journal.record_native_phase(root, binding, 1, started['revision'], 'd' * 64, 'checkpoint_start')
            with patch.object(native_container, '_docker', return_value='/usr/bin/docker'), \
                 patch.object(native_container.fixture, '_command', return_value='') as command:
                with self.assertRaisesRegex(ProtocolError, 'operation_unknown'):
                    native_container.recover(root, binding, 1, pending['revision'])
                with self.assertRaisesRegex(ProtocolError, 'operation_unknown'):
                    native_container.cleanup(root, binding, 1, pending['revision'])
                command.assert_not_called()

    def test_mismatched_checkpoint_and_corrupt_identity_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(journal.time, 'time', return_value=1000):
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps(enabled_policy()), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a' * 64, 'b' * 64, 'c' * 64)
            journal.create_chain(root, binding, journal.Usage(1, '0.1'), journal.TaskBudget(2, 4, '1.5', 2000))
            claim = journal.claim_native_start(root, binding, 1, 1, 'f' * 32)
            identity = journal.record_native_container(root, binding, 1, claim['revision'], 'd' * 64, 'e' * 64, 'f' * 32)
            started = journal.record_native_phase(root, binding, 1, identity['revision'], 'd' * 64, 'started')
            pending = journal.record_native_phase(root, binding, 1, started['revision'], 'd' * 64, 'checkpoint_start')
            denied = journal.record_native_checkpoint(root, binding, 1, pending['revision'], '1' * 64, '2' * 64)
            self.assertEqual(denied['reason'], 'container_mismatch')
            recorded = journal.record_native_checkpoint(root, binding, 1, pending['revision'], 'd' * 64, '2' * 64)
            self.assertFalse(recorded['dispatch_permitted'])
            path = root / '.getzilla/runtime/model-continuation/journal.json'
            value = json.loads(path.read_text(encoding='utf-8'))
            event = value['chains']['chain1']['events']['checkpoint_1']
            event['evidence']['container_id'] = '1' * 64
            event['digest'] = journal._digest(['native_checkpoint_v1', 1, '1' * 64, '2' * 64])
            value['checksum'] = journal._digest(value['chains'])
            path.write_text(json.dumps(value), encoding='utf-8')
            with self.assertRaisesRegex(journal.JournalError, 'journal_corrupt'):
                journal.inspect_chain(root, binding)

    @unittest.skipUnless(os.environ.get('GETZILLA_RUN_NATIVE_CONTAINER') == '1', 'requires local Docker and pinned Codex')
    def test_real_codex_container_stop_and_recovery(self):
        from getzilla import controlled_fixture, native_container
        from getzilla.codex_continuation import initialize, start_offline_container

        docker = shutil.which('docker', path='/usr/bin:/bin')
        codex = shutil.which('codex')
        self.assertIsNotNone(docker)
        self.assertIsNotNone(codex)
        with _docker_root() as directory:
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps(enabled_policy()), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a' * 64, 'b' * 64, 'c' * 64)
            journal.create_chain(root, binding, journal.Usage(1, '0.1'), journal.TaskBudget(2, 4, '1.5', int(time.time()) + 600))

            async def run():
                peer = await start_offline_container(root, binding, 1, 1)
                await initialize(peer)
                ident = peer._record['container_id']
                controlled_fixture._command([docker, 'exec', '-d', ident, '/bin/sh', '-c', 'sleep 300 & wait'])
                self.assertIn('sleep 300', controlled_fixture._command([docker, 'top', ident]))
                terminal = journal.record_terminal(root, binding, 1, 'terminal1', 'unknown')
                self.assertEqual(terminal['state'], 'terminal_unknown')
                stopped = await peer.close()
                self.assertEqual(stopped['state'], 'checkpoint_recorded')
                self.assertFalse(stopped['dispatch_permitted'])
                with self.assertRaises(controlled_fixture.FixtureError):
                    controlled_fixture._command([docker, 'top', ident])
                recovered = native_container.recover(root, binding, 1, stopped['revision'])
                self.assertEqual(recovered['state'], 'container_stopped')
                self.assertFalse(recovered['dispatch_permitted'])
                record = journal.inspect_native_container(root, binding, stopped['revision'], 1)
                snapshots = _test_volumes(docker, record['owner_nonce'])
                native_container._helper(docker, 'sha256:' + record['image_id'], native_container._volumes(record['owner_nonce']),
                                         record['owner_nonce'], "import os; os.chown('/work',0,0); open('/work/changed', 'w').write('changed')", root=True)
                with self.assertRaisesRegex(native_container.ProtocolError, 'checkpoint_changed'):
                    native_container.recover(root, binding, 1, stopped['revision'])
                original = controlled_fixture._command
                failed = False

                def fail_once(args, timeout=60):
                    nonlocal failed
                    if not failed and args[1:3] == ['image', 'rm']:
                        failed = True
                        raise controlled_fixture.FixtureError('injected_failure')
                    return original(args, timeout=timeout)

                with patch.object(controlled_fixture, '_command', side_effect=fail_once):
                    with self.assertRaises(controlled_fixture.FixtureError):
                        native_container.cleanup(root, binding, 1, stopped['revision'])
                self.assertTrue(failed)
                with self.assertRaisesRegex(native_container.ProtocolError, 'manual_volume_cleanup_required'):
                    native_container.cleanup(root, binding, 1, stopped['revision'])
                with self.assertRaisesRegex(native_container.ProtocolError, 'manual_volume_cleanup_required'):
                    native_container.cleanup(root, binding, 1, stopped['revision'])
                _remove_test_volumes(docker, snapshots)
                native_container.cleanup(root, binding, 1, stopped['revision'])

            try:
                asyncio.run(run())
            finally:
                try:
                    intent = journal.inspect_native_intent(root, binding, 1)
                except journal.JournalError:
                    pass
                else:
                    try:
                        native_container.cleanup(root, binding, 1, intent['revision'])
                    except native_container.ProtocolError as error:
                        if str(error) != 'manual_volume_cleanup_required':
                            raise

    @unittest.skipUnless(os.environ.get('GETZILLA_RUN_NATIVE_CONTAINER') == '1', 'requires local Docker and pinned Codex')
    def test_coordinator_crash_recovers_owned_container_without_replay(self):
        from getzilla import native_container
        with _docker_root() as directory:
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps(enabled_policy()), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a' * 64, 'b' * 64, 'c' * 64)
            journal.create_chain(root, binding, journal.Usage(1, '0.1'), journal.TaskBudget(2, 4, '1.5', int(time.time()) + 120))
            context = multiprocessing.get_context('spawn')
            receive, send = context.Pipe(duplex=False)
            process = context.Process(target=_start_then_exit, args=(str(root), binding, send))
            process.start()
            try:
                self.assertTrue(receive.poll(110), 'native peer did not initialize within policy ceiling')
                revision = receive.recv()
            finally:
                process.join(180)
            self.assertEqual(process.exitcode, 0)
            recovered = native_container.recover(root, binding, 1, revision)
            self.assertFalse(recovered['dispatch_permitted'])
            self.assertEqual(recovered['state'], 'container_stopped')
            self.assertEqual(native_container.recover(root, binding, 1, recovered['revision']), recovered)
            self.assertEqual(len(journal.inspect_chain(root, binding)['attempts']), 1)
            record = journal.inspect_native_container(root, binding, recovered['revision'], 1)
            snapshots = _test_volumes(native_container._docker(), record['owner_nonce'])
            with self.assertRaisesRegex(native_container.ProtocolError, 'manual_volume_cleanup_required'):
                native_container.cleanup(root, binding, 1, recovered['revision'])
            _remove_test_volumes(native_container._docker(), snapshots)
            native_container.cleanup(root, binding, 1, recovered['revision'])

    @unittest.skipUnless(os.environ.get('GETZILLA_RUN_NATIVE_CONTAINER') == '1', 'requires local Docker and pinned Codex')
    def test_interrupted_image_build_is_owned_and_cleanup_is_repeatable(self):
        from getzilla import native_container
        with _docker_root() as directory:
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps(enabled_policy()), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a' * 64, 'b' * 64, 'c' * 64)
            journal.create_chain(root, binding, journal.Usage(1, '0.1'), journal.TaskBudget(2, 4, '1.5', int(time.time()) + 120))
            original = native_container._build
            built = []

            def interrupted(*args):
                built.append(original(*args))
                raise RuntimeError('interrupted')

            with patch.object(native_container, '_build', side_effect=interrupted):
                with self.assertRaisesRegex(RuntimeError, 'interrupted'):
                    asyncio.run(native_container.start(root, binding, 1, 1))
            intent = journal.inspect_native_intent(root, binding, 1)
            self.assertFalse(intent['dispatch_permitted'])
            with self.assertRaisesRegex(native_container.ProtocolError, 'operation_unknown'):
                native_container.cleanup(root, binding, 1, intent['revision'])
            from getzilla import controlled_fixture
            docker = native_container._docker()
            details = json.loads(controlled_fixture._command([docker, 'image', 'inspect', built[0]]))
            self.assertEqual(details[0]['Id'], built[0])
            self.assertEqual(details[0]['Config']['Labels']['getzilla.owner'], intent['owner_nonce'])
            controlled_fixture._command([docker, 'image', 'rm', built[0]])

    @unittest.skipUnless(os.environ.get('GETZILLA_RUN_NATIVE_CONTAINER') == '1', 'requires local Docker and pinned Codex')
    def test_cleanup_preserves_foreign_container_with_inherited_image_label(self):
        from getzilla import controlled_fixture, native_container
        from getzilla.codex_continuation import initialize, start_offline_container
        docker = native_container._docker()
        with _docker_root() as directory:
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps(enabled_policy()), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a' * 64, 'b' * 64, 'c' * 64)
            journal.create_chain(root, binding, journal.Usage(1, '0.1'), journal.TaskBudget(2, 4, '1.5', int(time.time()) + 120))

            async def run():
                peer = await start_offline_container(root, binding, 1, 1)
                await initialize(peer)
                record = peer._record
                snapshots = _test_volumes(docker, record['owner_nonce'])
                foreign = controlled_fixture._command([docker, 'create', '--network', 'none', 'sha256:' + record['image_id']])
                try:
                    with self.assertRaises(controlled_fixture.FixtureError):
                        native_container.cleanup(root, binding, 1, peer._revision)
                    details = native_container.fence._inspect(docker, foreign)
                    self.assertEqual(details['Id'], foreign)
                finally:
                    controlled_fixture._command([docker, 'rm', '-f', foreign])
                    peer._process._transport.close()
                    intent = journal.inspect_native_intent(root, binding, 1)
                    with self.assertRaisesRegex(native_container.ProtocolError, 'manual_volume_cleanup_required'):
                        native_container.cleanup(root, binding, 1, intent['revision'])
                    _remove_test_volumes(docker, snapshots)
                    native_container.cleanup(root, binding, 1, intent['revision'])

            asyncio.run(run())

    @unittest.skipUnless(os.environ.get('GETZILLA_RUN_NATIVE_CONTAINER') == '1', 'requires local Docker and pinned Codex')
    def test_private_checkout_mode_builds_readable_verified_image(self):
        from getzilla import native_container
        docker = native_container._docker()
        codex = Path(shutil.which('codex')).resolve()
        with _docker_root() as directory:
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps(enabled_policy()), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a' * 64, 'b' * 64, 'c' * 64)
            journal.create_chain(root, binding, journal.Usage(1, '0.1'), journal.TaskBudget(2, 4, '1.5', int(time.time()) + 120))
            nonce = 'f' * 32
            claim = journal.claim_native_start(root, binding, 1, 1, nonce)
            script = root / 'fixture.py'
            shutil.copyfile(ROOT / 'tests/fixtures/codex_loopback_probe.py', script)
            script.chmod(0o600)
            try:
                image = native_container._build(docker, codex, script, nonce)
                self.assertTrue(image.startswith('sha256:'))
            finally:
                with self.assertRaisesRegex(native_container.ProtocolError, 'operation_unknown'):
                    native_container.cleanup(root, binding, 1, claim['revision'])
                from getzilla import controlled_fixture
                details = json.loads(controlled_fixture._command([docker, 'image', 'inspect', image]))
                self.assertEqual(details[0]['Id'], image)
                self.assertEqual(details[0]['Config']['Labels']['getzilla.owner'], nonce)
                controlled_fixture._command([docker, 'image', 'rm', image])
