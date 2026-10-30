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
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import model_continuation_state as journal
from tests.test_model_continuation import enabled_policy


def _start_then_exit(root, binding, pipe):
    from getzilla.codex_continuation import initialize, start_offline_container

    async def run():
        peer = await start_offline_container(Path(root), binding, 1, 1)
        await initialize(peer)
        pipe.send(peer._revision)
        os._exit(0)

    asyncio.run(run())


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
            result = journal.record_native_container(root, binding, 1, 1, 'd' * 64, 'e' * 64, 'f' * 32)
            self.assertEqual(result['state'], 'container_recorded')
            self.assertFalse(result['dispatch_permitted'])
            recovered = journal.inspect_native_container(root, binding, result['revision'], 1)
            self.assertEqual(recovered['container_id'], 'd' * 64)
            self.assertEqual(recovered['image_id'], 'e' * 64)
            self.assertEqual(recovered['owner_nonce'], 'f' * 32)
            self.assertFalse(recovered['dispatch_permitted'])
            self.assertEqual(journal.record_native_container(root, binding, 1, 1, 'd' * 64, 'e' * 64, 'f' * 32), result)
            self.assertNotEqual(journal.record_native_container(root, binding, 1, 1, '1' * 64, 'e' * 64, 'f' * 32), result)

    def test_mismatched_checkpoint_and_corrupt_identity_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(journal.time, 'time', return_value=1000):
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps(enabled_policy()), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a' * 64, 'b' * 64, 'c' * 64)
            journal.create_chain(root, binding, journal.Usage(1, '0.1'), journal.TaskBudget(2, 4, '1.5', 2000))
            journal.record_native_container(root, binding, 1, 1, 'd' * 64, 'e' * 64, 'f' * 32)
            denied = journal.record_native_checkpoint(root, binding, 1, 2, '1' * 64, '2' * 64)
            self.assertEqual(denied['reason'], 'container_mismatch')
            recorded = journal.record_native_checkpoint(root, binding, 1, 2, 'd' * 64, '2' * 64)
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
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps(enabled_policy()), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a' * 64, 'b' * 64, 'c' * 64)
            journal.create_chain(root, binding, journal.Usage(1, '0.1'), journal.TaskBudget(2, 4, '1.5', int(time.time()) + 60))

            async def run():
                peer = await start_offline_container(root, binding, 1, 1)
                await initialize(peer)
                ident = peer._record['container_id']
                controlled_fixture._command([docker, 'exec', '-d', ident, '/bin/sh', '-c', 'sleep 300 & wait'])
                self.assertIn('sleep 300', controlled_fixture._command([docker, 'top', ident]))
                stopped = await peer.close()
                self.assertFalse(stopped['dispatch_permitted'])
                with self.assertRaises(controlled_fixture.FixtureError):
                    controlled_fixture._command([docker, 'top', ident])
                recovered = native_container.recover(root, binding, 1, stopped['revision'])
                self.assertEqual(recovered['state'], 'container_stopped')
                self.assertFalse(recovered['dispatch_permitted'])
                native_container.cleanup(root, binding, 1, stopped['revision'])

            asyncio.run(run())

    @unittest.skipUnless(os.environ.get('GETZILLA_RUN_NATIVE_CONTAINER') == '1', 'requires local Docker and pinned Codex')
    def test_coordinator_crash_recovers_owned_container_without_replay(self):
        from getzilla import native_container
        with tempfile.TemporaryDirectory() as directory:
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
            self.assertTrue(receive.poll(60), 'native peer did not initialize')
            revision = receive.recv()
            process.join(10)
            self.assertEqual(process.exitcode, 0)
            recovered = native_container.recover(root, binding, 1, revision)
            self.assertFalse(recovered['dispatch_permitted'])
            self.assertEqual(recovered['state'], 'container_stopped')
            self.assertEqual(native_container.recover(root, binding, 1, recovered['revision']), recovered)
            self.assertEqual(len(journal.inspect_chain(root, binding)['attempts']), 1)
            native_container.cleanup(root, binding, 1, recovered['revision'])
