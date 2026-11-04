"""Real bounded storage/CAS controls for the local attempt registry."""
from __future__ import annotations

import copy
import hashlib
import multiprocessing
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from getzilla import execution_store as store
from getzilla.resource_inventory import classify, disposable


def record(root, execution_id='a' * 32, intent='b' * 64):
    return {
        'schema_version': 1, 'execution_id': execution_id, 'revision': 1,
        'execution_generation': 'c' * 32,
        'owner': {'workspace': str(root.resolve()), 'project': hashlib.sha256(str(root.resolve()).encode()).hexdigest(),
                  'session_id': 's1', 'route_id': 'r1', 'logical_task_id': 'task:one', 'change_id': None,
                  'authority_epoch': 0, 'principal_kind': 'session', 'principal_id': 's1',
                  'agent_id': None, 'agent_generation': None, 'run_id': None},
        'input': {'intent_digest': intent, 'request_digest': 'd' * 64, 'display': {'label': 'test'}},
        'source': {'git_head': None, 'fingerprint': 'e' * 64, 'dirty': False, 'context_digest': None,
                   'inventory_digest': 'f' * 64, 'evidence_links': []},
        'deadline': {'submitted_at': '2026-11-04T00:00:00+00:00', 'hard_deadline_at': '2026-11-04T00:00:10+00:00',
                     'duration_seconds': 10},
        'backend': {'kind': 'counting', 'token_digest': 'f' * 64, 'claim': 'committed', 'external_mutations': False},
        'operation_id': None, 'mcp_request_id': None, 'remote_task_id': None,
        'execution_status': 'running', 'cleanup_status': 'not_required', 'operation_outcome': 'not_applicable',
        'terminal_reason': None, 'source_final': None, 'source_changed': False, 'output': None,
        'retention_until': None, 'expired': False, 'event_receipts': {},
    }


def contender(path, revision, barrier, output):
    root = Path(path)
    value = store.load_registry(root)
    barrier.wait()
    try:
        store.commit_registry(root, revision, value)
        output.put('won')
    except store.RegistryError as error:
        output.put(error.code)


class ExecutionStoreTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def initial(self):
        value = store.empty_registry()
        item = record(self.root)
        value['records'][item['execution_id']] = item
        value['intents'][item['input']['intent_digest']] = item['execution_id']
        return store.commit_registry(self.root, None, value)

    def test_missing_observation_creates_no_runtime_and_cas_advances_once(self):
        with self.assertRaises(store.RegistryError) as caught:
            store.load_registry(self.root)
        self.assertEqual(caught.exception.code, 'registry_not_found')
        self.assertFalse((self.root / '.getzilla').exists())
        first = self.initial()
        self.assertEqual(first['revision'], 1)
        second = store.commit_registry(self.root, 1, first)
        self.assertEqual(second['revision'], 2)
        with self.assertRaises(store.RegistryError) as caught:
            store.commit_registry(self.root, 1, first)
        self.assertEqual(caught.exception.code, 'registry_conflict')

    def test_concurrent_processes_have_one_cas_winner(self):
        self.initial()
        context = multiprocessing.get_context('spawn')
        barrier = context.Barrier(4)
        output = context.Queue()
        processes = [context.Process(target=contender, args=(str(self.root), 1, barrier, output)) for _ in range(4)]
        for child in processes:
            child.start()
        for child in processes:
            child.join(15)
            self.assertEqual(child.exitcode, 0)
        outcomes = [output.get(timeout=2) for _ in processes]
        self.assertEqual(outcomes.count('won'), 1)
        self.assertEqual(outcomes.count('registry_conflict'), 3)
        self.assertEqual(store.load_registry(self.root)['revision'], 2)
        output.close()

    def test_closed_schema_dedup_and_immutable_owner_are_enforced(self):
        value = self.initial()
        for mutate in ('schema', 'intent', 'owner', 'record_revision', 'status', 'extra'):
            candidate = copy.deepcopy(value)
            item = candidate['records']['a' * 32]
            if mutate == 'schema':
                candidate['schema_version'] = 2
            elif mutate == 'intent':
                candidate['intents']['b' * 64] = '0' * 32
            elif mutate == 'owner':
                item['owner']['session_id'] = 'other'
                item['revision'] += 1
            elif mutate == 'record_revision':
                item['terminal_reason'] = 'changed without CAS'
            elif mutate == 'status':
                item['execution_status'] = 'queued'
            else:
                item['environment'] = {'SECRET': 'do not store'}
            with self.subTest(mutation=mutate), self.assertRaises(store.RegistryError):
                store.commit_registry(self.root, 1, candidate)
            self.assertEqual(store.load_registry(self.root), value)

    def test_strict_json_and_file_bounds_preserve_distinct_corrupt_outcome(self):
        self.initial()
        path = self.root / store.REGISTRY_PATH
        for raw in (b'{"schema_version":1,"schema_version":1}', b'{"revision":NaN}',
                    b'{', b' ' * (store.MAX_REGISTRY_BYTES + 1)):
            path.write_bytes(raw)
            with self.subTest(size=len(raw)), self.assertRaises(store.RegistryError) as caught:
                store.load_registry(self.root)
            self.assertEqual(caught.exception.code, 'registry_unavailable')

    def test_unsafe_links_fifo_and_hardlink_are_never_read_or_replaced(self):
        self.initial()
        path = self.root / store.REGISTRY_PATH
        original = path.read_bytes()
        target = self.root / 'outside'
        target.write_bytes(original)
        path.unlink()
        try:
            path.symlink_to(target)
        except OSError as error:
            self.skipTest(str(error))
        with self.assertRaises(store.RegistryError):
            store.load_registry(self.root)
        path.unlink()
        os.link(target, path)
        with self.assertRaises(store.RegistryError):
            store.load_registry(self.root)
        with self.assertRaises(store.RegistryError):
            store.commit_registry(self.root, None, store.empty_registry())
        path.unlink()
        if hasattr(os, 'mkfifo'):
            os.mkfifo(path)
            with self.assertRaises(store.RegistryError):
                store.load_registry(self.root)
        self.assertEqual(target.read_bytes(), original)

    def test_failed_publication_retains_prior_state_and_initialization_flushes_parents(self):
        first = self.initial()
        for boundary in ('replace_at', 'fsync_dir'):
            with self.subTest(boundary=boundary), patch.object(store.fsx, boundary, side_effect=OSError('injected')):
                with self.assertRaises(store.RegistryError):
                    store.commit_registry(self.root, 1, first)
            observed = store.load_registry(self.root)
            # A rename followed by failed directory flush is ambiguous, never acknowledged.
            self.assertIn(observed['revision'], (1, 2))
            first = observed
        with tempfile.TemporaryDirectory() as name, patch.object(store.fsx, 'fsync_dir', wraps=store.fsx.fsync_dir) as flush:
            store.commit_registry(Path(name), None, store.empty_registry())
            self.assertGreaterEqual(flush.call_count, 4)

    def test_capacity_is_finite_and_execution_state_is_not_disposable(self):
        value = store.empty_registry()
        for i in range(store.MAX_RECORDS + 1):
            item = record(self.root, f'{i:032x}', f'{i:064x}')
            value['records'][item['execution_id']] = item
            value['intents'][item['input']['intent_digest']] = item['execution_id']
        with self.assertRaises(store.RegistryError) as caught:
            store.commit_registry(self.root, None, value)
        self.assertEqual(caught.exception.code, 'registry_full')
        self.initial()
        self.assertEqual(classify(self.root, self.root / store.REGISTRY_PATH), 'protected')
        self.assertFalse(disposable(self.root, self.root / store.REGISTRY_PATH))
