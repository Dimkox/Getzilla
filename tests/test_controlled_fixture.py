from __future__ import annotations

import sys
import hashlib
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla import controlled_fixture
from getzilla import model_continuation_state as journal
from tests.test_model_continuation import enabled_policy


class ControlledFixtureTest(unittest.TestCase):
    def test_pinned_fixture_hash_matches_source(self):
        fixture = Path(__file__).resolve().parent / 'fixtures/codex_loopback_probe.py'
        self.assertEqual(hashlib.sha256(fixture.read_bytes()).hexdigest(), controlled_fixture.FIXTURE_SHA256)

    def test_immutable_image_rejects_tampered_fixture_and_cleans_image(self):
        container_id = 'a' * 64
        image_id = 'sha256:' + 'b' * 64
        calls = []

        def command(args, timeout=15):
            calls.append(args)
            if args[1] == 'create':
                return container_id
            if args[1] == 'commit':
                return image_id
            if args[1] == 'start':
                return 'wrong\n' + controlled_fixture.CODEX_SHA256
            return ''

        with patch.object(controlled_fixture, '_command', side_effect=command):
            with self.assertRaises(controlled_fixture.FixtureError):
                controlled_fixture._immutable_image('docker', Path('/fixture'), '/codex')
        self.assertIn(['docker', 'rm', '-fv', container_id], calls)
        self.assertIn(['docker', 'image', 'rm', image_id], calls)

    def test_immutable_image_checks_both_hashes_and_returns_content_id(self):
        staging, checker = 'a' * 64, 'c' * 64
        image_id = 'sha256:' + 'b' * 64
        calls = []

        def command(args, timeout=15):
            calls.append(args)
            if args[1] == 'create':
                return checker if '--entrypoint' in args else staging
            if args[1] == 'commit':
                return image_id
            if args[1] == 'start':
                return controlled_fixture.FIXTURE_SHA256 + '\n' + controlled_fixture.CODEX_SHA256
            return ''

        with patch.object(controlled_fixture, '_command', side_effect=command):
            self.assertEqual(controlled_fixture._immutable_image('docker', Path('/fixture'), '/codex'), image_id)
        self.assertIn(['docker', 'rm', '-fv', staging], calls)
        self.assertIn(['docker', 'rm', '-fv', checker], calls)
        self.assertNotIn(['docker', 'image', 'rm', image_id], calls)

    def test_existing_chain_stops_before_container_allocation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            policy = enabled_policy()
            policy['candidates'] = [{'provider': 'local_fixture', 'account_ref': 'synthetic', 'model': model}
                                    for model in ('fixture-a', 'fixture-b')]
            config.write_text(json.dumps(policy), encoding='utf-8')
            binding = journal.Binding('fixture-chain', 'fixture-task', 'fixture-owner', 'fixture-route',
                                      'fixture-session', 'a'*64, 'b'*64, 'c'*64)
            budget = journal.TaskBudget(2, 4, '1.5', int(time.time()) + 120)
            journal.create_controlled_chain(root, binding, journal.Usage(1, '0'), budget)
            with patch.object(controlled_fixture.shutil, 'which', return_value=sys.executable), \
                 patch.object(controlled_fixture.hashlib, 'file_digest') as digest, \
                 patch.object(controlled_fixture, '_command') as command:
                digest.return_value.hexdigest.return_value = controlled_fixture.CODEX_SHA256
                with self.assertRaises(controlled_fixture.FixtureError):
                    controlled_fixture.run(root, binding, budget)
                command.assert_not_called()

    def test_container_identity_rejects_network_and_credentials(self):
        info = {'Image': 'sha256:abc', 'Config': {'User': '65534:65534', 'Cmd': ['python', '-u', '/fixture.py'],
                'Env': ['PATH=/usr/bin', 'HOME=/tmp', 'CODEX_HOME=/tmp/codex', 'GETZILLA_CONTROLLED_GATE=1', 'GETZILLA_FIXTURE_NONCE=nonce']},
                'HostConfig': {'NetworkMode': 'none', 'ReadonlyRootfs': True, 'Privileged': False,
                               'CapDrop': ['ALL'], 'SecurityOpt': ['no-new-privileges'], 'PidMode': '', 'IpcMode': 'private',
                               'PidsLimit': 64, 'Memory': 536870912, 'NanoCpus': 2000000000,
                               'Tmpfs': {'/tmp': 'rw,nosuid,nodev,size=64m,mode=1777',
                                         '/work': 'rw,nosuid,nodev,size=64m,mode=1777'}},
                'Mounts': [{'Type': 'bind', 'Source': '/fixture.py', 'Destination': '/fixture.py', 'RW': False},
                           {'Type': 'bind', 'Source': '/codex', 'Destination': '/fixture-codex', 'RW': False}]}
        mounts = {'/fixture.py': '/fixture.py', '/fixture-codex': '/codex'}
        self.assertTrue(controlled_fixture._validate_container(info, 'sha256:abc', mounts, 'nonce'))
        info['HostConfig']['NetworkMode'] = 'bridge'
        self.assertFalse(controlled_fixture._validate_container(info, 'sha256:abc', mounts, 'nonce'))
        info['HostConfig']['NetworkMode'] = 'none'
        info['HostConfig']['CapAdd'] = ['SYS_ADMIN']
        self.assertFalse(controlled_fixture._validate_container(info, 'sha256:abc', mounts, 'nonce'))
        info['HostConfig']['CapAdd'] = None
        info['Config']['Env'].append('OPENAI_API_KEY=secret')
        self.assertFalse(controlled_fixture._validate_container(info, 'sha256:abc', mounts, 'nonce'))
        info['Config']['Env'].pop()
        info['HostConfig']['Tmpfs']['/work'] = 'rw'
        self.assertFalse(controlled_fixture._validate_container(info, 'sha256:abc', mounts, 'nonce'))
        info['HostConfig']['Tmpfs']['/work'] = 'rw,nosuid,nodev,size=64m,mode=1777'
        info['Mounts'] = []
        self.assertTrue(controlled_fixture._validate_container(info, 'sha256:abc', {}, 'nonce'))
        info['Mounts'].append({'Type': 'bind', 'Source': '/fixture.py', 'Destination': '/fixture.py', 'RW': False})
        self.assertFalse(controlled_fixture._validate_container(info, 'sha256:abc', {}, 'nonce'))

    def test_second_terminal_must_match_and_have_no_tool_effect(self):
        events = [{'method': 'turn/started', 'params': {'threadId': 't', 'turn': {'id': 'u', 'status': 'inProgress'}}},
                  {'method': 'turn/completed', 'params': {'threadId': 't',
                  'turn': {'id': 'u', 'status': 'completed', 'error': None, 'items': []}}}]
        self.assertTrue(controlled_fixture._second_valid(events, 't', 'u'))
        self.assertFalse(controlled_fixture._second_valid(events, 't', 'other'))
        events[1]['params']['turn']['items'] = [{'type': 'commandExecution'}]
        self.assertFalse(controlled_fixture._second_valid(events, 't', 'u'))

    def test_first_error_requires_correlated_terminal_and_no_native_retry(self):
        info = {'responseTooManyFailedAttempts': {'httpStatusCode': 429}}
        error = {'method': 'error', 'params': {'threadId': 't', 'turnId': 'u', 'willRetry': False,
                                               'error': {'codexErrorInfo': info}}}
        done = {'method': 'turn/completed', 'params': {'threadId': 't', 'turn': {'id': 'u', 'status': 'failed',
                'error': {'codexErrorInfo': info}, 'items': []}}}
        frame = {'type': 'before_b', 'version': 1, 'nonce': 'n', 'thread': 't', 'turn': 'u',
                 'first': {'status': 'failed', 'error_info': info, 'items': []}, 'retry_flags': [False],
                 'item_types': ['userMessage'], 'server_requests': [], 'events': [error, done]}
        self.assertTrue(controlled_fixture._first_valid(frame, 'n'))
        error['params']['willRetry'] = True
        self.assertFalse(controlled_fixture._first_valid(frame, 'n'))
        error['params']['willRetry'] = False
        done['params']['threadId'] = 'other'
        self.assertFalse(controlled_fixture._first_valid(frame, 'n'))
        done['params']['threadId'] = 't'
        frame['first']['error_info'] = {'responseTooManyFailedAttempts': {'httpStatusCode': 429.0}}
        self.assertFalse(controlled_fixture._first_valid(frame, 'n'))
        frame['first']['error_info'] = info
        done['params']['turn']['error'] = {'codexErrorInfo': {'responseTooManyFailedAttempts': {'httpStatusCode': 429.0}}}
        self.assertFalse(controlled_fixture._first_valid(frame, 'n'))

    @unittest.skipUnless(os.environ.get('GETZILLA_RUN_CODEX_FIXTURE') == '1', 'requires local pinned Docker image and Codex binary')
    def test_actual_isolated_codex_fixture_and_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            policy = enabled_policy()
            policy['candidates'] = [{'provider': 'local_fixture', 'account_ref': 'synthetic', 'model': model}
                                    for model in ('fixture-a', 'fixture-b')]
            config.write_text(json.dumps(policy), encoding='utf-8')
            binding = journal.Binding('fixture-chain', 'fixture-task', 'fixture-owner', 'fixture-route',
                                      'fixture-session', 'a'*64, 'b'*64, 'c'*64)
            budget = journal.TaskBudget(2, 4, '1.5', int(time.time()) + 120)
            self.assertEqual(controlled_fixture.run(root, binding, budget)['state'], 'fixture_succeeded')
            state = journal.inspect_controlled_chain(root, binding)
            self.assertEqual([attempt['state'] for attempt in state['attempts']], ['failed', 'succeeded'])
            self.assertEqual(sum(attempt['requests'] for attempt in state['attempts']), 2)
            with self.assertRaises(controlled_fixture.FixtureError):
                controlled_fixture.run(root, binding, budget)
            self.assertEqual(journal.inspect_controlled_chain(root, binding), state)

    @unittest.skipUnless(os.environ.get('GETZILLA_RUN_CODEX_FIXTURE') == '1', 'requires local pinned Docker image and Codex binary')
    def test_isolated_fixture_failures_preserve_unknown_and_never_restart(self):
        original = journal.record_controlled_terminal
        for stage in ('before_b', 'after_b', 'denied_success'):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                config = root / '.getzilla/config/model-continuation.json'
                config.parent.mkdir(parents=True)
                policy = enabled_policy()
                policy['candidates'] = [{'provider': 'local_fixture', 'account_ref': 'synthetic', 'model': model}
                                        for model in ('fixture-a', 'fixture-b')]
                config.write_text(json.dumps(policy), encoding='utf-8')
                binding = journal.Binding('fixture-chain', 'fixture-task', 'fixture-owner', 'fixture-route',
                                          'fixture-session', 'a'*64, 'b'*64, 'c'*64)
                budget = journal.TaskBudget(2, 4, '1.5', int(time.time()) + 120)

                def record(*args):
                    if args[-1] == 'success':
                        if stage == 'denied_success':
                            return {'state': 'denied', 'reason': 'stale_revision', 'dispatch_permitted': False}
                        raise journal.JournalError('storage_unavailable')
                    return original(*args)

                target = 'reserve_controlled_next' if stage == 'before_b' else 'record_controlled_terminal'
                replacement = journal.JournalError('storage_unavailable') if stage == 'before_b' else record
                with patch.object(journal, target, side_effect=replacement), self.assertRaises(ValueError):
                    controlled_fixture.run(root, binding, budget)
                state = journal.inspect_controlled_chain(root, binding)
                self.assertEqual(state['attempts'][-1]['state'], 'failed' if stage == 'before_b' else 'send_unknown')
                with self.assertRaises(controlled_fixture.FixtureError):
                    controlled_fixture.run(root, binding, budget)
                self.assertEqual(journal.inspect_controlled_chain(root, binding), state)

    @unittest.skipUnless(os.environ.get('GETZILLA_RUN_CODEX_FIXTURE') == '1', 'requires local pinned Docker image and Codex binary')
    def test_cleanup_uncertainty_keeps_attempt_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            policy = enabled_policy()
            policy['candidates'] = [{'provider': 'local_fixture', 'account_ref': 'synthetic', 'model': model}
                                    for model in ('fixture-a', 'fixture-b')]
            config.write_text(json.dumps(policy), encoding='utf-8')
            binding = journal.Binding('fixture-chain', 'fixture-task', 'fixture-owner', 'fixture-route',
                                      'fixture-session', 'a'*64, 'b'*64, 'c'*64)
            budget = journal.TaskBudget(2, 4, '1.5', int(time.time()) + 120)
            original = controlled_fixture._command
            removals = 0

            def uncertain_cleanup(args, timeout=15):
                nonlocal removals
                result = original(args, timeout=timeout)
                if args[1] == 'rm':
                    removals += 1
                    if removals == 3:
                        raise controlled_fixture.FixtureError('container_unavailable')
                return result

            with patch.object(controlled_fixture, '_command', side_effect=uncertain_cleanup):
                with self.assertRaisesRegex(controlled_fixture.FixtureError, 'cleanup_uncertain'):
                    controlled_fixture.run(root, binding, budget)
            state = journal.inspect_controlled_chain(root, binding)
            self.assertEqual(state['attempts'][-1]['state'], 'send_unknown')
            with self.assertRaises(controlled_fixture.FixtureError):
                controlled_fixture.run(root, binding, budget)
            self.assertEqual(journal.inspect_controlled_chain(root, binding), state)
