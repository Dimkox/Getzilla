from __future__ import annotations

import sys
import hashlib
import json
import multiprocessing
import os
import re
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla import controlled_fixture
from getzilla import fenced_fixture
from getzilla import model_continuation_state as journal
from tests.test_model_continuation import enabled_policy


def _fenced_policy():
    policy = enabled_policy()
    policy['bounds']['deadline_seconds'] = 600
    return policy


def _resume_fixture_process(root, binding, budget, results):
    phases = []
    original = fenced_fixture._create

    def track(*args, **kwargs):
        phases.append(args[4])
        return original(*args, **kwargs)

    try:
        with patch.object(fenced_fixture, '_create', side_effect=track):
            result = controlled_fixture.run_fenced(Path(root), binding, budget)
        results.put((result, phases))
    except Exception as error:
        results.put(({'state': 'error', 'reason': type(error).__name__}, phases))


def _crash_fixture_process(root, binding, budget):
    def crash(*args, **kwargs):
        os._exit(75)

    with patch.object(journal, 'reserve_fenced_next', side_effect=crash):
        controlled_fixture.run_fenced(Path(root), binding, budget)


def _crash_after_b_claim_process(root, binding, budget):
    original = journal.consume_controlled_send

    def consume(*args, **kwargs):
        result = original(*args, **kwargs)
        if args[2] == 2 and result.get('claimed'):
            os._exit(76)
        return result

    with patch.object(journal, 'consume_controlled_send', side_effect=consume):
        controlled_fixture.run_fenced(Path(root), binding, budget)


def _crash_after_b_result_process(root, binding, budget):
    original = controlled_fixture._Lines.read

    def read(peer, *args, **kwargs):
        result = original(peer, *args, **kwargs)
        if result.get('type') == 'fenced_b_result':
            os._exit(77)
        return result

    with patch.object(controlled_fixture._Lines, 'read', read):
        controlled_fixture.run_fenced(Path(root), binding, budget)


def _cleanup_owned_fixture(root, binding, *, required=False):
    volumes = fenced_fixture._volume_names(root, binding)
    try:
        details = json.loads(controlled_fixture._command(['/usr/bin/docker', 'volume', 'inspect', volumes[0]]))
        nonce = details[0]['Labels']['getzilla.owner']
        if not isinstance(nonce, str) or not re.fullmatch(r'[a-f0-9]{32}', nonce):
            raise AssertionError('unexpected cleanup owner')
        other = json.loads(controlled_fixture._command(['/usr/bin/docker', 'volume', 'inspect', volumes[1]]))
        if other[0]['Labels']['getzilla.owner'] != nonce:
            raise AssertionError('unexpected cleanup volume')
        ids = controlled_fixture._command(['/usr/bin/docker', 'ps', '-a', '--no-trunc',
                                          '--filter', 'label=getzilla.owner=' + nonce, '--format', '{{.ID}}']).splitlines()
        images = set()
        for ident in ids:
            info = fenced_fixture._inspect('/usr/bin/docker', ident)
            if info['Id'] != ident or info['Config']['Labels'].get('getzilla.owner') != nonce:
                raise AssertionError('unexpected cleanup target')
            images.add(info['Image'])
            controlled_fixture._command(['/usr/bin/docker', 'rm', '-fv', ident])
        for name in volumes:
            controlled_fixture._command(['/usr/bin/docker', 'volume', 'rm', name])
        for image in images:
            controlled_fixture._command(['/usr/bin/docker', 'image', 'rm', image])
    except controlled_fixture.FixtureError:
        if required:
            raise


class ControlledFixtureTest(unittest.TestCase):
    def test_checkpoint_volumes_reject_unknown_attached_container(self):
        with patch.object(controlled_fixture, '_command', side_effect=['a\n', 'a\n']):
            self.assertTrue(fenced_fixture._exclusive_volumes('docker', ['v1', 'v2'], ['a']))
        with patch.object(controlled_fixture, '_command', side_effect=['a\nb\n']):
            self.assertFalse(fenced_fixture._exclusive_volumes('docker', ['v1', 'v2'], ['a']))

    def test_docker_errors_distinguish_timeout_without_exposing_output(self):
        for error, reason in ((subprocess.TimeoutExpired(['docker'], 1), 'container_timeout'),
                              (subprocess.CalledProcessError(1, ['docker'], stderr='private'), 'container_command_failed')):
            with self.subTest(reason=reason), patch.object(controlled_fixture.subprocess, 'run', side_effect=error):
                with self.assertRaisesRegex(controlled_fixture.FixtureError, '^' + reason + '$'):
                    controlled_fixture._command(['docker', 'inspect', 'synthetic'])

    def test_fenced_resume_observations_are_bound_and_ordered(self):
        started = {'method': 'turn/started', 'params': {'threadId': 't', 'turn': {'id': 'u', 'status': 'inProgress'}}}
        completed = {'method': 'turn/completed', 'params': {'threadId': 't',
                     'turn': {'id': 'u', 'status': 'completed', 'error': None, 'items': []}}}
        clear = {'method': 'thread/goal/cleared', 'params': {'threadId': 't'}}
        self.assertTrue(fenced_fixture._valid_second_events([clear, started, completed], 't', 'u'))
        self.assertFalse(fenced_fixture._valid_second_events([clear, clear, started, completed], 't', 'u'))
        self.assertFalse(fenced_fixture._valid_second_events([started, clear, completed], 't', 'u'))
        self.assertFalse(fenced_fixture._valid_second_events([{'method': 'thread/goal/cleared', 'params': {'threadId': 'other'}}, started, completed], 't', 'u'))
        self.assertFalse(fenced_fixture._valid_second_events([{'id': 1, 'method': 'thread/goal/cleared', 'params': {'threadId': 't'}}, started, completed], 't', 'u'))

    @unittest.skipUnless(os.environ.get('GETZILLA_RUN_CODEX_FIXTURE') == '1', 'requires local pinned Docker image and Codex binary')
    def test_fenced_fixture_resumes_after_first_container_stops(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            policy = _fenced_policy()
            policy['candidates'] = [{'provider': 'local_fixture', 'account_ref': 'synthetic', 'model': model}
                                    for model in ('fixture-a', 'fixture-b')]
            config.write_text(json.dumps(policy), encoding='utf-8')
            binding = journal.Binding('fenced-chain', 'fenced-task', 'fixture-owner', 'fixture-route',
                                      'fixture-session', 'a'*64, 'b'*64, 'c'*64)
            budget = journal.TaskBudget(2, 4, '1.5', int(time.time()) + 600)
            steps = []
            create, stopped, checkpoint, reserve = (fenced_fixture._create, fenced_fixture._stopped,
                                                       fenced_fixture._checkpoint, journal.reserve_fenced_next)

            def track_create(*args, **kwargs):
                steps.append('create-' + args[4])
                return create(*args, **kwargs)

            def track_stop(*args, **kwargs):
                result = stopped(*args, **kwargs)
                if result:
                    steps.append('stopped-' + args[5])
                return result

            def track_checkpoint(*args, **kwargs):
                result = checkpoint(*args, **kwargs)
                steps.append('checkpoint')
                return result

            def track_reserve(*args, **kwargs):
                steps.append('reserve')
                return reserve(*args, **kwargs)

            with patch.object(fenced_fixture, '_create', side_effect=track_create), \
                 patch.object(fenced_fixture, '_stopped', side_effect=track_stop), \
                 patch.object(fenced_fixture, '_checkpoint', side_effect=track_checkpoint), \
                 patch.object(journal, 'reserve_fenced_next', side_effect=track_reserve):
                result = controlled_fixture.run_fenced(root, binding, budget)
            self.assertEqual(result['state'], 'fixture_succeeded')
            self.assertFalse(result['dispatch_permitted'])
            self.assertLess(steps.index('stopped-a'), steps.index('reserve'))
            self.assertIn('checkpoint', steps[steps.index('stopped-a'):steps.index('reserve')])
            self.assertLess(steps.index('reserve'), steps.index('create-b'))
            state = journal.inspect_controlled_chain(root, binding)
            self.assertEqual([attempt['state'] for attempt in state['attempts']], ['failed', 'succeeded'])
            self.assertEqual(controlled_fixture.run_fenced(root, binding, budget)['state'], 'fixture_succeeded')

    @unittest.skipUnless(os.environ.get('GETZILLA_RUN_CODEX_FIXTURE') == '1', 'requires local pinned Docker image and Codex binary')
    def test_fenced_fixture_recovers_recorded_fence_without_resending_a(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            policy = _fenced_policy()
            policy['candidates'] = [{'provider': 'local_fixture', 'account_ref': 'synthetic', 'model': model}
                                    for model in ('fixture-a', 'fixture-b')]
            config.write_text(json.dumps(policy), encoding='utf-8')
            binding = journal.Binding('fenced-chain', 'fenced-task', 'fixture-owner', 'fixture-route',
                                      'fixture-session', 'a'*64, 'b'*64, 'c'*64)
            budget = journal.TaskBudget(2, 4, '1.5', int(time.time()) + 600)
            try:
                context = multiprocessing.get_context('spawn')
                first = context.Process(target=_crash_fixture_process, args=(str(root), binding, budget))
                first.start()
                first.join(timeout=240)
                if first.is_alive():
                    first.terminate()
                    first.join(timeout=5)
                    self.fail('first process timed out')
                self.assertEqual(first.exitcode, 75)
                before = journal.inspect_controlled_chain(root, binding)
                self.assertEqual(len(before['attempts']), 1)
                self.assertEqual(before['attempts'][0]['state'], 'failed')
                self.assertIn('fence_1', before['events'])
                results = context.Queue()
                process = context.Process(target=_resume_fixture_process, args=(str(root), binding, budget, results))
                process.start()
                process.join(timeout=240)
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)
                    self.fail('recovery process timed out')
                self.assertEqual(process.exitcode, 0)
                result, phases = results.get(timeout=5)
                self.assertEqual(result['state'], 'fixture_succeeded')
                self.assertEqual(phases, ['b'])
                after = journal.inspect_controlled_chain(root, binding)
                self.assertEqual([attempt['state'] for attempt in after['attempts']], ['failed', 'succeeded'])
                self.assertEqual(sum(attempt['requests'] for attempt in after['attempts']), 2)
            finally:
                _cleanup_owned_fixture(root, binding)

    @unittest.skipUnless(os.environ.get('GETZILLA_RUN_CODEX_FIXTURE') == '1', 'requires local pinned Docker image and Codex binary')
    def test_fenced_fixture_does_not_resend_after_b_claim_crash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            policy = _fenced_policy()
            policy['candidates'] = [{'provider': 'local_fixture', 'account_ref': 'synthetic', 'model': model}
                                    for model in ('fixture-a', 'fixture-b')]
            config.write_text(json.dumps(policy), encoding='utf-8')
            binding = journal.Binding('fenced-chain', 'fenced-task', 'fixture-owner', 'fixture-route',
                                      'fixture-session', 'a'*64, 'b'*64, 'c'*64)
            budget = journal.TaskBudget(2, 4, '1.5', int(time.time()) + 600)
            context = multiprocessing.get_context('spawn')
            process = context.Process(target=_crash_after_b_claim_process, args=(str(root), binding, budget))
            process.start()
            reached_crash = False
            try:
                process.join(timeout=240)
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)
                    self.fail('claim process timed out')
                self.assertEqual(process.exitcode, 76)
                reached_crash = True
                state = journal.inspect_controlled_chain(root, binding)
                self.assertEqual(state['attempts'][-1]['state'], 'send_unknown')
                with patch.object(controlled_fixture, '_command') as docker:
                    with self.assertRaisesRegex(controlled_fixture.FixtureError, 'recovery_required'):
                        controlled_fixture.run_fenced(root, binding, budget)
                    docker.assert_not_called()
            finally:
                if reached_crash:
                    _cleanup_owned_fixture(root, binding, required=True)

    @unittest.skipUnless(os.environ.get('GETZILLA_RUN_CODEX_FIXTURE') == '1', 'requires local pinned Docker image and Codex binary')
    def test_fenced_fixture_does_not_resend_after_b_result_crash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            policy = _fenced_policy()
            policy['candidates'] = [{'provider': 'local_fixture', 'account_ref': 'synthetic', 'model': model}
                                    for model in ('fixture-a', 'fixture-b')]
            config.write_text(json.dumps(policy), encoding='utf-8')
            binding = journal.Binding('fenced-chain', 'fenced-task', 'fixture-owner', 'fixture-route',
                                      'fixture-session', 'a'*64, 'b'*64, 'c'*64)
            budget = journal.TaskBudget(2, 4, '1.5', int(time.time()) + 600)
            context = multiprocessing.get_context('spawn')
            process = context.Process(target=_crash_after_b_result_process, args=(str(root), binding, budget))
            process.start()
            reached_crash = False
            try:
                process.join(timeout=240)
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)
                    self.fail('result process timed out')
                self.assertEqual(process.exitcode, 77)
                reached_crash = True
                state = journal.inspect_controlled_chain(root, binding)
                self.assertEqual(state['attempts'][-1]['state'], 'send_unknown')
                with patch.object(controlled_fixture, '_command') as docker:
                    with self.assertRaisesRegex(controlled_fixture.FixtureError, 'recovery_required'):
                        controlled_fixture.run_fenced(root, binding, budget)
                    docker.assert_not_called()
            finally:
                if reached_crash:
                    _cleanup_owned_fixture(root, binding, required=True)

    @unittest.skipUnless(os.environ.get('GETZILLA_RUN_CODEX_FIXTURE') == '1', 'requires local pinned Docker image and Codex binary')
    def test_fenced_fixture_preserves_changed_workspace_and_never_sends_b(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            policy = _fenced_policy()
            policy['candidates'] = [{'provider': 'local_fixture', 'account_ref': 'synthetic', 'model': model}
                                    for model in ('fixture-a', 'fixture-b')]
            config.write_text(json.dumps(policy), encoding='utf-8')
            binding = journal.Binding('fenced-chain', 'fenced-task', 'fixture-owner', 'fixture-route',
                                      'fixture-session', 'a'*64, 'b'*64, 'c'*64)
            budget = journal.TaskBudget(2, 4, '1.5', int(time.time()) + 600)
            original = fenced_fixture._checkpoint
            count = 0
            volumes_seen = False

            def changed(docker, image, volumes):
                nonlocal count, volumes_seen
                volumes_seen = True
                count += 1
                if count == 2:
                    fenced_fixture._helper(docker, image, volumes,
                        "import os; from pathlib import Path; os.chown('/work',0,0); Path('/work/partial').write_text('synthetic'); os.chown('/work',65534,65534)", root=True)
                return original(docker, image, volumes)

            try:
                with patch.object(fenced_fixture, '_checkpoint', side_effect=changed):
                    with self.assertRaisesRegex(controlled_fixture.FixtureError, 'checkpoint_changed'):
                        controlled_fixture.run_fenced(root, binding, budget)
                state = journal.inspect_controlled_chain(root, binding)
                self.assertEqual(len(state['attempts']), 1)
                self.assertEqual(state['attempts'][0]['state'], 'send_unknown')
                for name in fenced_fixture._volume_names(root, binding):
                    self.assertTrue(controlled_fixture._command(['/usr/bin/docker', 'volume', 'inspect', name]))
                retained = fenced_fixture._helper('/usr/bin/docker', controlled_fixture.IMAGE,
                    fenced_fixture._volume_names(root, binding), "from pathlib import Path; print(Path('/work/partial').read_text())")
                self.assertEqual(retained, 'synthetic')
                with self.assertRaises(controlled_fixture.FixtureError):
                    controlled_fixture.run_fenced(root, binding, budget)
            finally:
                if volumes_seen:
                    for name in fenced_fixture._volume_names(root, binding):
                        controlled_fixture._command(['/usr/bin/docker', 'volume', 'rm', name])

    @unittest.skipUnless(os.environ.get('GETZILLA_RUN_CODEX_FIXTURE') == '1', 'requires local pinned Docker image and Codex binary')
    def test_fenced_fixture_unknown_stop_never_reserves_or_sends_b(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            policy = _fenced_policy()
            policy['candidates'] = [{'provider': 'local_fixture', 'account_ref': 'synthetic', 'model': model}
                                    for model in ('fixture-a', 'fixture-b')]
            config.write_text(json.dumps(policy), encoding='utf-8')
            binding = journal.Binding('fenced-chain', 'fenced-task', 'fixture-owner', 'fixture-route',
                                      'fixture-session', 'a'*64, 'b'*64, 'c'*64)
            budget = journal.TaskBudget(2, 4, '1.5', int(time.time()) + 600)
            reached_stop = False

            def uncertain_stop(*args):
                nonlocal reached_stop
                reached_stop = True
                return False

            try:
                with patch.object(fenced_fixture, '_stopped', side_effect=uncertain_stop):
                    with self.assertRaisesRegex(controlled_fixture.FixtureError, 'shutdown_uncertain'):
                        controlled_fixture.run_fenced(root, binding, budget)
                state = journal.inspect_controlled_chain(root, binding)
                self.assertEqual(len(state['attempts']), 1)
                self.assertEqual(state['attempts'][0]['state'], 'send_unknown')
                self.assertEqual(state['events'], {})
                with self.assertRaises(controlled_fixture.FixtureError):
                    controlled_fixture.run_fenced(root, binding, budget)
            finally:
                if reached_stop:
                    for name in fenced_fixture._volume_names(root, binding):
                        controlled_fixture._command(['/usr/bin/docker', 'volume', 'rm', name])

    def test_container_stop_requires_exact_owned_exited_process(self):
        ident = 'a' * 64
        info = {'Id': ident, 'Image': 'sha256:abc', 'Config': {'Labels': {'getzilla.owner': 'nonce'}},
                'State': {'Running': False, 'Restarting': False, 'Dead': False, 'Status': 'exited', 'Pid': 0}}
        self.assertTrue(controlled_fixture._container_stopped(info, ident, 'sha256:abc', 'nonce'))
        self.assertFalse(controlled_fixture._container_stopped(info, 'b' * 64, 'sha256:abc', 'nonce'))
        self.assertFalse(controlled_fixture._container_stopped(info, ident, 'sha256:abc', 'other'))
        for field, value in [('Running', True), ('Restarting', True), ('Dead', True), ('Pid', 12), ('Status', 'running')]:
            with self.subTest(field=field):
                altered = dict(info, State=dict(info['State'], **{field: value}))
                self.assertFalse(controlled_fixture._container_stopped(altered, ident, 'sha256:abc', 'nonce'))

    def test_pinned_fixture_hash_matches_source(self):
        fixture = Path(__file__).resolve().parent / 'fixtures/codex_loopback_probe.py'
        self.assertEqual(hashlib.sha256(fixture.read_bytes()).hexdigest(), controlled_fixture.FIXTURE_SHA256)

    def test_immutable_image_rejects_tampered_inputs_and_cleans_image(self):
        container_id = 'a' * 64
        image_id = 'sha256:' + 'b' * 64
        for hashes in (('wrong', controlled_fixture.CODEX_SHA256), (controlled_fixture.FIXTURE_SHA256, 'wrong')):
            with self.subTest(hashes=hashes):
                calls = []

                def command(args, timeout=15):
                    calls.append(args)
                    if args[1] == 'create':
                        return container_id
                    if args[1] == 'commit':
                        return image_id
                    if args[1] == 'start':
                        return '\n'.join(hashes)
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

    @unittest.skipIf(os.name == 'nt', 'directory fsync admission is unsupported on Windows')
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
        original_stopped = controlled_fixture._container_stopped
        for stage in ('before_b', 'after_b', 'denied_success', 'uncertain_stop'):
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
                replacement = journal.JournalError('storage_unavailable') if stage == 'before_b' else (
                    original if stage == 'uncertain_stop' else record)
                stopped = (lambda *args: False) if stage == 'uncertain_stop' else original_stopped
                with patch.object(journal, target, side_effect=replacement), \
                     patch.object(controlled_fixture, '_container_stopped', side_effect=stopped), self.assertRaises(ValueError):
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
            policy = _fenced_policy()
            policy['candidates'] = [{'provider': 'local_fixture', 'account_ref': 'synthetic', 'model': model}
                                    for model in ('fixture-a', 'fixture-b')]
            config.write_text(json.dumps(policy), encoding='utf-8')
            binding = journal.Binding('fixture-chain', 'fixture-task', 'fixture-owner', 'fixture-route',
                                      'fixture-session', 'a'*64, 'b'*64, 'c'*64)
            budget = journal.TaskBudget(2, 4, '1.5', int(time.time()) + 600)
            original = controlled_fixture._command
            removals = 0

            def uncertain_cleanup(args, timeout=60):
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
