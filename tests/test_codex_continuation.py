from __future__ import annotations

import unittest
import sys
import asyncio
import tempfile
import json
import time
import os
import signal
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla import codex_continuation
from getzilla import model_continuation_state as journal
from tests.test_model_continuation import enabled_policy


class CodexContinuationTest(unittest.TestCase):
    def test_eligible_error_requires_matching_terminal_error(self):
        for terminal_error in (None, {}, {'codexErrorInfo': 'internalServerError'}):
            with self.subTest(terminal_error=terminal_error):
                state = codex_continuation.TurnObserver('thread', 'turn')
                state.observe({'method': 'error', 'params': {'threadId': 'thread', 'turnId': 'turn',
                              'willRetry': False, 'error': {'codexErrorInfo': 'rateLimitExceeded'}}})
                state.observe({'method': 'turn/completed', 'params': {'threadId': 'thread', 'turn': {
                    'id': 'turn', 'status': 'failed', 'error': terminal_error}}})
                self.assertFalse(state.eligible)
                self.assertFalse(state.dispatch_permitted)

        state = codex_continuation.TurnObserver('thread', 'turn')
        state.observe({'method': 'error', 'params': {'threadId': 'thread', 'turnId': 'turn', 'willRetry': False,
                      'error': {'codexErrorInfo': {'responseTooManyFailedAttempts': {'httpStatusCode': 429}}}}})
        state.observe({'method': 'turn/completed', 'params': {'threadId': 'thread', 'turn': {'id': 'turn',
                      'status': 'failed', 'error': {'codexErrorInfo': {'responseTooManyFailedAttempts': {'httpStatusCode': 429.0}}}}}})
        self.assertFalse(state.eligible)

    def test_native_typed_429_with_bound_lifecycle_is_eligible_observation_only(self):
        state = codex_continuation.TurnObserver('thread', 'turn')
        for event in (
            {'method': 'thread/started', 'params': {'thread': {'id': 'thread'}}},
            {'method': 'thread/status/changed', 'params': {'threadId': 'thread', 'status': {'type': 'active'}}},
            {'method': 'turn/started', 'params': {'threadId': 'thread', 'turn': {'id': 'turn', 'status': 'inProgress'}}},
            {'method': 'item/started', 'params': {'threadId': 'thread', 'turnId': 'turn', 'item': {'id': 'm', 'type': 'userMessage'}}},
            {'method': 'item/completed', 'params': {'threadId': 'thread', 'turnId': 'turn', 'item': {'id': 'm', 'type': 'userMessage'}}},
            {'method': 'error', 'params': {'threadId': 'thread', 'turnId': 'turn', 'willRetry': False,
             'error': {'codexErrorInfo': {'responseTooManyFailedAttempts': {'httpStatusCode': 429}}}}},
            {'method': 'turn/completed', 'params': {'threadId': 'thread', 'turn': {'id': 'turn', 'status': 'failed',
             'error': {'codexErrorInfo': {'responseTooManyFailedAttempts': {'httpStatusCode': 429}}}}}},
        ):
            state.observe(event)
        self.assertTrue(state.eligible)
        self.assertFalse(state.dispatch_permitted)

    def test_typed_429_rejects_malformed_or_conflicting_details(self):
        for info in ({'responseTooManyFailedAttempts': {'httpStatusCode': '429'}},
                     {'responseTooManyFailedAttempts': {'httpStatusCode': True}},
                     {'responseTooManyFailedAttempts': {'httpStatusCode': 401}},
                     {'responseTooManyFailedAttempts': {'httpStatusCode': 402}},
                     {'responseTooManyFailedAttempts': {'httpStatusCode': 403}},
                     {'responseTooManyFailedAttempts': {'httpStatusCode': 500}},
                     {'responseTooManyFailedAttempts': {'httpStatusCode': None}},
                     {'responseTooManyFailedAttempts': {'httpStatusCode': 429}, 'other': {}},
                     {'responseTooManyFailedAttempts': {'httpStatusCode': 429, 'other': 1}}):
            with self.subTest(info=info):
                state = codex_continuation.TurnObserver('thread', 'turn')
                state.observe({'method': 'error', 'params': {'threadId': 'thread', 'turnId': 'turn',
                              'willRetry': False, 'error': {'codexErrorInfo': info}}})
                state.observe({'method': 'turn/completed', 'params': {'threadId': 'thread',
                              'turn': {'id': 'turn', 'status': 'failed'}}})
                self.assertFalse(state.eligible)

    def test_mismatched_terminal_error_or_lifecycle_fails_closed(self):
        good = {'responseTooManyFailedAttempts': {'httpStatusCode': 429}}
        for variant in ('different_error', 'stale_thread', 'stale_turn', 'native_retry', 'unknown_event'):
            with self.subTest(variant=variant):
                state = codex_continuation.TurnObserver('thread', 'turn')
                state.observe({'method': 'turn/started', 'params': {
                    'threadId': 'other' if variant == 'stale_thread' else 'thread',
                    'turn': {'id': 'other' if variant == 'stale_turn' else 'turn', 'status': 'inProgress'}}})
                if variant == 'unknown_event':
                    state.observe({'method': 'new/unknown', 'params': {}})
                state.observe({'method': 'error', 'params': {'threadId': 'thread', 'turnId': 'turn',
                              'willRetry': variant == 'native_retry', 'error': {'codexErrorInfo': good}}})
                state.observe({'method': 'turn/completed', 'params': {'threadId': 'thread', 'turn': {
                    'id': 'turn', 'status': 'failed', 'error': {'codexErrorInfo':
                    'unauthorized' if variant == 'different_error' else good}}}})
                self.assertFalse(state.eligible)

    def test_global_advisory_is_not_authority_and_malformed_advisory_denied(self):
        typed = {'responseTooManyFailedAttempts': {'httpStatusCode': 429}}
        for advisory, accepted in (
            ({'method': 'configWarning', 'params': {'summary': 'synthetic'}}, True),
            ({'method': 'account/rateLimits/updated', 'params': {'rateLimits': {}}}, True),
            ({'method': 'remoteControl/status/changed', 'params': {'installationId': 'i', 'serverName': 's', 'status': 'disabled'}}, True),
            ({'method': 'remoteControl/status/changed', 'params': {'installationId': 'i', 'serverName': 's', 'status': {}}}, False),
            ({'method': 'configWarning', 'params': {'summary': 3}}, False),
            ({'id': 9, 'method': 'configWarning', 'params': {'summary': 'synthetic'}}, False),
        ):
            with self.subTest(advisory=advisory):
                state = codex_continuation.TurnObserver('thread', 'turn')
                state.observe(advisory)
                state.observe({'method': 'error', 'params': {'threadId': 'thread', 'turnId': 'turn',
                              'willRetry': False, 'error': {'codexErrorInfo': typed}}})
                state.observe({'method': 'turn/completed', 'params': {'threadId': 'thread',
                              'turn': {'id': 'turn', 'status': 'failed', 'error': {'codexErrorInfo': typed}}}})
                self.assertEqual(state.eligible, accepted)
                self.assertFalse(state.dispatch_permitted)

    def test_stale_usage_notification_is_not_ignored(self):
        state = codex_continuation.TurnObserver('thread', 'turn')
        state.observe({'method': 'thread/tokenUsage/updated', 'params': {'threadId': 'thread',
                      'turnId': 'other', 'tokenUsage': {}}})
        state.observe({'method': 'error', 'params': {'threadId': 'thread', 'turnId': 'turn',
                      'willRetry': False, 'error': {'codexErrorInfo': 'rateLimitExceeded'}}})
        state.observe({'method': 'turn/completed', 'params': {'threadId': 'thread',
                      'turn': {'id': 'turn', 'status': 'failed'}}})
        self.assertFalse(state.eligible)

    def test_terminal_snapshot_cannot_hide_a_tool_effect(self):
        for item_type, eligible in (('agentMessage', True), ('commandExecution', False)):
            with self.subTest(item_type=item_type):
                state = codex_continuation.TurnObserver('thread', 'turn')
                error = {'codexErrorInfo': 'rateLimitExceeded'}
                state.observe({'method': 'error', 'params': {'threadId': 'thread', 'turnId': 'turn',
                              'willRetry': False, 'error': error}})
                state.observe({'method': 'turn/completed', 'params': {'threadId': 'thread', 'turn': {
                    'id': 'turn', 'status': 'failed', 'error': error,
                    'items': [{'id': 'x', 'type': item_type}]}}})
                self.assertEqual(state.eligible, eligible)
                self.assertFalse(state.dispatch_permitted)

    def test_unhashable_item_type_fails_closed(self):
        state = codex_continuation.TurnObserver('thread', 'turn')
        state.observe({'method': 'item/started', 'params': {'threadId': 'thread', 'turnId': 'turn',
                      'item': {'id': 'x', 'type': []}}})
        self.assertFalse(state.eligible)

    def test_not_yet_qualified(self):
        self.assertFalse(codex_continuation.LIVE_QUALIFIED)

    def test_retry_requires_correlated_completed_failure_and_no_effects(self):
        state = codex_continuation.TurnObserver('thread', 'turn')
        state.observe({'method': 'error', 'params': {'threadId': 'thread', 'turnId': 'turn',
                      'willRetry': False, 'error': {'message': 'redacted', 'codexErrorInfo': 'rateLimitExceeded'}}})
        self.assertFalse(state.eligible)
        state.observe({'method': 'turn/completed', 'params': {'threadId': 'thread',
                      'turn': {'id': 'turn', 'status': 'failed', 'error': {'codexErrorInfo': 'rateLimitExceeded'}}}})
        self.assertTrue(state.eligible)
        self.assertFalse(state.dispatch_permitted)

    def test_tool_or_retry_or_wrong_turn_blocks_retry(self):
        for changed in ('tool', 'retry', 'wrong'):
            with self.subTest(changed=changed):
                state = codex_continuation.TurnObserver('thread', 'turn')
                if changed == 'tool':
                    state.observe({'method': 'item/started', 'params': {'threadId': 'thread', 'turnId': 'turn',
                                  'item': {'id': 'x', 'type': 'commandExecution'}}})
                state.observe({'method': 'error', 'params': {'threadId': 'thread', 'turnId': 'turn',
                              'willRetry': changed == 'retry', 'error': {'codexErrorInfo': 'rateLimitExceeded'}}})
                state.observe({'method': 'turn/completed', 'params': {'threadId': 'thread',
                              'turn': {'id': 'other' if changed == 'wrong' else 'turn', 'status': 'failed'}}})
                self.assertFalse(state.eligible)

    def test_non_model_failures_never_qualify(self):
        for error in ('sessionBudgetExceeded', 'unauthorized', 'contextWindowExceeded',
                      'badRequest', 'cyberPolicy', 'modelNotFound', 'other', None):
            with self.subTest(error=error):
                state = codex_continuation.TurnObserver('thread', 'turn')
                state.observe({'method': 'error', 'params': {'threadId': 'thread', 'turnId': 'turn',
                              'willRetry': False, 'error': {'codexErrorInfo': error}}})
                state.observe({'method': 'turn/completed', 'params': {'threadId': 'thread',
                              'turn': {'id': 'turn', 'status': 'failed'}}})
                self.assertFalse(state.eligible)

    def test_approval_request_and_interrupt_ack_never_prove_stop(self):
        state = codex_continuation.TurnObserver('thread', 'turn')
        state.observe({'id': 9, 'method': 'item/commandExecution/requestApproval', 'params': {}})
        self.assertFalse(state.eligible)
        self.assertFalse(state.dispatch_permitted)
        state.observe({'id': 4, 'result': {}})
        self.assertFalse(state.eligible)

    def test_owned_jsonl_peer_controls_and_limits_local_process(self):
        async def exercise():
            with tempfile.TemporaryDirectory() as temp:
                script = Path(temp) / 'peer.py'
                script.write_text('import sys\nfor line in sys.stdin:\n sys.stdout.write(line); sys.stdout.flush()\n')
                peer = await codex_continuation.OwnedJsonlPeer.start(sys.executable, str(script))
                try:
                    await peer.send({'id': 1, 'method': 'turn/interrupt', 'params': {'threadId': 't', 'turnId': 'u'}})
                    self.assertEqual((await peer.read())['method'], 'turn/interrupt')
                finally:
                    await peer.close()
                self.assertIsNotNone(peer.returncode)
        asyncio.run(exercise())

    def test_oversize_or_invalid_json_fails_closed(self):
        async def exercise():
            with tempfile.TemporaryDirectory() as temp:
                script = Path(temp) / 'peer.py'
                for payload in ('{invalid', '{"id":1,"id":2}', 'x' * 65536):
                    script.write_text('print(' + repr(payload) + ', flush=True)\n')
                    peer = await codex_continuation.OwnedJsonlPeer.start(sys.executable, str(script))
                    try:
                        with self.assertRaisesRegex(codex_continuation.ProtocolError, 'invalid_frame'):
                            await peer.read()
                    finally:
                        await peer.close()
        asyncio.run(exercise())

    def test_initialize_real_jsonl_peer_without_inference(self):
        async def exercise():
            with tempfile.TemporaryDirectory() as temp:
                script = Path(temp) / 'peer.py'
                script.write_text("import json,sys\nr=json.loads(sys.stdin.readline())\n"
                                  "assert r['method']=='initialize'\n"
                                  "print(json.dumps({'method':'configWarning','params':{'summary':'synthetic'}}),flush=True)\n"
                                  "print(json.dumps({'id':r['id'],'result':{}}),flush=True)\n"
                                  "r=json.loads(sys.stdin.readline())\n"
                                  "print(json.dumps({'method':r['method'],'params':{}}),flush=True)\n")
                peer = await codex_continuation.OwnedJsonlPeer.start(sys.executable, str(script))
                try:
                    await codex_continuation.initialize(peer)
                    self.assertEqual((await peer.read())['method'], 'initialized')
                finally:
                    await peer.close()
        asyncio.run(exercise())

    def test_handshake_rejects_wrong_response_id(self):
        async def exercise():
            with tempfile.TemporaryDirectory() as temp:
                script = Path(temp) / 'peer.py'
                script.write_text("import sys\nsys.stdin.readline()\nprint('{\"id\":2,\"result\":{}}',flush=True)\n")
                peer = await codex_continuation.OwnedJsonlPeer.start(sys.executable, str(script))
                try:
                    with self.assertRaisesRegex(codex_continuation.ProtocolError, 'initialization_failed'):
                        await codex_continuation.initialize(peer)
                finally:
                    await peer.close()
        asyncio.run(exercise())

    @unittest.skipIf(os.name == 'nt', 'durable journal admission is unsupported on Windows')
    def test_real_journal_and_local_jsonl_peer_never_dispatch_unqualified_retry(self):
        async def exercise():
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                config = root / '.getzilla/config/model-continuation.json'
                config.parent.mkdir(parents=True)
                config.write_text(json.dumps(enabled_policy()), encoding='utf-8')
                binding = journal.Binding('chain', 'task', 'owner', 'route', 'session', 'a'*64, 'b'*64, 'c'*64)
                journal.create_chain(root, binding, journal.Usage(1, '0.1'),
                                     journal.TaskBudget(2, 4, '1.5', int(time.time()) + 120))
                script = root / 'peer.py'
                frames = [
                    {'method': 'error', 'params': {'threadId': 'thread', 'turnId': 'turn',
                     'willRetry': False, 'error': {'message': 'private', 'codexErrorInfo': 'rateLimitExceeded'}}},
                    {'method': 'turn/completed', 'params': {'threadId': 'thread',
                     'turn': {'id': 'turn', 'status': 'failed', 'error': {'codexErrorInfo': 'rateLimitExceeded'}}}},
                ]
                script.write_text('import sys\n' + ''.join('print(' + repr(json.dumps(f)) + ', flush=True)\n' for f in frames))
                peer = await codex_continuation.OwnedJsonlPeer.start(sys.executable, str(script))
                try:
                    result = await codex_continuation.observe_and_reserve(
                        peer, root, binding, 1, 'failure', 'thread', 'turn', journal.Usage(1, '0.2'))
                    self.assertEqual(result['reason'], 'failure_not_eligible')
                    self.assertFalse(result['dispatch_permitted'])
                    self.assertEqual(len(journal.inspect_chain(root, binding)['attempts']), 1)
                    self.assertEqual(journal.inspect_chain(root, binding)['attempts'][0]['category'], 'unknown')
                    self.assertNotIn('private', json.dumps(result))
                finally:
                    await peer.close()
        asyncio.run(exercise())

    def test_journal_rejects_unsupported_windows_admission(self):
        with tempfile.TemporaryDirectory() as temp:
            binding = journal.Binding('chain', 'task', 'owner', 'route', 'session', 'a'*64, 'b'*64, 'c'*64)
            with patch.object(journal.fsx, 'WINDOWS', True), self.assertRaisesRegex(journal.JournalError, 'durability_unsupported'):
                journal.create_chain(Path(temp), binding, journal.Usage(1, '0.1'),
                                     journal.TaskBudget(2, 4, '1.5', int(time.time()) + 120))

    @unittest.skipIf(os.name == 'nt', 'POSIX signal behavior')
    def test_close_is_bounded_when_descendant_retains_stdout(self):
        async def exercise():
            with tempfile.TemporaryDirectory() as temp:
                script = Path(temp) / 'peer.py'
                descendant = Path(temp) / 'descendant.py'
                descendant.write_text("import os,sys\nrelease,ack=map(int,sys.argv[1:])\n"
                                      "os.write(ack,b'R')\nassert os.read(release,1)==b''\n"
                                      "os.write(ack,b'E')\n")
                script.write_text("import os,signal,subprocess,sys\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                                  "release,ack=map(int,sys.argv[1:3])\n"
                                  "subprocess.Popen([sys.executable,sys.argv[3],str(release),str(ack)],"
                                  "pass_fds=(release,ack))\n"
                                  "os.close(release)\nos.close(ack)\nprint('ready', flush=True)\n"
                                  "while True: signal.pause()\n")
                release_read, release_write = os.pipe()
                ack_read, ack_write = os.pipe()
                with (os.fdopen(release_read, 'rb') as release_input,
                      os.fdopen(release_write, 'wb') as release_output,
                      os.fdopen(ack_read, 'rb') as ack_input,
                      os.fdopen(ack_write, 'wb') as ack_output):
                    acknowledgement = asyncio.StreamReader()
                    ack_transport, _ = await asyncio.get_running_loop().connect_read_pipe(
                        lambda: asyncio.StreamReaderProtocol(acknowledgement), ack_input)
                    try:
                        process = await asyncio.create_subprocess_exec(
                            sys.executable, str(script), str(release_input.fileno()),
                            str(ack_output.fileno()), str(descendant),
                            pass_fds=(release_input.fileno(), ack_output.fileno()), start_new_session=True,
                            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.DEVNULL)
                        release_input.close()
                        ack_output.close()
                        peer = codex_continuation.OwnedJsonlPeer(process, 0.1)
                        try:
                            self.assertEqual(await asyncio.wait_for(process.stdout.readline(), 5), b'ready\n')
                            self.assertEqual(await asyncio.wait_for(acknowledgement.readexactly(1), 5), b'R')
                            started = time.monotonic()
                            try:
                                await asyncio.wait_for(peer.close(), 3)
                            except codex_continuation.ProtocolError as exc:
                                self.assertEqual(str(exc), 'shutdown_incomplete')
                            self.assertTrue(process._transport.is_closing())
                            self.assertLess(time.monotonic() - started, 3)
                        finally:
                            # EOF cannot be missed when the temporary directory disappears.
                            release_output.close()
                            try:
                                exited = await asyncio.wait_for(acknowledgement.read(), 5)
                                self.assertIn(exited, (b'E', b'RE'))
                            finally:
                                # Also stop the peer if an assertion failed before close().
                                try:
                                    os.killpg(process.pid, signal.SIGKILL)
                                except ProcessLookupError:
                                    pass
                                process._transport.close()
                                await asyncio.wait_for(process.wait(), 5)
                                await asyncio.wait_for(acknowledgement.read(), 5)
                    finally:
                        ack_transport.close()
        asyncio.run(exercise())

    @unittest.skipIf(os.name == 'nt', 'POSIX process behavior')
    def test_close_releases_pipes_after_peer_already_exited(self):
        async def exercise():
            with tempfile.TemporaryDirectory() as temp:
                script = Path(temp) / 'peer.py'
                script.write_text("import subprocess,sys\n"
                                  "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(2)'])\n"
                                  "print('ready', flush=True)\n")
                peer = await codex_continuation.OwnedJsonlPeer.start(sys.executable, str(script), timeout=0.1)
                await peer._process.stdout.readline()
                for _ in range(50):
                    if peer.returncode is not None:
                        break
                    await asyncio.sleep(0.01)
                self.assertIsNotNone(peer.returncode)
                await peer.close()
                self.assertTrue(peer._process._transport.is_closing())
        asyncio.run(exercise())

    def test_close_handles_both_reaped_and_retained_pipe_outcomes(self):
        class Transport:
            closed = False

            def close(self):
                self.closed = True

        class Process:
            returncode = None

            def __init__(self, blocked):
                self.blocked = blocked
                self._transport = Transport()

            def terminate(self):
                pass

            def kill(self):
                pass

            async def wait(self):
                if self.blocked:
                    await asyncio.Event().wait()
                return -9

        async def exercise():
            finished = Process(False)
            await asyncio.wait_for(codex_continuation.OwnedJsonlPeer(finished, 0.05).close(), 1)
            self.assertTrue(finished._transport.closed)
            blocked = Process(True)
            with self.assertRaisesRegex(codex_continuation.ProtocolError, 'shutdown_incomplete'):
                await asyncio.wait_for(codex_continuation.OwnedJsonlPeer(blocked, 0.05).close(), 1)
            self.assertTrue(blocked._transport.closed)
        asyncio.run(exercise())
