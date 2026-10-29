from __future__ import annotations

import unittest
import sys
import asyncio
import tempfile
import json
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla import codex_continuation
from getzilla import model_continuation_state as journal
from tests.test_model_continuation import enabled_policy


class CodexContinuationTest(unittest.TestCase):
    def test_not_yet_qualified(self):
        self.assertFalse(codex_continuation.LIVE_QUALIFIED)

    def test_retry_requires_correlated_completed_failure_and_no_effects(self):
        state = codex_continuation.TurnObserver('thread', 'turn')
        state.observe({'method': 'error', 'params': {'threadId': 'thread', 'turnId': 'turn',
                      'willRetry': False, 'error': {'message': 'redacted', 'codexErrorInfo': 'rateLimitExceeded'}}})
        self.assertFalse(state.eligible)
        state.observe({'method': 'turn/completed', 'params': {'threadId': 'thread',
                      'turn': {'id': 'turn', 'status': 'failed'}}})
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
                     'turn': {'id': 'turn', 'status': 'failed'}}},
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
