from __future__ import annotations

import sys
import unittest
import json
import tempfile
import multiprocessing
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))

from getzilla import openai_model_request
from getzilla import model_continuation_state as journal
from tests.test_model_continuation import enabled_policy


def fixture_dispatch(status, body, delay=0):
    def send(root, binding, contract, request, generation, revision, credential):
        claim = journal.consume_fixture_model_request(root, binding, contract, request, generation, revision)
        if not claim['claimed']:
            raise openai_model_request.RequestError('request_not_admitted')
        if status is None:
            raise openai_model_request.RequestError('transport_unknown')
        journal._record_model_only_response(root, binding, contract, request, generation, claim['revision'], status, body, delay)
        return status, body
    return send


def inspect_consumed_after_restart(root, binding, contract, request, revision, results):
    with patch.object(journal.time, 'time', return_value=1000):
        results.put(journal.consume_fixture_model_request(Path(root), binding, contract, request, 2, revision))


class OpenAIModelRequestTest(unittest.TestCase):
    def test_classifies_only_structured_temporary_rate_limit(self):
        self.assertEqual(openai_model_request.classify_response(429, b'{"error":{"type":"rate_limit_error","code":"slow_down"}}'), 'rate_limit')
        self.assertEqual(openai_model_request.classify_response(429, b'{"error":{"type":"rate_limit_error","code":"insufficient_quota"}}'), 'needs_action')
        self.assertEqual(openai_model_request.classify_response(429, b'not json'), 'unknown')

    def test_refuses_unknown_conflicting_and_duplicate_error_fields(self):
        fixtures = [
            (429, b'{"error":{"type":"other","code":"slow_down"}}'),
            (503, b'{"error":{"type":"rate_limit_error","code":"slow_down"}}'),
            (429, b'{"error":{"type":"rate_limit_error","type":"rate_limit_error","code":"slow_down"}}'),
            (429, b'{"error":{"type":"rate_limit_error","code":"slow_down"},"n":NaN}'),
            (200, b'{"error":{"type":"rate_limit_error","code":"slow_down"}}'),
        ]
        for status, body in fixtures:
            with self.subTest(status=status, body=body):
                self.assertEqual(openai_model_request.classify_response(status, body), 'unknown')

    def test_success_requires_completed_text_response_without_refusal(self):
        good = b'{"object":"response","status":"completed","model":"model-a","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok"}]}]}'
        bad = b'{"object":"response","status":"completed","model":"model-a","output":[{"type":"message","role":"assistant","content":[{"type":"refusal","refusal":"no"}]}]}'
        self.assertEqual(openai_model_request.classify_response(200, good, model='model-a'), 'success')
        self.assertEqual(openai_model_request.classify_response(200, bad, model='model-a'), 'unknown')
        self.assertEqual(openai_model_request.classify_response(200, good, model='model-b'), 'unknown')
        self.assertEqual(openai_model_request.classify_response(200, b'{"object":"response","status":"completed","model":null,"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok"}]}]}'), 'unknown')
        self.assertEqual(openai_model_request.classify_response(200, b'{"object":"response","status":"completed","model":"model-a","output":[{"type":"reasoning"}]}', model='model-a'), 'unknown')

    def setUp(self):
        self.contract = openai_model_request.Contract(
            model='model-a', account_ref='work', max_input_bytes=128, max_input_tokens=1000,
            max_output_tokens=100, input_usd_per_million='2',
            output_usd_per_million='10', rate_revision='2026-10', expires_epoch=2000)

    def test_prepares_text_only_request_and_reserves_full_input_bound(self):
        request = openai_model_request.prepare(self.contract, 'hello')
        self.assertEqual(request.body, b'{"input":"hello","max_output_tokens":100,"model":"model-a","store":false}')
        self.assertEqual(request.reserved_cost_micros, 3000)

    def test_rejects_unpriced_unbounded_or_invalid_contracts(self):
        for change in ({'input_usd_per_million': ''}, {'output_usd_per_million': 'NaN'},
                       {'input_usd_per_million': '1e-9999999'},
                       {'max_input_tokens': 0}, {'max_output_tokens': True},
                       {'model': 'other/model'}):
            with self.subTest(change=change), self.assertRaises(openai_model_request.RequestError):
                openai_model_request.prepare(replace(self.contract, **change), 'hello')

    def test_utf8_input_limit_and_no_payload_in_error_or_repr(self):
        sentinel = 'secret-sentinel'
        with self.assertRaises(openai_model_request.RequestError) as error:
            openai_model_request.prepare(replace(self.contract, max_input_bytes=1), sentinel)
        self.assertNotIn(sentinel, str(error.exception))
        self.assertNotIn(sentinel, repr(openai_model_request.prepare(self.contract, sentinel)))
        with self.assertRaises(openai_model_request.RequestError):
            openai_model_request.prepare(replace(self.contract, max_input_bytes=1), 'é')

    def test_rounds_fractional_micros_up(self):
        contract = replace(self.contract, max_input_tokens=1, max_output_tokens=1,
                           input_usd_per_million='0.1', output_usd_per_million='0.1')
        self.assertEqual(openai_model_request.prepare(contract, 'x').reserved_cost_micros, 1)

    def test_dispatch_without_live_admission_fails_before_opening_socket(self):
        request = openai_model_request.prepare(self.contract, 'hello')
        with patch('http.client.HTTPSConnection') as connection:
            with self.assertRaises((TypeError, openai_model_request.RequestError)):
                openai_model_request.dispatch(request)
        connection.assert_not_called()

    def test_retry_after_is_bounded_and_duplicate_is_unknown(self):
        self.assertEqual(openai_model_request._retry_delay([]), 0)
        self.assertEqual(openai_model_request._retry_delay([('Retry-After', '5')]), 5)
        self.assertIsNone(openai_model_request._retry_delay([('Retry-After', '1'), ('retry-after', '1')]))
        self.assertIsNone(openai_model_request._retry_delay([('Retry-After', 'not-a-number')]))
        self.assertIsNone(openai_model_request._retry_delay([('Retry-After', '86401')]))

    @unittest.skipIf(sys.platform == 'win32', 'directory fsync is unsupported on Windows')
    def test_live_claim_reserves_before_send_and_is_never_reissued(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(journal.time, 'time', return_value=1000):
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            policy = enabled_policy()
            policy['candidates'][0]['provider'] = 'openai'
            config.write_text(json.dumps(policy), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a'*64, 'b'*64, 'c'*64)
            budget = journal.TaskBudget(2, 4, '1.5', 2000)
            prepared = openai_model_request.prepare(self.contract, 'hello')
            initial = journal.create_model_only_chain(root, binding, self.contract, prepared, budget)
            first = journal.consume_model_only_request(root, binding, self.contract, prepared, 1, initial['revision'])
            self.assertTrue(first['claimed'])
            self.assertFalse(journal.consume_model_only_request(root, binding, self.contract, prepared, 1, first['revision'])['claimed'])
            state = journal.inspect_chain(root, binding)
            self.assertEqual(state['attempts'][0]['cost_micros'], 3000)
            self.assertEqual(state['attempts'][0]['state'], 'send_unknown')

    @unittest.skipIf(sys.platform == 'win32', 'directory fsync is unsupported on Windows')
    def test_synthetic_result_cannot_update_live_model_ledger(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(journal.time, 'time', return_value=1000):
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            policy = enabled_policy()
            policy['candidates'][0]['provider'] = 'openai'
            config.write_text(json.dumps(policy), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a'*64, 'b'*64, 'c'*64)
            request = openai_model_request.prepare(self.contract, 'hello')
            initial = journal.create_model_only_chain(root, binding, self.contract, request, journal.TaskBudget(2, 4, '1.5', 2000))
            claim = journal.consume_model_only_request(root, binding, self.contract, request, 1, initial['revision'])
            body = b'{"error":{"type":"rate_limit_error","code":"slow_down"}}'
            with self.assertRaises(journal.JournalError):
                journal._record_model_only_response(root, binding, self.contract, request, 1, claim['revision'], 429, body, 0)
            self.assertEqual(journal.inspect_chain(root, binding)['attempts'][0]['state'], 'send_unknown')
            synthetic = journal.create_fixture_model_chain(root, binding, self.contract, request, journal.TaskBudget(2, 4, '1.5', 2000))
            synthetic_claim = journal.consume_fixture_model_request(root, binding, self.contract, request, 1, synthetic['revision'])
            result = journal._record_model_only_response(root, binding, self.contract, request, 1, synthetic_claim['revision'], 429, body, 0)
            self.assertEqual(result['state'], 'failed')
            self.assertEqual(journal.inspect_chain(root, binding)['attempts'][0]['state'], 'send_unknown')
            self.assertEqual(journal.inspect_fixture_model_chain(root, binding)['attempts'][0]['state'], 'failed')

    @unittest.skipIf(sys.platform == 'win32', 'directory fsync is unsupported on Windows')
    def test_dispatch_denies_before_consumption_without_data_admission(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(journal.time, 'time', return_value=1000):
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            policy = enabled_policy()
            policy['candidates'][0]['provider'] = 'openai'
            config.write_text(json.dumps(policy), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a'*64, 'b'*64, 'c'*64)
            prepared = openai_model_request.prepare(self.contract, 'hello')
            initial = journal.create_model_only_chain(root, binding, self.contract, prepared, journal.TaskBudget(2, 4, '1.5', 2000))
            with patch('http.client.HTTPSConnection') as factory:
                with self.assertRaisesRegex(openai_model_request.RequestError, 'data_admission_unavailable'):
                    openai_model_request.dispatch(root, binding, self.contract, prepared, 1, initial['revision'], 'fake-test-key')
                factory.assert_not_called()
                self.assertEqual(journal.inspect_chain(root, binding)['attempts'][0]['state'], 'reserved_unknown')

    @unittest.skipIf(sys.platform == 'win32', 'directory fsync is unsupported on Windows')
    def test_rotation_denies_before_creating_a_journal_without_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a'*64, 'b'*64, 'c'*64)
            with self.assertRaisesRegex(openai_model_request.RequestError, 'data_admission_unavailable'):
                openai_model_request.start_fixture_rotation(root, binding, (self.contract,), 'hello', journal.TaskBudget(1, 1, '1', 2000), {'work': 'fake-test-key'})
            self.assertFalse((root / '.getzilla/runtime/model-continuation').exists())

    @unittest.skipIf(sys.platform == 'win32', 'directory fsync is unsupported on Windows')
    def test_changed_request_revocation_expiry_and_racing_claims(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(journal.time, 'time', return_value=1000):
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            policy = enabled_policy()
            policy['candidates'][0]['provider'] = 'openai'
            config.write_text(json.dumps(policy), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a'*64, 'b'*64, 'c'*64)
            request = openai_model_request.prepare(self.contract, 'hello')
            initial = journal.create_model_only_chain(root, binding, self.contract, request, journal.TaskBudget(2, 4, '1.5', 2000))
            changed = openai_model_request.prepare(self.contract, 'changed')
            self.assertFalse(journal.consume_model_only_request(root, binding, self.contract, changed, 1, initial['revision'])['claimed'])
            with patch.object(journal.time, 'time', return_value=2000):
                self.assertFalse(journal.consume_model_only_request(root, binding, self.contract, request, 1, initial['revision'])['claimed'])
            policy['enabled'] = False
            config.write_text(json.dumps(policy), encoding='utf-8')
            self.assertFalse(journal.consume_model_only_request(root, binding, self.contract, request, 1, initial['revision'])['claimed'])
            policy['enabled'] = True
            config.write_text(json.dumps(policy), encoding='utf-8')
            with ThreadPoolExecutor(max_workers=2) as pool:
                claims = list(pool.map(lambda _: journal.consume_model_only_request(root, binding, self.contract, request, 1, initial['revision']), range(2)))
            self.assertEqual(sum(bool(claim['claimed']) for claim in claims), 1)

    @unittest.skipIf(sys.platform == 'win32', 'directory fsync is unsupported on Windows')
    def test_failed_durable_publish_never_reissues_claim(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(journal.time, 'time', return_value=1000):
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            policy = enabled_policy()
            policy['candidates'][0]['provider'] = 'openai'
            config.write_text(json.dumps(policy), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a'*64, 'b'*64, 'c'*64)
            request = openai_model_request.prepare(self.contract, 'hello')
            initial = journal.create_model_only_chain(root, binding, self.contract, request, journal.TaskBudget(2, 4, '1.5', 2000))
            with patch.object(journal.fsx, 'fsync_dir', side_effect=OSError):
                with self.assertRaisesRegex(journal.JournalError, 'storage_unavailable'):
                    journal.consume_model_only_request(root, binding, self.contract, request, 1, initial['revision'])
            self.assertFalse(journal.consume_model_only_request(root, binding, self.contract, request, 1, initial['revision'] + 1)['claimed'])

    @unittest.skipIf(sys.platform == 'win32', 'directory fsync is unsupported on Windows')
    def test_wrong_account_and_insufficient_budget_do_not_create_chain(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(journal.time, 'time', return_value=1000):
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            policy = enabled_policy()
            policy['candidates'][0]['provider'] = 'openai'
            config.write_text(json.dumps(policy), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a'*64, 'b'*64, 'c'*64)
            other = replace(self.contract, account_ref='other')
            with self.assertRaisesRegex(journal.JournalError, 'model_contract_denied'):
                journal.create_model_only_chain(root, binding, other, openai_model_request.prepare(other, 'hello'), journal.TaskBudget(2, 4, '1.5', 2000))
            with self.assertRaisesRegex(journal.JournalError, 'initial_budget_exhausted'):
                journal.create_model_only_chain(root, binding, self.contract, openai_model_request.prepare(self.contract, 'hello'), journal.TaskBudget(2, 4, '0.002', 2000))

    @unittest.skipIf(sys.platform == 'win32', 'directory fsync is unsupported on Windows')
    def test_terminal_429_reserves_second_model_in_same_budget(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(journal.time, 'time', return_value=1000):
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            policy = enabled_policy()
            policy['candidates'] = [{'provider': 'openai', 'account_ref': 'work', 'model': 'model-a'},
                                    {'provider': 'openai', 'account_ref': 'work', 'model': 'model-b'}]
            config.write_text(json.dumps(policy), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a'*64, 'b'*64, 'c'*64)
            request = openai_model_request.prepare(self.contract, 'hello')
            initial = journal.create_fixture_model_chain(root, binding, self.contract, request, journal.TaskBudget(2, 4, '1.5', 2000))
            claim = journal.consume_fixture_model_request(root, binding, self.contract, request, 1, initial['revision'])
            body = b'{"error":{"type":"rate_limit_error","code":"slow_down"}}'
            terminal = journal._record_model_only_response(root, binding, self.contract, request, 1, claim['revision'], 429, body, 0)
            other = replace(self.contract, model='model-b')
            next_request = openai_model_request.prepare(other, 'hello')
            self.assertEqual(journal.reserve_model_only_next(root, binding, other, openai_model_request.prepare(other, 'changed'), terminal['revision'])['reason'], 'input_or_contract_invalid')
            with ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = list(pool.map(lambda _: journal.reserve_model_only_next(root, binding, other, next_request, terminal['revision']), range(2)))
            self.assertEqual(sum(item['state'] == 'reserved_unknown' for item in outcomes), 1)
            next_attempt = next(item for item in outcomes if item['state'] == 'reserved_unknown')
            self.assertEqual(next_attempt['generation'], 2)
            self.assertEqual(journal.reserve_model_only_next(root, binding, other, next_request, terminal['revision'])['reason'], 'stale_revision')
            self.assertEqual(journal._record_model_only_response(root, binding, self.contract, request, 1, claim['revision'], 429, body, 0)['reason'], 'stale_revision')
            self.assertEqual(sum(a['cost_micros'] for a in journal.inspect_fixture_model_chain(root, binding)['attempts']), 6000)
            second = journal.consume_fixture_model_request(root, binding, other, next_request, 2, next_attempt['revision'])
            context = multiprocessing.get_context('spawn')
            results = context.Queue()
            process = context.Process(target=inspect_consumed_after_restart, args=(str(root), binding, other, next_request, second['revision'], results))
            process.start()
            process.join(timeout=15)
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
                self.fail('restart check timed out')
            self.assertEqual(process.exitcode, 0)
            self.assertFalse(results.get(timeout=2)['claimed'])
            success = b'{"object":"response","status":"completed","model":"model-b","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok"}]}]}'
            terminal_b = journal._record_model_only_response(root, binding, other, next_request, 2, second['revision'], 200, success, 0)
            self.assertEqual(terminal_b['state'], 'succeeded')
            self.assertFalse(journal.consume_fixture_model_request(root, binding, other, next_request, 2, terminal_b['revision'])['claimed'])

    @unittest.skipIf(sys.platform == 'win32', 'directory fsync is unsupported on Windows')
    def test_fixture_records_429_before_next_reservation(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(journal.time, 'time', return_value=1000):
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            policy = enabled_policy()
            policy['candidates'] = [{'provider': 'openai', 'account_ref': 'work', 'model': 'model-a'},
                                    {'provider': 'openai', 'account_ref': 'work', 'model': 'model-b'}]
            config.write_text(json.dumps(policy), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a'*64, 'b'*64, 'c'*64)
            request = openai_model_request.prepare(self.contract, 'hello')
            initial = journal.create_fixture_model_chain(root, binding, self.contract, request, journal.TaskBudget(2, 4, '1.5', 2000))
            body = b'{"error":{"type":"rate_limit_error","code":"slow_down"}}'
            with patch.object(openai_model_request, 'dispatch', side_effect=fixture_dispatch(429, body, 2)):
                self.assertEqual(openai_model_request.dispatch(root, binding, self.contract, request, 1, initial['revision'], 'fake-test-key'), (429, body))
            state = journal.inspect_fixture_model_chain(root, binding)
            self.assertEqual(state['attempts'][0]['state'], 'failed')
            other = replace(self.contract, model='model-b')
            next_request = openai_model_request.prepare(other, 'hello')
            self.assertEqual(journal.reserve_model_only_next(root, binding, other, next_request, state['revision'])['reason'], 'retry_after_pending')
            with patch.object(journal.time, 'time', return_value=1002):
                self.assertEqual(journal.reserve_model_only_next(root, binding, other, next_request, state['revision'])['generation'], 2)

    @unittest.skipIf(sys.platform == 'win32', 'directory fsync is unsupported on Windows')
    def test_rotation_dispatches_a_then_b_once_with_shared_budget(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(journal.time, 'time', return_value=1000):
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            policy = enabled_policy()
            policy['candidates'] = [{'provider': 'openai', 'account_ref': 'work', 'model': 'model-a'},
                                    {'provider': 'openai', 'account_ref': 'work', 'model': 'model-b'}]
            config.write_text(json.dumps(policy), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a'*64, 'b'*64, 'c'*64)
            other = replace(self.contract, model='model-b')
            failed = b'{"error":{"type":"rate_limit_error","code":"slow_down"}}'
            success = b'{"object":"response","status":"completed","model":"model-b","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok"}]}]}'
            outcomes = iter([fixture_dispatch(429, failed), fixture_dispatch(200, success)])
            with patch.object(openai_model_request, '_data_admission_available', return_value=True), patch.object(openai_model_request, 'dispatch', side_effect=lambda *args: next(outcomes)(*args)) as send:
                result = openai_model_request.start_fixture_rotation(root, binding, (self.contract, other), 'hello', journal.TaskBudget(2, 4, '1.5', 2000), {'work': 'fake-test-key'})
                self.assertEqual(result['state'], 'succeeded')
                self.assertEqual(result['body'], success)
                self.assertEqual(send.call_count, 2)
                recovered = openai_model_request.resume_fixture_rotation(root, binding, (self.contract, other), 'hello', {'work': 'fake-test-key'})
                self.assertEqual(recovered['state'], 'succeeded')
                self.assertEqual(send.call_count, 2)
            self.assertEqual(sum(a['cost_micros'] for a in journal.inspect_fixture_model_chain(root, binding)['attempts']), 6000)

    @unittest.skipIf(sys.platform == 'win32', 'directory fsync is unsupported on Windows')
    def test_rotation_does_not_retry_unknown_or_billing_response(self):
        for case, outcome in [('lost', None), ('billing', (429, b'{"error":{"type":"rate_limit_error","code":"insufficient_quota"}}', 0))]:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory, patch.object(journal.time, 'time', return_value=1000):
                root = Path(directory)
                config = root / '.getzilla/config/model-continuation.json'
                config.parent.mkdir(parents=True)
                policy = enabled_policy()
                policy['candidates'] = [{'provider': 'openai', 'account_ref': 'work', 'model': 'model-a'},
                                        {'provider': 'openai', 'account_ref': 'work', 'model': 'model-b'}]
                config.write_text(json.dumps(policy), encoding='utf-8')
                binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a'*64, 'b'*64, 'c'*64)
                contracts = (self.contract, replace(self.contract, model='model-b'))
                status, body, delay = outcome if outcome is not None else (None, b'', 0)
                with patch.object(openai_model_request, '_data_admission_available', return_value=True), patch.object(openai_model_request, 'dispatch', side_effect=fixture_dispatch(status, body, delay)) as send:
                    result = openai_model_request.start_fixture_rotation(root, binding, contracts, 'hello', journal.TaskBudget(2, 4, '1.5', 2000), {'work': 'fake-test-key'})
                    expected = 'unknown' if case == 'lost' else 'failure_not_eligible'
                    self.assertEqual(result['state'], expected)
                    self.assertEqual(openai_model_request.resume_fixture_rotation(root, binding, contracts, 'hello', {'work': 'fake-test-key'})['state'], expected)
                    self.assertEqual(send.call_count, 1)

    @unittest.skipIf(sys.platform == 'win32', 'directory fsync is unsupported on Windows')
    def test_rotation_rejects_second_reservation_when_shared_cost_is_exhausted(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(journal.time, 'time', return_value=1000):
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            policy = enabled_policy()
            policy['candidates'] = [{'provider': 'openai', 'account_ref': 'work', 'model': 'model-a'},
                                    {'provider': 'openai', 'account_ref': 'work', 'model': 'model-b'}]
            config.write_text(json.dumps(policy), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a'*64, 'b'*64, 'c'*64)
            contracts = (self.contract, replace(self.contract, model='model-b'))
            failed = b'{"error":{"type":"rate_limit_error","code":"slow_down"}}'
            with patch.object(openai_model_request, '_data_admission_available', return_value=True), patch.object(openai_model_request, 'dispatch', side_effect=fixture_dispatch(429, failed)) as send:
                result = openai_model_request.start_fixture_rotation(root, binding, contracts, 'hello', journal.TaskBudget(2, 4, '0.005', 2000), {'work': 'fake-test-key'})
                self.assertEqual(result['state'], 'budget_exhausted')
                self.assertEqual(send.call_count, 1)

    @unittest.skipIf(sys.platform == 'win32', 'directory fsync is unsupported on Windows')
    def test_cancelled_generation_never_admits_late_terminal_or_successor(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(journal.time, 'time', return_value=1000):
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            policy = enabled_policy()
            policy['candidates'][0]['provider'] = 'openai'
            config.write_text(json.dumps(policy), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a'*64, 'b'*64, 'c'*64)
            request = openai_model_request.prepare(self.contract, 'hello')
            initial = journal.create_fixture_model_chain(root, binding, self.contract, request, journal.TaskBudget(2, 4, '1.5', 2000))
            claim = journal.consume_fixture_model_request(root, binding, self.contract, request, 1, initial['revision'])
            journal.cancel_fixture_model_chain(root, binding, claim['revision'])
            body = b'{"error":{"type":"rate_limit_error","code":"slow_down"}}'
            result = journal._record_model_only_response(root, binding, self.contract, request, 1, claim['revision'], 429, body, 0)
            self.assertEqual(result['reason'], 'stale_revision')
            self.assertEqual(journal.inspect_fixture_model_chain(root, binding)['state'], 'cancelled')

    @unittest.skipIf(sys.platform == 'win32', 'directory fsync is unsupported on Windows')
    def test_ambiguous_successor_publication_is_not_resent_on_resume(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(journal.time, 'time', return_value=1000):
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            policy = enabled_policy()
            policy['candidates'] = [{'provider': 'openai', 'account_ref': 'work', 'model': 'model-a'},
                                    {'provider': 'openai', 'account_ref': 'work', 'model': 'model-b'}]
            config.write_text(json.dumps(policy), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a'*64, 'b'*64, 'c'*64)
            request = openai_model_request.prepare(self.contract, 'hello')
            initial = journal.create_fixture_model_chain(root, binding, self.contract, request, journal.TaskBudget(2, 4, '1.5', 2000))
            claim = journal.consume_fixture_model_request(root, binding, self.contract, request, 1, initial['revision'])
            body = b'{"error":{"type":"rate_limit_error","code":"slow_down"}}'
            terminal = journal._record_model_only_response(root, binding, self.contract, request, 1, claim['revision'], 429, body, 0)
            other = replace(self.contract, model='model-b')
            next_request = openai_model_request.prepare(other, 'hello')
            with patch.object(journal.fsx, 'fsync_dir', side_effect=OSError):
                with self.assertRaisesRegex(journal.JournalError, 'storage_unavailable'):
                    journal.reserve_model_only_next(root, binding, other, next_request, terminal['revision'])
            with patch.object(openai_model_request, '_data_admission_available', return_value=True), patch.object(openai_model_request, 'dispatch') as send:
                result = openai_model_request.resume_fixture_rotation(root, binding, (self.contract, other), 'hello', {'work': 'fake-test-key'})
                self.assertEqual(result['state'], 'unknown')
                send.assert_not_called()


if __name__ == '__main__':
    unittest.main()
