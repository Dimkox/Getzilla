from __future__ import annotations

import sys
import unittest
import json
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))

from getzilla import openai_model_request
from getzilla import model_continuation_state as journal
from tests.test_model_continuation import enabled_policy


class OpenAIModelRequestTest(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()
