from __future__ import annotations

import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla import model_data_admission as admission
from getzilla import model_continuation_state as journal
from getzilla import openai_model_request as requests
from tests.test_model_continuation import enabled_policy


class ModelDataAdmissionTest(unittest.TestCase):
    def test_preview_matches_exact_request_but_never_authorizes_dispatch(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(admission.time, 'time', return_value=1000):
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            policy = enabled_policy()
            policy['candidates'][0]['provider'] = 'openai'
            config.write_text(json.dumps(policy), encoding='utf-8')
            binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1', 'a'*64, 'b'*64, 'c'*64)
            contract = requests.Contract('model-a', 'work', 128, 1000, 100, '2', '10', 'rates1', 2000)
            request = requests.prepare(contract, 'private-text')
            account = admission.AccountReference('openai', 'work', 'handle-1', 'version-1')
            with self.assertRaises(admission.AdmissionError):
                admission.prepare_preview(root, binding, contract, request, account, 1, 1500)
            with patch('socket.socket') as socket:
                preview = admission.prepare_preview(root, binding, contract, request, account, 1, 1100)
                result = admission.recheck_preview(root, preview, binding, contract, request, account, 1)
                socket.assert_not_called()
            self.assertEqual(result['state'], 'ready_for_review')
            self.assertFalse(result['dispatch_permitted'])
            self.assertFalse(result['account_identity_verified'])
            self.assertNotIn('private-text', repr(preview))
            self.assertNotIn('handle-1', repr(account))
            self.assertFalse((root / '.getzilla/runtime').exists())
            with tempfile.TemporaryDirectory() as other_directory:
                other = Path(other_directory)
                other_config = other / '.getzilla/config/model-continuation.json'
                other_config.parent.mkdir(parents=True)
                other_config.write_text(json.dumps(policy), encoding='utf-8')
                with self.assertRaises(admission.AdmissionError):
                    admission.recheck_preview(other, preview, binding, contract, request, account, 1)
            with self.assertRaises(admission.AdmissionError):
                admission.recheck_preview(root, replace(preview, endpoint='https://wrong.invalid'), binding, contract, request, account, 1)
            with self.assertRaises(admission.AdmissionError):
                admission.recheck_preview(root, replace(preview, issued_epoch='bad'), binding, contract, request, account, 1)
            for changed_binding, changed_request, changed_account in (
                    (replace(binding, owner_id='other'), request, account),
                    (binding, requests.prepare(contract, 'changed'), account),
                    (binding, request, replace(account, version='version-2'))):
                with self.assertRaises(admission.AdmissionError):
                    admission.recheck_preview(root, preview, changed_binding, contract, changed_request, changed_account, 1)
            with patch.object(admission.time, 'time', return_value=999), self.assertRaises(admission.AdmissionError):
                admission.recheck_preview(root, preview, binding, contract, request, account, 1)
            with patch.object(admission.time, 'time', return_value=1100), self.assertRaises(admission.AdmissionError):
                admission.recheck_preview(root, preview, binding, contract, request, account, 1)
            policy['enabled'] = False
            config.write_text(json.dumps(policy), encoding='utf-8')
            with self.assertRaises(admission.AdmissionError):
                admission.recheck_preview(root, preview, binding, contract, request, account, 1)

    def test_resolver_requires_unique_exact_mapping_and_never_verifies_identity(self):
        target = admission.AccountReference('openai', 'work', 'handle-1', 'version-1')
        result = admission.resolve_account('openai', 'work', (target,))
        self.assertEqual(result.reference, target)
        self.assertFalse(result.account_identity_verified)
        with self.assertRaises(TypeError):
            admission.AccountResolution(target, True)
        with self.assertRaises(admission.AdmissionError):
            admission.resolve_account('openai', 'work', (target, replace(target, version='version-2')))
        with self.assertRaises(admission.AdmissionError):
            admission.resolve_account('openai', 'other', (target,))
        with self.assertRaises(admission.AdmissionError):
            admission.resolve_account('openai', 'work', (replace(target, handle='sk-secret'),))


if __name__ == '__main__':
    unittest.main()
