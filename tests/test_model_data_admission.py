from __future__ import annotations

import json
import sys
import tempfile
import unittest
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla import model_data_admission as admission
from getzilla import model_continuation_state as journal
from getzilla import openai_model_request as requests
from getzilla import metrics_journal, state
from tests.test_model_continuation import enabled_policy


class ModelDataAdmissionTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'repository'
        self.config = self.root / '.getzilla/config/model-continuation.json'
        self.config.parent.mkdir(parents=True)
        self.policy = enabled_policy()
        self.policy['candidates'][0]['provider'] = 'openai'
        self.write_policy()
        self.binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1',
                                       'a' * 64, 'b' * 64, 'c' * 64)
        self.contract = requests.Contract('model-a', 'work', 128, 1000, 100,
                                          '2', '10', 'rates1', 2000)
        self.request = requests.prepare(self.contract, 'private-text-canary')
        self.account = admission.AccountReference('openai', 'work', 'private-handle-canary', 'version-1')
        clock_patch = patch.object(admission.time, 'time', return_value=1000)
        self.clock = clock_patch.start()
        self.addCleanup(clock_patch.stop)

    def write_policy(self):
        self.config.write_text(json.dumps(self.policy), encoding='utf-8')

    def prepare(self, **changes):
        inputs = dict(root=self.root, binding=self.binding, contract=self.contract,
                      request=self.request, account=self.account, generation=1,
                      revision=1, expires_epoch=1100)
        return admission.prepare_preview(**(inputs | changes))

    def recheck(self, preview, **changes):
        inputs = dict(root=self.root, preview=preview, binding=self.binding, contract=self.contract,
                      request=self.request, account=self.account, generation=1, revision=1)
        return admission.recheck_preview(**(inputs | changes))

    def test_valid_preview_is_non_authorizing_and_private(self):
        preview = self.prepare()
        result = self.recheck(preview)
        self.assertEqual(result, {'state': 'ready_for_review', 'dispatch_permitted': False,
                                  'account_identity_verified': False})
        self.assertEqual(preview.endpoint, 'https://api.openai.com/v1/responses')
        self.assertEqual(preview.request_bytes, len(self.request.body))
        self.assertEqual(preview.revision, 1)
        self.assertEqual(preview.issued_epoch, 1000)
        self.assertEqual(preview.expires_epoch, 1100)
        public = repr(preview) + repr(self.account) + repr(result)
        for private in ('private-text-canary', 'private-handle-canary', preview.request_digest):
            self.assertNotIn(private, public)
        self.assertFalse((self.root / '.getzilla/runtime').exists())

    def test_each_binding_field_is_rechecked(self):
        preview = self.prepare()
        for field, value in (('chain_id', 'chain2'), ('task_id', 'task2'),
                             ('owner_id', 'owner2'), ('route_id', 'route2'),
                             ('session_id', 'session2'), ('workspace_digest', 'd' * 64),
                             ('source_digest', 'e' * 64), ('checkpoint_digest', 'f' * 64)):
            with self.subTest(field=field), self.assertRaises(admission.AdmissionError):
                self.recheck(preview, binding=replace(self.binding, **{field: value}))
        self.assertEqual(self.recheck(preview)['state'], 'ready_for_review')

    def test_request_bytes_and_every_contract_field_are_bound(self):
        preview = self.prepare()
        with self.assertRaises(admission.AdmissionError):
            self.recheck(preview, request=requests.prepare(self.contract, 'changed-private-text'))
        fields = (('model', 'model-b'), ('account_ref', 'other'), ('max_input_bytes', 256),
                  ('max_input_tokens', 1001), ('max_output_tokens', 101),
                  ('input_usd_per_million', '3'), ('output_usd_per_million', '11'),
                  ('rate_revision', 'rates2'), ('expires_epoch', 2001), ('schema_version', 2))
        for field, value in fields:
            with self.subTest(field=field), self.assertRaises(admission.AdmissionError):
                self.recheck(preview, contract=replace(self.contract, **{field: value}))

    def test_every_account_field_and_generation_are_bound(self):
        preview = self.prepare()
        for field, value in (('provider', 'other'), ('account_ref', 'other'),
                             ('handle', 'other-handle'), ('version', 'version-2')):
            with self.subTest(field=field), self.assertRaises(admission.AdmissionError):
                self.recheck(preview, account=replace(self.account, **{field: value}))
        with self.assertRaises(admission.AdmissionError):
            self.recheck(preview, generation=2)

    def test_revision_reference_is_bound_without_reading_a_journal(self):
        preview = self.prepare(revision=7)
        self.assertEqual(self.recheck(preview, revision=7)['state'], 'ready_for_review')
        with self.assertRaises(admission.AdmissionError):
            self.recheck(preview, revision=8)
        self.assertFalse((self.root / '.getzilla/runtime').exists())

    def test_each_preview_field_rejects_independent_mutation(self):
        preview = self.prepare()
        for field, value in (('root_digest', '0' * 64), ('binding_digest', '0' * 64),
                             ('contract_digest', '0' * 64), ('policy_digest', '0' * 64),
                             ('request_digest', '0' * 64), ('request_bytes', 1),
                             ('account_digest', '0' * 64), ('generation', 2), ('revision', 2),
                             ('issued_epoch', 999), ('expires_epoch', 1110),
                             ('endpoint', 'https://other.invalid/v1/responses'),
                             ('preview_digest', '0' * 64)):
            with self.subTest(field=field), self.assertRaises(admission.AdmissionError):
                self.recheck(replace(preview, **{field: value}))

    def test_malformed_preview_never_exposes_private_values(self):
        preview = self.prepare()
        invalid = [None, object()]
        for field in ('issued_epoch', 'expires_epoch', 'request_bytes', 'generation', 'revision'):
            invalid.extend(replace(preview, **{field: value})
                           for value in (True, False, 0, -1, 'private-clock-canary'))
        for field in ('root_digest', 'binding_digest', 'contract_digest', 'policy_digest',
                      'request_digest', 'account_digest', 'preview_digest'):
            invalid.extend(replace(preview, **{field: value}) for value in (None, True, 'private-digest-canary'))
        for index, changed in enumerate(invalid):
            with self.subTest(index=index), self.assertRaises(admission.AdmissionError) as caught:
                self.recheck(changed)
            self.assertEqual(str(caught.exception), 'invalid_preview')

    def test_account_resolution_requires_unique_exact_metadata(self):
        other = replace(self.account, account_ref='other', handle='other-handle')
        resolved = admission.resolve_account('openai', 'work', (self.account, other))
        self.assertEqual(resolved.reference, self.account)
        self.assertFalse(resolved.account_identity_verified)
        self.assertNotIn('private-handle-canary', repr(resolved))
        with self.assertRaises(TypeError):
            admission.AccountResolution(self.account, True)
        for records in ((), [], None, (other,), (self.account, self.account),
                        (self.account, replace(self.account, version='version-2')),
                        (replace(self.account, handle='sk-secret-canary'),),
                        (self.account,) * 65, (None,)):
            with self.subTest(records_count=len(records) if isinstance(records, (tuple, list)) else None):
                with self.assertRaises(admission.AdmissionError) as caught:
                    admission.resolve_account('openai', 'work', records)
                self.assertIn(str(caught.exception), ('account_mapping_invalid', 'account_mapping_ambiguous'))

    def test_missing_or_malformed_account_cannot_prepare(self):
        invalid = [None, {}, admission.AccountResolution(self.account)]
        for field in ('provider', 'account_ref', 'handle', 'version'):
            invalid.extend(replace(self.account, **{field: value})
                           for value in ('', 'sk-secret-canary', 'a' * 65, True, 'private\ntext'))
        for index, account in enumerate(invalid):
            with self.subTest(index=index), self.assertRaisesRegex(admission.AdmissionError, '^invalid_account_reference$'):
                self.prepare(account=account)

    def test_malformed_and_noncanonical_requests_are_denied(self):
        body = self.request.body
        invalid = (b'', b'{private-invalid-canary', b'\xff', b'[]', b'null',
                   body + b' ', body.replace(b'"store":false', b'"store":true'),
                   body.replace(b'"model":"model-a"', b'"model":"model-a","model":"model-a"'),
                   body.replace(b'"max_output_tokens":100', b'"max_output_tokens":100.0'),
                   body.replace(b'"max_output_tokens":100', b'"max_output_tokens":true'),
                   body.replace(b'"input":"private-text-canary"', b'"input":null'),
                   body.replace(b'"store":false', b'"store":false,"extra":"private-extra-canary"'),
                   body.decode().encode('utf-16'), b' ' * 4_000_001,
                   b'[' * 2000 + b'0' + b']' * 2000)
        for index, malformed in enumerate(invalid):
            with self.subTest(index=index), self.assertRaisesRegex(admission.AdmissionError, '^preflight_denied$'):
                self.prepare(request=replace(self.request, body=malformed))
        for malformed in (self.request.body.decode(), bytearray(body), None):
            with self.subTest(type=type(malformed).__name__), self.assertRaises(admission.AdmissionError):
                self.prepare(request=replace(self.request, body=malformed))
        self.assertEqual(self.recheck(self.prepare())['state'], 'ready_for_review')

    def test_reserved_cost_requires_an_integer_even_when_true_equals_one(self):
        contract = replace(self.contract, max_input_tokens=1, max_output_tokens=1,
                           input_usd_per_million='0.1', output_usd_per_million='0.1')
        request = requests.prepare(contract, 'private-text-canary')
        self.assertEqual(request.reserved_cost_micros, 1)
        preview = self.prepare(contract=contract, request=request)
        self.assertEqual(self.recheck(preview, contract=contract, request=request)['state'], 'ready_for_review')
        for value in (True, 1.0, '1', 0, -1, None):
            with self.subTest(value=value), self.assertRaises(admission.AdmissionError):
                self.prepare(contract=contract, request=replace(request, reserved_cost_micros=value))

    def test_invalid_numeric_and_binding_inputs_fail_closed(self):
        for field in ('generation', 'revision', 'expires_epoch'):
            for value in (True, False, 0, -1, 1.0, 'private-number-canary', None):
                with self.subTest(field=field, value=value), self.assertRaises(admission.AdmissionError):
                    self.prepare(**{field: value})
        for field, value in (('generation', 65), ('revision', 1_000_000_001),
                             ('expires_epoch', journal.MAX_EPOCH_SECONDS + 1)):
            with self.subTest(field=field), self.assertRaises(admission.AdmissionError):
                self.prepare(**{field: value})
        for field in ('max_input_bytes', 'max_input_tokens', 'max_output_tokens', 'expires_epoch', 'schema_version'):
            with self.subTest(field=field), self.assertRaises(admission.AdmissionError):
                self.prepare(contract=replace(self.contract, **{field: True}))
        for binding in (None, {}, replace(self.binding, chain_id=True), replace(self.binding, source_digest='private-source-canary')):
            with self.assertRaisesRegex(admission.AdmissionError, '^preflight_denied$'):
                self.prepare(binding=binding)

    def test_expiry_is_bounded_by_contract_and_policy(self):
        self.assertEqual(self.prepare(expires_epoch=1120).expires_epoch, 1120)
        for expiry in (1000, 999, 1121, 1500, 2001):
            with self.subTest(expiry=expiry), self.assertRaises(admission.AdmissionError):
                self.prepare(expires_epoch=expiry)
        with self.assertRaises(admission.AdmissionError):
            self.prepare(contract=replace(self.contract, expires_epoch=1099))

    def test_recheck_expires_and_refuses_clock_rollback(self):
        preview = self.prepare()
        self.clock.return_value = 1099
        self.assertEqual(self.recheck(preview)['state'], 'ready_for_review')
        for now in (999, 1100, 1101):
            self.clock.return_value = now
            with self.subTest(now=now), self.assertRaisesRegex(admission.AdmissionError, '^expired_or_clock_uncertain$'):
                self.recheck(preview)

    def test_invalid_clock_is_a_fixed_private_free_error(self):
        preview = self.prepare()
        for now in (True, False, 0, -1, float('nan'), float('inf'), 'private-clock-canary', None):
            self.clock.return_value = now
            for operation in (self.prepare, lambda: self.recheck(preview)):
                with self.subTest(now=now), self.assertRaisesRegex(admission.AdmissionError, '^clock_uncertain$'):
                    operation()

    def test_changed_or_revoked_policy_denies_recheck(self):
        preview = self.prepare()
        self.policy['bounds']['deadline_seconds'] = 119
        self.write_policy()
        with self.assertRaisesRegex(admission.AdmissionError, '^preview_changed$'):
            self.recheck(preview)
        self.policy['enabled'] = False
        self.write_policy()
        with self.assertRaisesRegex(admission.AdmissionError, '^preflight_denied$'):
            self.recheck(preview)
        self.config.write_bytes(b'{"private-policy-canary":')
        with self.assertRaisesRegex(admission.AdmissionError, '^preflight_denied$'):
            self.recheck(preview)
        self.config.unlink()
        with self.assertRaisesRegex(admission.AdmissionError, '^preflight_denied$'):
            self.recheck(preview)

    def test_root_replacement_denies_recheck(self):
        preview = self.prepare()
        self.root.rename(self.root.with_name('retained-root'))
        self.config.parent.mkdir(parents=True)
        self.write_policy()
        with self.assertRaisesRegex(admission.AdmissionError, '^preview_changed$'):
            self.recheck(preview)

    def test_root_change_during_policy_read_is_denied(self):
        real_policy = journal._policy

        def replace_after_read(root):
            result = real_policy(root)
            self.root.rename(self.root.with_name('retained-root'))
            self.config.parent.mkdir(parents=True)
            self.write_policy()
            return result

        with patch.object(journal, '_policy', side_effect=replace_after_read):
            with self.assertRaisesRegex(admission.AdmissionError, '^preflight_denied$'):
                self.prepare()

    def test_root_change_during_request_validation_is_denied(self):
        real_prepare = requests.prepare

        def replace_after_validation(contract, text):
            result = real_prepare(contract, text)
            self.root.rename(self.root.with_name('retained-root'))
            self.config.parent.mkdir(parents=True)
            self.write_policy()
            return result

        with patch.object(requests, 'prepare', side_effect=replace_after_validation):
            with self.assertRaisesRegex(admission.AdmissionError, '^preflight_denied$'):
                self.prepare()

    def test_private_filesystem_failures_are_sanitized(self):
        with patch.object(journal.fsx, 'open_dir', side_effect=OSError('private-path-canary')):
            with self.assertRaisesRegex(admission.AdmissionError, '^preflight_denied$') as caught:
                self.prepare()
        self.assertIsNone(caught.exception.__cause__)

    @unittest.skipIf(sys.platform == 'win32', 'directory fsync is unsupported on Windows')
    def test_preview_and_denial_leave_budget_and_runtime_unchanged(self):
        initial = journal.create_model_only_chain(self.root, self.binding, self.contract,
                                                  self.request, journal.TaskBudget(2, 4, '1.5', 2000))
        before = journal.inspect_chain(self.root, self.binding)
        runtime = self.root / '.getzilla/runtime'
        files_before = {p.relative_to(runtime).as_posix(): p.read_bytes()
                        for p in runtime.rglob('*') if p.is_file()}
        real_open_at = journal.fsx.open_at

        def policy_only(parent, name, flags, *args, **kwargs):
            if name != 'model-continuation.json':
                raise AssertionError('unexpected file read or write')
            return real_open_at(parent, name, flags, *args, **kwargs)

        with ExitStack() as guards:
            for target in ('socket.socket', 'http.client.HTTPSConnection', 'subprocess.Popen',
                           'builtins.open', 'pathlib.Path.open'):
                guards.enter_context(patch(target, side_effect=AssertionError('unexpected external or file operation')))
            for module, method in ((journal, '_store'), (state, 'add_approval'), (metrics_journal, 'record')):
                guards.enter_context(patch.object(module, method, side_effect=AssertionError('unexpected state mutation')))
            guards.enter_context(patch.object(journal.fsx, 'open_at', side_effect=policy_only))
            preview = self.prepare(revision=initial['revision'])
            self.assertFalse(self.recheck(preview, revision=initial['revision'])['dispatch_permitted'])
            with self.assertRaises(admission.AdmissionError):
                self.recheck(preview, request=requests.prepare(self.contract, 'changed'))
            with self.assertRaisesRegex(requests.RequestError, '^data_admission_unavailable$'):
                requests.dispatch(self.root, self.binding, self.contract, self.request,
                                  1, initial['revision'], object())
        self.assertEqual(journal.inspect_chain(self.root, self.binding), before)
        self.assertEqual({p.relative_to(runtime).as_posix(): p.read_bytes()
                          for p in runtime.rglob('*') if p.is_file()}, files_before)
        self.assertEqual(before['attempts'][0]['state'], 'reserved_unknown')
        self.assertEqual(before['attempts'][0]['cost_micros'], 3000)


if __name__ == '__main__':
    unittest.main()
