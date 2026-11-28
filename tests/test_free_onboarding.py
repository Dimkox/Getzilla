from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import model_continuation as continuation


def free_policy():
    return {'schema_version': 1, 'enabled': True,
            'candidates': [{'provider': 'openrouter', 'account_ref': 'free-account',
                            'model': 'vendor/writer:free'},
                           {'provider': 'openrouter', 'account_ref': 'free-account',
                            'model': 'vendor/reviewer:free'}],
            'bounds': {'max_attempts': 2, 'max_requests': 4,
                       'deadline_seconds': 60, 'max_cost_usd': 1},
            'admission': {'profile': 'openrouter-free', 'observed_epoch': 1000,
                          'expires_epoch': 1060,
                          'models': [
                              {'id': model, 'pricing': {'prompt': '0', 'completion': '0', 'request': '0'}}
                              for model in ['vendor/writer:free', 'vendor/reviewer:free']]}}


class FreePolicyTests(unittest.TestCase):
    def parse(self, value, now=1000):
        with patch('time.time', return_value=now):
            return continuation._parse(json.dumps(value).encode())

    def test_explicit_profile_admits_every_free_candidate(self):
        policy = self.parse(free_policy())
        self.assertEqual(policy.admission.profile, 'openrouter-free')
        self.assertEqual(len(policy.candidates), 2)

    def test_all_positions_and_price_components_refuse_paid_or_unknown(self):
        for index in range(2):
            for mutation in ('paid', 'unknown', 'provider', 'alias', 'price', 'missing', 'extra_charge'):
                value = free_policy()
                if mutation == 'paid':
                    value['candidates'][index]['model'] = 'vendor/paid'
                elif mutation == 'unknown':
                    value['candidates'][index]['model'] = 'vendor/unknown:free'
                elif mutation == 'provider':
                    value['candidates'][index]['provider'] = 'other'
                elif mutation == 'alias':
                    value['candidates'][index]['model'] = 'openrouter/free'
                elif mutation == 'price':
                    value['admission']['models'][index]['pricing']['prompt'] = '0.000001'
                elif mutation == 'missing':
                    del value['admission']['models'][index]['pricing']['completion']
                else:
                    value['admission']['models'][index]['pricing']['image'] = '1'
                with self.subTest(index=index, mutation=mutation), self.assertRaises(ValueError):
                    self.parse(value)

    def test_current_observation_is_required_at_each_parse(self):
        for now in (999, 1060, 1061):
            with self.subTest(now=now), self.assertRaises(ValueError):
                self.parse(free_policy(), now=now)
        value = free_policy()
        value['admission']['expires_epoch'] = 1400
        with self.assertRaises(ValueError):
            self.parse(value)

    def test_unknown_nonfinite_negative_and_boolean_prices_refuse(self):
        for price in (None, True, 0, '-0', '-1', 'NaN', 'Infinity', 'unknown', '', '0e999999'):
            value = free_policy()
            value['admission']['models'][0]['pricing']['prompt'] = price
            with self.subTest(price=price), self.assertRaises(ValueError):
                self.parse(value)

    def test_existing_paid_policy_is_unchanged_without_opt_in(self):
        value = free_policy()
        del value['admission']
        value['candidates'][0]['model'] = 'vendor/paid'
        before = copy.deepcopy(value)
        self.assertIsNone(self.parse(value).admission)
        self.assertEqual(value, before)

    def test_duplicate_extra_or_missing_catalog_entries_refuse(self):
        for mutation in ('duplicate', 'extra', 'missing'):
            value = free_policy()
            models = value['admission']['models']
            if mutation == 'duplicate':
                models.append(copy.deepcopy(models[0]))
            elif mutation == 'extra':
                models.append({'id': 'vendor/extra:free', 'pricing': {'prompt': '0', 'completion': '0', 'request': '0'}})
            else:
                models.pop()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.parse(value)


class OpenRouterRehearsalTests(unittest.TestCase):
    def run_fixture(self, steps):
        from tempfile import TemporaryDirectory
        from getzilla.free_onboarding import rehearse_openrouter
        policy = free_policy()
        with TemporaryDirectory() as directory, patch('time.time', return_value=1000):
            config = Path(directory) / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps(policy))
            return rehearse_openrouter(Path(directory), 'vendor/writer:free', steps)

    def step(self, role='writer', outcome='ok'):
        return {'role': role, 'observation': free_policy()['admission'], 'outcome': outcome}

    def test_all_roles_require_zero_prices_again_before_each_request(self):
        for role in ('writer', 'reviewer', 'helper', 'fallback'):
            changed = self.step(role)
            changed['observation']['models'][0]['pricing']['tool'] = '0.1'
            result = self.run_fixture([self.step(), changed])
            self.assertEqual(result['reason'], 'admission_price_unknown_or_paid')
            self.assertEqual((result['checkpoint'], result['requests']), (1, 1))
            self.assertFalse(result['dispatch_permitted'])
            self.assertEqual(result['qualification'], 'NOT_TESTED')

    def test_rate_or_quota_stops_at_last_completed_checkpoint(self):
        for outcome in ('429', 'quota_exhausted'):
            result = self.run_fixture([self.step(), self.step('helper', outcome), self.step('fallback')])
            self.assertEqual(result['reason'], outcome)
            self.assertEqual((result['checkpoint'], result['requests']), (1, 2))

    def test_stale_observation_and_fallback_substitution_refuse_without_send(self):
        stale = self.step()
        stale['observation']['expires_epoch'] = 1000
        changed_model = dict(self.step('fallback'), model='vendor/paid')
        for step in (stale, changed_model):
            self.assertEqual(self.run_fixture([step])['requests'], 0)


def local_policy():
    value = free_policy()
    value['candidates'] = [{'provider': 'ollama', 'account_ref': 'local', 'model': 'local-code:q4'}]
    value['bounds']['max_attempts'] = 1
    value['admission'] = {
        'profile': 'ollama-local-qwen', 'endpoint': 'http://127.0.0.1:11434/v1',
        'network': 'closed', 'client': 'qwen', 'client_version': '1.0.0',
        'server_version': '1.0.0', 'os': 'linux-x64',
        'resources': {'memory_bytes': 1000000000, 'disk_bytes': 1000000000, 'max_output_bytes': 1000000},
        'models': [{'id': 'local-code:q4', 'digest': 'a' * 64, 'tokenizer': 'example-v1',
                    'format': 'gguf', 'quantization': 'Q4_K_M', 'context_tokens': 8192,
                    'tools': True}]}
    return value


class LocalPolicyTests(unittest.TestCase):
    parse = FreePolicyTests.parse
    def test_local_profile_is_explicit_and_not_native_qualification(self):
        self.assertEqual(self.parse(local_policy()).admission.profile, 'ollama-local-qwen')

    def test_cloud_lan_and_unknown_versions_resources_or_capabilities_refuse(self):
        mutations = [('endpoint', 'http://example.test/v1'),
                     ('endpoint', 'http://192.168.1.1:11434/v1'),
                     ('network', 'open'), ('client', 'codex'), ('client_version', ''),
                     ('server_version', 'latest')]
        for key, bad in mutations:
            value = local_policy()
            value['admission'][key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                self.parse(value)
        for key in ('memory_bytes', 'disk_bytes', 'max_output_bytes'):
            value = local_policy()
            value['admission']['resources'][key] = 0
            with self.subTest(resource=key), self.assertRaises(ValueError):
                self.parse(value)
        for key, bad in (('tools', False), ('context_tokens', 0), ('digest', 'unknown'),
                         ('tokenizer', ''), ('quantization', 'unknown')):
            value = local_policy()
            value['admission']['models'][0][key] = bad
            with self.subTest(model_field=key), self.assertRaises(ValueError):
                self.parse(value)

    def test_no_cloud_reviewer_auxiliary_or_fallback_in_local_profile(self):
        for provider, model in (('openrouter', 'vendor/reviewer:free'), ('ollama', 'local-code:cloud'),
                                ('ollama', 'unknown-model:q4')):
            value = local_policy()
            value['candidates'].append({'provider': provider, 'account_ref': 'local', 'model': model})
            with self.subTest(provider=provider, model=model), self.assertRaises(ValueError):
                self.parse(value)


class OnboardingStatusTests(unittest.TestCase):
    def test_status_never_claims_configuration_is_qualified_or_writes_paid_settings(self):
        import tempfile
        from getzilla import free_onboarding
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / '.getzilla/config/model-continuation.json'
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps(local_policy()))
            paid = root / '.qwen/settings.json'
            paid.parent.mkdir()
            paid.write_bytes(b'paid settings must remain unchanged')
            before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            status = free_onboarding.onboarding_status(root)
            self.assertEqual(status['profile'], 'ollama-local-qwen')
            self.assertEqual(status['qualification'], 'NOT_TESTED')
            self.assertFalse(status['dispatch_permitted'])
            self.assertFalse(status['network_isolation_verified'])
            after = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            self.assertEqual(before, after)


@unittest.skipIf(sys.platform == 'win32', 'durable journal requires directory fsync')
class FreeJournalTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        from getzilla import model_continuation_state as journal
        self.journal = journal
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = self.root / '.getzilla/config/model-continuation.json'
        self.config.parent.mkdir(parents=True)
        self.policy = free_policy()
        self.config.write_text(json.dumps(self.policy))
        self.work = self.root / 'work.txt'
        self.work.write_bytes(b'preserve original and partial work')
        self.binding = journal.Binding('chain1', 'task1', 'owner1', 'route1', 'session1',
                                       'a'*64, 'b'*64, 'c'*64)
        self.budget = journal.TaskBudget(2, 2, '1', 1060)
        clock = patch('time.time', return_value=1000)
        clock.start()
        self.addCleanup(clock.stop)

    def test_nonzero_observed_cost_is_refused_before_free_chain(self):
        with self.assertRaisesRegex(ValueError, 'free_charge_denied'):
            self.journal.create_controlled_chain(self.root, self.binding, self.journal.Usage(1, '0.1'), self.budget)

    def test_429_and_quota_keep_existing_retry_budget_cancel_and_work(self):
        j = self.journal
        j.create_controlled_chain(self.root, self.binding, j.Usage(1, '0'), self.budget)
        j.consume_controlled_send(self.root, self.binding, 1, 1)
        j.record_controlled_terminal(self.root, self.binding, 1, 2, 'rate_limit')
        self.assertEqual(j.reserve_controlled_next(self.root, self.binding, 3, j.Usage(1, '0'))['generation'], 2)
        j.consume_controlled_send(self.root, self.binding, 2, 4)
        j.record_controlled_terminal(self.root, self.binding, 2, 5, 'quota_exhausted')
        self.assertEqual(j.reserve_controlled_next(self.root, self.binding, 6, j.Usage(1, '0'))['reason'], 'budget_exhausted')
        self.assertEqual(j.cancel_controlled_chain(self.root, self.binding, 6)['state'], 'cancelled')
        self.assertEqual(self.work.read_bytes(), b'preserve original and partial work')

    def test_changed_paid_fallback_or_expired_price_never_reserves(self):
        j = self.journal
        for mode in ('paid_fallback', 'expiry'):
            with self.subTest(mode=mode):
                self.config.write_text(json.dumps(self.policy))
                binding = j.Binding('chain_' + mode, 'task_' + mode, 'owner1', 'route1', 'session1',
                                    'a'*64, 'b'*64, 'c'*64)
                j.create_controlled_chain(self.root, binding, j.Usage(1, '0'), self.budget)
                j.consume_controlled_send(self.root, binding, 1, 1)
                j.record_controlled_terminal(self.root, binding, 1, 2, 'provider_unavailable')
                changed = copy.deepcopy(self.policy)
                if mode == 'paid_fallback':
                    changed['candidates'][1]['model'] = 'vendor/paid'
                else:
                    changed['admission']['expires_epoch'] = 1000
                self.config.write_text(json.dumps(changed))
                result = j.reserve_controlled_next(self.root, binding, 3, j.Usage(1, '0'))
                self.assertEqual(result['reason'], 'policy_revoked')
                self.assertFalse(result['dispatch_permitted'])
                self.assertEqual(self.work.read_bytes(), b'preserve original and partial work')

    def test_paid_policy_digest_stays_compatible(self):
        from dataclasses import asdict
        j = self.journal
        value = free_policy()
        del value['admission']
        self.config.write_text(json.dumps(value))
        policy, digest = j._policy(self.root)
        data = asdict(policy)
        data.pop('admission')
        self.assertEqual(digest, j._digest(data))


class MalformedProfileTests(unittest.TestCase):
    def test_local_container_values_remain_closed_policy_errors(self):
        import tempfile
        for field in ('os', 'client', 'client_version', 'resources', 'models', 'endpoint'):
            for bad in (None, [], {}, True):
                value = local_policy()
                value['admission'][field] = bad
                with self.subTest(field=field, bad=bad), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    config = root / '.getzilla/config/model-continuation.json'
                    config.parent.mkdir(parents=True)
                    config.write_text(json.dumps(value))
                    self.assertEqual(continuation.load_policy(root).state, 'invalid')


class OllamaSetupTests(unittest.TestCase):
    def test_preview_apply_repeat_and_rollback_with_a_changed_policy(self):
        import os
        import tempfile
        from unittest import mock
        from scripts import getzilla_setup_agent

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.getzilla/config').mkdir(parents=True)
            (root / '.getzilla/AGBP_SYNC.json').write_text('{}')
            target = root / continuation.POLICY_PATH
            previous = b'{ "schema_version": 1, "enabled": false }\n'
            target.write_bytes(previous)
            declaration = root / 'ollama-profile.json'
            declaration.write_text(json.dumps(local_policy()))
            with mock.patch('pathlib.Path.cwd', return_value=root), mock.patch('socket.socket',
                    side_effect=AssertionError('network access')), mock.patch('subprocess.Popen',
                    side_effect=AssertionError('external command')), mock.patch.dict(os.environ, {}, clear=True):
                def run(*args):
                    import io
                    stream = io.StringIO()
                    with mock.patch('sys.stdout', stream):
                        self.assertEqual(getzilla_setup_agent.main(['ollama', *args]), 0)
                    return json.loads(stream.getvalue())

                preview = run('preview')
                self.assertEqual(preview['qualification'], 'NOT_TESTED')
                self.assertFalse(preview['dispatch_permitted'])
                self.assertIn('a' * 64, preview['diff'])
                self.assertEqual(target.read_bytes(), previous)
                self.assertFalse((root / '.getzilla/runtime').exists())
                ticket = preview['token']
                for key, value in [('endpoint', 'http://example.invalid/v1'), ('client_version', '')]:
                    bad = local_policy()
                    bad['admission'][key] = value
                    declaration.write_text(json.dumps(bad))
                    self.assertEqual(getzilla_setup_agent.main(['ollama', 'apply', ticket]), 2)
                    self.assertEqual(target.read_bytes(), previous)
                bad = local_policy()
                bad['admission']['models'][0]['digest'] = 'latest'
                declaration.write_text(json.dumps(bad))
                self.assertEqual(getzilla_setup_agent.main(['ollama', 'preview']), 2)
                bad = local_policy()
                bad['candidates'].append(free_policy()['candidates'][0])
                declaration.write_text(json.dumps(bad))
                self.assertEqual(getzilla_setup_agent.main(['ollama', 'apply', ticket]), 2)
                declaration.write_text(json.dumps(local_policy()) + ' ')
                self.assertEqual(getzilla_setup_agent.main(['ollama', 'apply', ticket]), 2)
                self.assertEqual(target.read_bytes(), previous)
                declaration.write_text(json.dumps(local_policy()))
                self.assertEqual(run('apply', ticket)['state'], 'applied')
                applied = target.read_bytes()
                self.assertEqual(run('apply', ticket)['state'], 'unchanged')
                target.write_bytes(applied + b' ')
                self.assertEqual(getzilla_setup_agent.main(['ollama', 'rollback', ticket]), 2)
                self.assertEqual(target.read_bytes(), applied + b' ')
                target.write_bytes(applied)
                self.assertEqual(run('rollback', ticket)['state'], 'restored')
                self.assertEqual(target.read_bytes(), previous)


if __name__ == '__main__':
    unittest.main()
