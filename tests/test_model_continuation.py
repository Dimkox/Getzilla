from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.model_continuation import classify_failure, load_policy, startup_status


def enabled_policy():
    return {'schema_version': 1, 'enabled': True,
            'candidates': [{'provider': 'native', 'account_ref': 'work', 'model': 'model-a'},
                           {'provider': 'other', 'account_ref': 'approved', 'model': 'org/model-b'}],
            'bounds': {'max_attempts': 2, 'max_requests': 4,
                       'deadline_seconds': 120, 'max_cost_usd': 1.5}}


class ModelContinuationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / '.getzilla/config/model-continuation.json'
        self.path.parent.mkdir(parents=True)

    def write(self, data):
        self.path.write_text(json.dumps(data), encoding='utf-8')

    def test_missing_disabled_configured_are_distinct(self):
        self.assertEqual(load_policy(self.root).state, 'missing')
        self.write({'schema_version': 1, 'enabled': False})
        self.assertEqual(load_policy(self.root).state, 'disabled')
        self.write(enabled_policy())
        loaded = load_policy(self.root)
        self.assertEqual(loaded.state, 'configured')
        self.assertEqual([c.model for c in loaded.policy.candidates], ['model-a', 'org/model-b'])
        for harness in ('grok', 'qwen', 'claude', 'codex', 'gemini', 'copilot'):
            with self.subTest(harness=harness):
                status = startup_status(self.root, harness)
                self.assertTrue(status['configured'])
                self.assertTrue(status['requested_enabled'])
                self.assertFalse(status['adapter_qualified'])
                self.assertFalse(status['continuation_available'])
                self.assertEqual(status['reason'], 'adapter_not_qualified')
                self.assertNotIn('account_ref', json.dumps(status))

    def test_closed_schema_and_finite_bounds(self):
        invalid = [None, [], {}, {'schema_version': True, 'enabled': False},
                   {'schema_version': 2, 'enabled': False},
                   {'schema_version': 1, 'enabled': 0},
                   {'schema_version': 1, 'enabled': False, 'token': 'SECRET'},
                   {'schema_version': 1, 'enabled': True}]
        for key in ('max_attempts', 'max_requests', 'deadline_seconds', 'max_cost_usd'):
            for value in (True, False, 0, -1, float('inf'), float('nan'), '1'):
                policy = enabled_policy()
                policy['bounds'][key] = value
                invalid.append(policy)
        for value in ([], [{}], [enabled_policy()['candidates'][0]] * 2):
            policy = enabled_policy()
            policy['candidates'] = value
            invalid.append(policy)
        for field in ('provider', 'account_ref', 'model'):
            for value in ('https://secret.invalid/token', 'secret\ntext', '', 'a' * 129, True):
                policy = enabled_policy()
                policy['candidates'][0][field] = value
                invalid.append(policy)
        for policy in invalid:
            with self.subTest(policy=policy):
                self.write(policy)
                self.assertEqual(load_policy(self.root).state, 'invalid')
                self.assertFalse(startup_status(self.root, 'codex')['continuation_available'])

    def test_provider_model_variant_is_an_opaque_identifier(self):
        policy = enabled_policy()
        model = 'nvidia/nemotron-3-ultra-550b-a55b:free'
        policy['candidates'][0]['model'] = model
        self.write(policy)
        loaded = load_policy(self.root)
        self.assertEqual(loaded.state, 'configured')
        self.assertEqual(loaded.policy.candidates[0].model, model)
        for field in ('provider', 'account_ref'):
            changed = enabled_policy()
            changed['candidates'][0][field] = 'ref:credential'
            self.write(changed)
            self.assertEqual(load_policy(self.root).state, 'invalid')

    def test_duplicate_keys_reject_an_otherwise_valid_policy(self):
        policy = enabled_policy()
        self.write(policy)
        self.assertEqual(load_policy(self.root).state, 'configured')
        duplicate = '{"enabled": false, ' + json.dumps(policy)[1:]
        self.assertEqual(json.loads(duplicate), policy)
        self.path.write_text(duplicate, encoding='utf-8')
        self.assertEqual(load_policy(self.root).state, 'invalid')

    def test_invalid_bytes_size_and_sanitized_diagnostics(self):
        for data in (b'\xff', b'{', b' ' * 16385, b'{"secret":"SECRET_SENTINEL"}'):
            self.path.write_bytes(data)
            self.assertEqual(load_policy(self.root).state, 'invalid')
            self.assertNotIn('SECRET', json.dumps(startup_status(self.root, 'SECRET\n')))

    def test_extreme_numeric_exponent_is_invalid(self):
        data = json.dumps(enabled_policy()).replace('"max_cost_usd": 1.5', '"max_cost_usd": 1e999999999999999999999')
        self.path.write_text(data, encoding='utf-8')
        self.assertEqual(load_policy(self.root).state, 'invalid')

    def test_nonregular_file_and_symlink_are_invalid(self):
        self.path.mkdir()
        self.assertEqual(load_policy(self.root).state, 'invalid')
        self.path.rmdir()
        if hasattr(os, 'symlink'):
            try:
                self.path.symlink_to(self.root / 'missing')
            except OSError:
                self.skipTest('symlinks unavailable')
            self.assertEqual(load_policy(self.root).state, 'invalid')
            self.path.unlink()
        if hasattr(os, 'mkfifo'):
            os.mkfifo(self.path)
            self.assertEqual(load_policy(self.root).state, 'invalid')

    def test_parent_symlink_and_read_failure_do_not_load(self):
        from getzilla import model_continuation
        with patch.object(model_continuation.fsx, 'open_dir', side_effect=PermissionError):
            self.assertEqual(load_policy(self.root).state, 'invalid')
        self.path.parent.rmdir()
        other = self.root / 'other'
        other.mkdir()
        (other / self.path.name).write_text(json.dumps(enabled_policy()), encoding='utf-8')
        try:
            self.path.parent.symlink_to(other, target_is_directory=True)
        except OSError:
            self.skipTest('symlinks unavailable')
        self.assertEqual(load_policy(self.root).state, 'invalid')

    def test_passive_status_never_probes_clients_or_network(self):
        self.write(enabled_policy())
        with patch('subprocess.run', side_effect=AssertionError('client probe')), \
                patch('socket.socket', side_effect=AssertionError('network probe')):
            self.assertFalse(startup_status(self.root, 'codex')['continuation_available'])

    def test_normalized_failure_table_and_non_model_origins(self):
        eligible = ('rate_limit', 'quota_exhausted', 'provider_unavailable',
                    'inference_transport_failure', 'generation_failure', 'inference_deadline')
        stop = ('cancelled', 'safety_refusal', 'policy_refusal', 'tool_failure', 'test_failure',
                'unknown', 'context_overflow', 'invalid_request', 'unsupported_tool',
                'slow_output', 'price', 'quality', 'task_kind', 'success', 'task_budget_exhausted')
        for category in (*eligible, *stop, 'authentication', 'billing'):
            event = {'schema_version': 1, 'origin': 'model', 'category': category}
            expected = 'eligible' if category in eligible else (
                'needs_action' if category in ('authentication', 'billing') else 'stop')
            self.assertEqual(classify_failure(event), expected)
            for origin in ('tool', 'test', 'user', '', None):
                self.assertEqual(classify_failure({**event, 'origin': origin}), 'stop')
        for event in (None, [], {}, {'origin': 'model', 'category': 'rate_limit'},
                      {'schema_version': True, 'origin': 'model', 'category': 'rate_limit'},
                      {'schema_version': 1, 'origin': 'model', 'category': 'rate_limit', 'willRetry': True}):
            self.assertEqual(classify_failure(event), 'stop')


    def test_six_startup_hooks_without_route_report_policy_once(self):
        shutil.copytree(ROOT / '.getzilla/getzilla', self.root / '.getzilla/getzilla',
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        shutil.copytree(ROOT / '.grok/hooks', self.root / '.grok/hooks',
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        for data, state in ((None, 'missing'), ({'schema_version': 1, 'enabled': False}, 'disabled'),
                            (enabled_policy(), 'configured'), ({'secret': 'NEVER_ECHO'}, 'invalid')):
            if data is not None:
                self.write(data)
            for harness in ('grok', 'qwen', 'claude', 'codex', 'gemini', 'copilot'):
                with self.subTest(state=state, harness=harness):
                    result = subprocess.run(
                        [sys.executable, str(self.root / '.grok/hooks/session_start.py'), '--harness', harness],
                        cwd=self.root, input=json.dumps({'cwd': str(self.root)}),
                        capture_output=True, text=True, timeout=15,
                        env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', 'HOME': str(self.root)})
                    self.assertEqual(result.returncode, 0, result.stderr)
                    output = json.loads(result.stdout)
                    if harness != 'copilot':
                        output = output['hookSpecificOutput']
                        self.assertEqual(output['hookEventName'], 'SessionStart')
                    context = output['additionalContext']
                    self.assertIn('No active route.', context)
                    self.assertEqual(context.count('Model continuation:'), 1)
                    self.assertIn(f'Model continuation: {state}; unavailable', context)
                    self.assertIn(f'harness={harness}', context)
                    self.assertNotIn('NEVER_ECHO', result.stdout)

    def test_status_cli_uses_project_policy_and_explicit_harness(self):
        shutil.copytree(ROOT / '.getzilla/getzilla', self.root / '.getzilla/getzilla',
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        (self.root / 'scripts').mkdir()
        shutil.copy2(ROOT / 'scripts/getzilla_status.py', self.root / 'scripts/getzilla_status.py')
        self.write(enabled_policy())
        result = subprocess.run(
            [sys.executable, str(self.root / 'scripts/getzilla_status.py'),
             '--model-continuation', '--harness', 'copilot'], cwd=self.root,
            capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        status = json.loads(result.stdout)
        self.assertEqual(status['policy_state'], 'configured')
        self.assertEqual(status['harness'], 'copilot')
        self.assertEqual(status['startup_visibility'], 'unqualified')
        self.assertFalse(status['continuation_available'])


    def test_selected_harness_archive_install_loads_its_own_policy(self):
        from scripts import install_into
        target = self.root / 'installed'
        self.write(enabled_policy())  # Outer project is enabled; installed project is disabled.
        install_into._materialize_new(
            ROOT, target, include_dependencies=False, include_optional=False,
            selection=install_into.PayloadSelection(('codex',), engine_archive=True))
        self.assertTrue((target / '.getzilla/getzilla.zip').is_file())
        self.assertFalse((target / '.getzilla/getzilla/model_continuation.py').exists())
        self.assertFalse((target / '.claude').exists())
        result = subprocess.run(
            [sys.executable, str(target / '.grok/hooks/session_start.py'), '--harness', 'codex'],
            cwd=target, input=json.dumps({'cwd': str(target)}), capture_output=True,
            text=True, timeout=15, env={**os.environ, 'HOME': str(self.root)})
        self.assertEqual(result.returncode, 0, result.stderr)
        context = json.loads(result.stdout)['hookSpecificOutput']['additionalContext']
        self.assertIn('Model continuation: disabled;', context)
        config = json.loads((target / '.codex/hooks.json').read_text(encoding='utf-8'))
        self.assertIn("'--harness','codex'", json.dumps(config['hooks']['SessionStart']))


if __name__ == '__main__':
    unittest.main()
