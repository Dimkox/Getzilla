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


def _startup_stage(code, stdout, harness, state):
    """Return only a closed stage; never retain child output in diagnostics."""
    if code != 0:
        return 'nonzero'
    try:
        output = json.loads(stdout)
    except (TypeError, ValueError):
        return 'json'
    if not isinstance(output, dict):
        return 'shape'
    if harness != 'copilot':
        output = output.get('hookSpecificOutput')
        if not isinstance(output, dict):
            return 'shape'
        if output.get('hookEventName') != 'SessionStart':
            return 'event'
    context = output.get('additionalContext')
    if not isinstance(context, str):
        return 'context'
    if 'No active route.' not in context:
        return 'no-route'
    if context.count('Model continuation:') != 1:
        return 'note-count'
    if f'Model continuation: {state}; unavailable' not in context:
        return 'policy-state'
    if f'harness={harness}' not in context:
        return 'harness-note'
    if 'NEVER_ECHO' in stdout:
        return 'canary'
    return 'ok'


def _startup_hook_stage(root, harness, state):
    # Fail outside exception handlers: traceback chaining must not expose child values.
    stage = None
    try:
        result = subprocess.run(
            [sys.executable, str(root / '.getzilla/hooks/session_start.py'), '--harness', harness],
            cwd=root, input=json.dumps({'cwd': str(root)}),
            capture_output=True, text=True, timeout=15,
            env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', 'HOME': str(root)})
    except subprocess.TimeoutExpired:
        stage = 'timeout'
    except OSError:
        stage = 'spawn'
    if stage is not None:
        return stage
    return _startup_stage(result.returncode, result.stdout, harness, state)


def _assert_startup_stage(case, stage, state, harness):
    if stage == 'ok':
        return
    with case.subTest(diagnostic='stage'):
        if stage == 'timeout':
            case.fail('startup stage=timeout')
        if stage == 'spawn':
            case.fail('startup stage=spawn')
        if stage == 'nonzero':
            case.fail('startup stage=nonzero')
        if stage == 'json':
            case.fail('startup stage=json')
        if stage == 'shape':
            case.fail('startup stage=shape')
        if stage == 'event':
            case.fail('startup stage=event')
        if stage == 'context':
            case.fail('startup stage=context')
        if stage == 'no-route':
            case.fail('startup stage=no-route')
        if stage == 'note-count':
            case.fail('startup stage=note-count')
        if stage == 'policy-state':
            case.fail('startup stage=policy-state')
        if stage == 'harness-note':
            case.fail('startup stage=harness-note')
        if stage == 'canary':
            case.fail('startup stage=canary')
        case.fail('startup stage=unknown')
    with case.subTest(diagnostic='state'):
        if state == 'missing':
            case.fail('startup state=missing')
        if state == 'disabled':
            case.fail('startup state=disabled')
        if state == 'configured':
            case.fail('startup state=configured')
        if state == 'invalid':
            case.fail('startup state=invalid')
        case.fail('startup state=unknown')
    with case.subTest(diagnostic='harness'):
        if harness == 'grok':
            case.fail('startup harness=grok')
        if harness == 'qwen':
            case.fail('startup harness=qwen')
        if harness == 'claude':
            case.fail('startup harness=claude')
        if harness == 'codex':
            case.fail('startup harness=codex')
        if harness == 'gemini':
            case.fail('startup harness=gemini')
        if harness == 'copilot':
            case.fail('startup harness=copilot')
        case.fail('startup harness=unknown')


class StartupDiagnosticTests(unittest.TestCase):
    def test_closed_stages_preserve_each_original_assertion(self):
        text = 'No active route. Model continuation: configured; unavailable harness=codex'
        body = {'hookSpecificOutput': {'hookEventName': 'SessionStart', 'additionalContext': text}}
        variants = (
            ([], 'shape'), ({}, 'shape'),
            ({'hookSpecificOutput': {'hookEventName': 'CANARY', 'additionalContext': text}}, 'event'),
            ({'hookSpecificOutput': {'hookEventName': 'SessionStart', 'additionalContext': []}}, 'context'),
        )
        self.assertEqual(_startup_stage(0, json.dumps(body), 'codex', 'configured'), 'ok')
        self.assertEqual(_startup_stage(0, json.dumps({'additionalContext': text.replace('codex', 'copilot')}),
                                        'copilot', 'configured'), 'ok')
        self.assertEqual(_startup_stage(0, 'PRIVATE_CANARY', 'codex', 'configured'), 'json')
        for value, expected in variants:
            self.assertEqual(_startup_stage(0, json.dumps(value), 'codex', 'configured'), expected)
        for changed, expected in (
                (text.replace('No active route.', ''), 'no-route'),
                (text + ' Model continuation:', 'note-count'),
                (text.replace('configured', 'missing'), 'policy-state'),
                (text.replace('codex', 'copilot'), 'harness-note'),
                (text + ' NEVER_ECHO', 'canary')):
            value = {'hookSpecificOutput': {'hookEventName': 'SessionStart', 'additionalContext': changed}}
            self.assertEqual(_startup_stage(0, json.dumps(value), 'codex', 'configured'), expected)
        for stage in ('timeout', 'spawn', 'nonzero', 'json', 'shape', 'event', 'context',
                      'no-route', 'note-count', 'policy-state', 'harness-note', 'canary', 'PRIVATE_CANARY'):
            case = unittest.FunctionTestCase(lambda: _assert_startup_stage(case, stage, 'configured', 'codex'))
            result = unittest.TestResult()
            case.run(result)
            rendered = ''.join(detail for _, detail in result.failures)
            self.assertEqual(len(result.failures), 3)
            self.assertFalse(result.errors)
            self.assertNotIn('PRIVATE_CANARY', rendered)
            self.assertIn('startup stage=' + ('unknown' if stage == 'PRIVATE_CANARY' else stage), rendered)
            self.assertIn('case.fail(', rendered)

    def test_spawn_and_timeout_drop_exception_values_and_keep_deadline(self):
        for error, expected in ((OSError('PRIVATE_CANARY'), 'spawn'),
                                (subprocess.TimeoutExpired('PRIVATE_CANARY', 15,
                                                          output='PRIVATE_CANARY', stderr='PRIVATE_CANARY'), 'timeout')):
            with patch.object(subprocess, 'run', side_effect=error) as run:
                stage = _startup_hook_stage(Path('inert-public-fixture'), 'codex', 'configured')
            self.assertEqual(stage, expected)
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.kwargs['timeout'], 15)
            self.assertTrue(run.call_args.kwargs['capture_output'])
            self.assertTrue(run.call_args.kwargs['text'])
            self.assertNotIn('PRIVATE_CANARY', stage)

    def test_nonzero_startup_diagnostic_omits_child_values(self):
        case = ModelContinuationTest('test_six_startup_hooks_without_route_report_policy_once')
        result = unittest.TestResult()
        child = subprocess.CompletedProcess([], 7, 'PRIVATE_CHILD_CANARY', 'PRIVATE_CHILD_CANARY')
        with patch.object(subprocess, 'run', return_value=child):
            case.run(result)
        self.assertTrue(result.failures)
        self.assertFalse(result.errors)
        rendered = ''.join(detail for _, detail in result.failures)
        self.assertNotIn('PRIVATE_CHILD_CANARY', rendered)
        self.assertIn('startup stage=nonzero', rendered)
        self.assertIn('startup state=missing', rendered)
        self.assertIn('startup harness=copilot', rendered)


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
        shutil.copytree(ROOT / '.getzilla/hooks', self.root / '.getzilla/hooks',
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        for data, state in ((None, 'missing'), ({'schema_version': 1, 'enabled': False}, 'disabled'),
                            (enabled_policy(), 'configured'), ({'secret': 'NEVER_ECHO'}, 'invalid')):
            if data is not None:
                self.write(data)
            for harness in ('grok', 'qwen', 'claude', 'codex', 'gemini', 'copilot'):
                with self.subTest(state=state, harness=harness):
                    _assert_startup_stage(self, _startup_hook_stage(self.root, harness, state), state, harness)

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

    def test_six_startup_hooks_keep_policy_note_when_utf8_route_is_truncated(self):
        from getzilla.continuity import submit
        from getzilla.router import build_route
        from tests._support import activate_owned_route, project_copy

        with project_copy(git=True) as root:
            route = build_route(root, 'Preserve original intake marker.', 'rotation-owner').to_dict()
            activate_owned_route(root, route)
            for index in range(5):
                submit(root, f'Context {index}: ' + 'я' * 4000, 'rotation-owner')
            (root / '.getzilla/config/model-continuation.json').write_text(
                json.dumps(enabled_policy()), encoding='utf-8')
            for harness in ('grok', 'qwen', 'claude', 'codex', 'gemini', 'copilot'):
                with self.subTest(harness=harness):
                    result = subprocess.run(
                        [sys.executable, str(root / '.getzilla/hooks/session_start.py'), '--harness', harness],
                        cwd=root, input=json.dumps({'cwd': str(root), 'session_id': 'rotation-owner'}).encode(),
                        capture_output=True, timeout=15,
                        env={**os.environ, 'HOME': str(root), 'PYTHONDONTWRITEBYTECODE': '1'})
                    self.assertEqual(result.returncode, 0, result.stderr.decode())
                    output = json.loads(result.stdout)
                    if harness != 'copilot':
                        output = output['hookSpecificOutput']
                    context = output['additionalContext']
                    self.assertEqual(context.count('Model continuation:'), 1)
                    self.assertIn('Model continuation: configured; unavailable', context)
                    self.assertIn('harness=' + harness, context)
                    self.assertIn('Preserve original intake marker.', context)
                    self.assertIn('omitted', context)
                    self.assertIn(route['route_id'] + '.json', context)
                    self.assertLessEqual(len(context.encode('utf-8')), 16384)


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
            [sys.executable, str(target / '.getzilla/hooks/session_start.py'), '--harness', 'codex'],
            cwd=target, input=json.dumps({'cwd': str(target)}), capture_output=True,
            text=True, timeout=15, env={**os.environ, 'HOME': str(self.root)})
        self.assertEqual(result.returncode, 0, result.stderr)
        context = json.loads(result.stdout)['hookSpecificOutput']['additionalContext']
        self.assertIn('Model continuation: disabled;', context)
        config = json.loads((target / '.codex/hooks.json').read_text(encoding='utf-8'))
        self.assertIn("'--harness','codex'", json.dumps(config['hooks']['SessionStart']))


if __name__ == '__main__':
    unittest.main()
