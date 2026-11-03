import hashlib
import json
import unittest

from tests._support import project_copy, run_hook


class DenialCircuitBreakerTest(unittest.TestCase):
    def test_breaker_keeps_independent_work_available_without_resetting_denials(self):
        with project_copy(git=True) as root:
            (root / 'README.md').write_text('fixture\n', encoding='utf-8')
            payload = {'cwd': str(root), 'session_id': 'discovery-circuit',
                       'tool_name': 'Bash', 'tool_input': {'command': 'rg --files | rg -i policy'}}
            _, first, _ = run_hook(root, 'pre_tool_use.py', payload)
            _, repeated, _ = run_hook(root, 'pre_tool_use.py', payload)
            self.assertEqual(first['decision'], 'deny', first)
            self.assertEqual(repeated['decision'], 'deny', repeated)
            self.assertIn('exact tool invocation was denied again', repeated['reason'])
            ledger_path = root / '.getzilla/runtime/tool-denials.json'
            denied_ledger = ledger_path.read_bytes()
            for command in ('git status --short', 'cat README.md',
                            "rg --files --hidden -g '!.git' --iglob '*README*'"):
                with self.subTest(command=command):
                    payload['tool_input'] = {'command': command}
                    code, allowed, error = run_hook(root, 'pre_tool_use.py', payload)
                    self.assertEqual(code, 0, error)
                    self.assertEqual(allowed['decision'], 'allow', allowed)
                    self.assertEqual(ledger_path.read_bytes(), denied_ledger)
            payload['tool_input'] = {'command': 'rg --files | rg -i policy'}
            _, still_denied, _ = run_hook(root, 'pre_tool_use.py', payload)
            self.assertEqual(still_denied['decision'], 'deny', still_denied)
            self.assertIn('exact tool invocation was denied again', still_denied['reason'])
            self.assertIn('Continue independent permitted work', repeated['reason'])
            self.assertIn('only this operation', repeated['reason'])

    def test_second_identical_denial_stops_retry_loop(self):
        with project_copy() as root:
            payload = {
                'cwd': str(root),
                'session_id': 'circuit-test',
                'tool_name': 'Bash',
                'tool_input': {
                    'command': "curl -X POST -d '{}' http://<redacted-network>/webhooks/github?access_token=ledger-secret",
                },
            }
            run_hook(root, 'pre_tool_use.py', payload)
            code, data, error = run_hook(root, 'pre_tool_use.py', payload)
            self.assertEqual(code, 0, error)
            reason = data['hookSpecificOutput']['permissionDecisionReason']
            self.assertIn('exact tool invocation was denied again', reason)
            self.assertIn('objective BLOCKED', reason)
            ledger = json.loads((root / '.getzilla/runtime/tool-denials.json').read_text(encoding='utf-8'))
            self.assertEqual(ledger['schema_version'], 3)
            entry = next(iter(ledger['exact'].values()))
            self.assertEqual(entry['session_cwd'], str(root))
            self.assertEqual(entry['session_root'], str(root))
            self.assertEqual(entry['effective_root'], str(root))
            self.assertEqual(entry['resolution_status'], 'session-root')
            self.assertEqual(entry['action'], 'external-write')
            self.assertEqual(entry['reason'], 'External write denied by repository policy.')
            self.assertNotIn('command', entry)
            self.assertNotIn('ledger-secret', json.dumps(ledger, sort_keys=True))
            expected = hashlib.sha256(json.dumps(
                payload['tool_input'], sort_keys=True, separators=(',', ':'), ensure_ascii=False,
            ).encode('utf-8')).hexdigest()
            self.assertEqual(entry['tool_input_sha256'], expected)

    def test_native_validation_denials_record_exact_and_objective_retries(self):
        with project_copy() as root:
            payload = {'cwd': str(root), 'session_id': 'native-invalid',
                       'tool_name': 'exec_command', 'tool_input': {'cmd': ''}}
            run_hook(root, 'pre_tool_use.py', payload)
            _, data, _ = run_hook(root, 'pre_tool_use.py', payload)
            self.assertEqual(data['decision'], 'deny')
            self.assertIn('exact tool invocation was denied again', data['reason'])
            ledger = json.loads((root / '.getzilla/runtime/tool-denials.json').read_text())
            self.assertEqual(next(iter(ledger['exact'].values()))['count'], 2)
            self.assertEqual(next(iter(ledger['exact'].values()))['action'], 'invalid-tool-input')
            payload['tool_input']['cmd'] = None
            _, data, _ = run_hook(root, 'pre_tool_use.py', payload)
            self.assertIn('rewritten invocation was denied for the same objective', data['reason'])

    def test_validation_denial_survives_root_and_ledger_failures(self):
        import importlib.util
        import sys
        from unittest.mock import patch
        from tests._support import PROJECT
        sys.path.insert(0, str(PROJECT / '.grok/hooks'))
        spec = importlib.util.spec_from_file_location('denial_probe_hook', PROJECT / '.grok/hooks/pre_tool_use.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with project_copy() as root:
            payload = {'cwd': str(root), 'tool_name': 'exec_command', 'tool_input': {'cmd': ''}}
            for broken in ('root_context', '_record_denial', '_fingerprint'):
                emitted = []
                with patch.object(module, 'read_payload', return_value=payload), \
                     patch.object(module, 'emit', side_effect=emitted.append), \
                     patch.object(module, broken, side_effect=RuntimeError('injected')):
                    module.main()
                self.assertEqual(emitted[-1]['decision'], 'deny', broken)



if __name__ == '__main__':
    unittest.main()
