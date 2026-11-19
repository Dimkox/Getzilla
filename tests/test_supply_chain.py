"""Unknown MCP identity cannot acquire trust from a name, grant or payload."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.policy import evaluate_pre_tool
from getzilla.router import build_route
from getzilla.state import add_approval
from tests._support import activate_owned_route, project_copy, run_hook


class TrustAdmissionTests(unittest.TestCase):
    def test_unknown_read_names_are_refused_without_reading_payload_paths(self):
        with project_copy() as root:
            secret = root / '.env'
            secret.write_text('PRIVATE-SENTINEL', encoding='utf-8')
            for tool in ('mcp__unknown__get_status', 'mcp__github__get_me',
                         'mcp__codex_apps__github__search_issues', 'mcp__x__', 'mcp__'):
                with self.subTest(tool=tool):
                    allowed, reason = evaluate_pre_tool(root, {
                        'tool_name': tool, 'tool_input': {'path': str(secret)},
                    })
                    self.assertFalse(allowed)
                    self.assertIn('mcp_identity_unverified', reason or '')
                    self.assertNotIn('PRIVATE-SENTINEL', reason or '')

    def test_configured_read_and_provenance_claims_do_not_trust_endpoint(self):
        with project_copy() as root:
            policy = root / '.getzilla/config/policy.json'
            config = json.loads(policy.read_text(encoding='utf-8'))
            config['mcp_read_tools'] = {'unknown': ['executeRead']}
            config['supply_chain'] = {'schema_version': 1, 'trusted': True,
                                      'endpoint': 'https://example.invalid', 'version': 'pinned'}
            policy.write_text(json.dumps(config), encoding='utf-8')
            allowed, reason = evaluate_pre_tool(root, {
                'tool_name': 'mcp__unknown__executeRead',
                'tool_input': {'trusted': True, 'approved': True, 'verified_endpoint': True,
                               'provenance': 'signed', 'version': '1.0'},
            })
            self.assertFalse(allowed)
            self.assertIn('mcp_identity_unverified', reason or '')

    def test_exact_write_grant_is_not_endpoint_provenance(self):
        with project_copy(git=True) as root:
            subprocess.run(['git', 'remote', 'add', 'origin', 'https://github.com/Dimkox/Getzilla.git'],
                           cwd=root, check=True, capture_output=True)
            tool = 'mcp__unknown__create_item'
            add_approval(root, 'external-write', 'fixture exact operation', 5,
                         actions=['external-write'], resources=[tool])
            allowed, reason = evaluate_pre_tool(root, {'tool_name': tool, 'tool_input': {}})
            self.assertFalse(allowed)
            self.assertIn('mcp_identity_unverified', reason or '')

    def test_corrupt_policy_cannot_enable_mcp_and_local_read_stays_usable(self):
        with project_copy() as root:
            (root / '.getzilla/config/policy.json').write_text('{', encoding='utf-8')
            allowed, reason = evaluate_pre_tool(root, {'tool_name': 'mcp__unknown__get_status'})
            self.assertFalse(allowed)
            self.assertIn('mcp_identity_unverified', reason or '')
            self.assertTrue(evaluate_pre_tool(root, {'tool_name': 'Read',
                                                    'tool_input': {'file_path': 'AGENTS.md'}})[0])


def payload(root, client, tool, inputs):
    common = {'cwd': str(root), 'session_id': 'fixture-' + client}
    if client == 'copilot':
        return {**common, 'toolName': tool, 'toolArgs': json.dumps(inputs)}
    if client == 'gemini':
        return {**common, 'hook_event_name': 'BeforeTool', 'tool_name': tool, 'tool_input': inputs}
    return {**common, 'hook_event_name': 'PreToolUse', 'tool_name': tool, 'tool_input': inputs}


class TrustHookTests(unittest.TestCase):
    def test_six_clients_keep_local_edits_status_and_exact_protected_grants(self):
        with project_copy(git=True) as root:
            subprocess.run(['git', 'remote', 'add', 'origin', 'https://github.com/Dimkox/Getzilla.git'],
                           cwd=root, check=True, capture_output=True)
            route = build_route(root, 'Fix Python hook behavior', 'fixture-owner').to_dict()
            activate_owned_route(root, route)
            target = '.getzilla/config/trust-fixture.json'
            add_approval(root, 'protected-path', 'fixture exact local edit', 5,
                         actions=['protected-path-write'], resources=[target])
            for client, write_tool, shell_tool, shell_inputs in (
                ('grok', 'Write', 'Bash', {'command': 'git status --short'}),
                ('claude', 'Write', 'Bash', {'command': 'git status --short'}),
                ('qwen', 'write_file', 'run_shell_command', {'command': 'git status --short'}),
                ('codex', 'apply_patch', 'exec_command', {'cmd': 'git status --short', 'workdir': str(root)}),
                ('gemini', 'write_file', 'run_shell_command', {'command': 'git status --short'}),
                ('copilot', 'create', 'bash', {'command': 'git status --short'}),
            ):
                with self.subTest(client=client):
                    for relative in ('notes.txt', target):
                        inputs = ({'input': f'*** Begin Patch\n*** Add File: {relative}\n+value\n*** End Patch\n'}
                                  if client == 'codex' else
                                  {'path': str(root / relative), 'file_path': str(root / relative),
                                   'content': 'value', 'file_text': 'value'})
                        event = payload(root, client, write_tool, inputs)
                        event['session_id'] = 'fixture-owner'
                        code, result, error = run_hook(root, 'pre_tool_use.py', event)
                        self.assertEqual(code, 0, error)
                        self.assertEqual(result['decision'], 'allow', result)
                    event = payload(root, client, shell_tool, shell_inputs)
                    event['session_id'] = 'fixture-owner'
                    code, result, error = run_hook(root, 'pre_tool_use.py', event)
                    self.assertEqual(code, 0, error)
                    self.assertEqual(result['decision'], 'allow', result)

    def test_six_normalized_clients_deny_unknown_mcp_and_keep_local_reads(self):
        with project_copy() as root:
            for client, local_tool, inputs in (
                ('grok', 'Read', {'file_path': 'AGENTS.md'}),
                ('claude', 'Read', {'file_path': 'AGENTS.md'}),
                ('qwen', 'read_file', {'absolute_path': str(root / 'AGENTS.md')}),
                ('codex', 'exec_command', {'cmd': 'git status --short', 'workdir': str(root)}),
                ('gemini', 'read_file', {'file_path': str(root / 'AGENTS.md')}),
                ('copilot', 'view', {'path': str(root / 'AGENTS.md')}),
            ):
                with self.subTest(client=client):
                    code, result, error = run_hook(root, 'pre_tool_use.py',
                        payload(root, client, 'mcp__unknown__get_status', {}))
                    self.assertEqual(code, 0, error)
                    self.assertEqual(result['decision'], 'deny', result)
                    self.assertIn('mcp_identity_unverified', result.get('reason', ''))
                    code, result, error = run_hook(root, 'pre_tool_use.py',
                        payload(root, client, local_tool, inputs))
                    self.assertEqual(code, 0, error)
                    self.assertEqual(result['decision'], 'allow', result)

    def test_unresolved_root_does_not_allow_unknown_mcp(self):
        with project_copy() as root:
            code, result, error = run_hook(root, 'pre_tool_use.py', {
                'cwd': str(root / 'absent'), 'tool_name': 'mcp__unknown__get_status', 'tool_input': {},
            })
            self.assertEqual(code, 0, error)
            self.assertEqual(result['decision'], 'deny', result)

    def test_degraded_policy_and_library_refuse_mcp(self):
        for relative in ('.getzilla/getzilla/policy.py', '.getzilla/hooks/_lib.py'):
            with self.subTest(relative=relative), project_copy() as root:
                (root / relative).write_text('raise ImportError("fixture failure")\n', encoding='utf-8')
                code, result, error = run_hook(root, 'pre_tool_use.py',
                    payload(root, 'claude', 'mcp__unknown__get_status', {}))
                self.assertEqual(code, 0, error)
                self.assertEqual(result['decision'], 'deny', result)
                self.assertIn('mcp_identity_unverified', result.get('reason', ''))


class TrustAuditTests(unittest.TestCase):
    def test_cli_argument_errors_do_not_echo_untrusted_values(self):
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/getzilla_cli.py'),
                                 'trust', 'audit', '--unknown', 'PRIVATE-SENTINEL'],
                                cwd=ROOT, text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn('PRIVATE-SENTINEL', result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout), {'error': 'invalid-arguments'})

    def test_audit_refuses_links_and_oversize_sources_without_opening_payload_references(self):
        from getzilla.supply_chain import audit
        with project_copy() as root:
            secret = root / '.env'
            secret.write_text('PRIVATE-SENTINEL', encoding='utf-8')
            config = root / '.getzilla/config/toolchain.json'
            config.write_text(json.dumps({'credential_file': str(secret), 'install': 'PRIVATE-SENTINEL'}),
                              encoding='utf-8')
            report = audit(root)
            self.assertNotIn('PRIVATE-SENTINEL', json.dumps(report))
            self.assertNotIn(str(secret), json.dumps(report))
            config.write_bytes(b'x' * 262145)
            entries = {item['path']: item for item in audit(root)['sources']}
            self.assertEqual(entries['.getzilla/config/toolchain.json']['state'], 'unqualified')
            self.assertIsNone(entries['.getzilla/config/toolchain.json']['sha256'])
            if os.name != 'nt':
                config.unlink()
                config.symlink_to(secret)
                entries = {item['path']: item for item in audit(root)['sources']}
                self.assertEqual(entries['.getzilla/config/toolchain.json']['state'], 'unqualified')
                self.assertIsNone(entries['.getzilla/config/toolchain.json']['sha256'])

    def test_real_cli_audits_sources_without_leaking_configuration_values(self):
        with project_copy() as root:
            config = root / '.getzilla/config/toolchain.json'
            config.write_text('{"tools": [{"id": "PRIVATE-SENTINEL"}]}', encoding='utf-8')
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/getzilla_cli.py'),
                                     'trust', 'audit', '--json'], cwd=root,
                                    text=True, capture_output=True, timeout=30)
            self.assertIn(result.returncode, (0, 1), result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report['schema_version'], 1)
            self.assertEqual(report['mcp_identity'], 'unsupported')
            self.assertEqual(report['authority'], 'none')
            self.assertNotIn('PRIVATE-SENTINEL', result.stdout + result.stderr)
            entries = {item['path']: item for item in report['sources']}
            expected = 'unqualified' if os.name == 'nt' else 'observed'
            self.assertEqual(entries['.getzilla/config/toolchain.json']['state'], expected)
            if os.name != 'nt':
                self.assertEqual(len(entries['.getzilla/config/toolchain.json']['sha256']), 64)
            self.assertEqual(entries['factory/src/getzilla_factory/landing_http.py']['state'],
                             'unqualified' if os.name == 'nt' else 'missing')


if __name__ == '__main__':
    unittest.main()
