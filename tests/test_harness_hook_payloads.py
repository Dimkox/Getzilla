"""Qwen Code and Claude Code payloads reach the same policy as Grok Build payloads.

Qwen Code names its tools run_shell_command, monitor, write_file, edit and agent,
and its shell tool takes a `directory` relative to the project root. If any of
those names slipped past the alias table, the policy would see an unknown tool
and allow it, so each case below must be denied exactly like its Grok twin.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from pathlib import Path

from tests._support import PROJECT, project_copy, run_hook


class HarnessHookPayloadTests(unittest.TestCase):
    def _pre_tool(self, root, tool: str, tool_input: dict) -> dict:
        code, data, stderr = run_hook(root, 'pre_tool_use.py', {
            'cwd': str(root),
            'session_id': 'qwen',
            'hook_event_name': 'PreToolUse',
            'tool_name': tool,
            'tool_input': tool_input,
        })
        self.assertEqual(code, 0, stderr)
        return data

    def test_shell_tools_are_policy_checked(self) -> None:
        with project_copy() as root:
            for tool in ('run_shell_command', 'monitor', 'Monitor', 'PowerShell', 'shell', 'exec_command'):
                data = self._pre_tool(root, tool, {'command': 'terraform destroy'})
                self.assertEqual(data['hookSpecificOutput']['permissionDecision'], 'deny', tool)
                data = self._pre_tool(root, tool, {'command': 'printf x >> AGENTS.md'})
                self.assertEqual(data['decision'], 'deny', tool)

    def test_copilot_payloads_are_policy_checked(self) -> None:
        with project_copy() as root:
            for tool, args in (
                ('bash', {'command': 'terraform destroy'}),
                ('powershell', {'command': 'printf x >> AGENTS.md'}),
                ('create', {'path': str(root / 'AGENTS.md'), 'file_text': 'x'}),
                ('edit', {'path': str(root / '.github/hooks/getzilla.json'), 'old_str': 'a', 'new_str': 'b'}),
                ('view', {'path': str(root / '.env')}),
            ):
                code, data, stderr = run_hook(root, 'pre_tool_use.py', {
                    'timestamp': 1, 'cwd': str(root), 'toolName': tool, 'toolArgs': json.dumps(args),
                })
                self.assertEqual(code, 0, stderr)
                self.assertEqual(data['decision'], 'deny', tool)

    def test_codex_list_commands_and_patch_inputs_are_policy_checked(self) -> None:
        with project_copy() as root:
            data = self._pre_tool(root, 'shell', {'command': ['bash', '-lc', 'printf x >> AGENTS.md']})
            self.assertEqual(data['decision'], 'deny')
            data = self._pre_tool(root, 'exec_command', {'command': ['terraform', 'destroy']})
            self.assertEqual(data['decision'], 'deny')
            patch = '*** Begin Patch\n*** Update File: AGENTS.md\n@@\n-a\n+b\n*** End Patch\n'
            for key in ('patch', 'input'):
                data = self._pre_tool(root, 'apply_patch', {key: patch})
                self.assertEqual(data['decision'], 'deny', key)

    def test_notebook_and_multi_file_paths_are_checked(self) -> None:
        with project_copy() as root:
            data = self._pre_tool(root, 'NotebookEdit', {'notebook_path': str(root / '.claude/x.ipynb'), 'new_source': ''})
            self.assertEqual(data['decision'], 'deny')
            data = self._pre_tool(root, 'read_many_files', {'paths': ['.env']})
            self.assertEqual(data['decision'], 'deny')

    def test_harmless_shell_command_is_allowed(self) -> None:
        with project_copy() as root:
            data = self._pre_tool(root, 'run_shell_command', {'command': 'ls', 'description': 'list'})
            self.assertEqual(data['decision'], 'allow')

    def test_structured_writes_to_protected_paths_need_a_grant(self) -> None:
        with project_copy() as root:
            for tool, tool_input in (
                ('write_file', {'file_path': str(root / 'AGENTS.md'), 'content': 'x'}),
                ('edit', {'file_path': str(root / 'AGENTS.md'), 'old_string': 'a', 'new_string': 'b'}),
                ('replace', {'file_path': str(root / 'AGENTS.md'), 'old_string': 'a', 'new_string': 'b'}),
                ('MultiEdit', {'file_path': str(root / 'AGENTS.md'), 'edits': []}),
            ):
                data = self._pre_tool(root, tool, tool_input)
                self.assertEqual(data['decision'], 'deny', tool)

    def test_agents_cannot_rewrite_their_own_harness_hooks(self) -> None:
        with project_copy() as root:
            for rel in ('.claude/settings.json', '.qwen/settings.json', '.codex/hooks.json'):
                data = self._pre_tool(root, 'Write', {'file_path': str(root / rel), 'content': '{}'})
                self.assertEqual(data['decision'], 'deny', rel)
                data = self._pre_tool(root, 'run_shell_command', {'command': f'rm {rel}'})
                self.assertEqual(data['decision'], 'deny', rel)

    def test_shell_directory_outside_any_getzilla_root_fails_closed_for_sensitive_commands(self) -> None:
        with project_copy(git=True) as root:
            outside = root.parent
            data = self._pre_tool(root, 'run_shell_command', {
                'command': 'git push origin feature',
                'directory': str(outside),
            })
            self.assertEqual(data['decision'], 'deny')



class OversizeCommandHookTests(unittest.TestCase):
    """Round-3 review: an oversize Bash command is denied at hook entry, before any parsing."""

    def test_oversize_command_is_denied_well_within_the_hook_timeout(self) -> None:
        import time
        command = 'x;' * 150000 + 'rm -rf /'
        with project_copy() as root:
            start = time.monotonic()
            code, data, stderr = run_hook(root, 'pre_tool_use.py', {
                'cwd': str(root), 'session_id': 'oversize', 'hook_event_name': 'PreToolUse',
                'tool_name': 'Bash', 'tool_input': {'command': command},
            })
            elapsed = time.monotonic() - start
        self.assertEqual(code, 0, stderr)
        decision = data.get('decision') or (data.get('hookSpecificOutput') or {}).get('permissionDecision')
        self.assertEqual(decision, 'deny', data)
        self.assertLess(elapsed, 3.0, f'hook took {elapsed:.1f}s')


class GeneratedHookCommandTests(unittest.TestCase):
    """Run the exact generated hook commands, from a subdirectory, as each agent would."""

    def _run(self, root: Path, settings: str, payload: dict) -> tuple[int, str]:
        hooks = json.loads((root / settings).read_text(encoding='utf-8'))['hooks']
        if 'preToolUse' in hooks:
            command = hooks['preToolUse'][0]['bash']
        elif 'BeforeTool' in hooks:
            command = hooks['BeforeTool'][0]['hooks'][0]['command']
        else:
            command = hooks['PreToolUse'][0]['hooks'][0]['command']
        sub = root / 'src' / 'deep'
        sub.mkdir(parents=True, exist_ok=True)
        proc = subprocess.run(['bash', '-c', command], cwd=sub, input=json.dumps(payload), text=True,
                              capture_output=True, timeout=120)
        return proc.returncode, proc.stdout.strip()

    def test_claude_compatible_agents_get_a_schema_valid_verdict(self) -> None:
        with project_copy() as root:
            for rel in ('.claude', '.qwen', '.codex'):
                shutil.copytree(PROJECT / rel, root / rel)
            for settings in ('.claude/settings.json', '.qwen/settings.json', '.codex/hooks.json'):
                code, out = self._run(root, settings, {
                    'cwd': str(root), 'hook_event_name': 'PreToolUse', 'tool_name': 'Bash',
                    'tool_input': {'command': 'terraform destroy'},
                })
                self.assertEqual(code, 0, settings)
                data = json.loads(out)
                self.assertNotIn('decision', data, settings)
                self.assertEqual(data['hookSpecificOutput']['permissionDecision'], 'deny', settings)
                self.assertTrue(data['hookSpecificOutput']['permissionDecisionReason'], settings)
                code, out = self._run(root, settings, {
                    'cwd': str(root), 'hook_event_name': 'PreToolUse', 'tool_name': 'Bash',
                    'tool_input': {'command': 'ls'},
                })
                self.assertEqual(code, 0, settings)
                self.assertIn(out, ('', '{}'), settings)

    def test_gemini_and_copilot_get_their_own_verdict_shape(self) -> None:
        with project_copy() as root:
            shutil.copytree(PROJECT / '.gemini', root / '.gemini')
            (root / '.github').mkdir()
            shutil.copytree(PROJECT / '.github/hooks', root / '.github/hooks')
            code, out = self._run(root, '.gemini/settings.json', {
                'cwd': str(root), 'hook_event_name': 'BeforeTool', 'tool_name': 'run_shell_command',
                'tool_input': {'command': 'terraform destroy'},
            })
            self.assertEqual(code, 0)
            data = json.loads(out)
            self.assertEqual(data['decision'], 'deny')
            self.assertTrue(data['reason'])
            self.assertNotIn('hookSpecificOutput', data)
            code, out = self._run(root, '.github/hooks/getzilla.json', {
                'timestamp': 1, 'cwd': str(root), 'toolName': 'bash',
                'toolArgs': json.dumps({'command': 'terraform destroy'}),
            })
            self.assertEqual(code, 0)
            data = json.loads(out)
            self.assertEqual(data['permissionDecision'], 'deny')
            self.assertTrue(data['permissionDecisionReason'])
            for settings in ('.gemini/settings.json', '.github/hooks/getzilla.json'):
                code, out = self._run(root, settings, {
                    'cwd': str(root), 'toolName': 'bash', 'toolArgs': json.dumps({'command': 'ls'}),
                    'tool_name': 'run_shell_command', 'tool_input': {'command': 'ls'},
                })
                self.assertIn(out, ('', '{}'), settings)

    def test_a_hook_planted_in_a_subdirectory_is_never_run(self) -> None:
        with project_copy() as root:
            for rel in ('.claude', '.qwen', '.codex'):
                shutil.copytree(PROJECT / rel, root / rel)
            planted = root / 'src/deep/.grok/hooks'
            planted.mkdir(parents=True)
            (planted / 'pre_tool_use.py').write_text('print("{}")\n', encoding='utf-8')
            for settings in ('.claude/settings.json', '.qwen/settings.json', '.codex/hooks.json'):
                code, out = self._run(root, settings, {
                    'cwd': str(root), 'hook_event_name': 'PreToolUse', 'tool_name': 'Bash',
                    'tool_input': {'command': 'terraform destroy'},
                })
                self.assertEqual(json.loads(out)['hookSpecificOutput']['permissionDecision'], 'deny', settings)

    def test_nested_harness_directories_are_protected(self) -> None:
        with project_copy() as root:
            for rel in ('src/.grok/hooks/pre_tool_use.py', 'src/.claude/settings.json', '_lib.py'):
                _, data, _ = run_hook(root, 'pre_tool_use.py', {
                    'cwd': str(root), 'tool_name': 'Write',
                    'tool_input': {'file_path': str(root / rel), 'content': 'x'},
                })
                self.assertEqual(data['decision'], 'deny', rel)

    def test_grok_keeps_its_legacy_verdict_shape(self) -> None:
        with project_copy() as root:
            _, data, _ = run_hook(root, 'pre_tool_use.py', {
                'cwd': str(root), 'tool_name': 'Bash', 'tool_input': {'command': 'ls'},
            })
            self.assertEqual(data['decision'], 'allow')
            self.assertEqual(data['hookSpecificOutput']['permissionDecision'], 'allow')


if __name__ == '__main__':
    unittest.main()
