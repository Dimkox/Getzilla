"""Qwen Code and Claude Code payloads reach the same policy as Grok Build payloads.

Qwen Code names its tools run_shell_command, monitor, write_file, edit and agent,
and its shell tool takes a `directory` relative to the project root. If any of
those names slipped past the alias table, the policy would see an unknown tool
and allow it, so each case below must be denied exactly like its Grok twin.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path

from tests._support import PROJECT, project_copy, run_hook


def _posix_shell() -> str | None:
    """bash, which runs these hook commands; on Windows the Git Bash that Claude Code uses."""
    if os.name != 'nt':
        return shutil.which('bash')
    git = shutil.which('git')
    if git is None:
        return None
    bash = Path(git).resolve().parents[1] / 'bin' / 'bash.exe'
    return str(bash) if bash.is_file() else None


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

    def test_codex_cmd_payload_reaches_sensitive_command_policy(self) -> None:
        with project_copy() as root:
            for command in ('git push origin main', 'terraform destroy', 'cat .env',
                            'printf x >> AGENTS.md'):
                with self.subTest(command=command):
                    data = self._pre_tool(root, 'exec_command', {
                        'cmd': command, 'workdir': str(root),
                    })
                    self.assertEqual(data['decision'], 'deny', data)

    def test_codex_cmd_is_authoritative_for_exec_command(self) -> None:
        with project_copy() as root:
            data = self._pre_tool(root, 'exec_command', {
                'cmd': 'git push origin main', 'command': 'ls', 'workdir': str(root),
            })
            self.assertEqual(data['decision'], 'deny', data)

    def test_codex_conflicting_and_malformed_commands_are_denied(self) -> None:
        with project_copy() as root:
            for inputs in (
                {'cmd': 'ls', 'command': 'terraform destroy'},
                {'cmd': 'terraform destroy', 'command': 'ls'},
                {}, {'cmd': None}, {'cmd': ''}, {'cmd': '   '},
                {'cmd': 1}, {'cmd': False}, {'cmd': ['ls']},
                {'cmd': {}, 'command': 'ls'}, None, [],
            ):
                with self.subTest(inputs=inputs):
                    self.assertEqual(self._pre_tool(root, 'exec_command', inputs)['decision'], 'deny')

    def test_codex_envelopes_and_oversize_commands_are_checked(self) -> None:
        with project_copy() as root:
            for key in ('tool_input', 'toolInput', 'toolArgs'):
                inputs = {'cmd': 'terraform destroy', 'workdir': str(root)}
                code, data, stderr = run_hook(root, 'pre_tool_use.py', {
                    'cwd': str(root), 'toolName': 'exec_command',
                    key: json.dumps(inputs) if key == 'toolArgs' else inputs,
                })
                self.assertEqual(code, 0, stderr)
                self.assertEqual(data['decision'], 'deny', key)
            data = self._pre_tool(root, 'exec_command', {'cmd': 'x' * 131073})
            self.assertEqual(data['decision'], 'deny')
            self.assertIn('longer', data['reason'])

    def test_codex_legacy_and_equal_alias_commands_stay_supported(self) -> None:
        with project_copy() as root:
            for inputs in ({'command': 'ls'}, {'command': ['ls']},
                           {'cmd': 'ls', 'command': 'ls'}, {'cmd': 'ls', 'command': ['ls']}):
                self.assertEqual(self._pre_tool(root, 'exec_command', inputs)['decision'], 'allow')

    def test_normalization_preserves_input_and_does_not_invent_alias_contracts(self) -> None:
        import copy
        import importlib.util
        import sys
        spec = importlib.util.spec_from_file_location('cmd_hook_fixture', PROJECT / '.grok/hooks/_lib.py')
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        inputs = {'cmd': 'ls', 'workdir': '/somewhere', 'extra': ['value']}
        payload = {'tool_name': 'exec_command', 'tool_input': inputs}
        before = copy.deepcopy(payload)
        result = module.tool_input(payload)
        self.assertEqual(result['command'], 'ls')
        self.assertEqual(result['workdir'], '/somewhere')
        self.assertEqual(payload, before)
        self.assertIsNot(result, inputs)
        unknown = module.tool_input({'tool_name': 'shell', 'tool_input': {'cmd': 'ls'}})
        self.assertNotIn('command', unknown)

    @unittest.skipIf(os.name == 'nt', 'POSIX helper script')
    def test_root_probe_does_not_run_a_helper_from_the_probed_repository_config(self) -> None:
        # #215: an agent can make a repository whose own config names an fsmonitor program.
        import importlib.util
        import sys
        import tempfile
        spec = importlib.util.spec_from_file_location('root_probe_fixture', PROJECT / '.grok/hooks/_lib.py')
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / 'repo'
            (repo / '.getzilla/config').mkdir(parents=True)
            (repo / '.getzilla/config/policy.json').write_text('{}\n', encoding='utf-8')
            marker = Path(tmp) / 'ran'
            helper = Path(tmp) / 'helper.sh'
            helper.write_text(f'#!/bin/sh\ntouch {marker}\n', encoding='utf-8')
            helper.chmod(0o755)
            subprocess.run(['git', 'init', '-q', str(repo)], check=True)
            subprocess.run(['git', '-C', str(repo), 'add', '.getzilla/config/policy.json'], check=True)
            subprocess.run(['git', '-C', str(repo), 'config', 'core.fsmonitor', str(helper)], check=True)
            self.assertTrue(module._installed_root(repo))
            self.assertFalse(marker.exists())

    def test_installed_codex_launcher_checks_native_cmd(self) -> None:
        import importlib.util
        import sys
        spec = importlib.util.spec_from_file_location('cmd_install_fixture', PROJECT / 'scripts/install_into.py')
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        with project_copy() as root:
            target = root.parent / 'installed'
            module.materialize_new(PROJECT, target)
            self.assertIn('canonical project root', (target / 'AGENTS.md').read_text())
            self.assertIn('outside the reviewed candidate', (target / 'AGENTS.md').read_text())
            for consumer, configuration in ((root, PROJECT), (target, target)):
                hooks = json.loads((configuration / '.codex/hooks.json').read_text())
                launcher = hooks['hooks']['PreToolUse'][0]['hooks'][0]['command']
                result = subprocess.run(launcher, shell=True, cwd=consumer, input=json.dumps({
                    'cwd': str(consumer), 'tool_name': 'exec_command',
                    'tool_input': {'cmd': 'terraform destroy'},
                }), text=True, capture_output=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr)
                decision = json.loads(result.stdout)['hookSpecificOutput']
                self.assertEqual(decision['permissionDecision'], 'deny')
                # The native cmd reached the destructive-command policy; an empty normalized command
                # is denied too, but for another reason (#73).
                self.assertIn('Blocked destructive command', json.dumps(decision, ensure_ascii=False))
                allowed = subprocess.run(launcher, shell=True, cwd=consumer, input=json.dumps({
                    'cwd': str(consumer), 'tool_name': 'exec_command', 'tool_input': {'cmd': 'git status --short'},
                }), text=True, capture_output=True, timeout=20)
                self.assertEqual(allowed.returncode, 0, allowed.stderr)
                self.assertNotEqual(json.loads(allowed.stdout or '{}').get('hookSpecificOutput', {}).get('permissionDecision'),
                                    'deny', allowed.stdout)
                prompt_hook = consumer / '.grok/hooks/user_prompt_submit.py'
                prompt_hook.write_text(prompt_hook.read_text().replace(
                    '    emit({', "    emit({'source_identity': __file__,"))
                prompt = subprocess.run(hooks['hooks']['UserPromptSubmit'][0]['hooks'][0]['command'],
                    shell=True, cwd=consumer, input=json.dumps({'cwd': str(consumer),
                    'session_id': 'installed-routing', 'prompt': 'Fix security policy tests'}),
                    text=True, capture_output=True, timeout=30)
                self.assertEqual(prompt.returncode, 0, prompt.stderr)
                output = json.loads(prompt.stdout)
                self.assertEqual(Path(output.get('source_identity', '')).resolve(), prompt_hook.resolve())
                route = json.loads((consumer / '.getzilla/runtime/active-route.json').read_text())
                self.assertIn(route['write_agent'], route['allowed_agents'])
                self.assertIn(route['route_id'], output['hookSpecificOutput']['additionalContext'])

    def test_codex_cmd_respects_command_workdir(self) -> None:
        """#73: with an exact push grant only the workdir differs, so only root resolution can deny."""
        from getzilla.router import build_route
        from getzilla.state import add_approval
        from tests._support import activate_owned_route
        with project_copy(git=True) as root:
            subprocess.run(['git', 'remote', 'add', 'origin', 'git@github.com:Example/app.git'], cwd=root, check=True)
            subprocess.run(['git', 'checkout', '-qb', 'feature'], cwd=root, check=True)
            activate_owned_route(root, build_route(root, 'Publish the reviewed fix', 'workdir-test').to_dict())
            add_approval(root, 'production', 'ship', 5, actions=['git-push-branch'], resources=['feature'])
            inside = self._pre_tool(root, 'exec_command', {'cmd': 'git push origin feature', 'workdir': str(root)})
            self.assertEqual(inside['decision'], 'allow', inside)
            data = self._pre_tool(root, 'exec_command', {
                'cmd': 'git push origin feature', 'workdir': str(root.parent),
            })
            self.assertEqual(data['decision'], 'deny', data)
            self.assertIn('root resolution', data['reason'])

    def test_codex_read_only_cmd_is_allowed(self) -> None:
        with project_copy() as root:
            data = self._pre_tool(root, 'exec_command', {
                'cmd': 'git status --short', 'workdir': str(root),
            })
            self.assertEqual(data['decision'], 'allow', data)

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
            for rel in ('.claude/settings.json', '.qwen/settings.json', '.codex/hooks.json',
                        '.cursor/rules/getzilla/00-core.mdc'):
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
        shell = _posix_shell()
        if shell is None:
            self.skipTest('no POSIX shell (Git Bash on Windows) to run the generated hook command')
        proc = subprocess.run([shell, '-c', command], cwd=sub, input=json.dumps(payload), text=True,
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

    def test_nested_real_worktree_uses_its_own_route_and_denial_state(self) -> None:
        import os
        import sys
        sys.path.insert(0, str(PROJECT / '.getzilla'))
        with project_copy(git=True) as outer:
            from getzilla.harnesses import write
            write(outer)
            subprocess.run(['git', 'add', '.'], cwd=outer, check=True, capture_output=True)
            subprocess.run(['git', 'commit', '-qm', 'generated launchers'], cwd=outer, check=True)
            inner = outer / '.getzilla/runtime/worktrees/inner'
            subprocess.run(['git', 'worktree', 'add', '--detach', str(inner), 'HEAD'],
                           cwd=outer, check=True, capture_output=True)
            inner_hook = inner / '.grok/hooks/user_prompt_submit.py'
            inner_hook.write_text(inner_hook.read_text().replace('    emit({', "    emit({'source_identity': __file__,"))
            outer_hook = outer / '.grok/hooks/user_prompt_submit.py'
            outer_hook.write_text('print(' + repr(json.dumps({'outer-hook': True})) + ')\n')
            config = json.loads((inner / '.codex/hooks.json').read_text())['hooks']
            environment = {key: value for key, value in os.environ.items()
                           if key not in ('CLAUDE_PROJECT_DIR', 'QWEN_PROJECT_DIR', 'GEMINI_PROJECT_DIR')}
            deep = inner / 'src/deep'
            deep.mkdir(parents=True)
            for directory in (inner, deep):
                prompt = subprocess.run(config['UserPromptSubmit'][0]['hooks'][0]['command'],
                    shell=True, cwd=directory, env=environment, text=True, capture_output=True,
                    input=json.dumps({'cwd': str(inner), 'session_id': 'nested-route',
                                      'prompt': 'Fix command security policy tests'}), timeout=30)
                self.assertEqual(prompt.returncode, 0, prompt.stderr)
                output = json.loads(prompt.stdout)
                self.assertEqual(Path(output.get('source_identity', '')).resolve(), inner_hook.resolve())
                self.assertIn('additionalContext', output['hookSpecificOutput'])
                route = json.loads((inner / '.getzilla/runtime/active-route.json').read_text())
                self.assertIn(route['write_agent'], route['allowed_agents'])
                self.assertIn(route['route_id'], output['hookSpecificOutput']['additionalContext'])
            self.assertFalse((outer / '.getzilla/runtime/active-route.json').exists())
            denial = subprocess.run(config['PreToolUse'][0]['hooks'][0]['command'], shell=True,
                cwd=deep, env=environment, text=True, capture_output=True,
                input=json.dumps({'cwd': str(inner), 'tool_name': 'exec_command',
                                  'tool_input': {'cmd': 'terraform destroy'}}), timeout=30)
            self.assertEqual(json.loads(denial.stdout)['hookSpecificOutput']['permissionDecision'], 'deny')
            self.assertTrue((inner / '.getzilla/runtime/tool-denials.json').is_file())
            self.assertFalse((outer / '.getzilla/runtime/tool-denials.json').exists())
            environment['CLAUDE_PROJECT_DIR'] = str(outer)
            explicit = subprocess.run(config['UserPromptSubmit'][0]['hooks'][0]['command'],
                shell=True, cwd=deep, env=environment, text=True, capture_output=True,
                input='{}', timeout=30)
            self.assertTrue(json.loads(explicit.stdout)['outer-hook'])

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
