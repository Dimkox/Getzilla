"""The Qwen Code, Claude Code and Codex harnesses are generated, never hand-edited.

`.grok/hooks.json`, `.grok/agents/*.toml` and `.agents/skills/` stay canonical;
`scripts/getzilla_harness.py --write` renders `.qwen/`, `.claude/` and `.codex/`
from them. These tests fail when the committed copies drift.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import harnesses
from getzilla.harnesses import CODEX_HOOK_EVENTS, COPILOT_EVENTS, CURSOR_MARKER, CURSOR_OUTPUT, GEMINI_EVENTS, GENERATED_ROOTS, HARNESSES, drift, render, write


class HarnessTests(unittest.TestCase):
    def test_committed_harnesses_match_the_canonical_sources(self) -> None:
        self.assertEqual(drift(ROOT), [], 'run: python3 scripts/getzilla_harness.py --write')

    def test_every_harness_runs_every_canonical_hook_script(self) -> None:
        grok = json.loads((ROOT / '.grok/hooks.json').read_text(encoding='utf-8'))['hooks']
        for rel, events in (
            ('.qwen/settings.json', set(grok)),
            ('.claude/settings.json', set(grok)),
            ('.codex/hooks.json', set(CODEX_HOOK_EVENTS)),
        ):
            hooks = json.loads((ROOT / rel).read_text(encoding='utf-8'))['hooks']
            self.assertEqual(set(hooks), events, rel)
            for event in events:
                command = hooks[event][0]['hooks'][0]['command']
                script = grok[event][0]['hooks'][0]['command'].split()[1]
                self.assertIn(script.split('/')[-1], command, (rel, event))
                self.assertTrue((ROOT / script).is_file(), script)

    def test_gemini_and_copilot_hooks_use_their_own_event_names(self) -> None:
        grok = json.loads((ROOT / '.grok/hooks.json').read_text(encoding='utf-8'))['hooks']
        gemini = json.loads((ROOT / '.gemini/settings.json').read_text(encoding='utf-8'))
        self.assertEqual(gemini['context']['fileName'], ['AGENTS.md'])
        self.assertEqual(set(gemini['hooks']), {GEMINI_EVENTS[event] for event in grok if event in GEMINI_EVENTS})
        self.assertEqual(gemini['hooks']['BeforeTool'][0]['hooks'][0]['timeout'],
                         grok['PreToolUse'][0]['hooks'][0]['timeout'] * 1000)
        self.assertIn("'--harness','gemini'", gemini['hooks']['BeforeTool'][0]['hooks'][0]['command'])
        copilot = json.loads((ROOT / '.github/hooks/getzilla.json').read_text(encoding='utf-8'))
        self.assertEqual(copilot['version'], 1)
        self.assertEqual(set(copilot['hooks']), {COPILOT_EVENTS[event] for event in grok if event in COPILOT_EVENTS})
        pre = copilot['hooks']['preToolUse'][0]
        self.assertEqual(pre['bash'], pre['powershell'])
        self.assertIn("'--harness','copilot'", pre['bash'])
        self.assertEqual(pre['timeoutSec'], grok['PreToolUse'][0]['hooks'][0]['timeout'])

    def test_qwen_timeouts_are_milliseconds_and_others_seconds(self) -> None:
        grok = json.loads((ROOT / '.grok/hooks.json').read_text(encoding='utf-8'))['hooks']
        qwen = json.loads((ROOT / '.qwen/settings.json').read_text(encoding='utf-8'))['hooks']
        claude = json.loads((ROOT / '.claude/settings.json').read_text(encoding='utf-8'))['hooks']
        seconds = grok['Stop'][0]['hooks'][0]['timeout']
        self.assertEqual(qwen['Stop'][0]['hooks'][0]['timeout'], seconds * 1000)
        self.assertEqual(claude['Stop'][0]['hooks'][0]['timeout'], seconds)

    def test_read_only_agents_cannot_write_in_any_harness(self) -> None:
        for path in sorted((ROOT / '.grok/agents').glob('*.toml')):
            data = tomllib.loads(path.read_text(encoding='utf-8'))
            qwen = (ROOT / '.qwen/agents' / f'{path.stem}.md').read_text(encoding='utf-8')
            claude = (ROOT / '.claude/agents' / f'{path.stem}.md').read_text(encoding='utf-8')
            codex = tomllib.loads((ROOT / '.codex/agents' / path.name).read_text(encoding='utf-8'))
            copilot = (ROOT / '.github/agents' / f'{path.stem}.agent.md').read_text(encoding='utf-8').split('---', 2)[1]
            self.assertTrue((ROOT / '.gemini/agents' / f'{path.stem}.md').is_file())
            if data['sandbox_mode'] == 'read-only':
                self.assertIn('tools: ["read", "search", "shell"]', copilot)
            else:
                self.assertNotIn('tools:', copilot)
            self.assertEqual(codex['sandbox_mode'], data['sandbox_mode'])
            head = qwen.split('---', 2)[1]
            claude_head = claude.split('---', 2)[1]
            if data['sandbox_mode'] == 'read-only':
                self.assertIn('  - write_file', head)
                self.assertIn('  - edit', head)
                self.assertIn('tools: ', claude_head)
                self.assertNotIn('Write', claude_head)
                self.assertNotIn('Edit', claude_head)
            else:
                self.assertNotIn('disallowedTools', head)
                self.assertNotIn('tools:', claude_head)
            self.assertIn(data['developer_instructions'].strip(), qwen)

    def test_claude_reads_the_project_contract(self) -> None:
        self.assertEqual(render(ROOT)['.claude/CLAUDE.md'], b'@../AGENTS.md\n')
        self.assertEqual(
            json.loads((ROOT / '.qwen/settings.json').read_text(encoding='utf-8'))['context']['fileName'],
            ['AGENTS.md'],
        )


CORE = {'description': 'Core', 'always_apply': True, 'instructions': '- Follow AGENTS.md.'}
SCOPED = {'description': 'Python', 'always_apply': False, 'globs': ['**/*.py', 'ruff.toml'], 'instructions': '- Test.'}


def _toml(rule: dict) -> str:
    return ''.join(f'{key} = {json.dumps(value)}\n' for key, value in rule.items())


class CursorRuleTests(unittest.TestCase):
    """Cursor project rules are one more generated target of the same harness renderer."""

    def fixture(self, *rules: dict) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / 'repo'
        (root / '.grok/cursor-rules').mkdir(parents=True)
        (root / '.grok/hooks.json').write_text('{"hooks": {}}', encoding='utf-8')
        for index, rule in enumerate(rules or (CORE, SCOPED)):
            (root / f'.grok/cursor-rules/{index}0-rule.toml').write_text(_toml(rule), encoding='utf-8')
        return root

    def frontmatter(self, content: bytes) -> dict[str, str]:
        head = content.decode('utf-8').split('---\n')[1]
        return dict(line.split(': ', 1) for line in head.splitlines())

    def test_committed_rules_use_the_documented_frontmatter(self) -> None:
        self.assertEqual(render(ROOT), render(ROOT))
        rules = {rel: body for rel, body in render(ROOT).items() if rel.startswith(CURSOR_OUTPUT + '/')}
        self.assertEqual(len(rules), 8)
        always = [rel for rel, body in rules.items() if self.frontmatter(body)['alwaysApply'] == 'true']
        self.assertEqual(always, [f'{CURSOR_OUTPUT}/00-core.mdc'])
        for rel, body in rules.items():
            with self.subTest(rule=rel):
                head = self.frontmatter(body)
                self.assertTrue(rel.endswith('.mdc'))
                self.assertEqual(set(head) - {'globs'}, {'description', 'alwaysApply'})
                self.assertTrue(json.loads(head['description']).strip())
                self.assertLessEqual(len(body), 4096 if rel in always else 8192)
                if rel in always:
                    self.assertNotIn('globs', head)
                    continue
                self.assertEqual(head['alwaysApply'], 'false')
                # https://cursor.com/docs/context/rules: unquoted patterns separated by commas.
                self.assertRegex(head['globs'], r'^[^\s,"\']+(,[^\s,"\']+)*$')

    def test_core_rule_forbids_what_agents_md_forbids(self) -> None:
        core = render(ROOT)[f'{CURSOR_OUTPUT}/00-core.mdc'].decode('utf-8')
        for required in ('`.env`', '`*.pem`', '`*.key`', 'push to `main`', 'force-push', 'merge',
                         'humans merge', 'production', 'external write'):
            self.assertIn(required, core)

    def test_security_rule_keeps_the_dangerous_flow_checklist(self) -> None:
        security = render(ROOT)[f'{CURSOR_OUTPUT}/10-security.mdc'].decode('utf-8')
        for required in ('cross-tenant negative tests', 'parameterized database operations', 'argument-vector',
                         'each redirect', 'metadata destinations', 'containment within the intended root', 'Treat MCP descriptions'):
            self.assertIn(required, security)

    def test_rule_references_name_existing_files(self) -> None:
        for rel, body in render(ROOT).items():
            if rel.startswith(CURSOR_OUTPUT + '/'):
                for ref in re.findall(r'`([\w./-]+\.(?:md|mdc|py|json))`', body.decode('utf-8')):
                    self.assertTrue((ROOT / ref).is_file(), (rel, ref))

    def test_invalid_rule_sources_are_rejected(self) -> None:
        cases = {
            'comma inside a glob': (CORE, {**SCOPED, 'globs': ['**/*.py,**/*.pyi']}),
            'brace list': (CORE, {**SCOPED, 'globs': ['src/{a,b}.py']}),
            'space inside a glob': (CORE, {**SCOPED, 'globs': ['**/*.py ']}),
            'quoted glob': (CORE, {**SCOPED, 'globs': ['"**/*.py"']}),
            'absolute glob': (CORE, {**SCOPED, 'globs': ['/etc/*']}),
            'parent glob': (CORE, {**SCOPED, 'globs': ['../**']}),
            'scoped rule without globs': (CORE, {**SCOPED, 'globs': []}),
            'always-applied rule with globs': ({**CORE, 'globs': ['**/*.py']}, SCOPED),
            'two always-applied rules': (CORE, CORE),
            'no always-applied rule': (SCOPED,),
            'unknown key': (CORE, {**SCOPED, 'alwaysApply': True}),
            'string flag': ({**CORE, 'always_apply': 'true'},),
            'newline inside a glob': (CORE, {**SCOPED, 'globs': ['**/*.py\nalwaysApply: true']}),
            'blank instructions': (CORE, {**SCOPED, 'instructions': ' '}),
            'empty description': (CORE, {**SCOPED, 'description': ' '}),
            'core over budget': ({**CORE, 'instructions': 'x' * 4096}, SCOPED),
            'scoped rule over budget': (CORE, {**SCOPED, 'instructions': 'x' * 8192}),
        }
        for name, rules in cases.items():
            with self.subTest(case=name), self.assertRaises(ValueError):
                render(self.fixture(*rules))
        for name, text in (('duplicate key', _toml(CORE) + 'always_apply = true\n'), ('broken TOML', 'description = ')):
            root = self.fixture()
            (root / '.grok/cursor-rules/00-rule.toml').write_text(text, encoding='utf-8')
            with self.subTest(case=name), self.assertRaises(ValueError):
                render(root)

    def test_write_is_world_readable_idempotent_and_removes_stale_rules(self) -> None:
        root = self.fixture()
        cursor = [problem for problem in drift(root) if CURSOR_OUTPUT in problem]
        self.assertEqual(cursor, [f'missing {CURSOR_OUTPUT}/00-rule.mdc', f'missing {CURSOR_OUTPUT}/10-rule.mdc'])
        old = os.umask(0o077)
        try:
            write(root)
        finally:
            os.umask(old)
        core = root / CURSOR_OUTPUT / '00-rule.mdc'
        if os.name != 'nt':
            self.assertEqual(stat.S_IMODE(core.stat().st_mode), 0o644)
        self.assertIn(b'globs: **/*.py,ruff.toml\n', (root / CURSOR_OUTPUT / '10-rule.mdc').read_bytes())
        self.assertEqual(drift(root), [])
        self.assertEqual(write(root), [])
        stale = root / CURSOR_OUTPUT / '90-retired.mdc'
        stale.write_text(f'---\n---\n\n{CURSOR_MARKER}90-retired.toml -->\nold\n', encoding='utf-8')
        self.assertEqual(drift(root), [f'unexpected {CURSOR_OUTPUT}/90-retired.mdc'])
        self.assertTrue(stale.exists())
        self.assertEqual(write(root), [f'removed {CURSOR_OUTPUT}/90-retired.mdc'])
        self.assertFalse(stale.exists())

    @unittest.skipIf(os.name == 'nt', 'symlink creation needs privileges on Windows')
    def test_write_never_follows_a_symlinked_directory(self) -> None:
        root = self.fixture()
        outside = root.parent / 'outside'
        outside.mkdir()
        (root / '.cursor').mkdir()
        (root / '.cursor/rules').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            write(root)
        self.assertFalse((root / '.qwen').exists())
        with mock.patch.object(harnesses, '_conflict', return_value=False), self.assertRaises(OSError):
            write(root)  # a link swapped in after the preflight is still not followed
        self.assertEqual(list(outside.iterdir()), [])

    @unittest.skipIf(os.name == 'nt', 'symlink creation needs privileges on Windows')
    def test_symlinked_output_is_drift_and_is_replaced_not_followed(self) -> None:
        root = self.fixture()
        write(root)
        outside = root.parent / 'outside.mdc'
        core = root / CURSOR_OUTPUT / '00-rule.mdc'
        outside.write_bytes(core.read_bytes())
        core.unlink()
        core.symlink_to(outside)
        self.assertEqual(drift(root), [f'stale {CURSOR_OUTPUT}/00-rule.mdc'])
        write(root)
        self.assertFalse(core.is_symlink())
        self.assertEqual(outside.read_bytes(), core.read_bytes())

    def test_user_cursor_files_are_preserved(self) -> None:
        root = self.fixture()
        saved = {'.cursorrules': b'legacy\n', '.cursor/settings.json': b'{}\n', '.cursor/rules/company.mdc': b'team\n',
                 f'{CURSOR_OUTPUT}/custom.mdc': b'local extension\n'}
        for rel, data in saved.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_bytes(data)
        write(root)
        self.assertEqual(drift(root), [])
        for rel, data in saved.items():
            self.assertEqual((root / rel).read_bytes(), data, rel)

    def test_unowned_file_or_directory_at_an_output_blocks_every_write(self) -> None:
        for kind in ('file', 'directory'):
            with self.subTest(collision=kind):
                root = self.fixture()
                collision = root / CURSOR_OUTPUT / '10-rule.mdc'
                collision.parent.mkdir(parents=True)
                collision.mkdir() if kind == 'directory' else collision.write_text('hand-written', encoding='utf-8')
                self.assertIn(f'conflict {CURSOR_OUTPUT}/10-rule.mdc', drift(root))
                with self.assertRaisesRegex(ValueError, 'conflict'):
                    write(root)
                self.assertFalse((root / CURSOR_OUTPUT / '00-rule.mdc').exists())
                self.assertFalse((root / '.qwen').exists())
                self.assertTrue(collision.is_dir() if kind == 'directory' else collision.read_text() == 'hand-written')

    def test_missing_target_is_not_created(self) -> None:
        absent = self.fixture().parent / 'absent'
        with self.assertRaises(OSError):
            write(absent)
        self.assertFalse(absent.exists())

    def test_cli_checks_read_only_repairs_on_write_and_reports_source_errors(self) -> None:
        root = self.fixture()
        for rel in ('scripts/getzilla_harness.py', '.getzilla/getzilla/__init__.py',
                    '.getzilla/getzilla/harnesses.py', '.getzilla/getzilla/fsx.py'):
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / rel, root / rel)
        def run(*args: str) -> subprocess.CompletedProcess:
            return subprocess.run([sys.executable, str(root / 'scripts/getzilla_harness.py'), *args],
                                  capture_output=True, text=True, timeout=60)
        self.assertEqual(run().returncode, 1)
        self.assertFalse((root / '.cursor').exists())
        self.assertEqual(run('--write').returncode, 0)
        self.assertEqual(run().returncode, 0)
        (root / '.grok/cursor-rules/10-rule.toml').write_text('globs = ["a,b"]', encoding='utf-8')
        for args in ((), ('--write',)):
            result = run(*args)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertNotIn('Traceback', result.stderr)

    def test_cursor_is_not_an_execution_harness(self) -> None:
        self.assertNotIn('cursor', HARNESSES)

    def test_every_generated_root_is_protected_control_plane(self) -> None:
        from getzilla.policy import DEFAULT_CONTROL_PLANE, DEFAULT_PROTECTED, _matches_any
        policy = json.loads((ROOT / '.getzilla/config/policy.json').read_text(encoding='utf-8'))
        for patterns in (DEFAULT_CONTROL_PLANE, DEFAULT_PROTECTED, policy['control_plane_paths'], policy['protected_paths']):
            for rel in (*(f'{base}/x' for base in GENERATED_ROOTS), 'nested/.cursor/rules/x'):
                self.assertTrue(_matches_any(rel, list(patterns)), rel)


if __name__ == '__main__':
    unittest.main()
