"""The Qwen Code, Claude Code and Codex harnesses are generated, never hand-edited.

`.grok/hooks.json`, `.grok/agents/*.toml` and `.agents/skills/` stay canonical;
`scripts/getzilla_harness.py --write` renders `.qwen/`, `.claude/` and `.codex/`
from them. These tests fail when the committed copies drift.
"""

from __future__ import annotations

import json
import sys
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.harnesses import CODEX_HOOK_EVENTS, COPILOT_EVENTS, GEMINI_EVENTS, drift, render


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


if __name__ == '__main__':
    unittest.main()
