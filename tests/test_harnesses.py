"""The Qwen Code, Claude Code and Codex harnesses are generated, never hand-edited.

`.grok/hooks.json`, `.grok/agents/*.toml` and `.agents/skills/` stay canonical;
`scripts/getzilla_harness.py --repository-all --write` renders `.qwen/`, `.claude/` and `.codex/`
from them. These tests fail when the committed copies drift.
"""

from __future__ import annotations

import hashlib
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


def _select(root: Path) -> None:
    from getzilla.component_state import MANIFEST, V2, KNOWN_AGENTS, encode_manifest
    (root / '.getzilla').mkdir(exist_ok=True)
    (root / MANIFEST).write_bytes(encode_manifest({'schema_version': V2, 'agents': list(KNOWN_AGENTS), 'components': {}}))


class SelectedHarnessTests(unittest.TestCase):
    def fixture(self, agents: tuple[str, ...]) -> Path:
        from getzilla.component_state import V2, encode_manifest
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / '.getzilla').mkdir()
        (root / '.getzilla/managed-components.json').write_bytes(encode_manifest({
            'schema_version': V2, 'agents': list(agents), 'components': {},
        }))
        return root

    def test_empty_selection_does_not_read_unused_sources_or_initialize_outputs(self) -> None:
        root = self.fixture(())
        before = (root / '.getzilla/managed-components.json').read_bytes()
        self.assertEqual(render(root), {})
        self.assertEqual(drift(root), [])
        self.assertEqual(write(root), [])
        self.assertEqual((root / '.getzilla/managed-components.json').read_bytes(), before)
        self.assertFalse((root / '.codex').exists())

    def qwen(self) -> Path:
        root = self.fixture(('qwen',))
        (root / '.grok/cursor-rules').mkdir(parents=True)
        (root / '.grok/cursor-rules/unused.toml').write_text('not valid TOML')
        (root / '.grok/hooks.json').write_text('{"hooks": {}}')
        (root / '.agents/skills/example').mkdir(parents=True)
        (root / '.agents/skills/example/SKILL.md').write_text('first canonical version\n')
        return root

    def test_only_selected_outputs_are_generated_and_unknown_files_survive(self) -> None:
        root = self.qwen()
        (root / '.qwen/user-empty').mkdir(parents=True)
        (root / '.qwen/custom.txt').write_text('user')
        (root / '.codex').mkdir()
        (root / '.codex/config.toml').write_text('user codex configuration')
        self.assertTrue(all(path.startswith('.qwen/') for path in render(root)))
        write(root)
        self.assertEqual((root / '.qwen/custom.txt').read_text(), 'user')
        self.assertTrue((root / '.qwen/user-empty').is_dir())
        self.assertEqual((root / '.codex/config.toml').read_text(), 'user codex configuration')
        self.assertEqual(drift(root), [])

    def test_changed_owned_output_refuses_and_canonical_change_can_update(self) -> None:
        root = self.qwen()
        write(root)
        source = root / '.agents/skills/example/SKILL.md'
        source.write_text('second canonical version\n')
        write(root)
        output = root / '.qwen/skills/example/SKILL.md'
        self.assertEqual(output.read_text(), 'second canonical version\n')
        output.write_text('my custom version\n')
        source.write_text('third canonical version\n')
        with self.assertRaisesRegex(ValueError, 'conflict'):
            write(root)
        self.assertEqual(output.read_text(), 'my custom version\n')

    def test_kept_manifest_refuses_before_any_generated_effect(self) -> None:
        from getzilla.component_state import MANIFEST
        for legacy in (False, True):
            with self.subTest(legacy=legacy):
                root = self.qwen()
                original = (root / MANIFEST).read_bytes()
                relative = '.grok-stack/managed-components.json' if legacy else MANIFEST
                record = root / ('.grok-stack/AGBP_SYNC.json' if legacy else '.getzilla/AGBP_SYNC.json')
                record.parent.mkdir(exist_ok=True)
                record.write_text(json.dumps({'schema_version': 1, 'kept_local': [relative],
                                              'kept_local_sha256': {relative: hashlib.sha256(original).hexdigest()}}))
                with self.assertRaisesRegex(ValueError, 'kept.*manifest'):
                    write(root)
                self.assertEqual((root / MANIFEST).read_bytes(), original)
                self.assertFalse((root / '.qwen').exists())
                self.assertFalse((root / '.getzilla/runtime/.components.guard.lock').exists())

    def test_kept_manifest_noop_still_validates_its_declared_digest(self) -> None:
        from getzilla.component_state import MANIFEST
        root = self.qwen()
        write(root)
        original = (root / MANIFEST).read_bytes()
        (root / '.getzilla/AGBP_SYNC.json').write_text(json.dumps({
            'schema_version': 1, 'kept_local': [MANIFEST],
            'kept_local_sha256': {MANIFEST: hashlib.sha256(original).hexdigest()},
        }))
        self.assertEqual(write(root), [])
        self.assertEqual(drift(root), [])
        self.assertEqual((root / MANIFEST).read_bytes(), original)
        (root / MANIFEST).write_bytes(original + b'\n')
        with self.assertRaisesRegex(ValueError, 'digest'):
            write(root)
        self.assertEqual((root / MANIFEST).read_bytes(), original + b'\n')

    def test_windows_legacy_keep_alias_maps_before_managed_matching(self) -> None:
        from getzilla.component_state import MANIFEST, decode_keep_contract, match_kept_local
        path = '.GROK-STACK/MANAGED-COMPONENTS.JSON'
        digest = hashlib.sha256(b'manifest').hexdigest()
        raw = json.dumps({'kept_local': [path], 'kept_local_sha256': {path: digest}}).encode()
        with mock.patch.object(harnesses.fsx, 'WINDOWS', True):
            kept, digests = decode_keep_contract(raw, legacy=True)
            kept, digests = match_kept_local(kept, digests, (MANIFEST,))
        self.assertEqual(kept, {MANIFEST})
        self.assertEqual(digests, {MANIFEST: digest})
        with mock.patch.object(harnesses.fsx, 'WINDOWS', False):
            kept, _digests = decode_keep_contract(raw, legacy=True)
        self.assertEqual(kept, {path})

    def test_retirement_requires_unchanged_recorded_ownership(self) -> None:
        root = self.qwen()
        write(root)
        owned = root / '.qwen/skills/example/SKILL.md'
        unknown = root / '.qwen/skills/example/unknown.md'
        unknown.write_text('user')
        (root / '.agents/skills/example/SKILL.md').unlink()
        write(root)
        self.assertFalse(owned.exists())
        self.assertEqual(unknown.read_text(), 'user')
        self.assertTrue(owned.parent.is_dir())

    def test_declared_kept_paths_survive_changes_removal_and_absence(self) -> None:
        for scenario in ('changed', 'removed', 'absent'):
            with self.subTest(scenario=scenario):
                root = self.qwen()
                write(root)
                relative = '.qwen/skills/example/SKILL.md'
                output = root / relative
                original = output.read_bytes()
                (root / '.getzilla/AGBP_SYNC.json').write_text(json.dumps({
                    'schema_version': 1, 'kept_local': [relative],
                    'kept_local_sha256': {relative: hashlib.sha256(original).hexdigest()},
                }))
                source = root / '.agents/skills/example/SKILL.md'
                if scenario == 'removed':
                    source.unlink()
                elif scenario == 'absent':
                    output.unlink()
                else:
                    source.write_text('new canonical content\n')
                (root / '.agents/skills/another').mkdir()
                (root / '.agents/skills/another/SKILL.md').write_text('another canonical skill\n')
                before = output.read_bytes() if output.exists() else None
                self.assertFalse(any(relative in problem for problem in drift(root)))
                write(root)
                self.assertEqual(output.read_bytes() if output.exists() else None, before)
                self.assertEqual((root / '.qwen/skills/another/SKILL.md').read_text(), 'another canonical skill\n')
                manifest = json.loads((root / '.getzilla/managed-components.json').read_bytes())
                self.assertNotIn(relative, manifest['components']['agent:qwen']['owned'])

    def test_changed_keep_digest_refuses_even_if_current_equals_new_generated_bytes(self) -> None:
        root = self.qwen()
        write(root)
        relative = '.qwen/skills/example/SKILL.md'
        output = root / relative
        (root / '.getzilla/AGBP_SYNC.json').write_text(json.dumps({
            'schema_version': 1, 'kept_local': [relative],
            'kept_local_sha256': {relative: hashlib.sha256(output.read_bytes()).hexdigest()},
        }))
        output.write_text('unacknowledged new content\n')
        (root / '.agents/skills/example/SKILL.md').write_bytes(output.read_bytes())
        (root / '.agents/skills/another').mkdir()
        (root / '.agents/skills/another/SKILL.md').write_text('must not be published\n')
        manifest_before = (root / '.getzilla/managed-components.json').read_bytes()
        with self.assertRaisesRegex(ValueError, 'kept'):
            write(root)
        self.assertEqual(output.read_text(), 'unacknowledged new content\n')
        self.assertFalse((root / '.qwen/skills/another/SKILL.md').exists())
        self.assertEqual((root / '.getzilla/managed-components.json').read_bytes(), manifest_before)

    def test_kept_custom_content_does_not_gain_owned_proof(self) -> None:
        root = self.qwen()
        relative = '.qwen/skills/example/SKILL.md'
        output = root / relative
        output.parent.mkdir(parents=True)
        output.write_text('custom retained skill\n')
        (root / '.getzilla/AGBP_SYNC.json').write_text(json.dumps({
            'schema_version': 1, 'kept_local': [relative],
            'kept_local_sha256': {relative: hashlib.sha256(output.read_bytes()).hexdigest()},
        }))
        write(root)
        self.assertEqual(output.read_text(), 'custom retained skill\n')
        manifest = json.loads((root / '.getzilla/managed-components.json').read_bytes())
        self.assertNotIn(relative, manifest['components']['agent:qwen']['owned'])

    def test_invalid_keep_records_refuse_before_any_generated_effect(self) -> None:
        invalid = (
            b'{', b'[]', b'{"schema_version":true}',
            b'{"schema_version":1,"kept_local":[],"kept_local":[".qwen/settings.json"]}',
            b'{"kept_local":["../outside"]}',
            b'{"kept_local":[".qwen/settings.json",".QWEN/settings.json"]}',
            b'{"kept_local":[],"kept_local_sha256":{".qwen/settings.json":"bad"}}',
            b'{"kept_local":[],"unknown":true}',
            b' ' * 65536 + b'{}',
        )
        for content in invalid:
            with self.subTest(content=content):
                root = self.qwen()
                (root / '.getzilla/AGBP_SYNC.json').write_bytes(content)
                manifest_before = (root / '.getzilla/managed-components.json').read_bytes()
                with self.assertRaises(ValueError):
                    write(root)
                self.assertFalse((root / '.qwen').exists())
                self.assertFalse((root / '.getzilla/runtime/.components.guard.lock').exists())
                self.assertEqual((root / '.getzilla/managed-components.json').read_bytes(), manifest_before)

    def test_current_keep_record_takes_precedence_over_legacy(self) -> None:
        root = self.qwen()
        (root / '.getzilla/AGBP_SYNC.json').write_text('{"schema_version":1,"kept_local":[]}')
        (root / '.grok-stack').mkdir()
        (root / '.grok-stack/AGBP_SYNC.json').write_text('invalid legacy record must stay unused')
        write(root)
        self.assertTrue((root / '.qwen/skills/example/SKILL.md').is_file())
        self.assertEqual((root / '.grok-stack/AGBP_SYNC.json').read_text(), 'invalid legacy record must stay unused')

    def test_windows_keep_alias_matches_exact_managed_path_and_digest(self) -> None:
        from getzilla.component_state import decode_keep_contract, match_kept_local
        path, canonical = '.CODEX/CONFIG.TOML', '.codex/config.toml'
        digest = hashlib.sha256(b'kept config').hexdigest()
        kept, digests = decode_keep_contract(json.dumps({
            'kept_local': [path], 'kept_local_sha256': {path: digest},
        }).encode())
        with mock.patch.object(harnesses.fsx, 'WINDOWS', True):
            matched, matched_digests = match_kept_local(kept, digests, (canonical, '.codex/hooks.json'))
        self.assertEqual(matched, {canonical})
        self.assertEqual(matched_digests, {canonical: digest})

    def test_legacy_keep_record_maps_old_generated_skill_names(self) -> None:
        root = self.fixture(('grok',))
        source = root / '.agents/skills/getzilla-delivery/SKILL.md'
        source.parent.mkdir(parents=True)
        source.write_text('retained canonical version\n')
        write(root)
        relative = '.grok/skills/getzilla-delivery/SKILL.md'
        legacy = '.grok/skills/adaptive-delivery/SKILL.md'
        output = root / relative
        original = output.read_bytes()
        (root / '.grok-stack').mkdir()
        (root / '.grok-stack/AGBP_SYNC.json').write_text(json.dumps({
            'schema_version': 1, 'kept_local': [legacy],
            'kept_local_sha256': {legacy: hashlib.sha256(original).hexdigest()},
        }))
        source.write_text('new canonical version\n')
        write(root)
        self.assertEqual(output.read_bytes(), original)

    def test_codex_keep_cannot_bypass_pair_preflight(self) -> None:
        config_path, hooks_path = '.codex/config.toml', '.codex/hooks.json'
        for scenario in ('missing-config', 'missing-hooks', 'malformed-config', 'disabled-config', 'stale-hooks'):
            with self.subTest(scenario=scenario):
                root = self.fixture(('codex',))
                (root / '.grok/agents').mkdir(parents=True)
                (root / '.grok/hooks.json').write_text('{"hooks":{}}')
                write(root)
                kept = hooks_path if scenario in ('missing-hooks', 'stale-hooks') else config_path
                original = (root / kept).read_bytes()
                if scenario.startswith('missing-'):
                    (root / kept).unlink()
                elif scenario == 'malformed-config':
                    (root / kept).write_text('not valid TOML')
                elif scenario == 'disabled-config':
                    (root / kept).write_text('[features]\ncodex_hooks = false\n')
                else:
                    (root / '.grok/hooks.json').write_text(json.dumps({'hooks': {'Stop': [{'hooks': [{
                        'command': 'python3 .grok/hooks/stop_gate.py', 'timeout': 10,
                    }]}]}}))
                preserved = (root / kept).read_bytes() if (root / kept).exists() else None
                (root / '.getzilla/AGBP_SYNC.json').write_text(json.dumps({
                    'schema_version': 1, 'kept_local': [kept],
                    'kept_local_sha256': {kept: hashlib.sha256(preserved if preserved is not None else original).hexdigest()},
                }))
                (root / '.grok/agents/new.toml').write_text('description="new"\ndeveloper_instructions="new"\n')
                manifest_before = (root / '.getzilla/managed-components.json').read_bytes()
                with self.assertRaisesRegex(ValueError, 'conflict'):
                    write(root)
                self.assertEqual((root / kept).read_bytes() if (root / kept).exists() else None, preserved)
                self.assertFalse((root / '.codex/agents/new.toml').exists())
                self.assertEqual((root / '.getzilla/managed-components.json').read_bytes(), manifest_before)

    def test_coherent_kept_codex_pair_stays_unchanged_without_owned_proofs(self) -> None:
        root = self.fixture(('codex',))
        (root / '.grok').mkdir()
        (root / '.grok/hooks.json').write_text('{"hooks":{}}')
        write(root)
        paths = ('.codex/config.toml', '.codex/hooks.json')
        before = {path: (root / path).read_bytes() for path in paths}
        (root / '.getzilla/AGBP_SYNC.json').write_text(json.dumps({
            'schema_version': 1, 'kept_local': list(paths),
            'kept_local_sha256': {path: hashlib.sha256(content).hexdigest() for path, content in before.items()},
        }))
        write(root)
        self.assertEqual({path: (root / path).read_bytes() for path in paths}, before)
        owned = json.loads((root / '.getzilla/managed-components.json').read_bytes())['components']['agent:codex']['owned']
        self.assertFalse(set(paths) & set(owned))


class HarnessTests(unittest.TestCase):
    def test_codex_overlay_survives_regeneration_without_replacing_guards(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / '.grok', root / '.grok')
            _select(root)
            overlay = {'hooks': {
                'Stop': [{'hooks': [{'type': 'command', 'command': 'entire hooks codex stop', 'timeout': 30}]}],
                'SessionEnd': [{'hooks': [{'type': 'command', 'command': 'entire hooks codex session-end', 'timeout': 3}]}],
            }}
            (root / '.grok/codex-hooks.json').write_text(json.dumps(overlay), encoding='utf-8')
            outputs = render(root)
            hooks = json.loads(outputs['.codex/hooks.json'])['hooks']
            self.assertEqual(set(hooks), set(CODEX_HOOK_EVENTS) | {'SessionEnd'})
            self.assertIn('stop_gate.py', hooks['Stop'][0]['hooks'][0]['command'])
            self.assertEqual(hooks['Stop'][1:], overlay['hooks']['Stop'])
            self.assertEqual(hooks['SessionEnd'], overlay['hooks']['SessionEnd'])
            self.assertNotIn(b'entire hooks', outputs['.claude/settings.json'])
            write(root)
            self.assertEqual(render(root), outputs)
            self.assertEqual(drift(root), [])
            write(root)
            self.assertEqual((root / '.codex/hooks.json').read_bytes(), outputs['.codex/hooks.json'])
            (root / '.grok/codex-hooks.json').unlink()
            baseline = json.loads(render(root)['.codex/hooks.json'])['hooks']
            self.assertEqual(set(baseline), set(CODEX_HOOK_EVENTS))
            self.assertNotIn('entire', json.dumps(baseline))

    @unittest.skipIf(os.name == 'nt', 'Entire shell hooks require POSIX sh')
    def test_entire_missing_cli_is_nonblocking(self):
        overlay = json.loads((ROOT / '.grok/codex-hooks.json').read_text())['hooks']
        shell = shutil.which('sh')
        self.assertIsNotNone(shell)
        with tempfile.TemporaryDirectory() as empty_path:
            for event, groups in overlay.items():
                command = groups[0]['hooks'][0]['command']
                result = subprocess.run([shell, '-c', command.removeprefix('sh -c ')[1:-1]],
                                        env={**os.environ, 'PATH': empty_path},
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, (event, result.stderr))
                if event == 'SessionStart':
                    self.assertIn('Entire CLI', json.loads(result.stdout)['systemMessage'])

    def test_grok_skills_are_rendered_from_the_canonical_sources(self):
        outputs = render(ROOT)
        for source in (ROOT / '.agents/skills').rglob('*'):
            if source.is_file():
                relative = source.relative_to(ROOT / '.agents/skills').as_posix()
                self.assertEqual(outputs.get('.grok/skills/' + relative), source.read_bytes(), relative)

    def test_committed_harnesses_match_the_canonical_sources(self) -> None:
        self.assertEqual(drift(ROOT), [], 'run: python3 scripts/getzilla_harness.py --repository-all --write')

    def test_every_harness_runs_every_canonical_hook_script(self) -> None:
        grok = json.loads((ROOT / '.grok/hooks.json').read_text(encoding='utf-8'))['hooks']
        for rel, events in (
            ('.qwen/settings.json', set(grok)),
            ('.claude/settings.json', set(grok)),
            ('.codex/hooks.json', set(CODEX_HOOK_EVENTS)),
        ):
            hooks = json.loads((ROOT / rel).read_text(encoding='utf-8'))['hooks']
            extra = set(json.loads((ROOT / '.grok/codex-hooks.json').read_text())['hooks']) if rel == '.codex/hooks.json' else set()
            self.assertEqual(set(hooks), events | extra, rel)
            for event in events:
                command = hooks[event][0]['hooks'][0]['command']
                script = grok[event][0]['hooks'][0]['command'].split()[1]
                self.assertIn(script.split('/')[-1], command, (rel, event))
                self.assertTrue((ROOT / script).is_file(), script)

    def test_entire_is_codex_only_and_each_hook_runs_once(self):
        expected = {'SessionStart', 'UserPromptSubmit', 'PostToolUse', 'Stop',
                    'SessionEnd', 'SubagentStart', 'SubagentStop'}
        overlay = json.loads((ROOT / '.grok/codex-hooks.json').read_text())['hooks']
        self.assertEqual(set(overlay), expected)
        outputs = render(ROOT)
        codex = json.loads(outputs['.codex/hooks.json'])['hooks']
        for event in expected:
            additions = [hook for group in codex[event] for hook in group['hooks']
                         if 'exec entire hooks codex ' in hook['command']]
            self.assertEqual(additions, overlay[event][0]['hooks'])
            self.assertEqual(len(additions), 1)
        self.assertNotIn(b'entire hooks', outputs['.claude/settings.json'])
        cursor = ROOT / '.cursor/hooks.json'
        self.assertTrue(not cursor.exists() or 'entire' not in cursor.read_text())

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
        _select(root)
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

    def test_rules_do_not_inline_agents_md(self) -> None:
        # Cursor reads AGENTS.md itself; an `@AGENTS.md` include would load the whole contract a second time.
        for rel, body in render(ROOT).items():
            if rel.startswith(CURSOR_OUTPUT + '/'):
                self.assertNotIn(b'@AGENTS.md', body, rel)
        self.assertIn(b'AGENTS.md', render(ROOT)[f'{CURSOR_OUTPUT}/00-core.mdc'])

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
            'bare newline inside a glob': (CORE, {**SCOPED, 'globs': ['src/*.py\nsecrets/**']}),
            'glob starting with !': (CORE, {**SCOPED, 'globs': ['!**/*.py']}),
            'non-string instructions': (CORE, {**SCOPED, 'instructions': 5}),
            'list instructions': (CORE, {**SCOPED, 'instructions': ['- Test.']}),
            'scoped rule over 500 lines': (CORE, {**SCOPED, 'instructions': '\n'.join(['x'] * 501)}),
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

    def test_empty_rule_source_set_is_rejected_and_keeps_generated_rules(self) -> None:
        root = self.fixture()
        write(root)
        for source in (root / '.grok/cursor-rules').glob('*.toml'):
            source.unlink()
        with self.assertRaises(ValueError):
            write(root)
        self.assertTrue((root / CURSOR_OUTPUT / '00-rule.mdc').is_file())

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
        source = root / '.grok/cursor-rules/90-retired.toml'
        source.write_text(_toml(SCOPED), encoding='utf-8')
        write(root)
        stale = root / CURSOR_OUTPUT / '90-retired.mdc'
        source.unlink()
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
        self.assertEqual(list(outside.iterdir()), [])

    @unittest.skipIf(os.name == 'nt', 'symlink creation needs privileges on Windows')
    def test_symlink_in_the_rules_folder_is_the_users_and_never_read_through(self) -> None:
        root = self.fixture()
        write(root)
        outside = root.parent / 'outside.mdc'
        outside.write_bytes(f'{CURSOR_MARKER}looks generated -->\n'.encode('utf-8'))  # a marker behind a link proves nothing
        core = root / CURSOR_OUTPUT / '00-rule.mdc'
        core.unlink()
        core.symlink_to(outside)
        custom = root / CURSOR_OUTPUT / 'custom.mdc'
        custom.symlink_to(outside)
        self.assertEqual(drift(root), [f'conflict {CURSOR_OUTPUT}/00-rule.mdc'])
        with self.assertRaisesRegex(ValueError, 'conflict'):
            write(root)
        self.assertTrue(core.is_symlink() and custom.is_symlink())
        core.unlink()
        self.assertEqual(write(root), [f'wrote {CURSOR_OUTPUT}/00-rule.mdc'])
        self.assertTrue(custom.is_symlink())
        self.assertEqual(outside.read_bytes(), f'{CURSOR_MARKER}looks generated -->\n'.encode('utf-8'))

    @unittest.skipIf(os.name == 'nt', 'symlink creation needs privileges on Windows')
    def test_links_in_another_generated_root_are_drift_and_never_followed(self) -> None:
        root = self.fixture()
        write(root)
        outside = root.parent / 'outside.json'
        settings = root / '.qwen/settings.json'
        outside.write_bytes(settings.read_bytes())
        settings.unlink()
        settings.symlink_to(outside)  # same bytes behind a link are still stale
        extra = root / '.qwen/extra.json'
        extra.symlink_to(root.parent / 'absent.json')
        self.assertEqual(drift(root), ['conflict .qwen/settings.json'])
        with self.assertRaisesRegex(ValueError, 'conflict'):
            write(root)
        self.assertTrue(settings.is_symlink() and extra.is_symlink())
        settings.unlink()
        self.assertEqual(write(root), ['wrote .qwen/settings.json'])
        self.assertTrue(extra.is_symlink())
        self.assertEqual(outside.read_bytes(), settings.read_bytes())
        self.assertFalse((root.parent / 'absent.json').exists())

    def test_grok_skill_drift_repair_and_retirement_preserve_configuration(self) -> None:
        root = self.fixture()
        canonical = root / '.agents/skills/example/SKILL.md'
        canonical.parent.mkdir(parents=True)
        canonical.write_text('canonical skill')
        agent = root / '.grok/agents/owner.toml'
        agent.parent.mkdir(parents=True)
        agent_bytes = (ROOT / '.grok/agents/general_implementer.toml').read_bytes()
        agent.write_bytes(agent_bytes)
        hooks = (root / '.grok/hooks.json').read_bytes()
        write(root)
        mirror = root / '.grok/skills/example/SKILL.md'
        canonical.write_text('updated canonical skill')
        retired = root / '.grok/skills/retired.md'
        retired.write_text('user file')
        self.assertIn('stale .grok/skills/example/SKILL.md', drift(root))
        write(root)
        self.assertEqual(mirror.read_bytes(), canonical.read_bytes())
        self.assertEqual(retired.read_text(), 'user file')
        canonical.unlink()
        write(root)
        self.assertFalse(mirror.exists())
        self.assertEqual(retired.read_text(), 'user file')
        self.assertEqual((root / '.grok/hooks.json').read_bytes(), hooks)
        self.assertEqual(agent.read_bytes(), agent_bytes)

    def test_write_preserves_unowned_empty_directories(self) -> None:
        root = self.fixture()
        write(root)
        (root / '.qwen/agents/retired').mkdir(parents=True)
        self.assertEqual(write(root), [])
        self.assertTrue((root / '.qwen/agents/retired').is_dir())

    def test_edited_rule_is_a_conflict_and_is_preserved(self) -> None:
        root = self.fixture()
        write(root)
        core = root / CURSOR_OUTPUT / '00-rule.mdc'
        expected = core.read_bytes()
        core.write_bytes(expected + b'- Hand edit.\n')
        self.assertEqual(drift(root), [f'conflict {CURSOR_OUTPUT}/00-rule.mdc'])
        self.assertEqual(core.read_bytes(), expected + b'- Hand edit.\n')
        with self.assertRaisesRegex(ValueError, 'conflict'):
            write(root)
        self.assertEqual(core.read_bytes(), expected + b'- Hand edit.\n')
        core.write_bytes(expected)
        self.assertEqual(drift(root), [])

    def test_rule_with_a_long_frontmatter_stays_owned(self) -> None:
        wide = {**SCOPED, 'globs': [f'area{index:03d}/**/*.py' for index in range(260)]}
        root = self.fixture(CORE, wide)
        rule = render(root)[f'{CURSOR_OUTPUT}/10-rule.mdc']
        self.assertGreater(rule.index(CURSOR_MARKER.encode('utf-8')), 4096)
        self.assertLessEqual(len(rule), 8192)
        write(root)
        self.assertEqual(drift(root), [])
        self.assertEqual(write(root), [])

    def test_a_file_where_a_parent_directory_goes_blocks_every_write(self) -> None:
        root = self.fixture()
        write(root)
        shutil.rmtree(root / '.cursor')
        (root / '.cursor').write_bytes(b'not a directory\n')
        settings = root / '.claude/settings.json'
        settings.write_bytes(b'{}\n')
        self.assertIn(f'conflict {CURSOR_OUTPUT}/00-rule.mdc', drift(root))
        with self.assertRaisesRegex(ValueError, 'no generated files written'):
            write(root)
        self.assertEqual(settings.read_bytes(), b'{}\n')
        self.assertEqual((root / '.cursor').read_bytes(), b'not a directory\n')

    @unittest.skipIf(os.name == 'nt', 'POSIX file modes')
    def test_writes_use_an_exclusive_unfollowed_temp_and_world_readable_directories(self) -> None:
        root = self.fixture()
        calls = []
        real = harnesses.fsx.open_at
        def spy(parent, name, flags, mode=0o777):
            calls.append((name, flags, mode))
            return real(parent, name, flags, mode)
        old = os.umask(0o022)
        try:
            with mock.patch.object(harnesses.fsx, 'open_at', side_effect=spy):
                write(root)
        finally:
            os.umask(old)
        temporaries = [call for call in calls if call[0].endswith('.tmp')]
        self.assertTrue(temporaries)
        for name, flags, mode in temporaries:
            self.assertRegex(name, r'^\.getzilla-component-[0-9a-f]{32}\.tmp$')
            self.assertEqual(flags & (os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW), os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW)
            self.assertEqual(mode, 0o600)  # promoted to the final 0644 after the content is complete
        for rel in ('.cursor', '.cursor/rules', CURSOR_OUTPUT, '.qwen'):
            self.assertEqual(stat.S_IMODE((root / rel).stat().st_mode), 0o755, rel)

    def test_failed_replace_leaves_no_temp_file(self) -> None:
        root = self.fixture()
        write(root)
        (root / '.grok/cursor-rules/00-rule.toml').write_text(_toml({**CORE, 'instructions': '- Changed.'}))
        with mock.patch.object(harnesses.fsx, 'replace_at', side_effect=OSError('disk full')), \
                self.assertRaisesRegex(ValueError, 'incomplete'):
            write(root)
        leftovers = [path for path in root.rglob('*.tmp')]
        self.assertEqual(leftovers, [])

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
                    '.getzilla/getzilla/harnesses.py', '.getzilla/getzilla/fsx.py', '.getzilla/getzilla/component_state.py',
                    '.getzilla/getzilla/skill_inventory.py', '.getzilla/getzilla/skill_preflight.py'):
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
