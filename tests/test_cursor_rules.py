"""Scoped Cursor rules are generated; installation owns only its named outputs."""
from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import cursor_rules


class CursorRulesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'source'
        self.root.mkdir()
        (self.root / '.getzilla').mkdir()
        (self.root / 'AGENTS.md').write_text('# Project contract\n', encoding='utf-8')
        self.spec = {
            'version': 1,
            'rules': [
                {'id': '00-core', 'title': 'Project core', 'description': 'Project-wide instructions',
                 'alwaysApply': True, 'globs': [], 'references': ['AGENTS.md'],
                 'instructions': ['Preserve existing work.', 'Do not claim unexecuted checks passed.']},
                {'id': '20-python', 'title': 'Python', 'description': 'When changing Python code',
                 'alwaysApply': False, 'globs': ['**/*.py'], 'references': ['AGENTS.md'],
                 'instructions': ['Use the project test commands.']},
            ],
        }
        self.save()

    def save(self) -> None:
        (self.root / cursor_rules.SOURCE).write_text(json.dumps(self.spec), encoding='utf-8')

    def test_render_is_deterministic_and_scoped(self) -> None:
        first = cursor_rules.render(self.root)
        self.assertEqual(first, cursor_rules.render(self.root))
        self.assertEqual(len(first), 2)
        core = first[f'{cursor_rules.OUTPUT}/00-core.mdc'].decode()
        scoped = first[f'{cursor_rules.OUTPUT}/20-python.mdc'].decode()
        self.assertIn('alwaysApply: true', core)
        self.assertNotIn('globs:', core)
        self.assertIn('alwaysApply: false', scoped)
        self.assertIn('**/*.py', scoped)
        self.assertIn(cursor_rules.MARKER, scoped)
        self.assertNotIn('@AGENTS.md', core)

    def test_missing_then_write_then_clean_then_idempotent(self) -> None:
        self.assertEqual(len(cursor_rules.drift(self.root)), 2)
        self.assertEqual(len(cursor_rules.write(self.root)), 2)
        self.assertEqual(cursor_rules.drift(self.root), [])
        self.assertEqual(cursor_rules.write(self.root), [])

    def test_stale_generated_rule_is_detected_and_repaired(self) -> None:
        cursor_rules.write(self.root)
        path = self.root / cursor_rules.OUTPUT / '20-python.mdc'
        path.write_bytes(path.read_bytes() + b'\nOld generated content\n')
        self.assertTrue(any('stale' in p for p in cursor_rules.drift(self.root)))
        cursor_rules.write(self.root)
        self.assertEqual(cursor_rules.drift(self.root), [])

    def test_custom_rules_legacy_file_and_local_settings_are_preserved(self) -> None:
        saved = {
            '.cursorrules': b'legacy user instructions\n',
            '.cursor/settings.json': b'{"user":"settings"}\n',
            '.cursor/rules/company.mdc': b'company policy\n',
            f'{cursor_rules.OUTPUT}/custom.mdc': b'local extension\n',
        }
        for rel, data in saved.items():
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        cursor_rules.write(self.root)
        self.assertEqual(cursor_rules.drift(self.root), [])
        for rel, data in saved.items():
            self.assertEqual((self.root / rel).read_bytes(), data, rel)

    def test_unowned_collision_blocks_all_writes(self) -> None:
        path = self.root / cursor_rules.OUTPUT / '20-python.mdc'
        path.parent.mkdir(parents=True)
        path.write_text('human-owned rule', encoding='utf-8')
        with self.assertRaisesRegex(cursor_rules.RuleError, 'conflict'):
            cursor_rules.write(self.root)
        self.assertEqual(path.read_text(), 'human-owned rule')
        self.assertFalse((path.parent / '00-core.mdc').exists())

    def test_obsolete_generated_rule_is_reported_and_removed_only_on_write(self) -> None:
        cursor_rules.write(self.root)
        path = self.root / cursor_rules.OUTPUT / '90-retired.mdc'
        path.write_text(cursor_rules.MARKER + '\nold managed rule\n', encoding='utf-8')
        self.assertTrue(any('obsolete' in p for p in cursor_rules.drift(self.root)))
        self.assertTrue(path.exists())
        cursor_rules.write(self.root)
        self.assertFalse(path.exists())

    def test_install_to_existing_consumer_preserves_its_contract(self) -> None:
        target = Path(self.temp.name) / 'consumer'
        target.mkdir()
        contract = target / 'AGENTS.md'
        contract.write_text('consumer-specific contract', encoding='utf-8')
        cursor_rules.write(self.root, target)
        self.assertEqual(contract.read_text(), 'consumer-specific contract')
        self.assertEqual(cursor_rules.drift(self.root, target), [])
        self.assertFalse((self.root / '.cursor').exists())

    def test_missing_consumer_reference_blocks_before_writes(self) -> None:
        target = Path(self.temp.name) / 'consumer'
        target.mkdir()
        with self.assertRaisesRegex(cursor_rules.RuleError, 'reference'):
            cursor_rules.write(self.root, target)
        self.assertFalse((target / '.cursor').exists())

    def test_missing_target_is_not_created(self) -> None:
        target = Path(self.temp.name) / 'absent'
        with self.assertRaises(cursor_rules.RuleError):
            cursor_rules.write(self.root, target)
        self.assertFalse(target.exists())

    def test_detected_symlink_components_are_rejected_without_touching_outside(self) -> None:
        outside = Path(self.temp.name) / 'outside'
        outside.mkdir()
        link = self.root / '.cursor'
        try:
            link.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f'symlink creation unavailable: {exc}')
        with self.assertRaisesRegex(cursor_rules.RuleError, 'symlink'):
            cursor_rules.write(self.root)
        self.assertEqual(list(outside.iterdir()), [])

    def test_detected_output_symlink_is_rejected(self) -> None:
        outside = Path(self.temp.name) / 'outside.mdc'
        outside.write_text('untouched', encoding='utf-8')
        path = self.root / cursor_rules.OUTPUT / '20-python.mdc'
        path.parent.mkdir(parents=True)
        try:
            path.symlink_to(outside)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f'symlink creation unavailable: {exc}')
        with self.assertRaisesRegex(cursor_rules.RuleError, 'symlink'):
            cursor_rules.write(self.root)
        self.assertEqual(outside.read_text(), 'untouched')
        self.assertFalse((path.parent / '00-core.mdc').exists())

    def test_directory_collision_blocks_all_writes(self) -> None:
        path = self.root / cursor_rules.OUTPUT / '20-python.mdc'
        path.mkdir(parents=True)
        with self.assertRaises(cursor_rules.RuleError):
            cursor_rules.write(self.root)
        self.assertFalse((path.parent / '00-core.mdc').exists())

    def test_invalid_metadata_is_rejected(self) -> None:
        mutations = [
            lambda s: s.update(version=2),
            lambda s: s['rules'][0].update(alwaysApply='false'),
            lambda s: s['rules'][0].update(globs=['**/*']),
            lambda s: s['rules'][1].update(alwaysApply=True),
            lambda s: s['rules'][0].update(alwaysApply=False),
            lambda s: s['rules'][1].update(id='../escape'),
            lambda s: s['rules'][1].update(id='00-core'),
            lambda s: s['rules'][1].update(references=['../../secret']),
            lambda s: s['rules'][1].update(references=['/etc/passwd']),
            lambda s: s['rules'][1].update(description=''),
            lambda s: s['rules'][1].update(instructions=[]),
            lambda s: s['rules'][1].update(unknown='silently ignored'),
            lambda s: s['rules'][1].update(globs=['../**']),
            lambda s: s['rules'][1].update(globs=['**/*.py\nalwaysApply: true']),
        ]
        baseline = copy.deepcopy(self.spec)
        for mutate in mutations:
            with self.subTest(mutation=mutations.index(mutate)):
                self.spec = copy.deepcopy(baseline)
                mutate(self.spec)
                self.save()
                with self.assertRaises(cursor_rules.RuleError):
                    cursor_rules.render(self.root)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        path = self.root / cursor_rules.SOURCE
        path.write_text('{"version":1,"version":1,"rules":[]}', encoding='utf-8')
        with self.assertRaisesRegex(cursor_rules.RuleError, 'duplicate'):
            cursor_rules.render(self.root)

    def test_invalid_json_is_reported(self) -> None:
        (self.root / cursor_rules.SOURCE).write_text('{broken', encoding='utf-8')
        with self.assertRaises(cursor_rules.RuleError):
            cursor_rules.render(self.root)

    def test_core_context_budget_is_enforced(self) -> None:
        self.spec['rules'][0]['instructions'] = ['x' * cursor_rules.MAX_CORE_BYTES]
        self.save()
        with self.assertRaisesRegex(cursor_rules.RuleError, 'budget'):
            cursor_rules.render(self.root)

    def test_scoped_rule_context_budget_is_enforced(self) -> None:
        self.spec['rules'][1]['instructions'] = ['x' * cursor_rules.MAX_RULE_BYTES]
        self.save()
        with self.assertRaisesRegex(cursor_rules.RuleError, 'budget'):
            cursor_rules.render(self.root)

    def test_cli_is_read_only_without_write_and_repairs_explicitly(self) -> None:
        script = ROOT / '.getzilla/getzilla/cursor_rules.py'
        command = [sys.executable, str(script), '--source', str(self.root)]
        check = subprocess.run(command, capture_output=True, text=True, timeout=20)
        self.assertEqual(check.returncode, 1, check.stderr)
        self.assertFalse((self.root / '.cursor').exists())
        apply = subprocess.run(command + ['--write'], capture_output=True, text=True, timeout=20)
        self.assertEqual(apply.returncode, 0, apply.stderr)
        check = subprocess.run(command, capture_output=True, text=True, timeout=20)
        self.assertEqual(check.returncode, 0, check.stderr)

    def test_cli_reports_source_error_without_traceback(self) -> None:
        (self.root / cursor_rules.SOURCE).write_text('not-json', encoding='utf-8')
        result = subprocess.run(
            [sys.executable, str(ROOT / '.getzilla/getzilla/cursor_rules.py'), '--source', str(self.root)],
            capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotIn('Traceback', result.stderr)


class CommittedCursorRulesTests(unittest.TestCase):
    def test_committed_rules_are_current(self) -> None:
        expected = cursor_rules.render(ROOT)
        self.assertEqual(len(expected), 8)
        for rel, content in expected.items():
            self.assertTrue((ROOT / rel).is_file(), rel)
            self.assertEqual((ROOT / rel).read_bytes(), content, rel)

    def test_core_is_the_only_always_applied_rule(self) -> None:
        rules = list(cursor_rules.render(ROOT).values())
        self.assertEqual(sum(b'alwaysApply: true' in body for body in rules), 1)
        self.assertLessEqual(max(len(body.splitlines()) for body in rules), 500)


class CursorHarnessIntegrationTests(unittest.TestCase):
    def fixture(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for rel in ('scripts/getzilla_harness.py', '.getzilla/getzilla/harnesses.py',
                    '.getzilla/getzilla/cursor_rules.py'):
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / rel, target)
        (root / '.grok').mkdir()
        (root / '.grok/hooks.json').write_text('{"hooks":{}}', encoding='utf-8')
        (root / 'AGENTS.md').write_text('fixture contract', encoding='utf-8')
        manifest = {'version': 1, 'rules': [{
            'id': '00-core', 'title': 'Core', 'description': 'Fixture rules',
            'alwaysApply': True, 'globs': [], 'references': ['AGENTS.md'],
            'instructions': ['Preserve existing work.'],
        }]}
        (root / cursor_rules.SOURCE).write_text(json.dumps(manifest), encoding='utf-8')
        return root

    def test_existing_harness_cli_generates_and_checks_cursor_too(self) -> None:
        root = self.fixture()
        command = [sys.executable, str(root / 'scripts/getzilla_harness.py')]
        result = subprocess.run(command + ['--write'], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        output = root / cursor_rules.OUTPUT / '00-core.mdc'
        self.assertTrue(output.is_file(), 'existing harness CLI must also generate Cursor rules')
        self.assertTrue((root / '.qwen/settings.json').is_file())
        check = subprocess.run(command, capture_output=True, text=True, timeout=30)
        self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
        output.write_bytes(output.read_bytes() + b'changed')
        check = subprocess.run(command, capture_output=True, text=True, timeout=30)
        self.assertEqual(check.returncode, 1)
        self.assertIn('stale .cursor/rules/getzilla/00-core.mdc', check.stdout)

    def test_cursor_conflict_prevents_other_harness_rewrites(self) -> None:
        root = self.fixture()
        collision = root / cursor_rules.OUTPUT / '00-core.mdc'
        collision.parent.mkdir(parents=True)
        collision.write_text('user-owned', encoding='utf-8')
        result = subprocess.run(
            [sys.executable, str(root / 'scripts/getzilla_harness.py'), '--write'],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(collision.read_text(), 'user-owned')
        self.assertFalse((root / '.qwen').exists())

    def test_rules_do_not_register_a_cursor_execution_harness(self) -> None:
        from getzilla.harnesses import HARNESSES
        self.assertNotIn('cursor', HARNESSES)


if __name__ == '__main__':
    unittest.main()
