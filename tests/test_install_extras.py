"""A fresh install carries only what the target needs: no Bitrix or SEO skills, no root hook shims."""
from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

SPEC = importlib.util.spec_from_file_location('install_into_extras', ROOT / 'scripts/install_into.py')
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

from getzilla import on_demand  # noqa: E402


def paths(selection) -> set[str]:
    return {entry.path for entry in MODULE.build_payload(ROOT, selection=selection)}


class InstallExtrasTests(unittest.TestCase):
    def test_plain_repository_gets_no_domain_skills_or_root_shims(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / 'palindrome.py').write_text('print(1)\n', encoding='utf-8')
            self.assertEqual(MODULE.detect_extras(target), ())
            self.assertFalse(MODULE.has_root_shims(target))
            chosen = paths(MODULE.PayloadSelection(('qwen',), extras=MODULE.detect_extras(target),
                                                   root_shims=MODULE.has_root_shims(target)))
        self.assertFalse([p for p in chosen if '/skills/bitrix-development/' in p or '/skills/seo-landing/' in p])
        self.assertFalse(chosen & MODULE.ROOT_HOOK_SHIMS)
        self.assertIn('.agents/skills/getzilla-delivery/SKILL.md', chosen)
        self.assertIn('.grok/hooks/pre_tool_use.py', chosen)
        self.assertFalse([p for p in chosen if p.startswith('.grok/cursor-rules/')])

    def test_bitrix_folders_bring_the_bitrix_skill_for_the_chosen_agent_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / 'local/modules').mkdir(parents=True)
            self.assertEqual(MODULE.detect_extras(target), ('bitrix',))
        chosen = paths(MODULE.PayloadSelection(('qwen',), extras=('bitrix',)))
        bitrix = {p for p in chosen if '/skills/bitrix-development/' in p}
        self.assertTrue(any(p.startswith('.agents/') for p in bitrix))
        self.assertTrue(any(p.startswith('.qwen/') for p in bitrix))
        self.assertFalse(any(p.startswith('.claude/') for p in bitrix))
        self.assertFalse([p for p in chosen if '/skills/seo-landing/' in p])

    def test_an_upgrade_that_has_root_shims_keeps_them(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / 'pre_tool_use.py').write_text('# old shim\n', encoding='utf-8')
            self.assertTrue(MODULE.has_root_shims(target))
        chosen = paths(MODULE.PayloadSelection(('qwen',), root_shims=True))
        self.assertEqual(chosen & MODULE.ROOT_HOOK_SHIMS, MODULE.ROOT_HOOK_SHIMS)

    def test_cursor_rules_belong_to_the_cursor_agent_and_full_layout_keeps_everything(self) -> None:
        self.assertEqual(MODULE.component_of('.grok/cursor-rules/10-rule.toml'), 'agent:cursor')
        self.assertEqual(MODULE.component_of('.qwen/skills/seo-landing/SKILL.md'), 'extra:seo-landing')
        full = paths(MODULE.PayloadSelection.full_layout())
        self.assertTrue(full >= MODULE.ROOT_HOOK_SHIMS)
        self.assertTrue([p for p in full if '/skills/seo-landing/' in p])

    def test_unknown_extra_is_refused_and_components_add_knows_extras(self) -> None:
        with self.assertRaises(MODULE.UnsafeInstallTarget):
            MODULE.PayloadSelection(('qwen',), extras=('wordpress',))
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            for entry in MODULE.build_payload(ROOT, selection=MODULE.PayloadSelection(('qwen',))):
                target = project / entry.path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(entry.content)
            added = on_demand.ensure_components(project, ['extra:bitrix'], source=ROOT)
            files = added[0].files
            self.assertTrue(files)
            self.assertTrue(all('/skills/bitrix-development/' in path for path in files))
            self.assertFalse([path for path in files if path.startswith('.claude/')])
            self.assertIn('extra:bitrix', on_demand.load_manifest(project)['components'])


    def test_doctor_accepts_a_fresh_install_without_domain_skills(self) -> None:
        from getzilla.doctor import run_doctor
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            for entry in MODULE.build_payload(ROOT, selection=MODULE.PayloadSelection(('qwen',))):
                target = project / entry.path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(entry.content)
            items = {item.name: item for item in run_doctor(project)}
        self.assertEqual(items['skill:bitrix-development'].status, 'info')
        self.assertIn('extra:bitrix', items["skill:bitrix-development"].message)
        self.assertFalse([name for name, item in items.items() if name.startswith('skill:') and item.status == 'fail'])

    def test_fresh_install_ships_the_engine_as_one_deterministic_archive(self) -> None:
        selection = MODULE.PayloadSelection(('qwen',), engine_archive=True)
        first = {entry.path: entry for entry in MODULE.build_payload(ROOT, selection=selection)}
        second = {entry.path: entry for entry in MODULE.build_payload(ROOT, selection=selection)}
        self.assertEqual(first[MODULE.ENGINE_ARCHIVE].content, second[MODULE.ENGINE_ARCHIVE].content)
        engine = [p for p in first if p.startswith(MODULE.ENGINE_DIR)]
        self.assertEqual(engine, [MODULE.ENGINE_INIT])
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            for entry in first.values():
                target = project / entry.path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(entry.content)
            probe = ('import sys; sys.path.insert(0, ".getzilla"); import getzilla, getzilla.policy, getzilla.risk_terms, '
                     'getzilla.code_graph; print(getzilla.policy.__file__); print(getzilla.STACK_DIR)')
            result = subprocess.run([sys.executable, '-B', '-c', probe], cwd=project, capture_output=True, text=True, check=True)
            module_file, stack_dir = result.stdout.splitlines()
            self.assertIn('getzilla.zip', module_file)
            self.assertTrue(module_file.endswith('.pyc'), module_file)
            self.assertEqual(Path(stack_dir), (project / '.getzilla').resolve())
            from getzilla.doctor import run_doctor
            items = {item.name: item for item in run_doctor(project)}
            self.assertEqual(items['engine-archive'].status, 'pass')

    def test_an_upgrade_with_engine_files_keeps_them_and_a_checkout_uses_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            self.assertTrue(MODULE.wants_engine_archive(target))
            (target / '.getzilla/getzilla').mkdir(parents=True)
            (target / '.getzilla/getzilla/__init__.py').write_text('', encoding='utf-8')
            self.assertTrue(MODULE.wants_engine_archive(target))
            (target / '.getzilla/getzilla/policy.py').write_text('', encoding='utf-8')
            self.assertFalse(MODULE.wants_engine_archive(target))
        chosen = paths(MODULE.PayloadSelection(('qwen',)))
        self.assertNotIn(MODULE.ENGINE_ARCHIVE, chosen)
        self.assertIn('.getzilla/getzilla/policy.py', chosen)
        import getzilla
        self.assertEqual(getzilla.STACK_DIR, (ROOT / '.getzilla').resolve())

    def test_grok_agent_briefs_belong_to_grok_and_toml_stay_core(self) -> None:
        self.assertEqual(MODULE.component_of('.grok/agents/code_reviewer.md'), 'agent:grok')
        self.assertEqual(MODULE.component_of('.grok/agents/code_reviewer.toml'), 'core')
        plain = paths(MODULE.PayloadSelection(('qwen',)))
        self.assertFalse([p for p in plain if p.startswith('.grok/agents/') and p.endswith('.md')])
        self.assertIn('.grok/agents/code_reviewer.toml', plain)
        self.assertIn('.grok/agents/code_reviewer.md', paths(MODULE.PayloadSelection(('grok',))))

if __name__ == '__main__':
    unittest.main()
