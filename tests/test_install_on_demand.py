"""F01 and F03: the plan shows each component's size; a project gets core plus its agent, the rest on demand."""
from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.on_demand import MANIFEST, ensure_components, is_installed_project, load_manifest  # noqa: E402

SPEC = importlib.util.spec_from_file_location('install_into_on_demand_test', ROOT / 'scripts' / 'install_into.py')
INSTALL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = INSTALL
SPEC.loader.exec_module(INSTALL)


def plan(target: Path, *args: str) -> dict:
    env = {key: value for key, value in os.environ.items() if key != 'GETZILLA_AGENT'}
    result = subprocess.run([sys.executable, str(ROOT / 'scripts' / 'install_into.py'), '--plan', str(target), *args],
                            capture_output=True, text=True, check=True, env=env)
    return json.loads(result.stdout)


class FootprintTests(unittest.TestCase):
    def test_plan_reports_every_component_and_adds_up(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = plan(Path(tmp) / 'absent')
        full = INSTALL.build_payload(ROOT)
        self.assertEqual(sum(item['files'] for item in report['components'].values()), len(full))
        self.assertTrue({'core', 'factory', 'agent:qwen', 'agent:claude'} <= set(report['components']))
        self.assertEqual([item['component'] for item in report['post_install']], ['baseline:security', 'baseline:workflow'])

    def test_default_is_core_plus_one_agent_without_factory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = plan(Path(tmp) / 'absent')
        paths = {entry['path'] for entry in report['entries']}
        self.assertEqual(report['selection'], {'agents': ['qwen'], 'factory': False, 'full': False})
        self.assertFalse(any(path.startswith('factory/') for path in paths))
        self.assertFalse(any(path.startswith(('.claude/', '.codex/', '.gemini/', '.github/agents/')) for path in paths))
        self.assertTrue(any(path.startswith('.qwen/') for path in paths))
        self.assertTrue(any(path.startswith('.agents/skills/') for path in paths))  # one canonical skill source
        self.assertTrue({'AGENTS.md', '.grok/hooks/pre_tool_use.py'} <= paths)
        self.assertLess(len(paths), 400)  # was 672 for every agent plus factory

    def test_agents_flag_existing_folders_and_full_layout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            chosen = plan(target, '--agents', 'claude,codex')
            self.assertEqual(chosen['selection']['agents'], ['claude', 'codex'])
            (target / '.gemini').mkdir()
            self.assertEqual(plan(target)['selection']['agents'], ['gemini'])
            full = plan(target, '--full-layout')
        self.assertEqual(len(full['entries']), len(INSTALL.build_payload(ROOT)))
        bad = subprocess.run([sys.executable, str(ROOT / 'scripts' / 'install_into.py'), '--plan', '/tmp/x', '--agents', 'notepad'],
                             capture_output=True, text=True, check=False)
        self.assertEqual(bad.returncode, 2)


class OnDemandTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.target = Path(tmp.name) / 'project'
        INSTALL._materialize_new(ROOT, self.target, include_dependencies=False, include_optional=False,
                                 selection=INSTALL.PayloadSelection(('qwen',)))

    def test_lean_project_is_usable(self) -> None:
        self.assertFalse((self.target / 'factory').exists())
        self.assertFalse((self.target / '.claude').exists())
        self.assertTrue((self.target / '.qwen' / 'settings.json').is_file())
        self.assertTrue(is_installed_project(self.target))
        doctor = subprocess.run([sys.executable, str(self.target / 'scripts' / 'getzilla_doctor.py')], cwd=self.target,
                                capture_output=True, text=True, timeout=300, check=False)
        failing = [line for line in doctor.stdout.splitlines() if line.startswith('FAIL') and
                   ('.claude' in line or '.codex' in line or 'factory' in line)]
        self.assertEqual(failing, [], doctor.stdout[-2000:])

    def test_second_agent_is_added_on_demand_and_recorded(self) -> None:
        added = ensure_components(self.target, ['agent:codex'], source=ROOT)
        self.assertTrue(added[0].files)
        self.assertTrue((self.target / '.codex' / 'hooks.json').is_file())
        manifest = load_manifest(self.target)
        self.assertIn('agent:codex', manifest['components'])
        self.assertTrue((self.target / MANIFEST).is_file())
        again = ensure_components(self.target, ['agent:codex'], source=ROOT)
        self.assertEqual(again[0].files, [])

    def test_factory_on_demand_never_overwrites(self) -> None:
        own = self.target / 'factory' / 'README.md'
        own.parent.mkdir(parents=True)
        own.write_text('my own factory notes\n', encoding='utf-8')
        added = ensure_components(self.target, ['factory'], source=ROOT)
        self.assertTrue((self.target / 'factory' / 'pyproject.toml').is_file())
        self.assertEqual(own.read_text(encoding='utf-8'), 'my own factory notes\n')
        self.assertIn('factory/README.md', added[0].kept)
        with self.assertRaises(ValueError):
            ensure_components(self.target, ['agent:notepad'], source=ROOT)

    def test_components_cli_requires_an_installed_project(self) -> None:
        cli = [sys.executable, str(ROOT / 'scripts' / 'getzilla_components.py')]
        with tempfile.TemporaryDirectory() as tmp:
            refused = subprocess.run([*cli, 'add', 'factory', '--project', tmp], capture_output=True, text=True)
        self.assertEqual(refused.returncode, 2)
        result = subprocess.run([*cli, 'add', 'agent:claude', '--project', str(self.target)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.target / '.claude' / 'settings.json').is_file())
        with mock.patch.dict(os.environ, {'GETZILLA_AGENT': 'grok'}):
            self.assertEqual(INSTALL.detect_agents(self.target), ('grok',))


class ComponentPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.source = Path(tmp.name) / 'source'
        self.target = Path(tmp.name) / 'project'
        source_files = {
            'scripts/install_into.py': (ROOT / 'scripts/install_into.py').read_bytes(),
            '.getzilla/templates/consumer-AGENTS.md.tmpl': b'Fixture project instructions\n',
            '.getzilla/templates/consumer-factory-README.md.tmpl': b'Factory notes\n',
            '.getzilla/templates/hook_root_shim.py': b'# Fixture hook shim\n',
            'factory/README.md': b'Factory source notes\n',
            'factory/pyproject.toml': b'[project]\nname = "fixture-factory"\n',
            '.codex/hooks.json': b'{"hooks": []}\n',
            '.getzilla/compliance/eu-ai-act/rules.json': b'{"rules": []}\n',
            'VERSION': b'fixture-v1\n',
        }
        for relative in INSTALL.MANAGED_FILES:
            source_files.setdefault(relative, b'')
        target_files = {
            '.getzilla/AGBP_SYNC.json': b'{"schema_version": 1}\n',
            '.getzilla/config/compliance.json': b'{"schema_version":"getzilla-compliance-v1","enabled":[]}\n',
            MANIFEST: b'{"schema_version":"getzilla-managed-components-v1","components":{}}\n',
            'factory/README.md': b'My own factory notes\n',
            'local.txt': b'Unrelated user work\n',
        }
        for base, files in ((self.source, source_files), (self.target, target_files)):
            for relative, content in files.items():
                path = base / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
        (self.target / 'empty-user-directory').mkdir()

    def snapshot(self) -> dict:
        return {
            path.relative_to(self.target).as_posix(): (
                stat.S_IMODE(path.stat().st_mode), None if path.is_dir() else path.read_bytes()
            )
            for path in self.target.rglob('*')
        }

    def assert_rejected_without_mutation(self, needs: list[str]) -> None:
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "^unknown component 'agent:notepad'; expected one of "):
            ensure_components(self.target, needs, source=self.source)
        self.assertEqual(self.snapshot(), before)

    def test_unknown_component_after_valid_names_does_not_change_target(self) -> None:
        self.assert_rejected_without_mutation(['factory', 'agent:codex', 'compliance:eu-ai-act', 'agent:notepad'])

    def test_unknown_component_before_valid_names_does_not_change_target(self) -> None:
        self.assert_rejected_without_mutation(['agent:notepad', 'factory', 'agent:codex', 'compliance:eu-ai-act'])

    def test_valid_batch_preserves_order_ownership_and_user_edits(self) -> None:
        needs = ['compliance:eu-ai-act', 'agent:codex', 'factory', 'factory']
        added = ensure_components(self.target, needs, source=self.source)
        self.assertEqual([item.component for item in added], needs)
        self.assertEqual(added[0].files, [
            '.getzilla/compliance/eu-ai-act/rules.json', 'scripts/getzilla_audit_bundle.py',
            'scripts/getzilla_compliance.py',
        ])
        self.assertEqual(added[1].files, ['.codex/hooks.json'])
        self.assertIn('factory/pyproject.toml', added[2].files)
        self.assertNotIn('factory/README.md', added[2].files)
        self.assertEqual(added[3].files, [])
        self.assertEqual(added[2].kept, ['factory/README.md'])
        self.assertEqual((self.target / 'factory/README.md').read_bytes(), b'My own factory notes\n')
        manifest = load_manifest(self.target)
        self.assertEqual(set(manifest['components']), set(needs))
        for item in added[:3]:
            record = manifest['components'][item.component]
            self.assertEqual(record['files'], item.files)
            self.assertEqual(record['source_version'], 'fixture-v1')
            self.assertTrue(record['added_at'])
        config = json.loads((self.target / '.getzilla/config/compliance.json').read_text(encoding='utf-8'))
        self.assertEqual(config, {'schema_version': 'getzilla-compliance-v1', 'enabled': ['eu-ai-act']})

        custom = self.target / '.codex/hooks.json'
        custom.write_bytes(b'{"user": "custom hooks"}\n')
        before_repeat = self.snapshot()
        again = ensure_components(self.target, needs, source=self.source)
        self.assertEqual([item.component for item in again], needs)
        self.assertTrue(all(not item.files for item in again))
        self.assertEqual(again[1].kept, ['.codex/hooks.json'])
        self.assertEqual(self.snapshot(), before_repeat)


if __name__ == '__main__':
    unittest.main()
