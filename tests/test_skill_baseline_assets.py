from __future__ import annotations

import tempfile
import unittest
import sys
import csv
import hashlib
from dataclasses import replace
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import baseline_assets  # noqa: E402


class BaselineAssetTests(unittest.TestCase):
    def test_constructed_or_modified_payload_cannot_claim_shipped_source_approval(self):
        payload = baseline_assets.load('bmad', 'claude')
        forged = replace(payload, files=(('_bmad/core/config.yaml', b'unregistered instructions', 0o644),))
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            with self.assertRaisesRegex(ValueError, 'BOUND_ASSET_PAYLOAD_REQUIRED'):
                baseline_assets.materialize(project, forged)
            self.assertFalse(list(project.iterdir()))

    def test_every_existing_agent_and_script_variant_has_bound_real_assets(self):
        for agent in ('claude', 'codex', 'qwen', 'gemini', 'grok', 'copilot'):
            for component in ('superpowers', 'bmad', 'spec-kit'):
                for windows in ((False,) if component == 'bmad' else (False, True)):
                    with self.subTest(agent=agent, component=component, windows=windows):
                        payload = baseline_assets.load(component, agent, windows=windows)
                        self.assertTrue(payload.files)
                        self.assertFalse(payload.semantic_safety_qualified)
                        self.assertFalse(payload.permissions_granted)

    def test_missing_or_changed_bundle_cannot_be_used(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(ValueError):
                baseline_assets.load('bmad', 'claude', source_root=root)

    def test_materialization_never_launches_ambient_tools_and_preserves_user_dirs(self):
        payload = baseline_assets.load('bmad', 'claude')
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / 'my-project'
            project.mkdir()
            with mock.patch('subprocess.run', side_effect=AssertionError('ambient execution')):
                result = baseline_assets.materialize(project, payload)
            self.assertEqual(result['status'], 'ok')
            self.assertTrue((project / '_bmad/core/config.yaml').exists())
            self.assertIn('my-project', (project / '_bmad/core/config.yaml').read_text())
            rows = list(csv.reader((project / '_bmad/_config/files-manifest.csv').read_text().splitlines()))
            row = next(row for row in rows if len(row) == 5 and row[3] == 'core/config.yaml')
            self.assertEqual(row[4], hashlib.sha256((project / '_bmad/core/config.yaml').read_bytes()).hexdigest())
            path = project / '_bmad/core/config.yaml'
            path.write_text('user configuration')
            before = {p.relative_to(project).as_posix(): p.read_bytes() for p in project.rglob('*') if p.is_file()}
            self.assertEqual(baseline_assets.materialize(project, payload)['status'], 'preserved')
            self.assertEqual(before, {p.relative_to(project).as_posix(): p.read_bytes() for p in project.rglob('*') if p.is_file()})

    def test_escaped_destination_and_existing_adapter_conflict_refuse_before_any_copy(self):
        payload = baseline_assets.load('spec-kit', 'claude')
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / 'project'
            project.mkdir()
            (project / '.claude').symlink_to(Path(tmp), target_is_directory=True)
            with self.assertRaises(ValueError):
                baseline_assets.materialize(project, payload)
            self.assertFalse((project / '.specify').exists())

    def test_interrupted_owned_copy_cannot_be_mistaken_for_a_preserved_user_directory(self):
        from getzilla.component_state import ComponentTransaction
        payload = baseline_assets.load('bmad', 'claude')
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            original = ComponentTransaction.write

            def interrupt(transaction, name, content, mode, *, expected):
                if name == '_bmad/core/config.yaml':
                    raise OSError('fixture interrupted copy')
                return original(transaction, name, content, mode, expected=expected)

            with mock.patch.object(ComponentTransaction, 'write', interrupt), self.assertRaises(ValueError):
                baseline_assets.materialize(project, payload)
            self.assertTrue((project / '_bmad').is_dir())
            with self.assertRaisesRegex(ValueError, 'INTERRUPTED_BASELINE_MATERIALIZATION'):
                baseline_assets.materialize(project, payload)

    def test_real_baseline_consumer_uses_bound_assets_without_ambient_installers(self):
        from getzilla import baseline
        from tests.test_mandatory_baseline import FakeTools, which_all
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home, project = root / 'home', root / 'project'
            project.mkdir()
            tools = FakeTools()
            baseline.install_user(home, run=tools, which=which_all)
            tools.commands.clear()
            steps = baseline.apply_project(project, 'claude', home, run=tools)
            self.assertTrue(all(step.status == 'ok' for step in steps), steps)
            self.assertFalse([cmd for cmd in tools.commands if cmd[0] in ('npx', 'specify', 'node')])
            self.assertTrue((project / '_bmad/core/config.yaml').is_file())
            self.assertTrue((project / '.specify/templates/spec-template.md').is_file())

    def test_source_pin_mismatch_or_corrupt_asset_refuses_before_baseline_copy(self):
        from getzilla import baseline
        from tests.test_mandatory_baseline import FakeTools, which_all
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home, project = root / 'home', root / 'project'
            project.mkdir()
            tools = FakeTools()
            baseline.install_user(home, run=tools, which=which_all)
            tools.heads[str(baseline.pinned_checkout(home) / 'bmad')] = 'a' * 40
            steps = baseline.apply_project(project, 'claude', home, run=tools)
            self.assertTrue(any(step.status != 'ok' for step in steps))
            self.assertFalse(list(project.iterdir()))
