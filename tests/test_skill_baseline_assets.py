from __future__ import annotations

import tempfile
import unittest
import sys
import csv
import hashlib
import json
import shutil
from dataclasses import replace
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import baseline_assets  # noqa: E402


class BaselineAssetTests(unittest.TestCase):
    def test_actual_consumer_refuses_missing_stale_foreign_and_tampered_assets_before_writes(self):
        from getzilla import baseline
        from tests.test_mandatory_baseline import FakeTools, which_all
        cases = ('missing-manifest', 'tampered-manifest', 'foreign-manifest', 'stale-source',
                 'missing-blob', 'tampered-blob', 'wrong-script')
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                source, project, home = root / 'distribution', root / 'project', root / 'home'
                project.mkdir()
                shutil.copytree(ROOT / '.getzilla/templates/baseline', source / '.getzilla/templates/baseline')
                config_path = source / '.getzilla/config/toolchain.json'
                config_path.parent.mkdir(parents=True)
                config = json.loads((ROOT / '.getzilla/config/toolchain.json').read_bytes())
                component = next(item for item in config['workflow_sources']['components'] if item['id'] == 'bmad')
                record = component['generated_assets']['claude-sh']
                manifest_path = source / record['path']
                manifest = json.loads(manifest_path.read_bytes())
                if case == 'missing-manifest':
                    manifest_path.unlink()
                elif case == 'tampered-manifest':
                    manifest_path.write_bytes(manifest_path.read_bytes() + b'altered')
                elif case == 'foreign-manifest':
                    foreign = component['generated_assets']['grok-sh']
                    manifest_path.write_bytes((source / foreign['path']).read_bytes())
                    record['sha256'] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
                elif case == 'stale-source':
                    manifest['binding']['source_commit'] = 'b' * 40
                    manifest_path.write_text(json.dumps(manifest))
                    record['sha256'] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
                elif case in ('missing-blob', 'tampered-blob'):
                    blob = source / '.getzilla/templates/baseline/blobs' / (manifest['files'][0]['sha256'] + '.txt')
                    if case == 'missing-blob':
                        blob.unlink()
                    else:
                        blob.write_bytes(b'tampered code-bearing bytes')
                else:
                    component = next(item for item in config['workflow_sources']['components'] if item['id'] == 'spec-kit')
                    record = component['generated_assets']['claude-sh']
                    foreign = component['generated_assets']['claude-ps']
                    (source / record['path']).write_bytes((source / foreign['path']).read_bytes())
                    record['sha256'] = hashlib.sha256((source / record['path']).read_bytes()).hexdigest()
                config_path.write_text(json.dumps(config))
                tools = FakeTools()
                baseline.install_user(home, run=tools, which=which_all)
                # Substitute an installed distribution's file root, not authority.
                # The real consumer, manifest loader and no-follow filesystem run.
                with mock.patch.object(baseline_assets, 'STACK_DIR', source / '.getzilla'):
                    steps = baseline.apply_project(project, 'claude', home, run=tools)
                self.assertTrue(any(step.status == 'fail' for step in steps), steps)
                self.assertFalse(list(project.iterdir()))

    def test_all_generated_bytes_have_readable_pinned_source_representation(self):
        from getzilla.baseline import components
        for component in components().values():
            for record in component['generated_assets'].values():
                self.assertTrue(record['path'].endswith('.json'))
                manifest = json.loads((ROOT / record['path']).read_bytes())
                for entry in manifest['files']:
                    blob = ROOT / '.getzilla/templates/baseline/blobs' / (entry['sha256'] + '.txt')
                    content = blob.read_bytes()
                    content.decode('utf-8')
                    self.assertNotIn(b'\0', content)
                    self.assertEqual(hashlib.sha256(content).hexdigest(), entry['sha256'])

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

    def test_identical_superpowers_bytes_with_wrong_mode_refuse_without_chmod(self):
        payload = baseline_assets.load('superpowers', 'codex')
        cases = [next(item for item in payload.files if item[2] == mode) for mode in (0o644, 0o755)]
        for name, content, mode in cases:
            with self.subTest(path=name), tempfile.TemporaryDirectory() as tmp:
                project = Path(tmp)
                target = project / name
                target.parent.mkdir(parents=True)
                target.write_bytes(content)
                wrong_mode = 0o777 if mode == 0o644 else 0o644
                target.chmod(wrong_mode)
                with self.assertRaisesRegex(ValueError, 'BASELINE_ASSET_CONFLICT'):
                    baseline_assets.materialize(project, payload)
                self.assertEqual(target.read_bytes(), content)
                self.assertEqual(target.stat().st_mode & 0o777, wrong_mode)

    def test_cross_agent_incomplete_component_refuses_in_actual_consumer(self):
        from getzilla import baseline
        from getzilla.component_state import ComponentTransaction
        from tests.test_mandatory_baseline import FakeTools, which_all
        for component in ('bmad', 'spec-kit'):
            with self.subTest(component=component), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                project = root / 'project'
                project.mkdir()
                payload = baseline_assets.load(component, 'claude')
                original = ComponentTransaction.write
                copied = []

                def interrupt(transaction, name, content, mode, *, expected):
                    if name in {item[0] for item in payload.files}:
                        if copied:
                            raise OSError('fixture interruption after one target')
                        copied.append(name)
                    return original(transaction, name, content, mode, expected=expected)

                with mock.patch.object(ComponentTransaction, 'write', interrupt), self.assertRaises(ValueError):
                    baseline_assets.materialize(project, payload)
                before = {p.relative_to(project).as_posix(): (p.read_bytes(), p.stat().st_mode & 0o777)
                          for p in project.rglob('*') if p.is_file()}
                with self.assertRaisesRegex(ValueError, 'INTERRUPTED_BASELINE_MATERIALIZATION'):
                    baseline_assets.materialize(project, baseline_assets.load(component, 'codex'))
                tools = FakeTools()
                home = root / 'home'
                baseline.install_user(home, run=tools, which=which_all)
                steps = baseline.apply_project(project, 'codex', home, run=tools)
                self.assertTrue(any(step.status == 'fail' for step in steps), steps)
                self.assertEqual(before, {p.relative_to(project).as_posix(): (p.read_bytes(), p.stat().st_mode & 0o777)
                                         for p in project.rglob('*') if p.is_file()})

    def test_genuine_foreign_user_directories_stay_preserved_across_agents(self):
        for component, marker in (('bmad', '_bmad'), ('spec-kit', '.specify')):
            with self.subTest(component=component), tempfile.TemporaryDirectory() as tmp:
                project = Path(tmp)
                target = project / marker / 'user.txt'
                target.parent.mkdir()
                target.write_bytes(b'owned user data\n')
                target.chmod(0o777)
                for agent in ('claude', 'codex'):
                    result = baseline_assets.materialize(project, baseline_assets.load(component, agent))
                    self.assertEqual(result['status'], 'preserved')
                    self.assertNotIn('materialized_digest', result)
                    self.assertEqual(target.read_bytes(), b'owned user data\n')
                    self.assertEqual(target.stat().st_mode & 0o777, 0o777)
