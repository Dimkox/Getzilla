"""Tiny owned workflow data; acquisition and route effects are explicitly mocked."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'.getzilla'))
from getzilla import baseline_assets


class CurrentWorkflowTests(unittest.TestCase):
    def setUp(self):
        from getzilla import current_workflows
        self.module = current_workflows
        parent = ROOT/'.getzilla/runtime/scratch'
        parent.mkdir(parents=True, exist_ok=True)
        owned = tempfile.TemporaryDirectory(prefix='owned-current-workflow-', dir=parent)
        self.addCleanup(owned.cleanup)
        self.root = Path(owned.name)
        self.project = self.root/'project'
        self.project.mkdir()
        self.home = self.root/'home'
        self.home.mkdir()

    def acquire(self, version, body):
        payload = baseline_assets.AssetPayload('superpowers', 'qwen', version*64,
                                               (('.agents/skills/inert/SKILL.md', body, 0o644),))
        return {'superpowers': (payload, {'version': version, 'commit': version*40})}

    def test_fresh_payload_updates_owned_bytes_but_preserves_user_edit(self):
        with patch.object(self.module, '_acquire', return_value=self.acquire('a', b'first')), \
             patch.object(self.module.state, 'route_authority_present', return_value=False):
            self.module.apply_latest(self.project, 'qwen', self.home, fetch=lambda u: self.fail(u))
        path = self.project/'.agents/skills/inert/SKILL.md'
        with patch.object(self.module, '_acquire', return_value=self.acquire('b', b'second')), \
             patch.object(self.module.state, 'route_authority_present', return_value=False):
            result = self.module.apply_latest(self.project, 'qwen', self.home, fetch=lambda u: self.fail(u))
        self.assertEqual(path.read_bytes(), b'second')
        self.assertTrue(all(s.status == 'ok' for s in result))
        path.write_bytes(b'user edit')
        with patch.object(self.module, '_acquire', return_value=self.acquire('c', b'third')), \
             patch.object(self.module.state, 'route_authority_present', return_value=False):
            result = self.module.apply_latest(self.project, 'qwen', self.home, fetch=lambda u: self.fail(u))
        self.assertEqual(path.read_bytes(), b'user edit')
        self.assertEqual(result[0].status, 'fail')

    def test_no_scope_cannot_publish_constructor_payload(self):
        payload, _ = self.acquire('a', b'forged')['superpowers']
        with self.assertRaises(ValueError):
            self.module._publish(self.project, payload)
        self.assertEqual(list(self.project.iterdir()), [])

    def test_unknown_new_source_format_refuses(self):
        with self.assertRaises(ValueError):
            self.module.spec_payload({'unknown.txt': b'inert'}, 'qwen', '9.0.0', 'a'*40, windows=False)

    def test_new_file_policy_refusal_prevents_all_publication(self):
        with patch.object(self.module, '_acquire', return_value=self.acquire('a', b'first')), \
             patch.object(self.module.state, 'route_authority_present', return_value=True), \
             patch.object(self.module.state, 'require_route_owner'), \
             patch.object(self.module, 'evaluate_pre_tool', return_value=(False, 'inert policy denial')):
            result = self.module.apply_latest(self.project, 'qwen', self.home, fetch=lambda u: self.fail(u))
        self.assertEqual(result[0].status, 'fail')
        self.assertFalse((self.project/'.agents/skills/inert/SKILL.md').exists())

    def test_spec_data_adapter_binds_current_template_scripts_and_platform(self):
        source = {'templates/constitution-template.md': b'new constitution',
                  'templates/plan-template.md': b'new major plan',
                  'workflows/speckit/workflow.yml': b'version: 2.0.0\n',
                  'scripts/bash/owned.sh': b'inert shell source',
                  'scripts/powershell/owned.ps1': b'inert PowerShell source'}
        for stem in ('plan', 'specify', 'tasks', 'implement', 'constitution'):
            source['templates/commands/'+stem+'.md'] = b'---\ndescription: Owned command\nscripts:\n  sh: scripts/bash/owned.sh --json\n  ps: scripts/powershell/owned.ps1 -Json\n---\nRun {SCRIPT}\n'
        payload = self.module.spec_payload(source, 'codex', '2.0.0', 'b'*40, windows=True)
        files = {n: b for n, b, _ in payload.files}
        command = files['.agents/skills/speckit-plan/SKILL.md']
        self.assertIn(b'.specify/scripts/powershell/owned.ps1 -Json', command)
        self.assertNotIn(b'{SCRIPT}', command)
        self.assertEqual(files['.specify/templates/plan-template.md'], b'new major plan')
        self.assertIn(b'2.0.0', files['.specify/init-options.json'])
        self.assertFalse(payload.permissions_granted)
        del source['scripts/powershell/owned.ps1']
        with self.assertRaises(ValueError):
            self.module.spec_payload(source, 'codex', '2.0.0', 'b'*40, windows=True)
