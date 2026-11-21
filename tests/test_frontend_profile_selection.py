"""Real owned manifest facts and profile provenance; no Node tool execution."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'.getzilla'))
from getzilla import verification, verification_plan


class FrontendSelectionTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT/'.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = tempfile.TemporaryDirectory(prefix='owned-profile-', dir=scratch)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        env = {key: value for key, value in os.environ.items() if key in ('PATH', 'SystemRoot', 'WINDIR')}
        env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=str(self.root/'absent-config'), HOME=str(self.root))
        subprocess.run(['git', '-c', 'init.templateDir=', 'init', '-q', str(self.root)], env=env,
                       capture_output=True, check=True, timeout=10)
        self.route = {'quality_profiles': ['base', 'frontend']}

    def names(self, requested):
        return {row['check_id'] for row in verification_plan._native_obligations(
            self.root, 'pr', self.route, {}, files=[], profiles=requested, bases=[], documents=None)}

    def test_inferred_frontend_without_node_marker_has_no_node_plan_or_dispatch(self):
        self.assertNotIn('package-json', self.names(None))
        with mock.patch.object(verification, '_node_checks', side_effect=AssertionError('inferred task is not a Node workspace')):
            self.assertEqual(verification._node(self.root, 'pr', required_plan={}, requested_profiles=None), [])

    def test_explicit_frontend_without_manifest_remains_required_and_fails(self):
        self.assertIn('package-json', self.names(['frontend']))
        checks = verification._node(self.root, 'pr', required_plan={}, requested_profiles=['frontend'])
        self.assertEqual([(row.name, row.status) for row in checks], [('package-json', 'fail')])

    def test_actual_manifest_requires_node_for_inferred_or_nonfrontend_selection(self):
        (self.root/'package.json').write_text('{"scripts":{}}\n', encoding='utf-8', newline='\n')
        class NodeSelected(Exception):
            pass
        for requested in (None, ['base']):
            with self.subTest(requested=requested):
                self.assertTrue({'package-json', 'node-tooling', 'node-lockfile'} <= self.names(requested))
                with mock.patch.object(verification, '_node_checks', side_effect=NodeSelected), self.assertRaises(NodeSelected):
                    verification._node(self.root, 'pr', required_plan={}, requested_profiles=requested)

    def test_real_nested_manifest_keeps_missing_root_refusal(self):
        project = self.root/'web'
        project.mkdir()
        (project/'package.json').write_text('{}\n', encoding='utf-8', newline='\n')
        self.assertIn('package-json', self.names(None))
        checks = verification._node(self.root, 'pr', required_plan={}, requested_profiles=None)
        self.assertEqual([(row.name, row.status) for row in checks], [('package-json', 'fail')])

    def test_requested_profile_provenance_survives_effective_profile_reporting(self):
        select = verification_plan.requested_profiles_from_report
        self.assertIsNone(select({'profiles': ['frontend'], 'requested_profiles': None}))
        self.assertEqual(select({'profiles': ['frontend'], 'requested_profiles': []}), [])
        self.assertEqual(select({'profiles': ['frontend'], 'requested_profiles': ['frontend']}), ['frontend'])
        self.assertEqual(select({'profiles': ['frontend']}), ['frontend'], 'legacy reports remain conservative')
        with self.assertRaises(ValueError):
            select({'profiles': ['frontend'], 'requested_profiles': False})
