"""Readable skill assets retain executable supply-chain review and full verification."""
from __future__ import annotations

import sys
import unittest
import subprocess
import os
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.light_lane import inspect_light_diff  # noqa: E402
from getzilla import state  # noqa: E402
from getzilla.verification_scope import FULL_PROFILE, FOCUSED_TEST_TARGETS, select_docs_state_scope  # noqa: E402
from tests import test_review_plan as review_tests  # noqa: E402
from tests.branch_support import env as git_environment  # noqa: E402


class AssetScopeTests(unittest.TestCase):
    def setUp(self):
        token = state._SESSION.set(None)
        self.addCleanup(state._SESSION.reset, token)
        environment = mock.patch.dict(os.environ, {})
        environment.start()
        self.addCleanup(environment.stop)

    def test_content_addresses_preserve_crlf_bytes_without_hiding_text_diffs(self):
        fixture = review_tests.ReviewPlanTests()
        try:
            fixture.setUp()
            fixture.write('.gitattributes', (ROOT / '.gitattributes').read_text())
            path = '.getzilla/templates/baseline/blobs/' + 'b' * 64 + '.txt'
            target = fixture.root / path
            target.parent.mkdir(parents=True)
            content = b'first\r\nsecond\r\n'
            target.write_bytes(content)
            fixture.commit()
            stored = subprocess.run(['git', '-C', str(fixture.root), 'show', 'HEAD:' + path],
                                    env=git_environment(), capture_output=True, check=True).stdout
            self.assertEqual(stored, content)
            stats = subprocess.run(['git', '-C', str(fixture.root), 'diff', '--numstat', fixture.base, 'HEAD', '--', path],
                                   env=git_environment(), capture_output=True, check=True).stdout
            self.assertTrue(stats.startswith(b'2\t0\t'))
        finally:
            fixture.doCleanups()

    def test_asset_only_text_and_manifest_changes_keep_full_checks_and_risk_reviews(self):
        for path in ('.getzilla/templates/baseline/blobs/' + 'a' * 64 + '.txt',
                     '.getzilla/templates/baseline/bmad-claude-sh.json'):
            with self.subTest(path=path):
                fixture = review_tests.ReviewPlanTests()
                try:
                    fixture.setUp()
                    fixture.write(path, 'code-bearing asset data\n')
                    fixture.commit()
                    fixture.route('Fix a small documentation typo.')
                    route = fixture.reconcile()
                    self.assertEqual(route['risk_assessment']['status'], 'complete')
                    self.assertIn('security_reviewer', route['review_agents'])
                    self.assertIn('release_reviewer', route['review_agents'])
                    light = inspect_light_diff(fixture.root, [fixture.base], risk='low', complete=True)
                    self.assertFalse(light['admitted'])
                    self.assertEqual(light['reason'], 'sensitive_path')
                    scope = select_docs_state_scope('pr', [path], range_findings=[], range_base_count=1,
                                                    file_statuses=[{'path': path, 'status': 'A'}], status_inventory_trusted=True,
                                                    available_test_targets=FOCUSED_TEST_TARGETS, environment={})
                    self.assertFalse(scope['eligible'])
                    self.assertEqual(scope['profile'], FULL_PROFILE)
                    self.assertIn('shipped-executed-content', str(scope))
                finally:
                    fixture.doCleanups()
