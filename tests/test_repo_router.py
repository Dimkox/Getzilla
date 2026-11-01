"""Repository detection and the route record a delivered change package keeps.

This is a binding module of the docs-state-focused lane (verification_scope.py): the tests
below re-derive route records under engineering/changes/. Routing behaviour lives in
test_router_routes.py and test_router_operational_intent.py.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.change import start_change
from getzilla.repo import detect_repo
from getzilla.router import (
    build_route,
)
from tests._support import activate_owned_route
from getzilla.workflow_artifacts import load_runtime_authority
from tests._support import project_copy


class RepoDetectionTests(unittest.TestCase):
    def test_detects_bitrix(self) -> None:
        with project_copy() as root:
            (root / 'bitrix').mkdir()
            (root / 'local/modules/acme.demo').mkdir(parents=True)
            profile = detect_repo(root)
            self.assertEqual(profile.kind, 'bitrix')
            self.assertIn('bitrix', profile.domains)
            self.assertIn('acme.demo', profile.bitrix_modules)

    def test_detects_polyglot(self) -> None:
        with project_copy() as root:
            (root / 'composer.json').write_text('{}')
            (root / 'package.json').write_text('{"scripts":{"test":"vitest"}}')
            profile = detect_repo(root)
            self.assertEqual(profile.kind, 'polyglot')
            self.assertIn('php', profile.languages)
            self.assertIn('typescript', profile.languages)


class RouteRecordTests(unittest.TestCase):
    def test_issue_155_guard_task_does_not_select_frontend(self) -> None:
        historical = ROOT / 'engineering/changes/20260920-fix-issue-155-guards-inside-the-semantic-bind-re-c4e47e/route.json'
        task = json.loads(historical.read_text(encoding='utf-8'))['task']
        with project_copy() as root:
            route = build_route(root, task, 'issue-155')
            self.assertEqual(set(route.task_domains), {'data', 'integration'})
            self.assertEqual(route.write_agent, 'integration_implementer')
            self.assertNotIn('frontend', route.quality_profiles)
            self.assertNotIn('frontend-change', route.workflow_skills)
            self.assertEqual(route.to_dict().get('matched_keywords'), {
                'data': ['postgres'], 'integration': ['integration'],
            })

    def test_keyword_evidence_survives_persistence_and_excludes_repo_domains(self) -> None:
        with project_copy() as root:
            (root / 'bitrix').mkdir()
            generic = build_route(root, 'Fix distinguish handling', 'repo-fallback')
            self.assertEqual(generic.task_domains, [])
            self.assertEqual(generic.write_agent, 'bitrix_implementer')
            self.assertEqual(generic.review_agents, ['code_reviewer'])
            route = build_route(root, 'Fix SQL handling', 'persist')
            expected = {'data': ['sql']}
            self.assertEqual(route.to_dict().get('matched_keywords'), expected)
            self.assertIn('bitrix', route.domains)
            self.assertEqual(route.review_agents, ['code_reviewer'])
            self.assertEqual(build_route(root, route.task, 'again').to_dict().get('matched_keywords'), expected)
            activate_owned_route(root, route.to_dict())
            self.assertEqual(load_runtime_authority(root, 'route')['matched_keywords'], expected)
            archived = root / f'.getzilla/runtime/routes/{route.route_id}.json'
            self.assertEqual(json.loads(archived.read_text())['matched_keywords'], expected)
            change = start_change(root)
            copied = root / '.getzilla/runtime/changes' / change['change_id'] / 'route.json'
            self.assertEqual(json.loads(copied.read_text())['matched_keywords'], expected)


if __name__ == '__main__':
    unittest.main()
