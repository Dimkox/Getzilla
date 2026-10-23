"""Low-risk micro and standard routes take the light delivery lane; risky work keeps the full controller."""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.router import build_route, route_context  # noqa: E402
from getzilla.workflow_artifacts import RUNTIME_ROUTE_KEYS  # noqa: E402


class DeliveryLaneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.project = Path(cls.tmp.name)
        (cls.project / 'app.py').write_text('print(1)\n', encoding='utf-8')
        subprocess.run(['git', 'init', '-q', str(cls.project)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def route(self, prompt: str):
        return build_route(self.project, prompt)

    def test_low_risk_backlog_work_takes_the_light_lane(self) -> None:
        for prompt in ('Fix the typo in the greeting message', 'Исправь опечатку в сообщении приветствия',
                       'Add a CSV export button to the orders page'):
            with self.subTest(prompt=prompt):
                route = self.route(prompt)
                self.assertEqual(route.risk, 'low')
                self.assertEqual(route.delivery_lane, 'light')
                self.assertEqual(route.review_agents, ['code_reviewer'])
                self.assertEqual(route.analysis_agents, ['repo_explorer'])
                self.assertIsNotNone(route.write_agent)
                self.assertNotIn('test_review', route.required_evidence)
                self.assertIn('Lane: light', route_context(route))

    def test_risky_or_sensitive_work_keeps_the_full_controller(self) -> None:
        for prompt in ('Rotate the production database password and deploy',
                       'Fix the SQL injection in the login form',
                       'Add a migration that drops the legacy orders table',
                       'Release version 3.0'):
            with self.subTest(prompt=prompt):
                route = self.route(prompt)
                self.assertEqual(route.delivery_lane, 'full')
                self.assertEqual(route.review_agents, ['code_reviewer'])
                self.assertEqual(route.risk_assessment['status'], 'provisional')

    def test_read_only_work_is_never_light(self) -> None:
        route = self.route('Review the payment module changes')
        self.assertIsNone(route.write_agent)
        self.assertEqual(route.delivery_lane, 'full')

    def test_the_lane_is_a_known_runtime_route_key(self) -> None:
        self.assertIn('delivery_lane', RUNTIME_ROUTE_KEYS)
        self.assertIn('delivery_lane', self.route('Fix the typo in the greeting message').to_dict())

    def test_every_delivery_skill_copy_documents_the_light_lane(self) -> None:
        copies = sorted(ROOT.glob('.*/skills/getzilla-delivery/SKILL.md'))
        self.assertGreaterEqual(len(copies), 5)
        texts = {path.read_text(encoding='utf-8') for path in copies}
        self.assertEqual(len(texts), 1, 'skill copies differ')
        text = texts.pop()
        self.assertIn('## Light lane', text)
        self.assertIn('delivery_lane: light', text)
        self.assertIn('--mode fast', text)


if __name__ == '__main__':
    unittest.main()
