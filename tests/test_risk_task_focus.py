"""Risk comes from the task, not from what else the repository contains."""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.router import build_route  # noqa: E402


class RiskTaskFocusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.project = Path(cls.tmp.name)
        # A Django-shaped repository: an OpenAPI contract, migrations and prompts sit in the tree.
        (cls.project / 'migrations').mkdir()
        (cls.project / 'migrations/0001_initial.py').write_text('# migration\n', encoding='utf-8')
        (cls.project / 'prompts').mkdir()
        (cls.project / 'openapi.yaml').write_text('openapi: 3.1.0\n', encoding='utf-8')
        (cls.project / 'app').mkdir()
        (cls.project / 'app/views.py').write_text('def hello():\n    return "helo"\n', encoding='utf-8')
        subprocess.run(['git', 'init', '-q', str(cls.project)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def route(self, prompt: str):
        return build_route(self.project, prompt, 'risk-focus', base_commit_override=None,
                           base_fingerprint_override='0' * 64)

    def test_background_domains_do_not_raise_a_plain_task(self) -> None:
        route = self.route('Fix the typo in the greeting message')
        self.assertTrue({'api', 'data', 'ai'} <= set(route.domains), route.domains)
        self.assertEqual(route.task_domains, [])
        self.assertEqual((route.risk, route.complexity, route.delivery_lane), ('low', 'micro', 'light'))

    def test_a_task_about_the_risky_area_is_still_raised(self) -> None:
        for prompt, floor in (('Change the REST API pagination contract', 'medium'),
                              ('Add a SQL migration for the orders table', 'medium'),
                              ('Fix the SQL injection in the login form', 'high')):
            with self.subTest(prompt=prompt):
                route = self.route(prompt)
                order = {'low': 0, 'medium': 1, 'high': 2}
                self.assertGreaterEqual(order[route.risk], order[floor], route.rationale)
                self.assertEqual(route.delivery_lane, 'full')


if __name__ == '__main__':
    unittest.main()
