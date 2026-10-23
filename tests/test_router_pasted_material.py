"""Pasted documents name risky subjects without asking to change them (issue #138, item 3).

Seen 2026-10-22/23: a pasted CVE digest and a pasted project review became `incident`/high routes
with production gates, and short follow-up replies then reused those routes.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
sys.path.insert(0, str(ROOT))

from getzilla.router import _is_pasted_material, build_route  # noqa: E402
from tests._support import project_copy  # noqa: E402

PASTED_DIGEST = (
    '## Critical vulnerabilities disclosed today\n\n'
    + '- CVE-2026-1001 (PHP) — unauthenticated RCE, security incident in production, credentials exposed.\n' * 12
    + '\n```\nCVE-2026-1001 RCE auth bypass production outage\n```\n'
    + '\nThis incident shows how much insecure code reaches production every year. ' * 8
)


class PastedMaterialRouteTests(unittest.TestCase):
    def test_pasted_material_caps_word_risk_and_drops_incident_and_production_gate(self) -> None:
        self.assertGreater(len(PASTED_DIGEST), 1500)
        with project_copy() as root:
            route = build_route(root, PASTED_DIGEST, 's-pasted')
            self.assertNotEqual(route.intent, 'incident')
            self.assertEqual(route.risk, 'medium')
            self.assertNotIn('production_action_approval', route.human_gates)
            self.assertTrue(any('PASTED_MATERIAL' in line for line in route.rationale))

    def test_pasted_material_with_an_explicit_deploy_command_stays_high(self) -> None:
        with project_copy() as root:
            route = build_route(root, 'Deploy the patched build to production now.\n\n' + PASTED_DIGEST, 's-pasted-op')
            self.assertEqual(route.risk, 'high')
            self.assertIn('production_action_approval', route.human_gates)

    def test_short_risky_tasks_are_not_pasted_material(self) -> None:
        for prompt in ('прод упал почини срочно', 'Добавь RAG с tenant isolation и защитой от prompt injection',
                       'Review "publish SQL auth package in production"'):
            with self.subTest(prompt=prompt):
                self.assertFalse(_is_pasted_material(prompt))


if __name__ == '__main__':
    unittest.main()
