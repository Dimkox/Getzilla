"""A task that opens with a build imperative keeps a write owner even when it asks for reviews later."""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.router import build_route  # noqa: E402

# Shaped like a real consumer prompt that was routed as a read-only review (no writer) and had to be cancelled.
BUILD_WITH_PROCESS_WORDS = (
    'Implement approved selector spec stage 1 in the existing Bitrix component: versioned ranking, '
    'versioned API contracts and a full catalog comparison. Required focused checks, independent reviews '
    'and an honest UNVERIFIED aggregate.',
    'Реализуй этап 1 утверждённой спецификации подбора: ранжирование и контракт API версии 2. '
    'Нужны независимые review и документация изменений.',
    'Add a CSV export to the orders page; docs and a review are expected afterwards.',
)


class BuildIntentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.project = Path(cls.tmp.name)
        (cls.project / 'app.py').write_text('print(1)\n', encoding='utf-8')
        subprocess.run(['git', 'init', '-q', str(cls.project)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def test_build_imperative_keeps_a_writer(self) -> None:
        for prompt in BUILD_WITH_PROCESS_WORDS:
            with self.subTest(prompt=prompt[:40]):
                route = build_route(self.project, prompt)
                self.assertNotEqual(route.intent, 'review')
                self.assertIsNotNone(route.write_agent)
                self.assertIn('verification', route.required_evidence)

    def test_real_review_and_test_requests_are_unchanged(self) -> None:
        self.assertEqual(build_route(self.project, 'Review the payment module changes').intent, 'review')
        self.assertIsNone(build_route(self.project, 'Review the payment module changes').write_agent)
        self.assertEqual(build_route(self.project, 'добавь тест на парсер').intent, 'test')
        self.assertEqual(build_route(self.project, 'Implement a fix for the broken login bug').intent, 'bugfix')


if __name__ == '__main__':
    unittest.main()
