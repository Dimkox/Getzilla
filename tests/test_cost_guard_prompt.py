"""C01: paid or unbounded operations in the prompt raise risk and declare paid_run_approval."""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.cost_guard import GATE, prompt_cost_signals  # noqa: E402
from getzilla.router import build_route, route_context  # noqa: E402

PAID = (
    'сделай в n8n сценарий: генерируй 20 вариантов видео через Kling и выбери лучший',
    'подключи OpenRouter и гоняй генерацию картинок, пока не получится хорошо',
    'generate 50 variants of the banner with Midjourney',
    'call the OpenAI image API every hour and post the result',
    'make a zapier flow that sends every lead to Claude API',
)
FREE = (
    'добавь кнопку "Скачать" на страницу заказа',
    'напиши тест для генератора отчётов',
    'подключи OpenAI для ответа на один вопрос в чате поддержки',
    'list the versions of the API in the README',
)


class PromptCostSignalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.project = Path(cls.tmp.name)
        subprocess.run(['git', 'init', '-q', str(cls.project)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def test_paid_loops_are_signalled(self) -> None:
        for prompt in PAID:
            with self.subTest(prompt=prompt):
                self.assertIsNotNone(prompt_cost_signals(prompt))

    def test_single_or_free_work_is_not_signalled(self) -> None:
        for prompt in FREE:
            with self.subTest(prompt=prompt):
                self.assertIsNone(prompt_cost_signals(prompt))

    def test_route_declares_gate_and_never_stays_low(self) -> None:
        for prompt in PAID:
            with self.subTest(prompt=prompt):
                route = build_route(self.project, prompt)
                self.assertIn(GATE, route.human_gates)
                self.assertIn(route.risk, ('medium', 'high'))
                self.assertTrue(any(reason.startswith('COST_SIGNAL:') for reason in route.rationale))
                self.assertIn('cost-contract.json', route_context(route))

    def test_free_route_has_no_paid_gate(self) -> None:
        route = build_route(self.project, FREE[0])
        self.assertNotIn(GATE, route.human_gates)
        self.assertNotIn('cost-contract.json', route_context(route))


if __name__ == '__main__':
    unittest.main()
