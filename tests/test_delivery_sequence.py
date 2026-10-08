"""Keep the delivery instructions aligned with the contract's single final gate."""
from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = '.agents/skills/getzilla-delivery/SKILL.md'
COMPATIBILITY = '.grok/skills/getzilla-delivery/SKILL.md'
COPIES = ('.qwen', '.claude', '.gemini')


class DeliverySequenceTests(unittest.TestCase):
    def test_observations_and_reviews_precede_the_single_final_gate(self) -> None:
        for rel in (CANONICAL, COMPATIBILITY):
            with self.subTest(path=rel):
                text = (ROOT / rel).read_text(encoding='utf-8')
                headings = ('## 5. Bounded observations', '## 6. Independent review',
                            '## 7. Final verification and receipts', '## 8. Close')
                for heading in headings:
                    self.assertIn(heading, text)
                self.assertEqual(sorted(text.index(h) for h in headings), [text.index(h) for h in headings])
                before_final, final = text.split(headings[2], 1)
                self.assertNotIn('scripts/getzilla_verify.py --mode pr', before_final)
                self.assertEqual(final.count('scripts/getzilla_verify.py --mode pr'), 1)
                self.assertIn('commit and freeze', final)
                self.assertIn('NOT_RUN', final)
                self.assertLess(final.index('--mode pr'), final.index('scripts/getzilla_review.py code_review'))
                self.assertNotIn('reruns final verification', text)

    def test_generated_skill_copies_equal_the_canonical_source(self) -> None:
        expected = (ROOT / CANONICAL).read_bytes()
        for directory in COPIES:
            path = ROOT / directory / 'skills/getzilla-delivery/SKILL.md'
            self.assertEqual(path.read_bytes(), expected, str(path))

    def test_independent_review_and_grok_circuit_breaker_are_preserved(self) -> None:
        for rel in (CANONICAL, COMPATIBILITY):
            text = (ROOT / rel).read_text(encoding='utf-8')
            self.assertIn('reviewers must not write into the candidate worktree', text)
            self.assertIn('reviewed-tree-modified: no', text)
            self.assertIn('fingerprint-bound', text)
            self.assertIn('scope_and_design_approval', text)
        grok = (ROOT / COMPATIBILITY).read_text(encoding='utf-8')
        self.assertIn('## Tool-denial circuit breaker', grok)
        self.assertIn('Never repeat an identical denied invocation', grok)
        self.assertIn('One semantic rewrite is allowed', grok)


if __name__ == '__main__':
    unittest.main()
