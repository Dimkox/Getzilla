"""The delivery skills, the evidence template and AGENTS.md describe one delivery order.

Each document repeats the same canonical order line, so a reordered step fails here; the
other checks pin the invariants around it: receipts only after the final gate, the frozen
tree equals the reviewed tree, and any later change invalidates all receipts.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DELIVERY = ('.agents/skills/getzilla-delivery/SKILL.md', '.grok/skills/getzilla-delivery/SKILL.md')
DOCUMENTS = (*DELIVERY, '.agents/skills/verification-evidence/SKILL.md',
             '.grok/skills/verification-evidence/SKILL.md', '.getzilla/templates/change/evidence/README.md')
ORDER = ('Delivery order: 1. bounded local checks; 2. independent reviews of one committed candidate; '
         '3. save the complete review reports; 4. commit and freeze the candidate; '
         '5. one final qualifying `python3 scripts/getzilla_verify.py --mode pr`.')
FROZEN = ('The frozen candidate tree must equal the tree the reviewers saw except for the saved report files: '
          'before the final gate, `git diff --name-only <reviewed-commit> HEAD` lists only those reports; '
          'any other difference makes every review stale.')
INVALIDATION = ('Any change after review invalidates all receipts: repeat the independent reviews on the new tree, '
                'save the new reports, commit and freeze again, and run a new final gate. '
                'Never reuse evidence from another tree.')
RECEIPTS_AFTER_GATE = re.compile(r'after (?:that|the) (?:final|qualifying) gate (?:passes|succeeds)')
WEAKENINGS = (
    r'reruns? final verification',                        # the old verify -> review -> verify order
    r'\b(?:un)?affected (?:evidence|reviews?|controls)',  # softens "invalidates all receipts"
    r'\b(?:may|can) be reused\b',
    r'\b(?:persist|save|store)\w*\b[^.;]*\bafter\b[^.;]*\b(?:gate|verif\w*)',  # reports saved after the gate
)


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding='utf-8')


class DeliverySequenceTests(unittest.TestCase):
    def test_every_document_states_the_same_order_and_invariants(self) -> None:
        for rel in DOCUMENTS:
            with self.subTest(document=rel):
                text = read(rel)
                for sentence in (ORDER, FROZEN, INVALIDATION):
                    self.assertIn(sentence, text)
                self.assertRegex(text, RECEIPTS_AFTER_GATE)

    def test_no_document_reintroduces_a_weaker_order(self) -> None:
        for rel in (*DOCUMENTS, 'AGENTS.md'):
            text = ' '.join(read(rel).split()).lower()
            for pattern in WEAKENINGS:
                with self.subTest(document=rel, pattern=pattern):
                    self.assertIsNone(re.search(pattern, text))

    def test_delivery_skill_runs_reviews_first_and_records_receipts_last(self) -> None:
        for rel in DELIVERY:
            with self.subTest(document=rel):
                text = read(rel)
                before, final = text.split('## 7. Final verification and receipts', 1)
                self.assertIn('do not run a preliminary full qualifying gate before reviews', before)
                self.assertIn('Dispatch all route `review_agents` in parallel', before)
                self.assertIn("The existing fail-closed selector, not a route label or the agent's assertion", final)
                gate = final.index('python3 scripts/getzilla_verify.py --mode pr\n')
                self.assertLess(gate, final.index('scripts/getzilla_review.py code_review'))
                self.assertLess(gate, RECEIPTS_AFTER_GATE.search(final).start())

    def test_agents_md_keeps_all_reviews_and_invalidates_all_receipts(self) -> None:
        text = ' '.join(read('AGENTS.md').split())
        for sentence in (
            'rerun the bounded committed-HEAD controls and all independent reviews on the repaired tree before final freeze.',
            'A source change after freeze invalidates all receipts and requires the same writer\'s repair, '
            'fresh controls and independent reviews, a new frozen candidate and fresh exact-head gates',
            'the coordinator persists reports under the change evidence directory, commits/freezes that tree, '
            'then runs the single final qualifying verification and records fresh fingerprint-bound receipts.',
        ):
            self.assertIn(sentence, text)

    def test_grok_keeps_its_tool_denial_circuit_breaker(self) -> None:
        for delivery in DELIVERY:
            text = read(delivery)
            self.assertIn('## Tool-denial circuit breaker', text, delivery)
            self.assertIn('Never repeat an identical denied invocation', text, delivery)
            self.assertIn('One semantic rewrite is allowed', text, delivery)
            self.assertIn('An opaque denial requires explicit targets', text, delivery)


if __name__ == '__main__':
    unittest.main()
