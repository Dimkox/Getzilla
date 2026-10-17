"""M01: every behavioural claim on the landing names its mechanism and the tests that prove it."""
from __future__ import annotations

import ast
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / 'side-projects' / 'getzilla-landing'
MARKERS = ('keeps this out of main', 'tests that actually ran', 'grade its own homework', 'hidden tests',
           'typo gets a light touch', 'full treatment')
REQUIRED_GOLDENS = {'typo-light-touch': 'tests/test_trivial_profile.py', 'payments-full': 'tests/test_router_risk_golden.py'}


def _test_exists(reference: str) -> bool:
    path, *names = reference.split('::')
    file = ROOT / path
    if not file.is_file() or not names:
        return False
    nodes = ast.parse(file.read_text(encoding='utf-8')).body
    for name in names:
        found = next((node for node in nodes if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name == name), None)
        if found is None:
            return False
        nodes = getattr(found, 'body', [])
    return True


class LandingClaimsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = json.loads((PAGE / 'claims.json').read_text(encoding='utf-8'))
        cls.claims = cls.registry['claims']
        cls.template = (PAGE / 'template' / 'index.template.html').read_text(encoding='utf-8')
        cls.page = (PAGE / 'index.html').read_text(encoding='utf-8')

    def test_every_claim_marker_is_registered_and_on_the_page(self) -> None:
        for marker in MARKERS:
            with self.subTest(marker=marker):
                self.assertTrue(any(claim['marker'].lower() == marker for claim in self.claims), marker)
        for claim in self.claims:
            with self.subTest(claim=claim['id']):
                self.assertIn(claim['text'], self.template)
                self.assertIn(claim['text'], self.page)
                self.assertTrue(claim['mechanism'].strip())
                self.assertTrue(claim['tests'])

    def test_every_named_test_exists(self) -> None:
        for claim in self.claims:
            for reference in claim['tests']:
                with self.subTest(test=reference):
                    self.assertTrue(_test_exists(reference), reference)

    def test_conditional_claims_carry_the_footnote(self) -> None:
        footnote = re.search(r'<p[^>]*id="claim-conditions"[^>]*>(.*?)</p>', self.template, re.S)
        self.assertIsNotNone(footnote, 'the condition footnote is missing')
        for claim in self.claims:
            if not claim['requires']:
                continue
            with self.subTest(claim=claim['id']):
                after = self.template[self.template.index(claim['text']) + len(claim['text']):][:160]
                self.assertIn('href="#claim-conditions"', after)
                for requirement in claim['requires']:
                    self.assertIn(self.registry['requirements'][requirement], footnote.group(1))

    def test_typo_and_payment_claims_are_backed_by_the_golden_tests(self) -> None:
        by_id = {claim['id']: claim for claim in self.claims}
        for claim_id, golden in REQUIRED_GOLDENS.items():
            with self.subTest(claim=claim_id):
                self.assertTrue(any(reference.startswith(golden + '::') for reference in by_id[claim_id]['tests']))


if __name__ == '__main__':
    unittest.main()
