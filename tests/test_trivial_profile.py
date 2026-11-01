"""L01: a prose-only change at low risk needs verification and one independent review, proven by the diff."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla import verification  # noqa: E402
from getzilla.receipts import _waived_evidence, validate_evidence  # noqa: E402
from getzilla.router import trivial_waiver  # noqa: E402
from getzilla.util import tree_fingerprint  # noqa: E402
from tests.branch_support import git  # noqa: E402

TYPO = {'route_id': 'route-typo-1', 'risk': 'low', 'write_agent': 'general_implementer',
        'review_agents': ['code_reviewer', 'test_reviewer'],
        'required_evidence': ['verification', 'code_review', 'test_review']}


class TrivialProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = Path(tmp.name)
        git(self.repo, 'init', '-q', '-b', 'main')
        (self.repo / 'README.md').write_text('# app\nteh typo\n', encoding='utf-8')
        (self.repo / 'app.py').write_text('x = 1\n', encoding='utf-8')
        (self.repo / '.gitignore').write_text('.getzilla/runtime/\n')
        git(self.repo, 'add', '-A')
        git(self.repo, 'commit', '-q', '-m', 'base')
        self.base = git(self.repo, 'rev-parse', 'HEAD')

    def change(self, path: str, text: str) -> None:
        (self.repo / path).write_text(text, encoding='utf-8')
        git(self.repo, 'add', '-A')
        git(self.repo, 'commit', '-q', '-m', path)

    def check(self, route=TYPO, mode='pr'):
        from tests._support import activate_owned_route
        activate_owned_route(self.repo, dict(route))
        head = git(self.repo, 'rev-parse', 'HEAD')
        ranges = verification.GitRangeSelection(bases=[verification.GitRangeBase('route', 't', head, self.base)])
        return verification._diff_risk_check(self.repo, route, mode, ranges, tree_fingerprint(self.repo))

    def test_readme_typo_waives_test_review_and_keeps_one_reviewer(self) -> None:
        self.change('README.md', '# app\nthe typo\n')
        check, metadata = self.check()
        self.assertEqual(check.status, 'pass')
        self.assertIn('exact-source review plan', check.summary)
        self.assertEqual(metadata['profile_candidate'], 'trivial')
        self.assertEqual(metadata['waived_evidence'], [])
        self.assertNotEqual(TYPO['write_agent'], 'code_reviewer')  # the reviewer is not the author

    def test_same_prompt_with_code_change_keeps_the_standard_profile(self) -> None:
        self.change('README.md', '# app\nthe typo\n')
        self.change('app.py', 'x = 2\n')
        _, metadata = self.check()
        self.assertEqual(metadata['profile_candidate'], 'standard')
        self.assertEqual(metadata['waived_evidence'], [])

    def test_prompt_alone_or_raised_risk_never_waives(self) -> None:
        self.assertEqual(trivial_waiver(TYPO, 'low', 'standard', ROOT), [])
        self.assertEqual(trivial_waiver({**TYPO, 'risk': 'medium'}, 'medium', 'trivial', ROOT), [])
        self.assertEqual(trivial_waiver(TYPO, 'high', 'trivial', ROOT), [])
        no_review = {**TYPO, 'required_evidence': ['verification', 'test_review']}
        self.assertEqual(trivial_waiver(no_review, 'low', 'trivial', ROOT), [])

    def test_validate_evidence_honours_only_a_current_passing_trivial_receipt(self) -> None:
        current = tree_fingerprint(self.repo)
        directory = self.repo / '.getzilla' / 'runtime' / 'receipts' / TYPO['route_id']
        directory.mkdir(parents=True)

        def write(status='pass', fingerprint=current, reason='TRIVIAL_PROVEN_BY_DIFF'):
            receipt = {'schema_version': 1, 'route_id': TYPO['route_id'], 'kind': 'verification', 'status': status,
                       'created_at': '2026-10-17T00:00:00Z', 'tree_fingerprint': fingerprint, 'report': 'r',
                       'criterion_ids': [], 'spec_digest': None, 'spec_fingerprint': None,
                       'details': {'diff_risk': {'effective_risk': 'low', 'profile_reason': reason,
                                                 'waived_evidence': ['test_review', 'verification']}}}
            (directory / 'verification.json').write_text(json.dumps(receipt), encoding='utf-8')

        write()
        self.assertEqual(_waived_evidence(self.repo, TYPO['route_id'], TYPO['required_evidence'], current), ['test_review'])
        missing = validate_evidence(self.repo, TYPO, current_fingerprint=current)
        self.assertFalse(any(item.startswith('test_review') for item in missing), missing)
        self.assertTrue(any(item.startswith('code_review') for item in missing), missing)
        for variant in ({'status': 'fail'}, {'fingerprint': '0' * 64}, {'reason': None}):
            write(**variant)
            self.assertEqual(_waived_evidence(self.repo, TYPO['route_id'], TYPO['required_evidence'], current), [], variant)


if __name__ == '__main__':
    unittest.main()
