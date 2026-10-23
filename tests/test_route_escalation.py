"""H03: verify raises the route to the exact-head diff risk; evidence below that risk does not pass pr."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla import verification  # noqa: E402
from getzilla.receipts import _escalated_evidence, validate_evidence  # noqa: E402
from getzilla.router import escalate_route  # noqa: E402
from getzilla.util import tree_fingerprint  # noqa: E402
from tests.branch_support import git  # noqa: E402

LOW_ROUTE = {'route_id': 'route-low-1', 'risk': 'low', 'review_agents': ['code_reviewer', 'test_reviewer'],
             'required_evidence': ['verification', 'code_review', 'test_review']}


class EscalateRouteTests(unittest.TestCase):
    def test_low_route_with_high_diff_gets_security_and_release_review(self) -> None:
        result = escalate_route(LOW_ROUTE, 'high', ROOT)
        self.assertEqual(result['effective_risk'], 'high')
        self.assertEqual(result['added_evidence'], [])  # category-free risk never selects audits
        self.assertEqual(result['required_evidence'][:3], LOW_ROUTE['required_evidence'])

    def test_light_route_restores_full_floor_for_medium_or_large_diff(self) -> None:
        light = {**LOW_ROUTE, 'delivery_lane': 'light', 'review_agents': ['code_reviewer'],
                 'required_evidence': ['verification', 'code_review']}
        self.assertEqual(escalate_route(light, 'medium', ROOT)['required_evidence'], ['verification', 'code_review'])
        self.assertEqual(escalate_route(light, 'low', ROOT, force_full=True)['required_evidence'], ['verification', 'code_review'])

    def test_never_lowers_and_medium_adds_nothing(self) -> None:
        high = {**LOW_ROUTE, 'risk': 'high', 'review_agents': [*LOW_ROUTE['review_agents'], 'security_reviewer'],
                'required_evidence': [*LOW_ROUTE['required_evidence'], 'security_review']}
        self.assertEqual(escalate_route(high, 'low', ROOT)['effective_risk'], 'high')
        self.assertEqual(escalate_route(high, 'low', ROOT)['required_evidence'], high['required_evidence'])
        self.assertEqual(escalate_route(LOW_ROUTE, 'medium', ROOT)['added_evidence'], [])


class DiffRiskCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = Path(tmp.name)
        git(self.repo, 'init', '-q', '-b', 'main')
        (self.repo / '.gitignore').write_text('.getzilla/runtime/\n')
        (self.repo / 'README.md').write_text('# x\n', encoding='utf-8')
        git(self.repo, 'add', '-A')
        git(self.repo, 'commit', '-q', '-m', 'base')
        self.base = git(self.repo, 'rev-parse', 'HEAD')

    def commit(self, path: str, text: str) -> str:
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding='utf-8')
        git(self.repo, 'add', '-A')
        git(self.repo, 'commit', '-q', '-m', path)
        return git(self.repo, 'rev-parse', 'HEAD')

    def ranges(self) -> verification.GitRangeSelection:
        head = git(self.repo, 'rev-parse', 'HEAD')
        return verification.GitRangeSelection(bases=[verification.GitRangeBase('route', 'test', head, self.base)])

    def run_check(self, mode: str, route=LOW_ROUTE):
        if route:
            from getzilla.state import set_active_route
            set_active_route(self.repo, {**route, 'base_commit': self.base})
        return verification._diff_risk_check(self.repo, route, mode, self.ranges(), tree_fingerprint(self.repo))

    def test_payment_change_on_low_route_fails_pr_without_escalated_evidence(self) -> None:
        self.commit('app/payments.py', 'def pay():\n    return 1\n')
        check, metadata = self.run_check('pr')
        self.assertEqual(check.status, 'fail')
        self.assertIn('ROUTE_ESCALATED_EVIDENCE_MISSING', check.summary)
        self.assertEqual((metadata['route_risk'], metadata['diff_risk'], metadata['effective_risk']), ('low', 'high', 'high'))
        self.assertEqual(metadata['added_evidence'], ['security_review'])

    def test_fast_mode_warns_without_failing(self) -> None:
        self.commit('app/payments.py', 'def pay():\n    return 1\n')
        check, metadata = self.run_check('fast')
        self.assertEqual(check.status, 'pass')
        self.assertIn('exact-source review plan', check.summary)
        self.assertTrue(all(detail['severity'] == 'warning' for detail in check.details))

    def test_present_escalated_evidence_passes(self) -> None:
        self.commit('app/payments.py', 'def pay():\n    return 1\n')
        with mock.patch.object(verification, 'validate_evidence', return_value=[]):
            check, metadata = self.run_check('pr')
        self.assertEqual(check.status, 'pass')
        self.assertEqual(metadata['missing_evidence'], [])

    def test_docs_change_keeps_route_and_reports_trivial(self) -> None:
        self.commit('docs/guide.md', 'guide\n')
        check, metadata = self.run_check('pr')
        self.assertEqual(check.status, 'pass')
        self.assertEqual((metadata['diff_risk'], metadata['profile_candidate'], metadata['added_evidence']),
                         ('low', 'trivial', []))

    def test_no_base_skips_and_no_route_still_reports(self) -> None:
        self.commit('app/payments.py', 'x = 1\n')
        check, _ = verification._diff_risk_check(self.repo, LOW_ROUTE, 'fast', verification.GitRangeSelection(),
                                                 tree_fingerprint(self.repo))
        self.assertEqual(check.status, 'skip')
        check, metadata = self.run_check('pr', route=None)
        self.assertEqual((check.status, metadata['effective_risk']), ('pass', 'high'))


class EscalatedEvidenceTests(unittest.TestCase):
    def test_validate_evidence_requires_what_verification_escalated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            git(repo, 'init', '-q', '-b', 'main')
            (repo / 'a.txt').write_text('a\n', encoding='utf-8')
            current = tree_fingerprint(repo)
            receipt_dir = repo / '.getzilla' / 'runtime' / 'receipts' / LOW_ROUTE['route_id']
            receipt_dir.mkdir(parents=True)
            receipt = {'schema_version': 1, 'route_id': LOW_ROUTE['route_id'], 'kind': 'verification', 'status': 'pass',
                       'created_at': '2026-10-16T00:00:00Z', 'tree_fingerprint': current, 'report': 'r',
                       'criterion_ids': [], 'spec_digest': None, 'spec_fingerprint': None,
                       'details': {'diff_risk': {'added_evidence': ['security_review', 'release_review', 'bogus']}}}
            (receipt_dir / 'verification.json').write_text(json.dumps(receipt), encoding='utf-8')
            self.assertEqual(_escalated_evidence(repo, LOW_ROUTE['route_id'], LOW_ROUTE['required_evidence'], current),
                             ['security_review', 'release_review'])
            missing = validate_evidence(repo, LOW_ROUTE, current_fingerprint=current)
            self.assertTrue(any(item.startswith('security_review: missing receipt (required by exact-head diff risk)')
                                for item in missing), missing)
            self.assertEqual(_escalated_evidence(repo, LOW_ROUTE['route_id'], LOW_ROUTE['required_evidence'], '0' * 64), [])


if __name__ == '__main__':
    unittest.main()
