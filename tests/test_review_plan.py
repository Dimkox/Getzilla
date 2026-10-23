"""Committed source, rather than task prose, selects independent audit authority."""
from __future__ import annotations
import json
import sys
import tempfile
import unittest
from pathlib import Path
from tests.branch_support import git

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))


class ReviewPlanTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        git(self.root, 'init', '-q', '-b', 'work')
        self.write('.gitignore', '.getzilla/runtime/\n')
        for name in ('diff-risk-rules.json', 'routing.json'):
            self.write('.getzilla/config/' + name, (ROOT / '.getzilla/config' / name).read_text())
        self.write('app.py', 'value = 1\n')
        self.commit()
        self.base = git(self.root, 'rev-parse', 'HEAD')
        git(self.root, 'update-ref', 'refs/remotes/origin/main', self.base)

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def commit(self):
        git(self.root, 'add', '.')
        git(self.root, 'commit', '-qm', 'fixture')

    def route(self, prompt='Implement a large ordinary feature'):
        from getzilla.router import build_route
        from getzilla.state import set_active_route
        route = build_route(self.root, prompt).to_dict()
        route['base_commit'] = self.base
        set_active_route(self.root, route)
        return route

    def reconcile(self):
        from getzilla.review_plan import reconcile_route
        return reconcile_route(self.root)

    def test_exact_diff_plan_is_invariant_under_prompt_language_and_risk_words(self):
        self.write('app.py', 'value = 2\n' * 60)
        self.commit()
        plans = []
        for prompt in ('Implement ordinary feature', 'Implement security payment migration incident archives', 'Реализуй журнал ошибок авторизации'):
            self.route(prompt)
            result = self.reconcile()
            self.assertEqual(result['risk'], 'low')
            self.assertEqual(result['review_agents'], ['code_reviewer'])
            self.assertEqual(result['required_evidence'], ['verification', 'code_review'])
            self.assertEqual(result['risk_assessment']['status'], 'complete')
            plans.append(result['review_plan']['digest'])
        self.assertEqual(len(set(plans)), 1)

    def test_category_and_threshold_select_only_relevant_dispatchable_audit(self):
        from getzilla.agent_lifecycle import start_agent
        for path, expected in [('auth/login.py', 'security_reviewer'), ('migrations/001.sql', 'data_reviewer'),
                               ('.github/workflows/ci.yml', 'release_reviewer')]:
            with self.subTest(path=path):
                self.write(path, 'value = 1\n')
                self.commit()
                old = self.route()
                current = self.reconcile()
                self.assertEqual(current['review_agents'], ['code_reviewer', expected])
                self.assertEqual(current['write_agent'], old['write_agent'])
                self.assertEqual(current['analysis_agents'], old['analysis_agents'])
                self.assertEqual(current['human_gates'], old['human_gates'])
                self.assertEqual(start_agent(self.root, expected, expected)['lifecycle'], 'running')
                self.base = git(self.root, 'rev-parse', 'HEAD')
                git(self.root, 'update-ref', 'refs/remotes/origin/main', self.base)

    def test_dirty_binary_and_policy_weakening_do_not_prove_low_risk(self):
        self.route()
        self.write('app.py', 'value = 2\n')
        self.assertEqual(self.reconcile()['risk_assessment']['status'], 'incomplete')
        self.commit()
        rules = json.loads((self.root / '.getzilla/config/diff-risk-rules.json').read_text())
        rules['rules'] = []
        self.write('.getzilla/config/diff-risk-rules.json', json.dumps(rules))
        self.write('auth/login.py', 'value = 1\n')
        self.commit()
        current = self.reconcile()
        self.assertEqual(current['risk'], 'high')
        self.assertIn('security_reviewer', current['review_agents'])
        (self.root / 'app.py').write_bytes(b'\0binary')
        self.commit()
        self.assertEqual(self.reconcile()['risk_assessment']['status'], 'incomplete')

    def test_stale_source_or_tampered_plan_binding_is_rejected(self):
        from getzilla.review_plan import validate_review_plan
        self.route()
        self.write('app.py', 'value = 2\n')
        self.commit()
        route = self.reconcile()
        self.assertEqual(validate_review_plan(self.root, route), [])
        route['review_agents'] = []
        self.assertTrue(validate_review_plan(self.root, route))
        self.write('app.py', 'value = 3\n')
        self.commit()
        self.assertTrue(validate_review_plan(self.root, route))

    def test_legacy_explicit_reviews_remain_selected_and_incident_archive_is_not_outage(self):
        from getzilla.state import update_route
        route = self.route('Implement dated incidents and recurring lessons')
        self.assertNotEqual(route['intent'], 'incident')
        update_route(self.root, explicit_review_agents=['test_reviewer', 'security_reviewer', 'release_reviewer'])
        self.write('app.py', 'value = 2\n')
        self.commit()
        self.assertEqual(self.reconcile()['review_agents'], ['code_reviewer', 'test_reviewer', 'security_reviewer', 'release_reviewer'])

    def test_explicit_additional_reviewers_are_persisted_and_authorized(self):
        from getzilla.review_plan import reconcile_route, validate_review_plan
        from getzilla.agent_lifecycle import start_agent
        self.route()
        self.write('app.py', 'value = 2\n')
        self.commit()
        route = reconcile_route(self.root, additional_reviewers=('test_reviewer', 'release_reviewer'))
        self.assertEqual(route['review_agents'], ['code_reviewer', 'test_reviewer', 'release_reviewer'])
        self.assertEqual(validate_review_plan(self.root, route), [])
        self.assertEqual(start_agent(self.root, 'extra-review', 'test_reviewer')['lifecycle'], 'running')
        self.assertEqual(self.reconcile()['review_agents'], route['review_agents'])
        with self.assertRaisesRegex(ValueError, 'unknown explicit reviewer'):
            reconcile_route(self.root, additional_reviewers=('writer',))
