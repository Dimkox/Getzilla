"""H02: exact-head diff risk from changed paths, architecture and one hop of imports — not from the prompt."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.diff_risk import classify_diff, load_rules, matches  # noqa: E402
from getzilla.spec import validate_schema  # noqa: E402
from tests.branch_support import git  # noqa: E402

MODEL = {
    'system': {'nodes': [
        {'id': 'NODE-LEDGER', 'data_classification': 'DATA-LEDGER', 'repository_paths': ['ledger']},
        {'id': 'NODE-VAULT', 'data_classification': 'DATA-PUBLIC', 'secrets': ['SECRET-X'], 'repository_paths': ['vault']},
        {'id': 'NODE-UI', 'data_classification': 'DATA-PUBLIC', 'repository_paths': ['ui']},
    ]},
    'rules': {'tenant_authorization_policies': [{'id': 'FIT-X', 'data_classifications': ['DATA-LEDGER']}]},
}


class DiffRiskTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = Path(tmp.name)
        git(self.repo, 'init', '-q', '-b', 'main')
        self.write({'README.md': '# app\n', 'docs/guide.md': 'guide\n', 'app/util.py': 'def helper():\n    return 1\n',
                    'app/payments.py': 'from app.util import helper\ndef pay():\n    return helper()\n',
                    'app/__init__.py': '', 'tests/test_util.py': 'def test_helper():\n    assert True\n',
                    'ui/page.py': 'x = 1\n', 'ledger/book.py': 'x = 1\n', 'vault/keys.py': 'x = 1\n'})
        self.base = self.commit('base')

    def write(self, files: dict[str, str]) -> None:
        for path, text in files.items():
            target = self.repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding='utf-8')

    def commit(self, message: str) -> str:
        git(self.repo, 'add', '-A')
        git(self.repo, 'commit', '-q', '-m', message)
        return git(self.repo, 'rev-parse', 'HEAD')

    def change(self, files: dict[str, str], delete: tuple[str, ...] = (), **kwargs):
        self.write(files)
        for path in delete:
            (self.repo / path).unlink()
        head = self.commit('change')
        return classify_diff(self.repo, self.base, head, architecture=kwargs.pop('architecture', MODEL), **kwargs)

    def rules(self, risk):
        return {reason['rule'].split(':')[0] for reason in risk.reasons}

    def test_docs_only_change_is_trivial(self) -> None:
        risk = self.change({'README.md': '# app\nfixed typo\n', 'docs/guide.md': 'guide v2\n'})
        self.assertEqual((risk.risk, risk.profile_candidate), ('low', 'trivial'))
        self.assertTrue(risk.complete)

    def test_auth_money_and_restricted_node_are_high(self) -> None:
        for files, rule in (({'app/payments.py': 'def pay():\n    return 2\n'}, 'MONEY_PATH'),
                            ({'app/auth/session.py': 'x = 1\n'}, 'AUTH_PATH'),
                            ({'ledger/book.py': 'x = 2\n'}, 'ARCHITECTURE_RESTRICTED_NODE'),
                            ({'vault/keys.py': 'x = 2\n'}, 'ARCHITECTURE_RESTRICTED_NODE')):
            with self.subTest(rule=rule, files=list(files)):
                risk = self.change(files)
                self.assertEqual((risk.risk, risk.profile_candidate), ('high', 'full'))
                self.assertIn(rule, self.rules(risk))
                self.base = risk.head

    def test_prompt_wording_cannot_hide_a_payment_change(self) -> None:
        # The prompt said "typo"; the diff touches payments. Diff risk is computed without the prompt at all.
        risk = self.change({'README.md': '# app\n', 'app/payments.py': 'def pay():\n    return 3\n'})
        self.assertEqual(risk.risk, 'high')

    def test_dependency_ci_and_agent_instructions_are_medium(self) -> None:
        for path in ('.github/workflows/ci.yml', 'pyproject.toml', 'package-lock.json', 'AGENTS.md',
                     '.agents/skills/x/SKILL.md'):
            with self.subTest(path=path):
                risk = self.change({path: f'changed {path}\n'})
                self.assertEqual(risk.risk, 'medium')
                self.assertNotEqual(risk.profile_candidate, 'trivial')
                self.base = risk.head

    def test_test_removed_is_high_and_tests_only_is_medium(self) -> None:
        removed = self.change({}, delete=('tests/test_util.py',))
        self.assertEqual(removed.risk, 'high')
        self.assertIn('TEST_REMOVED', self.rules(removed))
        self.base = removed.head
        self.write({'tests/test_util.py': 'def test_helper():\n    assert 1\n'})
        only_tests = classify_diff(self.repo, self.base, self.commit('tests only'), architecture=MODEL)
        self.assertEqual(only_tests.risk, 'medium')
        self.assertIn('TESTS_CHANGED_WITHOUT_CODE', self.rules(only_tests))

    def test_helper_used_by_payments_is_at_least_medium(self) -> None:
        risk = self.change({'app/util.py': 'def helper():\n    return 2\n'})
        self.assertEqual(risk.risk, 'medium')
        self.assertTrue(any(r['rule'].startswith('DEPENDENT_IN_HIGH_RISK_PATH:MONEY_PATH:app/payments.py')
                            for r in risk.reasons))
        unrelated = classify_diff(self.repo, risk.head, self.change({'ui/page.py': 'x = 2\n'}).head, architecture=MODEL)
        self.assertEqual(unrelated.risk, 'low')
        self.assertEqual(unrelated.profile_candidate, 'standard')  # code is never trivial

    def test_unparsed_python_blocks_trivial_and_is_a_gap(self) -> None:
        risk = self.change({'ui/page.py': 'def broken(:\n'})
        self.assertIn('PARSE_INCOMPLETE:ui/page.py', risk.gaps)
        self.assertFalse(risk.complete)
        self.assertNotEqual(risk.profile_candidate, 'trivial')

    def test_identity_is_the_exact_head(self) -> None:
        risk = self.change({'docs/guide.md': 'v3\n'})
        self.assertEqual(risk.head, git(self.repo, 'rev-parse', 'HEAD'))
        self.assertEqual(risk.tree, git(self.repo, 'rev-parse', 'HEAD^{tree}'))
        self.assertEqual(risk.base, self.base)
        validate_schema(risk.to_dict(), json.loads((ROOT / 'schemas' / 'diff-risk-v1.schema.json').read_text(encoding='utf-8')))

    def test_prose_names_do_not_trigger_code_rules(self) -> None:
        risk = self.change({'docs/payments-guide.md': 'how payments work\n', 'docs/authentication.md': 'notes\n'})
        self.assertEqual((risk.risk, risk.profile_candidate), ('low', 'trivial'))

    def test_glob_semantics(self) -> None:
        self.assertTrue(matches('auth/x.py', ['**/auth/**']))
        self.assertTrue(matches('src/auth/x.py', ['**/auth/**']))
        self.assertFalse(matches('src/author/x.py', ['**/auth/**']))
        self.assertTrue(matches('README.md', ['*.md']))
        self.assertFalse(matches('docs/x.md', ['*.md']))
        self.assertTrue(matches('a/B/SKILL.md', ['**/skill.md']))
        self.assertEqual(load_rules()['schema_version'], 'diff-risk-rules-v1')


if __name__ == '__main__':
    unittest.main()
