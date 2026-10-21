"""Optional EU AI Act evidence layer: draft classes, the gate, the audit bundle and the opt-in."""
from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla import eu_ai_act  # noqa: E402
from getzilla.util import tree_fingerprint  # noqa: E402

TODAY = date(2026, 10, 20)
CONFIRMED = {'by': 'Jane Doe', 'role': 'legal counsel', 'date': '2026-10-20'}
ASSISTANT = ('import openai\n\nAI_DISCLOSURE = "You are talking to an AI assistant."\n\n'
             'def answer(question):\n    reply = openai.chat.completions.create(model="m", messages=[])\n'
             '    return mark_generated_content(reply, AI_DISCLOSURE)\n\n'
             'def mark_generated_content(reply, notice):\n    return {"reply": reply, "notice": notice, "c2pa": True}\n')
ASSISTANT_TEST = ('from src.support.bot import AI_DISCLOSURE, mark_generated_content\n\n'
                  'def test_disclosed_and_marked():\n    assert "AI" in AI_DISCLOSURE\n'
                  '    assert mark_generated_content("x", AI_DISCLOSURE)["c2pa"]\n')


def git(repo: Path, *args: str) -> str:
    return subprocess.run(['git', '-C', str(repo), *args], capture_output=True, text=True, check=True).stdout.strip()


class Repo:
    def __init__(self, test: unittest.TestCase, *, installed: bool = True) -> None:
        tmp = tempfile.TemporaryDirectory()
        test.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        git(self.root, 'init', '-q', '-b', 'main')
        git(self.root, 'config', 'user.name', 'Test')
        git(self.root, 'config', 'user.email', 'test@example.com')
        target = self.root / eu_ai_act.OBLIGATIONS
        target.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / eu_ai_act.OBLIGATIONS, target)
        self.fresh_matrix(TODAY)
        if installed:
            self.write(eu_ai_act.COMPLIANCE_CONFIG, eu_ai_act.opt_in_record(['eu-ai-act']).decode('utf-8'))
        self.write('README.md', '# app\n')
        self.base = self.commit('base')

    def write(self, rel: str, text: str) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')

    def registry(self, *systems: dict) -> None:
        self.write(eu_ai_act.REGISTRY, json.dumps({'schema_version': 'ai-systems-v1', 'systems': list(systems)}))

    def fresh_matrix(self, today: date) -> None:
        path = self.root / eu_ai_act.OBLIGATIONS
        matrix = json.loads(path.read_text(encoding='utf-8'))
        matrix['reviewed'] = today.isoformat()
        path.write_text(json.dumps(matrix), encoding='utf-8')

    def commit_sha(self) -> str:
        return git(self.root, 'rev-parse', 'HEAD')

    def commit(self, message: str) -> str:
        git(self.root, 'add', '-A')
        git(self.root, 'commit', '-q', '-m', message)
        return git(self.root, 'rev-parse', 'HEAD')

    def evaluate(self, mode: str = 'pr', today: date = TODAY):
        return eu_ai_act.evaluate(self.root, mode, [self.base], 'HEAD', today=today)


def codes(report) -> list[str]:
    return [problem.split(':', 1)[0] for problem in report.problems]


class DraftClassTests(unittest.TestCase):
    def test_purposes_get_the_expected_draft(self) -> None:
        for purpose, expected in (
            ('Creditworthiness scoring of loan applicants', 'high-risk'),
            ('Оценка заёмщиков для кредитного скоринга', 'high-risk'),
            ('CV screening for recruitment', 'high-risk'),
            ('Assistant that generates answers to customer questions', 'limited'),
            ('Чат-бот поддержки', 'limited'),
            ('Social scoring of citizens', 'prohibited'),
            ('Spell checker for invoices', 'minimal'),
        ):
            with self.subTest(purpose=purpose):
                self.assertEqual(eu_ai_act.draft_class(purpose).risk_class, expected)

    def test_the_most_restrictive_match_wins(self) -> None:
        draft = eu_ai_act.draft_class('Chatbot that decides loan approval for borrowers')
        self.assertEqual(draft.risk_class, 'high-risk')
        self.assertTrue(draft.reasons)


class MatrixFreshnessTests(unittest.TestCase):
    def test_exact_window_and_invalid_metadata(self):
        recent = {'reviewed': TODAY.isoformat(), 'sources': ['https://eur-lex.europa.eu/eli/reg/2024/1689/oj']}
        self.assertIsNone(eu_ai_act.matrix_review_problem(recent, TODAY + timedelta(days=180)))
        self.assertIn('181 days', eu_ai_act.matrix_review_problem(recent, TODAY + timedelta(days=181)))
        for data in ({}, {**recent, 'reviewed': 'bad'}, {**recent, 'reviewed': True},
                     {**recent, 'sources': []}, {**recent, 'sources': 'url'}, {**recent, 'sources': ['']},
                     {**recent, 'reviewed': (TODAY + timedelta(days=1)).isoformat()}):
            with self.subTest(data=data):
                self.assertIsNotNone(eu_ai_act.matrix_review_problem(data, TODAY))

    def test_empty_registry_reports_stale_matrix_and_legacy_still_parses(self):
        repo = Repo(self)
        data = json.loads((repo.root / eu_ai_act.OBLIGATIONS).read_text(encoding='utf-8'))
        data.pop('reviewed', None)
        data.pop('sources', None)
        repo.write(eu_ai_act.OBLIGATIONS, json.dumps(data))
        repo.registry()
        repo.commit('legacy matrix')
        self.assertTrue(eu_ai_act.load_obligations(repo.root))
        report = repo.evaluate()
        self.assertEqual(codes(report), ['MATRIX_STALE'])
        self.assertEqual((report.decision, report.status), ('review', 'fail'))
        self.assertEqual(repo.evaluate('fast').status, 'pass')
        repo.write(eu_ai_act.COMPLIANCE_CONFIG, '{}')
        self.assertEqual(repo.evaluate().status, 'skip')


class RiskRecordTests(unittest.TestCase):
    def test_next_review_is_enforced_only_when_obligation_applies(self):
        repo = Repo(self)
        repo.registry({'id': 'score', 'purpose': 'credit scoring', 'paths': ['src/score/*'],
                       'class': 'high-risk', 'annex': 'III', 'role': 'provider',
                       'confirmation': CONFIRMED, 'risk_register': 'risk.json'})
        repo.write('risk.json', json.dumps({'risks': [{'risk': 'bias', 'mitigation': 'evaluate',
                   'owner': 'risk team', 'reviewed': '2027-12-01', 'next_review': 'invalid'}]}))
        repo.fresh_matrix(date(2027, 12, 1))
        repo.commit('not applicable yet')
        before = repo.evaluate(today=date(2027, 12, 1))
        after = repo.evaluate(today=date(2027, 12, 2))
        self.assertEqual(next(row['status'] for row in before.matrix if row['obligation'] == 'AIA-9'), 'met')
        self.assertEqual(next(row['status'] for row in after.matrix if row['obligation'] == 'AIA-9'), 'unmet')

    def test_optional_scores_acceptance_and_deadlines(self):
        repo = Repo(self)
        risk = {'risk': 'bias', 'mitigation': 'evaluation', 'owner': 'risk team', 'reviewed': TODAY.isoformat()}
        cases = [({}, None), ({'likelihood': 1, 'severity': 5, 'residual': 'low'}, None)]
        for field in ('likelihood', 'severity'):
            cases += [({field: value}, f'{field} must be 1-5') for value in (0, 6, True, False, 2.0, '2', None)]
        cases += [({'residual': 'severe'}, 'residual must be low, medium or high'),
                  ({'residual': 'high'}, 'high residual risk needs accepted_by'),
                  ({'residual': 'high', 'accepted_by': CONFIRMED}, None),
                  ({'residual': 'high', 'accepted_by': {'by': 'x'}}, 'confirmation'),
                  ({'next_review': '2026-10-19'}, 'next_review 2026-10-19 has passed'),
                  ({'next_review': TODAY.isoformat()}, None), ({'next_review': 'bad'}, 'YYYY-MM-DD')]
        for extra, expected in cases:
            with self.subTest(extra=extra):
                repo.write('risk.json', json.dumps({'risks': [{**risk, **extra}]}))
                repo.commit('risk record')
                problem = eu_ai_act._risk_register_problem(repo.root, 'HEAD', 'risk.json', TODAY)
                if expected is None:
                    self.assertIsNone(problem)
                else:
                    self.assertIn(expected, problem or '')


class IsoMapTests(unittest.TestCase):
    def test_map_covers_obligations_and_is_non_gating(self):
        mapping = eu_ai_act.load_iso_map(ROOT)
        self.assertEqual(set(mapping), {item['id'] for item in eu_ai_act.load_obligations(ROOT)})
        for clauses in mapping.values():
            self.assertTrue(clauses)
            for clause in clauses:
                self.assertRegex(clause, r'^A\.(?:[2-9]|10)$')
        repo = Repo(self)
        baseline = repo.evaluate().decision
        for invalid in ('{', 'null', '[]', '{"AIA-9": ["wrong"]}'):
            repo.write('.getzilla/compliance/eu-ai-act/iso42001-map.json', invalid)
            self.assertIsNone(eu_ai_act.load_iso_map(repo.root))
            self.assertEqual(repo.evaluate().decision, baseline)


class GateTests(unittest.TestCase):
    def test_malformed_opt_in_is_disabled(self):
        repo = Repo(self)
        for value in ('eu-ai-act', {'eu-ai-act': True}, True, 1):
            repo.write(eu_ai_act.COMPLIANCE_CONFIG, json.dumps({'enabled': value}))
            self.assertFalse(eu_ai_act.enabled(repo.root))

    def test_without_the_opt_in_record_the_matrix_never_gates(self) -> None:
        repo = Repo(self, installed=False)
        repo.write('src/bot.py', ASSISTANT)
        repo.commit('ai code')
        self.assertEqual(repo.evaluate().status, 'skip')
        self.assertFalse(eu_ai_act.enabled(ROOT))

    def test_unregistered_ai_code_fails_pr_and_warns_fast(self) -> None:
        repo = Repo(self)
        repo.write('src/support/bot.py', ASSISTANT)
        repo.commit('ai code')
        self.assertEqual(codes(repo.evaluate()), ['AI_SYSTEM_UNREGISTERED'])
        self.assertEqual(repo.evaluate().status, 'fail')
        fast = repo.evaluate('fast')
        self.assertEqual(fast.status, 'pass')
        self.assertTrue(fast.summary.startswith('will fail pr/release'))

    def test_a_class_needs_a_person_and_obligations_need_tested_evidence(self) -> None:
        repo = Repo(self)
        repo.write('src/support/bot.py', ASSISTANT)
        system = {'id': 'support', 'purpose': 'Assistant that generates answers', 'paths': ['src/support/*.py'],
                  'class': 'limited', 'generates_content': True, 'role': 'provider',
                  'disclosure_symbol': 'AI_DISCLOSURE', 'marking_symbol': 'mark_generated_content'}
        repo.registry(system)
        repo.commit('registered, unconfirmed, untested')
        report = repo.evaluate()
        self.assertIn('AI_CLASS_UNCONFIRMED', codes(report))
        unmet = {p.split()[2] for p in report.problems if p.startswith('OBLIGATION_UNMET')}
        self.assertEqual(unmet, {'AIA-5', 'AIA-50-1', 'AIA-50-2'})
        repo.registry({**system, 'confirmation': CONFIRMED})
        repo.write('tests/test_support.py', ASSISTANT_TEST)
        repo.commit('confirmed and tested')
        report = repo.evaluate()
        self.assertEqual(report.status, 'pass', report.problems)
        rows = {row['obligation']: row['status'] for row in report.matrix}
        self.assertEqual(report.decision, 'pass')
        self.assertEqual(rows, {'AIA-5': 'met', 'AIA-50-1': 'met', 'AIA-50-2': 'met', 'AIA-50-4': 'not_applicable',
                                'AIA-9': 'not_applicable',
                                'AIA-11': 'not_applicable', 'AIA-12': 'not_applicable', 'AIA-14': 'not_applicable',
                                'AIA-15': 'not_applicable'})

    def test_a_class_below_the_draft_needs_a_reason_and_prohibited_never_ships(self) -> None:
        repo = Repo(self)
        repo.registry({'id': 'scoring', 'purpose': 'Credit scoring of borrowers', 'paths': ['src/scoring/*'],
                       'class': 'minimal', 'role': 'provider', 'confirmation': CONFIRMED},
                      {'id': 'citizens', 'purpose': 'Social scoring of citizens', 'paths': ['src/social/*'],
                       'class': 'prohibited', 'role': 'provider', 'confirmation': CONFIRMED})
        repo.commit('registry')
        report = repo.evaluate()
        self.assertIn('AI_CLASS_BELOW_DRAFT', codes(report))
        self.assertIn('AI_PROHIBITED_PRACTICE', codes(report))
        self.assertEqual(report.decision, 'block')
        self.assertTrue(report.summary.startswith('BLOCK: '))

    def test_high_risk_needs_a_current_risk_register_logs_and_oversight(self) -> None:
        repo = Repo(self)
        repo.write('src/scoring/model.py', 'def record_decision_event():\n    pass\n\ndef require_human_review():\n    pass\n'
                   'AI_DISCLOSURE = "automated"\n')
        repo.write('tests/test_scoring.py', 'from src.scoring.model import record_decision_event, require_human_review, AI_DISCLOSURE\n')
        system = {'id': 'scoring', 'purpose': 'Credit scoring of borrowers', 'paths': ['src/scoring/*'],
                  'class': 'high-risk', 'generates_content': False, 'confirmation': CONFIRMED,
                  'role': 'provider', 'annex': 'III',
                  'disclosure_symbol': 'AI_DISCLOSURE', 'logging_symbol': 'record_decision_event',
                  'oversight_symbol': 'require_human_review', 'risk_register': 'compliance/risks.json'}
        repo.registry(system)
        stale = {'risks': [{'risk': 'bias', 'mitigation': 'fairness eval', 'owner': 'risk team', 'reviewed': '2024-01-01'}]}
        repo.write('compliance/risks.json', json.dumps(stale))
        repo.commit('stale register')
        before = repo.evaluate()
        self.assertEqual(before.status, 'pass', before.problems)
        self.assertTrue(any('AIA-9' in item and '2027-12-02' in item for item in before.upcoming))
        self.assertTrue(any('AIA-9' in problem for problem in repo.evaluate(today=date(2027, 12, 2)).problems))
        repo.registry({**system, 'annex': 'I'})
        repo.fresh_matrix(date(2027, 12, 2))
        repo.commit('annex I')
        self.assertEqual(repo.evaluate(today=date(2027, 12, 2)).status, 'pass')
        self.assertEqual(repo.evaluate(today=date(2028, 8, 2)).decision, 'block')
        repo.registry(system)
        repo.fresh_matrix(TODAY)
        stale['risks'][0]['reviewed'] = '2026-10-01'
        repo.write('compliance/risks.json', json.dumps(stale))
        repo.commit('reviewed register')
        report = repo.evaluate()
        self.assertEqual(report.status, 'pass', report.problems)
        rows = {row['obligation']: row['status'] for row in report.matrix}
        self.assertEqual((rows['AIA-9'], rows['AIA-11'], rows['AIA-12'], rows['AIA-14'], rows['AIA-15'], rows['AIA-50-2']),
                         ('met', 'at_release', 'met', 'met', 'covered_by_verify', 'not_applicable'))


class DecisionTests(unittest.TestCase):
    SUPPORT = {'id': 'support', 'purpose': 'Assistant that generates answers', 'paths': ['src/support/*.py'],
               'class': 'limited', 'generates_content': True, 'disclosure_symbol': 'AI_DISCLOSURE',
               'confirmation': CONFIRMED}

    def test_undecided_cases_are_review_not_pass_and_not_block(self) -> None:
        repo = Repo(self)
        repo.write('src/support/bot.py', ASSISTANT)
        repo.write('tests/test_support.py', ASSISTANT_TEST)
        repo.registry({**self.SUPPORT, 'marking_symbol': 'mark_generated_content'})
        repo.commit('no role')
        report = repo.evaluate()
        self.assertEqual(codes(report), ['AI_ROLE_UNDECLARED'])
        self.assertEqual((report.status, report.decision), ('fail', 'review'))
        self.assertTrue(report.summary.startswith('REVIEW: '))
        fast = repo.evaluate('fast')
        self.assertEqual((fast.status, fast.decision), ('pass', 'review'))
        self.assertEqual(eu_ai_act.decision_of(['AI_SYSTEM_UNREGISTERED: x', 'OBLIGATION_UNMET: y']), 'block')

    def test_roles_select_obligations(self) -> None:
        repo = Repo(self)
        repo.write('src/support/bot.py', ASSISTANT)
        repo.write('tests/test_support.py', ASSISTANT_TEST)
        repo.registry({**self.SUPPORT, 'role': 'deployer', 'publishes_content': True,
                       'publication_disclosure_symbol': 'PUBLISHED_LABEL'})
        repo.commit('deployer that publishes')
        report = repo.evaluate()
        rows = {row['obligation']: row['status'] for row in report.matrix}
        self.assertEqual((rows['AIA-50-1'], rows['AIA-50-2'], rows['AIA-50-4']), ('not_applicable', 'not_applicable', 'unmet'))
        self.assertEqual(report.decision, 'block')
        repo.write('src/support/publish.py', 'PUBLISHED_LABEL = "Generated by AI"\n')
        repo.write('tests/test_publish.py', 'from src.support.publish import PUBLISHED_LABEL\n')
        repo.commit('labelled')
        self.assertEqual(repo.evaluate().status, 'pass')

    def test_art_50_2_waits_for_systems_placed_before_august_2026(self) -> None:
        repo = Repo(self)
        repo.write('src/support/bot.py', ASSISTANT)
        repo.write('tests/test_support.py', ASSISTANT_TEST.replace('mark_generated_content', 'AI_DISCLOSURE'))
        repo.registry({**self.SUPPORT, 'role': 'provider', 'marking_symbol': 'attach_content_credentials',
                       'placed_on_market': '2026-05-01'})
        repo.commit('legacy system, no marking yet')
        report = repo.evaluate()
        self.assertEqual(report.status, 'pass', report.problems)
        self.assertTrue(any('AIA-50-2' in item and '2026-12-02' in item for item in report.upcoming))
        self.assertEqual(repo.evaluate(today=date(2026, 12, 2)).decision, 'block')
        repo.registry({**self.SUPPORT, 'role': 'provider', 'marking_symbol': 'attach_content_credentials',
                       'placed_on_market': '2026-09-01'})
        repo.commit('new system')
        self.assertEqual(repo.evaluate().decision, 'block')

    def test_an_art_50_exemption_needs_a_basis_and_a_person(self) -> None:
        repo = Repo(self)
        repo.write('src/support/bot.py', ASSISTANT)
        repo.write('tests/test_support.py', ASSISTANT_TEST.replace('mark_generated_content', 'AI_DISCLOSURE'))
        exemption = {'obligation': 'AIA-50-2', 'basis': 'Art. 50(2): assistive function for standard editing'}
        repo.registry({**self.SUPPORT, 'role': 'provider', 'exemptions': [exemption]})
        repo.commit('unconfirmed exemption')
        report = repo.evaluate()
        self.assertIn('AI_EXEMPTION_UNCONFIRMED', codes(report))
        self.assertEqual(report.decision, 'block')  # the obligation is still checked and has no evidence
        repo.registry({**self.SUPPORT, 'role': 'provider', 'exemptions': [{**exemption, 'confirmation': CONFIRMED}]})
        repo.commit('confirmed exemption')
        report = repo.evaluate()
        self.assertEqual(report.status, 'pass', report.problems)
        self.assertEqual({row['obligation']: row['status'] for row in report.matrix}['AIA-50-2'], 'exempt')
        repo.registry({**self.SUPPORT, 'role': 'provider', 'marking_symbol': 'mark_generated_content',
                       'exemptions': [{'obligation': 'AIA-5', 'basis': 'not a prohibited practice', 'confirmation': CONFIRMED}]})
        repo.commit('art 5 is not exemptible')
        self.assertIn('AI_EXEMPTION_UNCONFIRMED', codes(repo.evaluate()))

    def test_high_risk_needs_an_annex(self) -> None:
        repo = Repo(self)
        repo.registry({'id': 'scoring', 'purpose': 'Credit scoring of borrowers', 'paths': ['src/scoring/*'],
                       'class': 'high-risk', 'role': 'provider', 'generates_content': False, 'confirmation': CONFIRMED})
        repo.commit('no annex')
        report = repo.evaluate()
        self.assertIn('AI_ANNEX_UNDECLARED', codes(report))
        self.assertTrue(report.upcoming)
        self.assertTrue(all('2027-12-02' in item for item in report.upcoming), report.upcoming)

    def test_the_new_art_5_prohibition_is_drafted(self) -> None:
        self.assertEqual(eu_ai_act.draft_class('Nudify app that undresses people in photos').risk_class, 'prohibited')
        self.assertEqual(eu_ai_act.draft_class('Генератор: интимные изображения без согласия').risk_class, 'prohibited')

    def test_the_example_registry_is_clean_except_for_its_fictional_evidence(self) -> None:
        repo = Repo(self)
        repo.write(eu_ai_act.REGISTRY, (ROOT / '.getzilla/templates/ai-systems.example.json').read_text(encoding='utf-8'))
        repo.commit('example')
        allowed = {'OBLIGATION_UNMET'}
        self.assertLessEqual(set(codes(repo.evaluate())), allowed)


class AuditBundleTests(unittest.TestCase):
    def _bundle_module(self):
        spec = importlib.util.spec_from_file_location('getzilla_audit_bundle_test', ROOT / 'scripts/getzilla_audit_bundle.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_release_decision_needs_met_obligations_and_a_passing_verification_of_this_tree(self) -> None:
        repo = Repo(self)
        repo.write('src/support/bot.py', ASSISTANT)
        repo.write('tests/test_support.py', ASSISTANT_TEST)
        repo.registry({'id': 'support', 'purpose': 'Assistant that generates answers', 'paths': ['src/support/*.py'],
                       'class': 'limited', 'generates_content': True, 'disclosure_symbol': 'AI_DISCLOSURE',
                       'role': 'provider', 'marking_symbol': 'mark_generated_content', 'confirmation': CONFIRMED})
        repo.write('.gitignore', '.getzilla/runtime/\n')
        repo.fresh_matrix(datetime.now(timezone.utc).date())
        repo.commit('release candidate')
        module = self._bundle_module()
        out = repo.root / 'out'
        self.assertEqual(module.main(['--root', str(repo.root), '--base', repo.base, '--out', str(out)]), 1)
        bundle = json.loads(next(out.glob('audit-*.json')).read_text(encoding='utf-8'))
        self.assertEqual(bundle['release_decision'], 'blocked')
        receipts = repo.root / '.getzilla/runtime/receipts/r1'
        receipts.mkdir(parents=True)
        (receipts / 'verification.json').write_text(json.dumps({
            'kind': 'verification', 'status': 'pass', 'tree_fingerprint': tree_fingerprint(repo.root)}), encoding='utf-8')
        self.assertEqual(module.main(['--root', str(repo.root), '--base', repo.base, '--out', str(out)]), 0)
        name = next(out.glob('audit-*.json'))
        bundle = json.loads(name.read_text(encoding='utf-8'))
        self.assertEqual(bundle['release_decision'], 'eligible')
        repo.registry({'id': 'support', 'purpose': 'Assistant that generates answers', 'paths': ['src/support/*.py'],
                       'class': 'limited', 'generates_content': True, 'disclosure_symbol': 'AI_DISCLOSURE',
                       'marking_symbol': 'mark_generated_content', 'confirmation': CONFIRMED})
        repo.commit('role dropped')
        (receipts / 'verification.json').write_text(json.dumps({
            'kind': 'verification', 'status': 'pass', 'tree_fingerprint': tree_fingerprint(repo.root)}), encoding='utf-8')
        self.assertEqual(module.main(['--root', str(repo.root), '--base', repo.base, '--out', str(out)]), 1)
        review = json.loads(next(out.glob(f'audit-{repo.commit_sha()[:12]}.json')).read_text(encoding='utf-8'))
        self.assertEqual(review['release_decision'], 'review')
        self.assertEqual(review['compliance']['eu_ai_act']['decision'], 'review')
        self.assertEqual(bundle['compliance']['eu_ai_act']['status'], 'pass')
        self.assertEqual([item['kind'] for item in bundle['receipts']], ['verification'])
        import hashlib
        recorded = (out / f'{name.name}.sha256').read_text(encoding='utf-8').split()[0]
        self.assertEqual(recorded, hashlib.sha256(name.read_bytes()).hexdigest())


class OptInTests(unittest.TestCase):
    def _installer(self):
        spec = importlib.util.spec_from_file_location('install_into_euaia', ROOT / 'scripts/install_into.py')
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module

    def test_the_component_is_installed_only_on_request(self) -> None:
        installer = self._installer()
        lean = installer.build_payload(ROOT, selection=installer.PayloadSelection(('qwen',)))
        chosen = installer.build_payload(ROOT, selection=installer.PayloadSelection(('qwen',), compliance=('eu-ai-act',)))
        self.assertNotIn(eu_ai_act.OBLIGATIONS, {entry.path for entry in lean})
        self.assertNotIn(eu_ai_act.COMPLIANCE_CONFIG, {entry.path for entry in lean})
        self.assertIn(eu_ai_act.OBLIGATIONS, {entry.path for entry in chosen})
        for path in ('scripts/getzilla_compliance.py', 'scripts/getzilla_audit_bundle.py'):
            self.assertIn(path, {entry.path for entry in lean})
        template = '.getzilla/templates/eu-ai-act/transparency/python/ai_transparency.py'
        self.assertNotIn(template, {entry.path for entry in lean})
        self.assertIn(template, {entry.path for entry in chosen})
        record = next(entry for entry in chosen if entry.path == eu_ai_act.COMPLIANCE_CONFIG)
        self.assertEqual(json.loads(record.content)['enabled'], ['eu-ai-act'])
        self.assertFalse((ROOT / eu_ai_act.COMPLIANCE_CONFIG).exists(), 'the Getzilla source never opts itself in')
        self.assertEqual(installer.component_of(eu_ai_act.OBLIGATIONS), 'compliance:eu-ai-act')

    def test_components_add_installs_the_matrix_and_records_the_opt_in(self) -> None:
        from getzilla.on_demand import ensure_components
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / '.getzilla/getzilla').mkdir(parents=True)
            (project / '.getzilla/getzilla/__init__.py').write_text('', encoding='utf-8')
            self.assertFalse(eu_ai_act.enabled(project))
            ensure_components(project, ['compliance:eu-ai-act'], source=ROOT)
            self.assertTrue(eu_ai_act.enabled(project))
            self.assertTrue((project / '.getzilla/templates/eu-ai-act/transparency/typescript/aiTransparency.ts').is_file())
            ensure_components(project, ['compliance:eu-ai-act'], source=ROOT)
            record = json.loads((project / eu_ai_act.COMPLIANCE_CONFIG).read_text(encoding='utf-8'))
            self.assertEqual(record['enabled'], ['eu-ai-act'])

    def _shell(self, env: dict[str, str], call: str) -> subprocess.CompletedProcess[str]:
        functions = subprocess.run(
            ['sed', '-n', '/^can_ask()/,/^}/p;/^ask()/,/^}/p;/^eu_hint()/,/^}/p;/^choose_eu_ai_act()/,/^}/p',
             str(ROOT / 'scripts/install.sh')], capture_output=True, text=True, check=True).stdout
        return subprocess.run(['bash', '-c', functions + '\n' + call], capture_output=True, text=True,
                              env={'PATH': '/usr/bin:/bin', 'GETZILLA_NONINTERACTIVE': '1', **env})

    @unittest.skipUnless(shutil.which('bash') and shutil.which('sed') and sys.platform != 'win32', 'POSIX shell')
    def test_the_installer_asks_only_on_offline_eu_hints_and_defaults_to_off(self) -> None:
        self.assertEqual(self._shell({'TZ': 'Europe/Berlin'}, 'eu_hint && echo eu').stdout.strip(), 'eu')
        self.assertEqual(self._shell({'TZ': 'Asia/Tokyo', 'LANG': 'de_DE.UTF-8'}, 'eu_hint && echo eu').stdout.strip(), 'eu')
        self.assertEqual(self._shell({'TZ': 'Asia/Tokyo', 'LANG': 'en_US.UTF-8'}, 'eu_hint || echo no').stdout.strip(), 'no')
        self.assertEqual(self._shell({'TZ': 'Europe/Berlin'}, 'choose_eu_ai_act').stdout, '')  # default no
        self.assertEqual(self._shell({'GETZILLA_EU_AI_ACT': '1'}, 'choose_eu_ai_act').stdout, 'eu-ai-act')
        self.assertEqual(self._shell({'GETZILLA_EU_AI_ACT': '0', 'TZ': 'Europe/Paris'}, 'choose_eu_ai_act').stdout, '')
        text = (ROOT / 'scripts/install.sh').read_text(encoding='utf-8')
        hint = text[text.index('eu_hint() {'):text.index('choose_provider() {')]
        self.assertNotRegex(hint, r'curl|wget|ipinfo|geoip|ip-api')

    def test_powershell_installer_has_the_same_offline_opt_in(self) -> None:
        text = (ROOT / 'scripts/install.ps1').read_text(encoding='utf-8-sig')
        hint = text[text.index('function Test-EuHint'):text.index('function Select-Agent')]
        self.assertIn("'n'", hint)
        self.assertNotRegex(hint, r'Invoke-WebRequest|Invoke-RestMethod|ipinfo|geoip|ip-api')
        self.assertIn("'--compliance', $Compliance", text)


if __name__ == '__main__':
    unittest.main()
