"""H01: English base vocabulary, translated language packs, and no 'low' for a prompt nobody can read."""
from __future__ import annotations

import contextlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla'), str(ROOT / 'scripts')]

from getzilla import router  # noqa: E402
from getzilla.risk_terms import (  # noqa: E402
    DEFAULT_DIR, RiskTermsError, check_packs, load_vocabulary, scaffold, uncovered_script,
)
import getzilla_risk_terms  # noqa: E402


def copy_packs(target: Path) -> Path:
    shutil.copytree(DEFAULT_DIR, target)
    return target


class RiskTermPackTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        load_vocabulary.cache_clear()
        self.addCleanup(load_vocabulary.cache_clear)

    def test_repository_packs_are_complete(self) -> None:
        self.assertEqual(check_packs(), [])
        vocabulary = load_vocabulary()
        self.assertEqual(vocabulary.languages[0], 'en')
        self.assertIn('ru', vocabulary.languages)
        self.assertTrue({'LATIN', 'CYRILLIC'} <= vocabulary.scripts)

    def test_missing_translation_and_bad_terms_are_reported(self) -> None:
        packs = copy_packs(self.base / 'packs')
        ru = json.loads((packs / 'ru.json').read_text(encoding='utf-8'))
        del ru['terms']['payment']
        ru['terms']['refund'] = ['воз*врат']
        ru['terms']['no-such-id'] = ['x']
        (packs / 'ru.json').write_text(json.dumps(ru, ensure_ascii=False), encoding='utf-8')
        (packs / 'de.json').write_text(json.dumps({**ru, 'lang': 'fr'}), encoding='utf-8')
        problems = '\n'.join(check_packs(packs))
        self.assertIn('ru.json:payment: missing translation', problems)
        self.assertIn('ru.json:refund: "*" is allowed only at the end of a word', problems)
        self.assertIn('ru.json:no-such-id: not a base term id', problems)
        self.assertIn('de.json: lang must equal the file name', problems)
        with self.assertRaises(RiskTermsError):
            load_vocabulary(packs)

    def test_agent_translated_pack_extends_the_vocabulary(self) -> None:
        packs = copy_packs(self.base / 'packs')
        pack = scaffold('de', 'latin', packs)
        self.assertEqual(set(pack['terms']), set(pack['hints']))
        self.assertNotIn('api', pack['terms'])  # neutral terms need no translation
        self.assertTrue(all(value == [] for value in pack['terms'].values()))
        (packs / 'de.json').write_text(json.dumps(pack), encoding='utf-8')
        self.assertTrue(any('de.json:payment: missing translation' in p for p in check_packs(packs)))
        pack['terms'] = {term_id: [f'de-{term_id}'] for term_id in pack['terms']}
        pack['terms']['payment'] = ['zahlung*', 'bezahl*']
        (packs / 'de.json').write_text(json.dumps(pack), encoding='utf-8')
        self.assertEqual(check_packs(packs), [])
        vocabulary = load_vocabulary(packs)
        self.assertIn('zahlung*', vocabulary.high)
        self.assertTrue(router._has_term('die Zahlungen schlagen fehl', 'zahlung*'))

    def test_uncovered_script_is_detected(self) -> None:
        vocabulary = load_vocabulary()
        self.assertEqual(uncovered_script('修复支付流程中的错误', vocabulary), 'CJK')
        self.assertEqual(uncovered_script('إصلاح عملية الدفع', vocabulary), 'ARABIC')
        self.assertIsNone(uncovered_script('почини оплату', vocabulary))
        self.assertIsNone(uncovered_script('fix the payment flow in 支付 module please', vocabulary))
        self.assertIsNone(uncovered_script('ok', vocabulary))

    def test_unreadable_prompt_is_never_low(self) -> None:
        project = self.base / 'project'
        project.mkdir()
        subprocess.run(['git', 'init', '-q', str(project)], check=True, capture_output=True)
        route = router.build_route(project, '修复支付流程中的错误')
        self.assertEqual(route.risk, 'medium')
        self.assertTrue(any(reason.startswith('PROMPT_LANGUAGE_NOT_COVERED:CJK') for reason in route.rationale))
        with mock.patch.object(router, 'load_vocabulary', side_effect=RiskTermsError('broken')):
            broken = router.build_route(project, 'исправь опечатку в README')
        self.assertEqual(broken.risk, 'medium')

    def test_cli_check_and_scaffold(self) -> None:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(getzilla_risk_terms.main(['check']), 0)
        self.assertTrue(json.loads(out.getvalue())['ok'])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(getzilla_risk_terms.main(['scaffold', '--lang', 'en', '--script', 'LATIN']), 2)
            target = self.base / 'zh.json'
            self.assertEqual(getzilla_risk_terms.main(['scaffold', '--lang', 'zh', '--script', 'CJK',
                                                       '--output', str(target)]), 0)
            self.assertEqual(getzilla_risk_terms.main(['scaffold', '--lang', 'zh', '--script', 'CJK',
                                                       '--output', str(target)]), 2)
        self.assertEqual(json.loads(target.read_text(encoding='utf-8'))['script'], 'CJK')


if __name__ == '__main__':
    unittest.main()
