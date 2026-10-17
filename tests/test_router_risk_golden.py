"""H01: prompt risk golden table — payments, login and paid loops are never 'low'; harmless words stay low."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.router import _has_term, build_route  # noqa: E402

GOLDEN = json.loads((ROOT / 'tests' / 'fixtures' / 'router' / 'risk-golden.json').read_text(encoding='utf-8'))
ORDER = {'low': 0, 'medium': 1, 'high': 2}


class RouterRiskGoldenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.project = Path(cls.tmp.name)
        (cls.project / 'app.py').write_text('print(1)\n', encoding='utf-8')
        subprocess.run(['git', 'init', '-q', str(cls.project)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def test_golden_prompts(self) -> None:
        for case in GOLDEN['cases']:
            with self.subTest(prompt=case['prompt']):
                route = build_route(self.project, case['prompt'])
                if 'risk' in case:
                    self.assertEqual(route.risk, case['risk'])
                if 'min_risk' in case:
                    self.assertGreaterEqual(ORDER[route.risk], ORDER[case['min_risk']])
                if 'complexity' in case:
                    self.assertEqual(route.complexity, case['complexity'])

    def test_stem_terms_match_inflections_only_from_word_start(self) -> None:
        self.assertTrue(_has_term('обработка оплаты', 'оплат*'))
        self.assertTrue(_has_term('Оплату картой', 'оплат*'))
        self.assertFalse(_has_term('переоплата', 'оплат*'))
        self.assertTrue(_has_term('номера карт клиентов', 'номер* карт*'))
        self.assertFalse(_has_term('номер банковской карты', 'номер* карт*'))  # tokens must be adjacent
        self.assertFalse(_has_term('логотип', 'логин*'))

    def test_plain_terms_keep_whole_word_matching(self) -> None:
        self.assertFalse(_has_term('новый продукт', 'прод'))
        self.assertTrue(_has_term('drop table users', 'drop table'))


if __name__ == '__main__':
    unittest.main()
