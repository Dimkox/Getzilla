"""Product code must control newlines when it writes text (CRLF on Windows breaks digests)."""
from __future__ import annotations

import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRODUCT = [*sorted((ROOT / '.getzilla/getzilla').rglob('*.py')), *sorted((ROOT / 'scripts').glob('*.py'))]


class TextWriteTests(unittest.TestCase):
    def test_write_text_always_names_a_newline(self) -> None:
        offenders = []
        for path in PRODUCT:
            tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == 'write_text'
                        and not any(keyword.arg == 'newline' for keyword in node.keywords)):
                    offenders.append(f'{path.relative_to(ROOT).as_posix()}:{node.lineno}')
        self.assertEqual(offenders, [], 'write_text without newline= writes CRLF on Windows')


if __name__ == '__main__':
    unittest.main()
