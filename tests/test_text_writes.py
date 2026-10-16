"""Product text I/O names its newline and encoding (Windows defaults: CRLF and the ANSI code page)."""
from __future__ import annotations

import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRODUCT = [*sorted((ROOT / '.getzilla/getzilla').rglob('*.py')), *sorted((ROOT / 'scripts').glob('*.py')),
           *sorted((ROOT / '.grok/hooks').glob('*.py'))]


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

    def test_text_reads_always_name_an_encoding(self) -> None:
        offenders = []
        for path in PRODUCT:
            tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                keywords = {keyword.arg for keyword in node.keywords}
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr == 'read_text':
                    named = 'encoding' in keywords or bool(node.args)
                elif isinstance(func, ast.Name) and func.id == 'open':
                    mode = node.args[1] if len(node.args) > 1 else next(
                        (keyword.value for keyword in node.keywords if keyword.arg == 'mode'), None)
                    if isinstance(mode, ast.Constant) and 'b' in str(mode.value):
                        continue
                    named = 'encoding' in keywords or len(node.args) > 3
                else:
                    continue
                if not named:
                    offenders.append(f'{path.relative_to(ROOT).as_posix()}:{node.lineno}')
        self.assertEqual(offenders, [], 'text read without encoding= decodes the ANSI code page on Windows')


if __name__ == '__main__':
    unittest.main()
