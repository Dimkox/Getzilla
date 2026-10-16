"""Getzilla CLIs write UTF-8 to pipes whatever the console code page (cp1251 on a Russian Windows)."""
from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CliUtf8Tests(unittest.TestCase):
    def test_redirected_output_is_utf8_whatever_the_code_page(self) -> None:
        code = ("import sys, getzilla; print('\u2192 \u041e\u0431\u0437\u043e\u0440'); "
                "print('\u2192', file=sys.stderr); print(sys.stderr.errors)")
        proc = subprocess.run(
            [sys.executable, '-c', code], capture_output=True, check=False, timeout=60,
            env={**os.environ, 'PYTHONIOENCODING': 'cp1251', 'PYTHONUTF8': '0',
                 'PYTHONPATH': str(ROOT / '.getzilla')},
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.decode('utf-8').split(), ['\u2192', '\u041e\u0431\u0437\u043e\u0440', 'backslashreplace'])
        self.assertEqual(proc.stderr.decode('utf-8').strip(), '\u2192')


if __name__ == '__main__':
    unittest.main()
