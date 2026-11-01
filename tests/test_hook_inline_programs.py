"""Interpreter code given inline must fail closed (security review of quote-aware parsing)."""
from __future__ import annotations

import contextlib
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.router import build_route
from tests._support import activate_owned_route
from tests._support import project_copy, run_hook

INLINE_PROGRAMS = (
    "python3 -c 'print(1)'",
    "python3 -Bc 'print(1)'",
    "python3.12 -I -c 'print(1)'",
    "pypy3 -c 'print(1)'",
    'python3 -',
    "python3 - <<'PY'\nprint(1)\nPY",
    "python3 <<'PY'\nimport os\nPY",
    "python3 <<< 'import os'",
    "python3 -c \"import subprocess; subprocess.run(['git', 'push', 'origin', 'main'])\"",
    "python3 -c \"import os; os.system('rm -rf engineering')\"",
    "nice -n 5 python3 -c 'print(1)'",
    "timeout 5 python3 -c 'print(1)'",
    "printf x; python3 -c 'print(1)'",
    "printf x && node -e 'console.log(1)'",
    "sh -c \"python3 -c 'print(1)'\"",
    "node -e 'require(\"child_process\").execSync(\"git push\")'",
    'node --eval=1',
    'node -p 1',
    'bun -e 1',
    "deno eval 'console.log(1)'",
    "perl -e 'system(\"git push\")'",
    "perl -ne 'print' VERSION",
    "ruby -e 'puts 1'",
    "php -r 'echo 1;'",
    "awk 'BEGIN { system(\"git push\") }'",
    "awk '{ print | \"sh\" }' VERSION",
    "gawk -e 'BEGIN { \"id\" | getline x }'",
)

FILE_PROGRAMS = (
    'python3 -B scripts/getzilla_route.py --show',
    'python3 scripts/getzilla_status.py',
    'python3 -m json.tool VERSION',
    'python3 --version',
    'node --version',
    "awk '{print $1}' VERSION",
    "awk -F'|' '{print $1}' VERSION",
    'lscpu; nproc --all; nproc; taskset -pc $$',
)


class InlineProgramTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.stack = contextlib.ExitStack()
        cls.root = cls.stack.enter_context(project_copy(git=True))
        activate_owned_route(cls.root, build_route(cls.root, 'Review inline interpreter handling', 'inline').to_dict())

    @classmethod
    def tearDownClass(cls) -> None:
        cls.stack.close()

    def verdict(self, command: str) -> dict:
        _, result, error = run_hook(self.root, 'pre_tool_use.py', {
            'cwd': str(self.root),
            'session_id': self.id() + hashlib.sha256(command.encode()).hexdigest(),
            'tool_name': 'exec_command',
            'tool_input': {'cmd': command, 'workdir': str(self.root)},
        })
        self.assertFalse(error, error)
        return result

    def test_inline_interpreter_code_is_denied(self) -> None:
        for command in INLINE_PROGRAMS:
            with self.subTest(command=command):
                result = self.verdict(command)
                self.assertEqual(result.get('decision'), 'deny', result)

    def test_script_files_modules_and_plain_tools_stay_allowed(self) -> None:
        for command in FILE_PROGRAMS:
            with self.subTest(command=command):
                result = self.verdict(command)
                self.assertEqual(result.get('decision', 'allow'), 'allow', result)

    def test_denial_names_the_inline_program_stage(self) -> None:
        command = "python3 -c 'import os; print(os.getcwd())'"
        self.assertEqual(self.verdict(command)['decision'], 'deny')
        ledger = json.loads((self.root / '.getzilla/runtime/tool-denials.json').read_text())
        digest = hashlib.sha256(command.encode()).hexdigest()
        entry = next(row for row in ledger['exact'].values() if row['command_sha256'] == digest)
        self.assertEqual(entry['root_failure_sources'], ['command.inline-program'])


if __name__ == '__main__':
    unittest.main()
