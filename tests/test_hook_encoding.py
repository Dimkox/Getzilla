"""Agents exchange UTF-8 JSON with hooks; the console code page (cp1251 on a Russian Windows) must not decide it."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.state import get_active_route  # noqa: E402
from tests._support import project_copy  # noqa: E402

# '✓' has no cp1251 byte: a hook that read or wrote through the code page would lose it.
PROMPT = 'Исправить баг ✓ в обработчике Битрикс D7'


def _hook(root: Path, name: str, payload: dict) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(root / '.grok/hooks' / name)],
        cwd=root,
        input=json.dumps(payload, ensure_ascii=False).encode('utf-8'),
        capture_output=True,
        env={**os.environ, 'PYTHONIOENCODING': 'cp1251', 'PYTHONUTF8': '0'},
        check=False,
        timeout=120,
    )


class HookEncodingTests(unittest.TestCase):
    def test_utf8_prompt_survives_a_legacy_console_encoding(self) -> None:
        with project_copy(git=True) as root:
            (root / 'bitrix').mkdir()
            proc = _hook(root, 'user_prompt_submit.py', {'cwd': str(root), 'prompt': PROMPT, 'session_id': 's1'})
            self.assertEqual(proc.returncode, 0, proc.stderr.decode('utf-8', 'replace'))
            data = json.loads(proc.stdout.decode('utf-8'))
            self.assertIn('ADAPTIVE GROK ROUTE', data['hookSpecificOutput']['additionalContext'])
            self.assertEqual(get_active_route(root)['task'], PROMPT)

    def test_verdict_is_written_as_utf8(self) -> None:
        with project_copy(git=True) as root:
            proc = _hook(root, 'pre_tool_use.py', {
                'cwd': str(root), 'hook_event_name': 'PreToolUse', 'tool_name': 'Bash',
                'tool_input': {'command': 'cat deploy/tls/ключ✓.key'},
            })
            self.assertEqual(proc.returncode, 0, proc.stderr.decode('utf-8', 'replace'))
            data = json.loads(proc.stdout.decode('utf-8'))
            verdict = json.dumps(data, ensure_ascii=False)
            self.assertIn('deny', verdict)
            self.assertIn('ключ✓.key', verdict)


if __name__ == '__main__':
    unittest.main()
