"""#78: a missing or broken mandatory control refuses protected actions; it is never taken as permission."""
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.hook_health import degraded_events  # noqa: E402
from tests._support import project_copy, run_hook  # noqa: E402

PROTECTED = (
    ('Bash', {'command': 'git push origin main'}),
    ('Bash', {'command': 'git -C . push --force origin HEAD'}),
    ('Bash', {'command': 'gh pr merge 7 --squash'}),
    ('Bash', {'command': 'npm publish'}),
    ('Bash', {'command': 'rm -rf build'}),
    ('Bash', {'command': 'printf x >> AGENTS.md'}),
    ('Bash', {'command': 'cp evil.py .grok/hooks/pre_tool_use.py'}),
    ('exec_command', {'cmd': 'terraform destroy'}),
    ('Write', {'file_path': '.getzilla/config/policy.json', 'content': '{}'}),
    ('Edit', {'file_path': 'AGENTS.md', 'old_string': 'a', 'new_string': 'b'}),
)
ORDINARY = (
    ('Bash', {'command': 'ls'}),
    ('Bash', {'command': 'git status --short'}),
    ('Bash', {'command': 'cat AGENTS.md'}),
    ('Read', {'file_path': 'AGENTS.md'}),
    ('Write', {'file_path': 'src/app.py', 'content': 'x = 1\n'}),
)


def decision(root: Path, tool: str, tool_input: dict) -> str:
    code, data, stderr = run_hook(root, 'pre_tool_use.py', {'cwd': str(root), 'session_id': 'degraded',
                                                             'tool_name': tool, 'tool_input': tool_input})
    assert code == 0, stderr
    return data.get('decision') or (data.get('hookSpecificOutput') or {}).get('permissionDecision') or 'allow'


class DegradedFailClosedTests(unittest.TestCase):
    def test_broken_fixture_policy_is_not_hidden_by_parent_pythonpath(self) -> None:
        with project_copy() as root:
            (root / '.getzilla/getzilla/policy.py').write_text(
                'raise ImportError("fixture policy broken")\n', encoding='utf-8',
            )
            polluted = os.pathsep.join(str(path) for path in (ROOT, ROOT / 'tests', ROOT / '.getzilla'))
            with mock.patch.dict(os.environ, {'PYTHONPATH': polluted}):
                code, data, err = run_hook(root, 'pre_tool_use.py', {
                    'cwd': str(root), 'tool_name': 'Bash', 'tool_input': {'command': 'ls'},
                })
                self.assertEqual(code, 0, err)
                self.assertEqual(data.get('decision'), 'allow')
                code, data, err = run_hook(root, 'pre_tool_use.py', {
                    'cwd': str(root), 'tool_name': 'Bash', 'tool_input': {'command': 'git push origin main'},
                })
                self.assertEqual(code, 0, err)
                self.assertEqual(data.get('decision'), 'deny')
            events = degraded_events(root)
            self.assertEqual(len(events), 2)
            for event in events:
                self.assertEqual(event['kind'], 'HOOK_DEGRADED')
                self.assertEqual(event['hook'], 'pre_tool_use')
                self.assertIn('fixture policy broken', event['error'])

    def _check(self, breakage: str, content: str) -> None:
        with project_copy() as root:
            (root / breakage).write_text(content, encoding='utf-8')
            for tool, tool_input in PROTECTED:
                with self.subTest(breakage=breakage, tool=tool, tool_input=tool_input):
                    self.assertEqual(decision(root, tool, tool_input), 'deny')
            for tool, tool_input in ORDINARY:
                with self.subTest(breakage=breakage, tool=tool, tool_input=tool_input):
                    self.assertEqual(decision(root, tool, tool_input), 'allow')
            events = [json.loads(line) for line in
                      (root / '.getzilla/runtime/hook-events.jsonl').read_text(encoding='utf-8').splitlines()]
            self.assertTrue(events and all(event['kind'] == 'HOOK_DEGRADED' for event in events))

    def test_policy_that_does_not_import(self) -> None:
        self._check('.getzilla/getzilla/policy.py', 'raise ImportError("broken on purpose")\n')

    def test_helper_library_that_does_not_import(self) -> None:
        self._check('.getzilla/getzilla/fsx.py', 'raise RuntimeError("fsx broken")\n')


if __name__ == '__main__':
    unittest.main()
