"""An ambiguous-root denial tells the agent what to run instead."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from tests._support import project_copy, run_hook  # noqa: E402


class RootHintTests(unittest.TestCase):
    def _decide(self, root: Path, session: str, tool: str, tool_input: dict) -> dict:
        _, data, error = run_hook(root, 'pre_tool_use.py', {
            'cwd': str(root), 'session_id': session, 'tool_name': tool, 'tool_input': tool_input,
        })
        self.assertIsInstance(data, dict, error)
        return data

    def test_denials_name_the_way_out(self) -> None:
        cases = (
            ('python3 -c "print(1)"', '.getzilla/runtime/scratch/<name>.py'),
            ("php -r 'echo 1;'", '.getzilla/runtime/scratch/<name>.py'),
            ('python3 - <<EOF\nprint(1)\nEOF', '.getzilla/runtime/scratch/<name>.py'),
            ('cd $(git rev-parse --show-toplevel) && git status', 'literal path'),
            ('git log | head', 'Split pipes'),
        )
        with project_copy(git=True) as root:
            for index, (command, hint) in enumerate(cases):
                with self.subTest(command=command):
                    data = self._decide(root, f'root-hint-{index}', 'Bash', {'command': command})
                    self.assertEqual(data['decision'], 'deny', data)
                    self.assertIn('root resolution status is ambiguous-command-root', data['reason'])
                    self.assertIn(hint, data['reason'])

    def test_the_suggested_scratch_script_is_allowed(self) -> None:
        with project_copy(git=True) as root:
            script = root / '.getzilla/runtime/scratch/probe.py'
            data = self._decide(root, 'root-hint-write', 'Write', {'file_path': str(script), 'content': 'print(1)\n'})
            self.assertNotEqual(data.get('decision'), 'deny', data)
            data = self._decide(root, 'root-hint-run', 'Bash', {'command': 'python3 .getzilla/runtime/scratch/probe.py'})
            self.assertNotEqual(data.get('decision'), 'deny', data)

    def test_agent_instructions_mention_the_scratch_script(self) -> None:
        for rel in ('AGENTS.md', '.getzilla/templates/consumer-AGENTS.md.tmpl'):
            with self.subTest(rel=rel):
                text = (ROOT / rel).read_text(encoding='utf-8')
                self.assertIn('python3 -c', text)
                self.assertIn('.getzilla/runtime/scratch/<name>.py', text)


if __name__ == '__main__':
    unittest.main()
