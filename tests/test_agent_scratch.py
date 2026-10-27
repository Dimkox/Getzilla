"""Agent working files in .getzilla/runtime/scratch/ need no grant; runtime authority state stays protected."""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.policy import evaluate_pre_tool  # noqa: E402
from tests._support import project_copy  # noqa: E402


def bash(command: str) -> dict:
    return {'tool_name': 'Bash', 'tool_input': {'command': command}}


def write(root: Path, rel: str) -> dict:
    return {'tool_name': 'Write', 'tool_input': {'file_path': str(root / rel), 'content': 'x\n'}}


class AgentScratchTests(unittest.TestCase):
    def test_scratch_writes_need_no_grant(self) -> None:
        with project_copy(git=True) as root:
            for event in (write(root, '.getzilla/runtime/scratch/bundle/notes.md'),
                          bash('python3 -c pass > .getzilla/runtime/scratch/bundle/selection.json'),
                          bash('cp README.md .getzilla/runtime/scratch/readme-copy.md')):
                with self.subTest(event=str(event)[:80]):
                    allowed, reason = evaluate_pre_tool(root, event)
                    self.assertTrue(allowed, reason)

    def test_runtime_authority_state_stays_protected_with_a_hint(self) -> None:
        with project_copy(git=True) as root:
            for rel in ('.getzilla/runtime/receipts/r1/verification.json', '.getzilla/runtime/active-route.json',
                        '.getzilla/runtime/scratch/../receipts/x.json', '.getzilla/runtime/bundle/selection.json'):
                with self.subTest(rel=rel):
                    allowed, reason = evaluate_pre_tool(root, write(root, rel))
                    self.assertFalse(allowed)
                    self.assertIn('.getzilla/runtime/scratch/', reason or '')
            allowed, reason = evaluate_pre_tool(root, bash('echo {} > .getzilla/runtime/active-route.json'))
            self.assertFalse(allowed)
            self.assertIn('scratch', reason or '')

    def test_a_reviewer_copy_in_scratch_can_be_checked_out_and_edited(self) -> None:
        # #183: a mutation probe edits `.getzilla/getzilla/...` inside its own copy in scratch.
        with project_copy(git=True) as root:
            copy = '.getzilla/runtime/scratch/review-1'
            (root / copy / '.getzilla/getzilla').mkdir(parents=True)
            for event in (write(root, f'{copy}/.getzilla/getzilla/policy.py'),
                          bash(f'git -C {copy} checkout -q HEAD'),
                          bash(f'cd {copy} && git checkout -q HEAD'),
                          bash(f'git -C {root / copy} checkout -q HEAD'),
                          bash(f'rm -rf {copy}')):
                with self.subTest(event=str(event)[:90]):
                    allowed, reason = evaluate_pre_tool(root, event)
                    self.assertTrue(allowed, reason)
            for command in (f'git -C {copy} checkout -q HEAD -- .getzilla/getzilla/policy.py && git checkout -- .grok/hooks',
                            'git checkout -q HEAD -- .getzilla/runtime/scratch/../../getzilla/policy.py',
                            # Security review of #183: the target set by another option or a list file.
                            f'git -C {copy} --work-tree=. checkout -q HEAD -- .grok/hooks/_lib.py',
                            f'git --git-dir={copy}/.git --work-tree=. checkout -q HEAD -- .grok',
                            f'git -C {copy} checkout-index -a --prefix=../../../../',
                            f'xargs -a {copy}/list rm -f',
                            f'cd {copy} && rm -rf .getzilla/getzilla',
                            f'GIT_WORK_TREE=. git -C {copy} checkout -q HEAD -- .grok'):
                with self.subTest(command=command):
                    allowed, _ = evaluate_pre_tool(root, bash(command))
                    self.assertFalse(allowed, 'a live control-plane path next to scratch stays refused')

    def test_a_symlink_out_of_scratch_is_still_protected(self) -> None:
        with project_copy(git=True) as root:
            scratch = root / '.getzilla' / 'runtime' / 'scratch'
            scratch.mkdir(parents=True)
            (root / '.getzilla' / 'runtime' / 'receipts').mkdir(parents=True, exist_ok=True)
            os.symlink('../receipts', scratch / 'escape')
            allowed, _ = evaluate_pre_tool(root, write(root, '.getzilla/runtime/scratch/escape/x.json'))
            self.assertFalse(allowed)


if __name__ == '__main__':
    unittest.main()
