"""New delivery evidence does not require a second source commit."""
from __future__ import annotations
import json
import subprocess
import sys
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla.change import start_change, transition
from getzilla.review_source import review_source_binding
from getzilla.router import build_route
from getzilla.state import get_active_change
from tests._support import activate_owned_route
from tests._support import project_copy

class DeliverySequenceTests(unittest.TestCase):
    def test_delivery_guidance_reconciles_committed_diff_before_review_dispatch(self):
        text = (ROOT / '.agents/skills/getzilla-delivery/SKILL.md').read_text()
        self.assertIn('getzilla_route.py --reconcile', text)
        self.assertIn('--add-reviewer test_reviewer', text)
        self.assertIn('one ordinary code review', text)
        self.assertIn('category and risk threshold', text)
        reviewer = (ROOT / '.grok/agents/code_reviewer.md').read_text()
        self.assertIn('test adequacy', reviewer)

    def test_runtime_reports_and_ready_state_preserve_reviewed_source_identity(self):
        with project_copy(git=True) as root:
            route = build_route(root, 'Fix a bounded feature', 'sequence').to_dict()
            activate_owned_route(root, route)
            state = start_change(root)
            package = root / get_active_change(root)['path']
            report = package / 'evidence/code-review.md'
            report.write_text('Independent review.\n')
            head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
            binding = review_source_binding(root, head, report.relative_to(root).as_posix())
            for target in ('scoped', 'approved', 'implementing', 'verifying', 'reviewing', 'ready'):
                transition(root, state['change_id'], target, 'sequence test')
            self.assertEqual(binding, review_source_binding(root, head, report.relative_to(root).as_posix()))
            self.assertEqual(subprocess.check_output(['git', 'status', '--porcelain'], cwd=root, text=True), '')
            self.assertEqual(json.loads((package / 'state.json').read_text())['status'], 'ready')

    def test_transition_copies_legacy_package_before_writing(self):
        with project_copy(git=True) as root:
            route = build_route(root, 'Fix a bounded feature', 'legacy').to_dict()
            activate_owned_route(root, route)
            state = start_change(root)
            runtime = root / get_active_change(root)['path']
            legacy = root / 'engineering/changes' / state['change_id']
            legacy.parent.mkdir(parents=True, exist_ok=True)
            runtime.rename(legacy)
            before = (legacy / 'state.json').read_bytes()
            from getzilla.state import set_active_change
            set_active_change(root, {'change_id': state['change_id'], 'path': legacy.relative_to(root).as_posix()})
            transition(root, state['change_id'], 'scoped', 'new runtime state')
            self.assertEqual((legacy / 'state.json').read_bytes(), before)
            self.assertEqual(json.loads((runtime / 'state.json').read_text())['status'], 'scoped')
