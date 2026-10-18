from __future__ import annotations

import sys
import subprocess
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.change import start_change, transition
from getzilla.human_gates import gate_block_reason, gate_statuses, record_gate_decision
from getzilla.policy import evaluate_pre_tool
from getzilla.router import build_route
from getzilla.state import add_approval, set_active_route
from tests._support import project_copy


class HumanGateTests(unittest.TestCase):
    def _active_change(self, root: Path, gates: list[str]):
        subprocess.run(
            ['git', 'remote', 'add', 'origin', 'git@github.com:Dimkox/Getzilla.git'],
            cwd=root,
            check=True,
        )
        route = build_route(root, 'Prepare production release and canary', 'gate-test').to_dict()
        route['human_gates'] = gates
        set_active_route(root, route)
        state = start_change(root)
        transition(root, state['change_id'], 'scoped', 'package scope prepared')
        return state

    def test_external_gate_aggregate_is_not_approved_when_any_target_is_rejected(self) -> None:
        with project_copy(git=True) as root:
            self._active_change(root, ['migration_or_external_write_approval'])
            first = 'https://api.example.test/v1/first'
            second = 'https://api.example.test/v1/second'
            for target, decision in ((first, 'approved'), (second, 'rejected')):
                record_gate_decision(
                    root,
                    'migration_or_external_write_approval',
                    decision,
                    f'{decision} this exact endpoint',
                    actor='human',
                    action='external-write',
                    resource=target,
                )

            status = gate_statuses(root)[0]
            self.assertEqual(status['state'], 'rejected')
            self.assertEqual(
                {item['state'] for item in status['targets']},
                {'approved', 'rejected'},
            )
            self.assertIn('every listed exact target', status['reason'])

    def test_revised_gate_decisions_are_append_only_and_latest_decision_is_current(self) -> None:
        with project_copy(git=True) as root:
            self._active_change(root, ['production_action_approval'])
            for decision, reason in (('approved', 'initial approval'), ('rejected', 'withdraw approval')):
                record_gate_decision(
                    root,
                    'production_action_approval',
                    decision,
                    reason,
                    actor='human',
                    action='git-push-branch',
                )

            status = gate_statuses(root)[0]
            self.assertEqual(status['state'], 'rejected')
            self.assertEqual(
                [item['decision'] for item in status['targets'][0]['decision_history']],
                ['approved', 'rejected'],
            )

    def test_missing_or_malformed_decision_is_reported_and_fails_closed(self) -> None:
        with project_copy(git=True) as root:
            state = self._active_change(root, ['production_action_approval'])
            status = gate_statuses(root)[0]
            self.assertEqual(status['state'], 'pending')
            self.assertEqual(status['evidence_path'], f"engineering/changes/{state['change_id']}/human-gates.json")

            package = root / 'engineering/changes' / state['change_id']
            (package / 'human-gates.json').write_text('{ malformed', encoding='utf-8')
            self.assertEqual(gate_statuses(root)[0]['state'], 'invalid')

    def test_status_cli_reports_every_gate_as_local_workflow_evidence(self) -> None:
        with project_copy(git=True) as root:
            self._active_change(root, ['scope_and_design_approval', 'production_action_approval'])
            proc = subprocess.run(
                [sys.executable, str(ROOT / 'scripts/getzilla_status.py')],
                cwd=root,
                text=True,
                capture_output=True,
                check=True,
            )
            result = json.loads(proc.stdout)
            self.assertEqual(
                [(item['gate'], item['state']) for item in result['human_gates']],
                [('scope_and_design_approval', 'pending'), ('production_action_approval', 'pending')],
            )
            self.assertTrue(all(item['evidence_path'].endswith('/human-gates.json') for item in result['human_gates']))
            self.assertFalse(result['human_gates'][0]['local_workflow_evidence_only'] is False)
            self.assertIn('not cryptographic identity', result['human_gate_notice'])

    def test_gate_decision_cli_requires_explicit_target_and_reports_local_evidence(self) -> None:
        with project_copy(git=True) as root:
            state = self._active_change(root, ['production_action_approval'])
            proc = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / 'scripts/getzilla_gate.py'),
                    'decide',
                    'production_action_approval',
                    'approved',
                    '--action',
                    'git-push-branch',
                    '--reason',
                    'Approve only the named branch action',
                    '--actor',
                    'operator',
                ],
                cwd=root,
                text=True,
                capture_output=True,
                check=True,
            )
            result = json.loads(proc.stdout)
            self.assertEqual(result['decision']['change_id'], state['change_id'])
            self.assertEqual(result['decision']['action'], 'git-push-branch')
            self.assertTrue(result['local_workflow_evidence_only'])
            self.assertFalse(result.get('external_trust_ci_authority', False))

    # Owner decision 2026-10-18: gates are flags for transitions and actions; only paid runs block.
    def test_open_scope_gate_is_a_flag_on_the_transition_not_a_block(self) -> None:
        with project_copy(git=True) as root:
            state = self._active_change(root, ['scope_and_design_approval'])
            self.assertEqual(gate_statuses(root)[0]['state'], 'pending')
            result = transition(root, state['change_id'], 'approved', 'approve implementation')
            self.assertEqual(result['status'], 'approved')
            self.assertEqual(result['history'][-1]['open_human_gates'], ['scope_and_design_approval: pending'])

    def test_rejected_and_stale_decisions_stay_visible_as_flags(self) -> None:
        with project_copy(git=True) as root:
            state = self._active_change(root, ['scope_and_design_approval'])
            record_gate_decision(root, 'scope_and_design_approval', 'rejected', 'Needs revision', actor='human')
            self.assertEqual(gate_statuses(root)[0]['state'], 'rejected')
            record_gate_decision(root, 'scope_and_design_approval', 'approved', 'Revised scope accepted', actor='human')
            (root / 'engineering/changes' / state['change_id'] / 'requirements.md').write_text('changed scope\n', encoding='utf-8')
            self.assertEqual(gate_statuses(root)[0]['state'], 'stale')
            result = transition(root, state['change_id'], 'approved', 'scope changed after approval')
            self.assertEqual(result['history'][-1]['open_human_gates'], ['scope_and_design_approval: stale'])

    def test_an_approved_gate_leaves_no_flag(self) -> None:
        with project_copy(git=True) as root:
            state = self._active_change(root, ['scope_and_design_approval'])
            record_gate_decision(root, 'scope_and_design_approval', 'approved', 'Scope and design reviewed', actor='human')
            result = transition(root, state['change_id'], 'approved', 'approve implementation')
            self.assertNotIn('open_human_gates', result['history'][-1])

    def test_production_and_external_write_gates_never_block_actions(self) -> None:
        with project_copy(git=True) as root:
            self._active_change(root, ['production_action_approval', 'migration_or_external_write_approval'])
            self.assertIsNone(gate_block_reason(root, 'production', 'git-push-branch'))
            self.assertIsNone(gate_block_reason(root, 'external-write', 'external-write', None))
            # The exact local grant stays an independent control of the push itself.
            command = {'tool_name': 'Bash', 'tool_input': {'command': 'git push origin feature'}}
            allowed, reason = evaluate_pre_tool(root, command)
            self.assertFalse(allowed)
            self.assertIn('exact delegated local grant', reason or '')
            add_approval(root, 'production', 'ship', 5, actions=['git-push-branch'], resources=['feature'])
            allowed, reason = evaluate_pre_tool(root, command)
            self.assertTrue(allowed, reason)

    def test_the_first_live_paid_run_still_needs_the_human_decision(self) -> None:
        with project_copy(git=True) as root:
            self._active_change(root, ['paid_run_approval'])
            self.assertIn('requires an exact paid-run resource', gate_block_reason(root, 'paid-run', 'paid-run', None) or '')
            self.assertIn('paid_run_approval', gate_block_reason(root, 'paid-run', 'paid-run', 'n8n:workflow-42') or '')
            record_gate_decision(root, 'paid_run_approval', 'approved', 'First live run approved', actor='human',
                                 action='paid-run', resource='n8n:workflow-42')
            self.assertIsNone(gate_block_reason(root, 'paid-run', 'paid-run', 'n8n:workflow-42'))


if __name__ == '__main__':
    unittest.main()
