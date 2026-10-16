"""C03: a budget contract with a tested limit is required, and the first live run waits for a human."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.change import start_change, transition  # noqa: E402
from getzilla.cost_guard import CONTRACT_NAME, GATE, evaluate, paid_run_resource, write_state  # noqa: E402
from getzilla.human_gates import record_gate_decision  # noqa: E402
from getzilla.policy import evaluate_pre_tool  # noqa: E402
from getzilla.router import build_route  # noqa: E402
from getzilla.spec import validate_schema  # noqa: E402
from getzilla.state import get_active_change, set_active_route  # noqa: E402
from getzilla.util import runtime_dir  # noqa: E402
from tests._support import project_copy  # noqa: E402
from tests.branch_support import git  # noqa: E402

SIGNAL_ROUTE = {'route_id': 'r1', 'risk': 'medium', 'human_gates': [GATE],
                'rationale': ['COST_SIGNAL:automation-platform: test']}
CONTRACT = {'schema_version': 'cost-contract-v1', 'provider': 'Kling via n8n', 'max_calls': 20, 'max_spend_usd_cents': 1500,
            'stop_condition': 'stop after MAX_CALLS generations or the first accepted video',
            'alert': 'email the owner when spend passes 10 USD', 'limit_symbol': 'MAX_CALLS'}
BOUNDED = 'import openai\nMAX_CALLS = 20\nfor _ in range(MAX_CALLS):\n    openai.images.generate(prompt="x")\n'
UNBOUNDED = 'import openai\nwhile True:\n    openai.images.generate(prompt="x")\n'


class CostContractTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = Path(tmp.name)
        git(self.repo, 'init', '-q', '-b', 'main')
        (self.repo / 'README.md').write_text('# x\n', encoding='utf-8')
        git(self.repo, 'add', '-A')
        git(self.repo, 'commit', '-q', '-m', 'base')
        self.base = git(self.repo, 'rev-parse', 'HEAD')
        self.package = self.repo / 'engineering' / 'changes' / 'c1'
        self.package.mkdir(parents=True)

    def commit(self, files: dict[str, str], contract: dict | None = None) -> None:
        for path, text in files.items():
            target = self.repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding='utf-8')
        if contract is not None:
            (self.package / CONTRACT_NAME).write_text(json.dumps(contract), encoding='utf-8')
        git(self.repo, 'add', '-A')
        git(self.repo, 'commit', '-q', '-m', 'change')

    def evaluate(self, mode='pr', route=SIGNAL_ROUTE):
        return evaluate(self.repo, route, mode, [self.base], 'HEAD', self.package)

    def test_signal_without_contract_fails_pr_and_warns_fast(self) -> None:
        self.commit({'gen.py': BOUNDED})
        report = self.evaluate()
        self.assertEqual(report.status, 'fail')
        self.assertTrue(report.problems[0].startswith('COST_CONTRACT_MISSING'))
        fast = self.evaluate('fast')
        self.assertEqual(fast.status, 'pass')
        self.assertTrue(fast.summary.startswith('will fail pr/release'))

    def test_invalid_contract_is_reported(self) -> None:
        self.commit({'gen.py': BOUNDED}, {**CONTRACT, 'max_calls': 0, 'stop_condition': 'stop', 'extra': 1})
        problems = '\n'.join(self.evaluate().problems)
        self.assertIn('max_calls must be a positive integer', problems)
        self.assertIn('stop_condition must say what happens', problems)
        self.assertIn('unknown fields', problems)

    def test_contract_with_tested_limit_passes(self) -> None:
        self.commit({'gen.py': BOUNDED, 'tests/test_gen.py': 'from gen import MAX_CALLS\nassert MAX_CALLS == 20\n'},
                    CONTRACT)
        report = self.evaluate()
        self.assertEqual(report.status, 'pass', report.problems)

    def test_untested_limit_fails(self) -> None:
        self.commit({'gen.py': BOUNDED, 'tests/test_gen.py': 'def test_nothing():\n    assert True\n'}, CONTRACT)
        self.assertTrue(any(p.startswith('COST_BOUND_UNTESTED') for p in self.evaluate().problems))

    def test_unbounded_loop_fails_even_with_a_contract(self) -> None:
        self.commit({'gen.py': UNBOUNDED + 'MAX_CALLS = 20\n', 'tests/test_gen.py': 'MAX_CALLS = 20\n'}, CONTRACT)
        report = self.evaluate(route=None)
        self.assertEqual(report.status, 'fail')
        self.assertTrue(report.problems[0].startswith('UNBOUNDED_PAID_LOOP'))

    def test_nothing_paid_passes_without_contract(self) -> None:
        self.commit({'app.py': 'print(1)\n'})
        self.assertEqual(self.evaluate(route=None).status, 'pass')

    def test_contract_schema(self) -> None:
        schema = json.loads((ROOT / 'schemas' / 'cost-contract-v1.schema.json').read_text(encoding='utf-8'))
        validate_schema(CONTRACT, schema)


class PaidRunGateTests(unittest.TestCase):
    def test_paid_run_detection_ignores_reading(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp)
            write_state(runtime, 'a' * 40, [type('F', (), {'path': 'flows/gen.py'})()])
            self.assertEqual(paid_run_resource('n8n execute --id 7'), 'n8n')
            self.assertEqual(paid_run_resource('curl -s https://api.openai.com/v1/models'), 'api.openai.com')
            self.assertEqual(paid_run_resource('python3 flows/gen.py --live', runtime), 'flows/gen.py')
            self.assertIsNone(paid_run_resource('grep -rn api.openai.com .'))
            self.assertIsNone(paid_run_resource('cat flows/gen.py', runtime))
            self.assertIsNone(paid_run_resource('python3 other.py', runtime))

    def test_live_run_is_blocked_until_a_human_approves_the_exact_resource(self) -> None:
        with project_copy(git=True) as root:
            subprocess.run(['git', 'remote', 'add', 'origin', 'git@github.com:Dimkox/Getzilla.git'], cwd=root, check=True)
            route = build_route(root, 'подключи OpenRouter и гоняй генерацию картинок, пока не получится хорошо', 'paid')
            self.assertIn(GATE, route.human_gates)
            set_active_route(root, route.to_dict())
            state = start_change(root)
            transition(root, state['change_id'], 'scoped', 'package scope prepared')
            command = {'tool_name': 'Bash', 'tool_input': {'command': 'n8n execute --id 7'}}
            allowed, reason = evaluate_pre_tool(root, command)
            self.assertFalse(allowed)
            self.assertIn('paid_run_approval', reason or '')
            with self.assertRaisesRegex(ValueError, 'paid-run decisions require'):
                record_gate_decision(root, GATE, 'approved', 'run it', actor='human', action='paid-run', resource='*')
            record_gate_decision(root, GATE, 'approved', 'one supervised run', actor='human', action='paid-run',
                                 resource='n8n')
            allowed, reason = evaluate_pre_tool(root, command)
            self.assertTrue(allowed, reason)
            other = {'tool_name': 'Bash', 'tool_input': {'command': 'curl https://api.openai.com/v1/images -d "{}"'}}
            self.assertFalse(evaluate_pre_tool(root, other)[0])
            self.assertTrue(get_active_change(root))
            self.assertTrue(runtime_dir(root).is_dir())


if __name__ == '__main__':
    unittest.main()
