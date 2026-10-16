"""E02: a hook that fails open still lets the agent work, but it is recorded and high risk cannot pass with it."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla import verification  # noqa: E402
from getzilla.hook_health import degraded_events, events_path, route_degraded_events  # noqa: E402
from getzilla.router import build_route  # noqa: E402
from getzilla.state import get_active_route, set_active_route  # noqa: E402
from tests._support import project_copy, run_hook  # noqa: E402

BASH = {'tool_name': 'Bash', 'tool_input': {'command': 'ls'}}


def write_event(root: Path, ts: str, hook: str = 'pre_tool_use') -> None:
    path = events_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a', encoding='utf-8') as handle:
        handle.write(json.dumps({'ts': ts, 'kind': 'HOOK_DEGRADED', 'hook': hook, 'error': 'test'}) + '\n')


class HookDegradedTests(unittest.TestCase):
    def test_policy_import_failure_allows_and_records(self) -> None:
        with project_copy() as root:
            (root / '.getzilla/getzilla/policy.py').write_text('raise ImportError("broken on purpose")\n', encoding='utf-8')
            code, data, err = run_hook(root, 'pre_tool_use.py', {'cwd': str(root), **BASH})
            self.assertEqual(code, 0, err)
            self.assertNotIn('deny', json.dumps(data).lower())
            events = degraded_events(root)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]['hook'], 'pre_tool_use')
            self.assertIn('broken on purpose', events[0]['error'])

    def test_unimportable_lib_allows_and_records_with_stdlib_only(self) -> None:
        with project_copy() as root:
            (root / '.getzilla/getzilla/fsx.py').write_text('raise RuntimeError("fsx broken")\n', encoding='utf-8')
            code, data, err = run_hook(root, 'pre_tool_use.py', {'cwd': str(root), **BASH})
            self.assertEqual(code, 0, err)
            self.assertEqual(data.get('decision'), 'allow')
            events = degraded_events(root)
            self.assertEqual([event['hook'] for event in events], ['pre_tool_use'])
            self.assertIn('fsx broken', events[0]['error'])

    def test_healthy_hook_records_nothing(self) -> None:
        with project_copy() as root:
            run_hook(root, 'pre_tool_use.py', {'cwd': str(root), **BASH})
            self.assertEqual(degraded_events(root), [])

    def test_stop_gate_reports_degraded_hooks_of_this_route(self) -> None:
        with project_copy(git=True) as root:
            set_active_route(root, build_route(root, 'Добавить функцию', 's1').to_dict())
            created = get_active_route(root)['created_at']
            write_event(root, '2000-01-01T00:00:00Z')  # before the route: not counted
            write_event(root, '2999-01-01T00:00:00Z')
            self.assertEqual(len(route_degraded_events(root, get_active_route(root))), 1)
            self.assertTrue(created)
            _, data, err = run_hook(root, 'stop_gate.py', {'cwd': str(root), 'stop_hook_active': False})
            self.assertIn('1 hook call(s) failed open', str(data.get('systemMessage')), err)

    def test_verify_fails_high_risk_pr_with_degraded_hooks(self) -> None:
        with project_copy(git=True) as root:
            route = build_route(root, 'Добавить функцию', 's1').to_dict()
            write_event(root, '2999-01-01T00:00:00Z')
            failing, metadata = verification._hook_health_check(root, route, 'pr', {'effective_risk': 'high'})
            self.assertEqual(failing.status, 'fail')
            self.assertIn('HOOKS_DEGRADED_ON_HIGH_RISK', failing.summary)
            self.assertEqual(metadata['degraded_events'], 1)
            for mode, risk in (('fast', 'high'), ('pr', 'medium')):
                check, _ = verification._hook_health_check(root, route, mode, {'effective_risk': risk})
                self.assertEqual(check.status, 'pass')
                self.assertEqual(check.details[0]['code'], 'hook-degraded')

    def test_no_events_passes(self) -> None:
        with project_copy(git=True) as root:
            route = build_route(root, 'Добавить функцию', 's1').to_dict()
            check, metadata = verification._hook_health_check(root, route, 'pr', {'effective_risk': 'high'})
            self.assertEqual((check.status, metadata['degraded_events']), ('pass', 0))


if __name__ == '__main__':
    unittest.main()
