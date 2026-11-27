"""Task budget behavior through canonical authority and real local effects."""
from __future__ import annotations

import importlib
import sys
import unittest

from tests._support import PROJECT, project_copy

sys.path.insert(0, str(PROJECT / '.getzilla'))
from getzilla import state
from getzilla.continuity import submit


class TaskBudgetTests(unittest.TestCase):
    def tearDown(self):
        state.bind_session(None)

    def test_pure_historical_projection_validates_unknown_exposure_without_owner_mutation(self):
        with project_copy(git=True) as root:
            route = submit(root, 'Run a bounded local check.', 'budget-owner')
            from getzilla import task_budget as budget
            limits = {'calls': 3, 'failures': 2, 'repeat_failures': 2, 'deadline_epoch': 2000000000,
                      'tokens': None, 'cpu_ms': None, 'cost_micros': None, 'elapsed_ms': 10000}
            budget.initialize(root, limits, route['authority_epoch'], route['state_revision'], task_id=route['logical_task_id'])
            current = state.get_active_route(root)
            budget.reserve(root, 'one', 'a'*64, {'tokens': None, 'cpu_ms': None, 'cost_micros': None, 'elapsed_ms': 100},
                           current['authority_epoch'], current['state_revision'], task_id=current['logical_task_id'])
            captured = state.get_active_route(root)
            before = (root/'.getzilla/runtime/routes'/f"{route['route_id']}.json").read_bytes()
            state.bind_session(None)
            self.assertTrue(hasattr(budget, 'project_budget'), 'No pure validated historical budget projection exists')
            result = budget.project_budget(captured)
            self.assertEqual((result['calls'], result['unresolved'], result['charged']['elapsed_ms']), (1, 1, 100))
            self.assertIsNone(result['observed']['cost_micros'])
            self.assertEqual((root/'.getzilla/runtime/routes'/f"{route['route_id']}.json").read_bytes(), before)

    def test_unknown_token_bound_refuses_before_reservation(self):
        # Bug caught: treating missing usage as zero admits a capped operation.
        with project_copy(git=True) as root:
            route = submit(root, 'Run local checks.', 'budget-owner')
            self.assertIsNotNone(importlib.util.find_spec('getzilla.task_budget'),
                                 'No cumulative canonical task budget consumer exists')
            from getzilla import task_budget as budget
            limits = {'calls': 3, 'failures': 2, 'repeat_failures': 2, 'deadline_epoch': 2000000000,
                      'tokens': 10, 'cpu_ms': None, 'cost_micros': None, 'elapsed_ms': 10000}
            budget.initialize(root, limits, route['authority_epoch'], route['state_revision'], task_id=route['logical_task_id'])
            current = state.get_active_route(root)
            with self.assertRaisesRegex(ValueError, 'unknown-reservation'):
                budget.reserve(root, 'one', 'a' * 64, {'tokens': None, 'cpu_ms': None,
                    'cost_micros': None, 'elapsed_ms': 100}, current['authority_epoch'],
                    current['state_revision'], task_id=current['logical_task_id'], now=1900000000)
            self.assertEqual(budget.inspect(root)['calls'], 0)

class BudgetFixture:

    def tearDown(self):
        state.bind_session(None)

    def setup_budget(self, root, **changes):
        from getzilla import task_budget as budget
        route = submit(root, 'Run a bounded local check.', 'budget-owner')
        limits = {'calls': 3, 'failures': 2, 'repeat_failures': 2,
                  'deadline_epoch': 2000000000, 'tokens': None, 'cpu_ms': None,
                  'cost_micros': None, 'elapsed_ms': 10000}
        limits.update(changes)
        budget.initialize(root, limits, route['authority_epoch'], route['state_revision'], task_id=route['logical_task_id'])
        return budget


class ManagedCommandTests(BudgetFixture, unittest.TestCase):
    def test_managed_command_replay_never_repeats_real_effect(self):
        # Bug caught: replaying a settled reservation runs the command twice.
        with project_copy(git=True) as root:
            budget = self.setup_budget(root)
            self.assertTrue(hasattr(budget, 'execute_local'), 'No pre-effect budget consumer exists')
            argv = [sys.executable, '-c', 'from pathlib import Path; p=Path("marker"); p.write_text(p.read_text()+"x" if p.exists() else "x")']
            result = budget.execute_local(root, 'op-one', argv, timeout=1)
            replay = budget.execute_local(root, 'op-one', argv, timeout=1)
            self.assertEqual(result['outcome'], 'succeeded')
            self.assertEqual(replay['outcome'], 'succeeded')
            self.assertEqual((root / 'marker').read_text(), 'x')
            self.assertEqual(budget.inspect(root)['calls'], 1)
            self.assertIsNone(budget.inspect(root)['observed']['cost_micros'])

    def test_capped_opaque_child_never_starts(self):
        with project_copy(git=True) as root:
            budget = self.setup_budget(root, tokens=100)
            self.assertTrue(hasattr(budget, 'execute_local'), 'No pre-effect budget consumer exists')
            with self.assertRaisesRegex(ValueError, 'unknown-reservation'):
                budget.execute_local(root, 'op-one', [sys.executable, '-c', 'open("marker","w").close()'], timeout=1)
            self.assertFalse((root / 'marker').exists())
            self.assertEqual(budget.inspect(root)['calls'], 0)

class BudgetAuthorityTests(BudgetFixture, unittest.TestCase):
    def test_spend_survives_continuation_and_reinitialization_cannot_refill(self):
        with project_copy(git=True) as root:
            budget = self.setup_budget(root, calls=1)
            argv = [sys.executable, '-c', 'pass']
            budget.execute_local(root, 'one', argv, timeout=1)
            submit(root, 'continue', 'budget-owner')
            route = state.get_active_route(root)
            budget.initialize(root, budget.inspect(root)['limits'], route['authority_epoch'], route['state_revision'], task_id=route['logical_task_id'])
            with self.assertRaisesRegex(ValueError, 'calls-exhausted'):
                budget.execute_local(root, 'two', argv, timeout=1)
            changed = {**budget.inspect(root)['limits'], 'calls': 2}
            route = state.get_active_route(root)
            with self.assertRaisesRegex(ValueError, 'reset-or-increase'):
                budget.initialize(root, changed, route['authority_epoch'], route['state_revision'], task_id=route['logical_task_id'])

    def test_failure_loop_and_timeout_stop_real_effects(self):
        with project_copy(git=True) as root:
            budget = self.setup_budget(root, failures=3, repeat_failures=1)
            argv = [sys.executable, '-c', 'raise SystemExit(2)']
            self.assertEqual(budget.execute_local(root, 'one', argv, timeout=1)['outcome'], 'failed')
            with self.assertRaisesRegex(ValueError, 'failure-loop-stop'):
                budget.execute_local(root, 'two', argv, timeout=1)
            self.assertEqual(budget.inspect(root)['failures'], 1)
        with project_copy(git=True) as root:
            budget = self.setup_budget(root)
            self.assertEqual(budget.execute_local(root, 'one', [sys.executable, '-c', 'import time; time.sleep(5); open("marker","w").close()'], timeout=0.05)['outcome'], 'failed')
            self.assertFalse((root / 'marker').exists())
            self.assertTrue(budget.inspect(root)['stopped'])

    def test_failure_budget_counts_different_failed_commands(self):
        with project_copy(git=True) as root:
            budget = self.setup_budget(root, failures=1)
            budget.execute_local(root, 'one', [sys.executable, '-c', 'raise SystemExit(2)'], timeout=1)
            with self.assertRaisesRegex(ValueError, 'failure-loop-stop'):
                budget.execute_local(root, 'two', [sys.executable, '-c', 'open("marker","w").close()'], timeout=1)
            self.assertFalse((root / 'marker').exists())

    def test_old_task_binding_cannot_reserve_for_another_task(self):
        # Bug caught: epoch/revision alone are valid again on a different task.
        with project_copy(git=True) as root:
            budget = self.setup_budget(root)
            route = state.get_active_route(root)
            usage = {'tokens': None, 'cpu_ms': None, 'cost_micros': None, 'elapsed_ms': 1}
            with self.assertRaisesRegex(ValueError, 'stale-budget-authority'):
                budget.reserve(root, 'one', 'a' * 64, usage, route['authority_epoch'],
                               route['state_revision'], task_id='task:different')

    def test_running_unknown_record_blocks_reexecution_and_new_effect(self):
        with project_copy(git=True) as root:
            budget = self.setup_budget(root)
            route = state.get_active_route(root)
            usage = {'tokens': None, 'cpu_ms': None, 'cost_micros': None, 'elapsed_ms': 1000}
            budget.reserve(root, 'lost', 'a' * 64, usage, route['authority_epoch'], route['state_revision'], task_id=route['logical_task_id'])
            route = state.get_active_route(root)
            budget.claim(root, 'lost', route['authority_epoch'], route['state_revision'], task_id=route['logical_task_id'])
            with self.assertRaisesRegex(ValueError, 'unresolved-outcome'):
                budget.execute_local(root, 'other', [sys.executable, '-c', 'open("marker","w").close()'], timeout=1)
            self.assertFalse((root / 'marker').exists())
            self.assertEqual(budget.inspect(root)['unresolved'], 1)

    def test_stale_cas_wrong_owner_and_cancelled_task_deny(self):
        with project_copy(git=True) as root:
            budget = self.setup_budget(root)
            route = state.get_active_route(root)
            usage = {'tokens': None, 'cpu_ms': None, 'cost_micros': None, 'elapsed_ms': 1}
            with self.assertRaisesRegex(ValueError, 'stale-budget-authority'):
                budget.reserve(root, 'one', 'a' * 64, usage, route['authority_epoch'] + 1, route['state_revision'], task_id=route['logical_task_id'])
            with self.assertRaisesRegex(ValueError, 'stale-budget-authority'):
                budget.reserve(root, 'one', 'a' * 64, usage, route['authority_epoch'], route['state_revision'] - 1, task_id=route['logical_task_id'])
            state.bind_session('wrong-owner')
            with self.assertRaises(ValueError):
                budget.execute_local(root, 'one', [sys.executable, '-c', 'open("marker","w").close()'], timeout=1)
            self.assertFalse((root / 'marker').exists())

class BudgetCliTests(unittest.TestCase):
    def tearDown(self):
        state.bind_session(None)

    def test_real_cli_initializes_runs_once_and_shows_unknown_economics(self):
        import json
        import os
        import subprocess
        with project_copy(git=True) as root:
            submit(root, 'Run an offline local check.', 'budget-owner')
            script = PROJECT / 'scripts/getzilla_task_budget.py'
            def cli(*args):
                return subprocess.run([sys.executable, str(script), *args], cwd=root,
                    env={**os.environ, 'GETZILLA_SESSION_ID': 'budget-owner'},
                    capture_output=True, text=True, timeout=10)
            result = cli('init', '--calls', '2', '--failures', '1', '--repeat-failures', '1',
                         '--elapsed-ms', '2000', '--deadline-epoch', '2000000000')
            self.assertEqual(result.returncode, 0, result.stderr)
            argv = [sys.executable, '-c', 'from pathlib import Path; p=Path("marker"); p.write_text(p.read_text()+"x" if p.exists() else "x")']
            for _ in range(2):
                result = cli('run', '--operation-id', 'one', '--timeout', '1', '--', *argv)
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / 'marker').read_text(), 'x')
            result = cli('show')
            data = json.loads(result.stdout)
            self.assertEqual(data['calls'], 1)
            self.assertIsNone(data['accepted_pr_cost'])
            self.assertIsNone(data['observed']['tokens'])
            bad = cli('run', '--operation-id', 'bad', '--timeout', '1', '--', sys.executable, '-c', 'raise SystemExit(3)')
            self.assertEqual(bad.returncode, 1, bad.stderr)

class BudgetEdgeTests(BudgetFixture, unittest.TestCase):
    def reserve(self, root, budget, identity='one', key='a' * 64, **updates):
        route = state.get_active_route(root)
        usage = {'tokens': None, 'cpu_ms': None, 'cost_micros': None, 'elapsed_ms': 1000}
        usage.update(updates)
        return budget.reserve(root, identity, key, usage, route['authority_epoch'], route['state_revision'], task_id=route['logical_task_id'])

    def test_exact_replay_collision_and_unknown_usage_charge(self):
        with project_copy(git=True) as root:
            budget = self.setup_budget(root)
            first = self.reserve(root, budget)
            self.assertEqual(first, self.reserve(root, budget))
            with self.assertRaisesRegex(ValueError, 'idempotency-conflict'):
                self.reserve(root, budget, key='b' * 64)
            self.assertEqual(budget.inspect(root)['charged']['elapsed_ms'], 1000)
            for name in ('tokens', 'cpu_ms', 'cost_micros'):
                self.assertIsNone(budget.inspect(root)['charged'][name])
            self.assertEqual(budget.inspect(root)['escalation'], 'needs-review')

    def test_deadline_and_wall_cap_refuse_without_effect(self):
        import time
        for changes in ({'deadline_epoch': int(time.time())}, {'elapsed_ms': 10}):
            with self.subTest(changes=changes), project_copy(git=True) as root:
                budget = self.setup_budget(root, **changes)
                with self.assertRaises(ValueError):
                    budget.execute_local(root, 'one', [sys.executable, '-c', 'open("marker","w").close()'], timeout=1)
                self.assertFalse((root / 'marker').exists())
                self.assertEqual(budget.inspect(root)['calls'], 0)

    def test_handoff_and_head_change_preserve_spend(self):
        import subprocess
        with project_copy(git=True) as root:
            budget = self.setup_budget(root, calls=1)
            budget.execute_local(root, 'one', [sys.executable, '-c', 'pass'], timeout=1)
            (root / 'budget-fixture').write_text('new source')
            subprocess.run(['git', 'add', 'budget-fixture'], cwd=root, check=True, capture_output=True)
            subprocess.run(['git', 'commit', '-m', 'fixture source change'], cwd=root, check=True, capture_output=True)
            route = state.get_active_route(root)
            moved = submit(root, '', 'new-owner', continue_route=route['route_id'],
                expected_epoch=route['authority_epoch'], expected_revision=route['state_revision'], request_id='handoff-budget')
            self.assertEqual(moved['authority_epoch'], 1)
            self.assertEqual(budget.inspect(root)['calls'], 1)
            with self.assertRaisesRegex(ValueError, 'calls-exhausted'):
                budget.execute_local(root, 'two', [sys.executable, '-c', 'open("marker","w").close()'], timeout=1)
            self.assertFalse((root / 'marker').exists())

    def test_concurrent_reservations_use_one_current_cas(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        with project_copy(git=True) as root:
            budget = self.setup_budget(root, calls=1)
            route = state.get_active_route(root)
            barrier = Barrier(2)
            def reserve(identity):
                state.bind_session('budget-owner')
                barrier.wait(timeout=3)
                try:
                    budget.reserve(root, identity, 'a' * 64, {'tokens': None, 'cpu_ms': None,
                        'cost_micros': None, 'elapsed_ms': 1}, route['authority_epoch'],
                        route['state_revision'], task_id=route['logical_task_id'])
                    return 'reserved'
                except ValueError:
                    return 'denied'
            with ThreadPoolExecutor(max_workers=2) as pool:
                self.assertCountEqual(pool.map(reserve, ['one', 'two']), ['reserved', 'denied'])
            self.assertEqual(budget.inspect(root)['calls'], 1)

    def test_actual_overrun_latches_stop_and_duplicate_reconcile_is_idempotent(self):
        with project_copy(git=True) as root:
            budget = self.setup_budget(root, tokens=10)
            self.reserve(root, budget, tokens=5)
            route = state.get_active_route(root)
            budget.claim(root, 'one', route['authority_epoch'], route['state_revision'], task_id=route['logical_task_id'])
            actual = {'tokens': 11, 'cpu_ms': None, 'cost_micros': None, 'elapsed_ms': 10}
            route = state.get_active_route(root)
            result = budget.reconcile(root, 'one', 'succeeded', actual, route['authority_epoch'], route['state_revision'], task_id=route['logical_task_id'])
            self.assertTrue(result['stopped'])
            self.assertEqual(result['observed']['tokens'], 11)
            route = state.get_active_route(root)
            self.assertEqual(budget.reconcile(root, 'one', 'succeeded', actual, route['authority_epoch'], route['state_revision'], task_id=route['logical_task_id']), result)
            with self.assertRaisesRegex(ValueError, 'hard-stop'):
                self.reserve(root, budget, identity='two', tokens=1)

    def test_mandatory_unknown_money_and_cpu_never_admit_opaque_child(self):
        for dimension in ('cost_micros', 'cpu_ms'):
            with self.subTest(dimension=dimension), project_copy(git=True) as root:
                budget = self.setup_budget(root, **{dimension: 100})
                with self.assertRaisesRegex(ValueError, 'unknown-reservation'):
                    budget.execute_local(root, 'one', [sys.executable, '-c', 'open("marker","w").close()'], timeout=1)
                self.assertFalse((root / 'marker').exists())

    def test_route_cancellation_and_policy_refusal_do_not_start_process(self):
        from getzilla.continuity import finish_task
        with project_copy(git=True) as root:
            budget = self.setup_budget(root)
            with self.assertRaisesRegex(ValueError, 'policy-refused'):
                budget.execute_local(root, 'one', ['git', 'push', 'origin', 'main'], timeout=1)
            self.assertEqual(budget.inspect(root)['calls'], 0)
            finish_task(root, cancel=True)
            with self.assertRaisesRegex(ValueError, 'inactive-budget-authority'):
                budget.execute_local(root, 'two', [sys.executable, '-c', 'open("marker","w").close()'], timeout=1)
            self.assertFalse((root / 'marker').exists())

class BudgetCancellationTests(BudgetFixture, unittest.TestCase):
    def test_owner_can_cancel_while_child_runs_and_process_stops(self):
        import time
        from concurrent.futures import ThreadPoolExecutor
        from getzilla.continuity import finish_task
        with project_copy(git=True) as root:
            budget = self.setup_budget(root)
            route = state.get_active_route(root)
            def run():
                state.bind_session('budget-owner')
                return budget.execute_local(root, 'one', [sys.executable, '-c',
                    'from pathlib import Path; import time; Path("started").touch(); time.sleep(4); Path("marker").touch()'], timeout=5)
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(run)
                deadline = time.monotonic() + 2
                while not (root / 'started').exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue((root / 'started').exists())
                start = time.monotonic()
                finish_task(root, cancel=True)
                self.assertLess(time.monotonic() - start, 0.5, 'Owner cancellation waited for the child budget lock')
                result = future.result(timeout=2)
            self.assertEqual(result['outcome'], 'unknown')
            self.assertEqual(result['stopped_for'], 'authority-withdrawn')
            self.assertFalse((root / 'marker').exists())
            canonical = state.canonical_route(root, route['route_id'])
            self.assertEqual(canonical['task_budget']['operations']['one']['state'], 'running')

class BudgetEpochWithdrawalTests(BudgetFixture, unittest.TestCase):
    def test_epoch_handoff_stops_previous_owner_and_preserves_unknown_charge(self):
        import time
        from concurrent.futures import ThreadPoolExecutor
        with project_copy(git=True) as root:
            budget = self.setup_budget(root)
            argv = [sys.executable, '-c', 'from pathlib import Path; import time; Path("started").touch(); time.sleep(4); Path("marker").touch()']
            def run():
                state.bind_session('budget-owner')
                return budget.execute_local(root, 'one', argv, timeout=5)
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(run)
                deadline = time.monotonic() + 2
                while not (root / 'started').exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue((root / 'started').exists())
                route = state.get_active_route(root)
                start = time.monotonic()
                moved = submit(root, '', 'new-owner', continue_route=route['route_id'],
                    expected_epoch=route['authority_epoch'], expected_revision=route['state_revision'], request_id='live-handoff')
                self.assertLess(time.monotonic() - start, 0.5)
                self.assertEqual(future.result(timeout=2)['outcome'], 'unknown')
            self.assertEqual(moved['authority_epoch'], 1)
            self.assertEqual(budget.inspect(root)['unresolved'], 1)
            self.assertEqual(budget.inspect(root)['charged']['elapsed_ms'], 5000)
            self.assertFalse((root / 'marker').exists())
            with self.assertRaisesRegex(ValueError, 'already-claimed-or-stale'):
                budget.execute_local(root, 'one', argv, timeout=5)
            self.assertEqual(budget.inspect(root)['calls'], 1)

class BudgetReviewRegressionTests(BudgetFixture, unittest.TestCase):
    def test_task_switch_with_two_real_children_never_settles_foreign_operation(self):
        import time
        from concurrent.futures import ThreadPoolExecutor
        with project_copy(git=True) as root:
            budget = self.setup_budget(root)
            original = state.get_active_route(root)
            def command(name):
                return [sys.executable, '-c',
                    'from pathlib import Path; import time; '
                    f'Path("{name}-started").touch(); '\
                    f'\nwhile not Path("{name}-release").exists(): time.sleep(.01)\n'\
                    f'Path("{name}-done").touch()']
            def run(argv):
                state.bind_session('budget-owner')
                return budget.execute_local(root, 'shared', argv, timeout=4)
            def started(name):
                deadline = time.monotonic() + 2
                while not (root / (name + '-started')).exists() and time.monotonic() < deadline:
                    time.sleep(.005)
                self.assertTrue((root / (name + '-started')).exists())
            with ThreadPoolExecutor(max_workers=2) as pool:
                old = pool.submit(run, command('old'))
                other = None
                try:
                    started('old')
                    foreign = submit(root, 'Run a distinct local check.', 'budget-owner', new_task=True)
                    limits = {'calls': 3, 'failures': 2, 'repeat_failures': 2,
                              'deadline_epoch': 2000000000, 'tokens': None, 'cpu_ms': None,
                              'cost_micros': None, 'elapsed_ms': 10000}
                    budget.initialize(root, limits, foreign['authority_epoch'], foreign['state_revision'], task_id=foreign['logical_task_id'])
                    other = pool.submit(run, command('new'))
                    started('new')
                    path = root / '.getzilla/runtime/routes' / (foreign['route_id'] + '.json')
                    before = path.read_bytes()
                    (root / 'old-release').touch()
                    outcome = old.result(timeout=2)
                    self.assertFalse((root / 'new-done').exists(), 'Foreign child must still be running')
                    self.assertEqual(path.read_bytes(), before, 'Old effect changed the foreign canonical bytes/revision')
                    self.assertEqual(outcome['outcome'], 'unknown')
                    # The foreign child may still publish into routes/ and move the
                    # directory stamp. Read under the same lock that writers hold.
                    with state.task_transition(root):
                        original_row = state.canonical_route(root, original['route_id'])['task_budget']['operations']['shared']
                        foreign_row = state.canonical_route(root, foreign['route_id'])['task_budget']['operations']['shared']
                    self.assertNotEqual(original_row['key'], foreign_row['key'])
                    self.assertEqual(original_row['state'], 'running')
                    self.assertIsNone(original_row['actual'])
                finally:
                    (root / 'old-release').touch()
                    (root / 'new-release').touch()
                    old.result(timeout=5)
                    if other is not None:
                        result = other.result(timeout=5)
                self.assertEqual(result['outcome'], 'succeeded')
                self.assertEqual(budget.inspect(root)['calls'], 1)

class BudgetPublicAuthorityRegressionTests(BudgetFixture, unittest.TestCase):
    def test_all_public_mutations_refuse_invalid_required_authority_without_writes(self):
        for action in ('initialize', 'reserve', 'claim', 'reconcile'):
            for invalid in ('null-both', 'null-epoch', 'null-revision', 'bool-epoch',
                            'bool-revision', 'wrong-task', 'null-task', 'missing-task'):
                with self.subTest(action=action, invalid=invalid), project_copy(git=True) as root:
                    from getzilla import task_budget as budget
                    route = submit(root, 'Run a bounded check.', 'budget-owner')
                    limits = {'calls': 3, 'failures': 2, 'repeat_failures': 2,
                              'deadline_epoch': 2000000000, 'tokens': None, 'cpu_ms': None,
                              'cost_micros': None, 'elapsed_ms': 10000}
                    usage = {'tokens': None, 'cpu_ms': None, 'cost_micros': None, 'elapsed_ms': 100}
                    def authority():
                        current = state.get_active_route(root)
                        return current['authority_epoch'], current['state_revision'], {'task_id': current['logical_task_id']}
                    if action != 'initialize':
                        epoch, revision, task = authority()
                        budget.initialize(root, limits, epoch, revision, **task)
                    if action in ('claim', 'reconcile'):
                        epoch, revision, task = authority()
                        budget.reserve(root, 'one', 'a' * 64, usage, epoch, revision, **task)
                    if action == 'reconcile':
                        epoch, revision, task = authority()
                        budget.claim(root, 'one', epoch, revision, **task)
                    epoch, revision, task = authority()
                    if invalid == 'null-both':
                        epoch, revision, task = None, None, {'task_id': 'task:foreign'}
                    elif invalid == 'null-epoch':
                        epoch, task = None, {'task_id': 'task:foreign'}
                    elif invalid == 'null-revision':
                        revision = None
                    elif invalid == 'bool-epoch':
                        epoch = False
                    elif invalid == 'bool-revision':
                        revision = False
                    elif invalid == 'wrong-task':
                        task = {'task_id': 'task:foreign'}
                    elif invalid == 'null-task':
                        task = {'task_id': None}
                    else:
                        task = {}
                    path = root / '.getzilla/runtime/routes' / (route['route_id'] + '.json')
                    before = path.read_bytes()
                    arguments = {'initialize': (limits,), 'reserve': ('one', 'a' * 64, usage),
                                 'claim': ('one',), 'reconcile': ('one', 'succeeded', usage)}[action]
                    with self.assertRaises((ValueError, TypeError)):
                        getattr(budget, action)(root, *arguments, epoch, revision, **task)
                    self.assertEqual(path.read_bytes(), before)

class BudgetOperationBindingTests(BudgetFixture, unittest.TestCase):
    def test_changed_running_operation_key_keeps_unknown_without_settlement(self):
        import time
        from concurrent.futures import ThreadPoolExecutor
        with project_copy(git=True) as root:
            budget = self.setup_budget(root)
            def run():
                state.bind_session('budget-owner')
                return budget.execute_local(root, 'one', [sys.executable, '-c',
                    'from pathlib import Path; import time; Path("started").touch(); '\
                    '\nwhile not Path("release").exists(): time.sleep(.01)'], timeout=3)
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(run)
                try:
                    deadline = time.monotonic() + 2
                    while not (root / 'started').exists() and time.monotonic() < deadline:
                        time.sleep(.005)
                    self.assertTrue((root / 'started').exists())
                    current = state.get_active_route(root)
                    changed = current['task_budget']
                    changed['operations']['one']['key'] = 'b' * 64
                    # get_active_route returns a detached document; keep CAS original intact.
                    original = state.get_active_route(root)
                    state.update_route(root, expected_route=original, task_budget=changed)
                    path = root / '.getzilla/runtime/routes' / (current['route_id'] + '.json')
                    before = path.read_bytes()
                    (root / 'release').touch()
                    result = future.result(timeout=2)
                    self.assertEqual(result['outcome'], 'unknown')
                    self.assertEqual(path.read_bytes(), before)
                    self.assertEqual(budget.inspect(root)['unresolved'], 1)
                finally:
                    (root / 'release').touch()
                    future.result(timeout=4)


class BudgetTornReadTests(BudgetFixture, unittest.TestCase):
    def test_budget_poll_retries_when_selected_route_read_changes(self):
        from unittest.mock import patch
        from getzilla.package_status import InspectionError
        with project_copy(git=True) as root:
            budget = self.setup_budget(root)
            route = state.get_active_route(root)
            key = 'a' * 64
            def authority():
                current = state.get_active_route(root)
                return current['authority_epoch'], current['state_revision']
            budget.reserve(root, 'op', key, {'tokens': None, 'cpu_ms': None, 'cost_micros': None, 'elapsed_ms': 100},
                           *authority(), task_id=route['logical_task_id'])
            budget.claim(root, 'op', *authority(), task_id=route['logical_task_id'])
            read = state._route_document
            for directory in ('sessions', 'routes'):
                with self.subTest(directory=directory):
                    interrupted = []
                    def change_once(root, path, **options):
                        if path.parent.name == directory and not interrupted:
                            interrupted.append(path)
                            raise InspectionError('file_changed', 'selected input changed during the read')
                        return read(root, path, **options)
                    with patch.object(state, '_route_document', side_effect=change_once):
                        self.assertTrue(budget._same_authority(root, route, 'op', key))
                    self.assertEqual(len(interrupted), 1)

    def test_authority_poll_retries_only_a_torn_route_read(self):
        from unittest import mock
        from getzilla import task_budget as budget
        from getzilla.package_status import InspectionError
        torn = InspectionError('file_changed', 'selected input changed during the read')
        args = ('root', {}, 'op', 'k')
        with mock.patch.object(budget, '_same_authority_once', side_effect=[torn, torn, True]) as once, \
                mock.patch.object(budget.time, 'sleep'):
            self.assertTrue(budget._same_authority(*args))
        self.assertEqual(once.call_count, 3)
        with mock.patch.object(budget, '_same_authority_once', side_effect=torn) as once, \
                mock.patch.object(budget.time, 'sleep'):
            self.assertFalse(budget._same_authority(*args))
        self.assertEqual(once.call_count, budget._TORN_READ_RETRIES + 1)
        other = InspectionError('file_unsafe', 'unsafe')
        with mock.patch.object(budget, '_same_authority_once', side_effect=other) as once:
            self.assertFalse(budget._same_authority(*args))
        self.assertEqual(once.call_count, 1)


if __name__ == '__main__':
    unittest.main()
