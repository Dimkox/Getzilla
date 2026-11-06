"""Public inert policy budget controls; command strings are never executed."""
from __future__ import annotations

import contextvars
import os
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla import _policy_legacy as legacy, policy
from tests._support import windows_command_parser
from tests.test_policy_hardening import github_project


class InvocationBudgetTests(unittest.TestCase):
    def test_expiry_precedes_first_preprocessing_lex(self):
        event = {'tool_name': 'Bash', 'tool_input': {'command': 'cat src/app.py'}}
        with mock.patch.object(legacy, 'time') as clock, \
                mock.patch.object(policy, '_shell_mutation', side_effect=AssertionError('preprocessing ran')):
            clock.monotonic.side_effect = [100.0, 103.001]
            allowed, reason = policy.evaluate_pre_tool(Path('/public-inert-fixture'), event)
        self.assertFalse(allowed)
        self.assertIn('budget', reason)

    def test_nested_entry_shares_deadline_and_entry_count(self):
        with legacy._invocation_budget() as outer:
            outer.tick()
            with legacy._invocation_budget() as inner:
                self.assertIs(inner, outer)
                self.assertEqual(inner._entries, 1)
                self.assertEqual(inner._deadline, outer._deadline)
        self.assertIsNone(legacy._current_invocation_budget())

    def test_lexer_observes_active_deadline_before_word_decode(self):
        with legacy._invocation_budget() as budget:
            budget._deadline = float('-inf')
            with mock.patch.object(legacy, '_split_words', side_effect=AssertionError('decoded')):
                with self.assertRaises(legacy._BudgetExceeded):
                    legacy._shell_tokens('cat src/app.py')

    def test_long_word_has_checkpoint_before_decoder(self):
        with mock.patch.object(legacy, 'time') as clock:
            clock.monotonic.return_value = 100.0
            with legacy._invocation_budget(), mock.patch.object(
                legacy, '_split_words', side_effect=AssertionError('decoded')
            ):
                clock.monotonic.side_effect = [100.0, 100.0, 100.0, 103.001]
                with self.assertRaises(legacy._BudgetExceeded):
                    legacy._shell_tokens('x' * 4096)

    def test_preprocessing_time_cannot_be_reset_by_later_scan(self):
        event = {'tool_name': 'Bash', 'tool_input': {'command': 'cat src/app.py'}}
        with mock.patch.object(legacy, 'time') as clock:
            clock.monotonic.return_value = 100.0
            def preprocessing(*args, **kwargs):
                clock.monotonic.return_value = 103.001
                return [], False
            with mock.patch.object(policy, '_shell_mutation', side_effect=preprocessing):
                allowed, reason = policy.evaluate_pre_tool(Path('/public-inert-fixture'), event)
        self.assertFalse(allowed)
        self.assertIn('budget', reason)

    def test_scanner_does_not_restart_preprocessing_budget(self):
        with legacy._invocation_budget() as budget:
            budget._deadline = float('-inf')
            with mock.patch.object(legacy, '_Budget', side_effect=AssertionError('restarted')):
                self.assertEqual(legacy.shell_secret_reference(Path('/public-inert-fixture'), 'cat src/app.py', []), legacy._BUDGET_MARKER)

    def test_cleanup_on_base_exception_and_fresh_top_level(self):
        with self.assertRaises(KeyboardInterrupt):
            with legacy._invocation_budget() as first:
                raise KeyboardInterrupt
        self.assertIsNone(legacy._current_invocation_budget())
        with legacy._invocation_budget() as second:
            self.assertIsNot(first, second)

    def test_copy_of_finished_context_cannot_reuse_its_budget(self):
        with legacy._invocation_budget() as previous:
            copied = contextvars.copy_context()
        def later():
            with legacy._invocation_budget() as current:
                self.assertIsNot(current, previous)
        copied.run(later)

    def test_final_check_prevents_expired_positive_return(self):
        @legacy._bounded_invocation(False)
        def public_operation():
            legacy._current_invocation_budget()._deadline = float('-inf')
            return True
        self.assertFalse(public_operation())
        self.assertIsNone(legacy._current_invocation_budget())

    def test_reading_profile_is_unchanged_by_scope(self):
        with legacy._invocation_budget(), windows_command_parser():
            windows = legacy._shell_tokens(r'cat src\app.py')
            with legacy.posix_reading():
                posix = legacy._shell_tokens(r'cat src\app.py')
        self.assertEqual(windows[-1].value, r'src\app.py')
        self.assertEqual(posix[-1].value, 'srcapp.py')

    def test_copied_context_in_other_thread_gets_fresh_budget(self):
        observed = []
        with legacy._invocation_budget() as parent:
            copied = contextvars.copy_context()
            def child():
                with legacy._invocation_budget() as budget:
                    observed.append(budget is parent)
            worker = threading.Thread(target=lambda: copied.run(child))
            worker.start()
            worker.join(5)
            self.assertFalse(worker.is_alive())
            self.assertIs(legacy._current_invocation_budget(), parent)
        self.assertEqual(observed, [False])

    def test_foreign_process_scope_cannot_supply_budget(self):
        previous = legacy._Budget()
        token = legacy._INVOCATION_SCOPE.set(legacy._InvocationScope(
            previous, os.getpid() + 1, threading.get_ident(),
        ))
        try:
            with legacy._invocation_budget() as current:
                self.assertIsNot(current, previous)
        finally:
            legacy._INVOCATION_SCOPE.reset(token)

    def test_public_short_and_quoted_wrapper_readings(self):
        with github_project() as root:
            self.addCleanup(legacy._SECRET_SCAN_CACHE.clear)
            for command in ('cat src/app.py', "cat 'src/app.py'", "env cat src/app.py", "sh -c 'cat src/app.py'"):
                with self.subTest(command=command):
                    self.assertTrue(policy.evaluate_pre_tool(root, {'tool_name': 'Bash', 'tool_input': {'command': command}})[0])
            with legacy._invocation_budget() as budget:
                budget._deadline = float('-inf')
                self.assertFalse(policy.evaluate_pre_tool(root, {'tool_name': 'Read', 'tool_input': {'file_path': str(root / 'src/app.py')}})[0])
