"""Intent is scoped task data, never an extra blanket permission grant."""
from __future__ import annotations

import copy
import json
import shlex
import sys
import unittest

from tests._support import PROJECT, project_copy, windows_command_parser

sys.path.insert(0, str(PROJECT / '.getzilla'))
from getzilla import continuity, state
from getzilla.change import start_change
from getzilla.policy import evaluate_pre_tool
from getzilla.spec import dump_canonical_spec, load_spec


class TaskIntentTests(unittest.TestCase):
    def setUp(self):
        state.bind_session(None)

    def tearDown(self):
        state.bind_session(None)

    def task(self, root, *, light=False):
        state.bind_session('intent-owner')
        text = 'Fix a typo in README documentation.' if light else 'Implement functions A and B in the API with clear acceptance tests.'
        route = continuity.submit(root, text, 'intent-owner', new_task=True)
        (root / 'src').mkdir(exist_ok=True)
        for name in ('a.py', 'b.py'):
            (root / 'src' / name).write_text('value = 1\n')
        if light:
            return state.get_active_route(root)
        start_change(root)
        directory = root / state.get_active_change(root)['path']
        (root / 'tests').mkdir(exist_ok=True)
        (root / 'tests/test_intent_contract.py').write_text('import unittest\n')
        spec = load_spec(directory / 'change-spec.yaml')
        spec['objective'].update(success_metric='result values', target='A and B match their criteria')
        spec['acceptance_criteria'] = [
            {'id': 'AC-001', 'statement': 'A returns the requested count.', 'evidence': [{'test': 'tests/test_intent_contract.py'}]},
            {'id': 'AC-002', 'statement': 'B returns the requested total.', 'evidence': [{'test': 'tests/test_intent_contract.py'}]},
        ]
        spec['forbidden_outcomes'] = [{'id': 'FORBID-001', 'statement': 'No authority escalation.', 'evidence': [{'test': 'tests/test_intent_contract.py'}]}]
        spec['approvals']['required_scopes'] = ['local-implementation']
        (directory / 'change-spec.yaml').write_text(dump_canonical_spec(spec))
        (directory / 'requirements.md').write_text(text + '\nA and B are independent.\n')
        binding = continuity.context_binding(root)
        route = state.get_active_route(root)
        continuity.ack_scope(root, {'version': 1, 'operation_id': 'initial', 'route_id': route['route_id'],
            'logical_task_id': route['logical_task_id'], 'authority_epoch': route['authority_epoch'],
            'revision': route['context']['revision'], 'spec_digest': binding['spec_digest'],
            'requirements_digest': binding['requirements_digest'], 'items': {'original': ['OBJ-001', 'AC-001', 'AC-002']}})
        return state.get_active_route(root)

    def api(self):
        operation = getattr(continuity, 'update_intent', None)
        if operation is None:
            self.fail('The canonical route has no intent transition; affected implementation is not gated.')
        return operation

    def request(self, root, operation, identifier):
        route = state.get_active_route(root)
        return {'version': 1, 'operation_id': identifier, 'route_id': route['route_id'],
                'logical_task_id': route['logical_task_id'], 'authority_epoch': route['authority_epoch'],
                'context_revision': route['context']['revision'], 'state_revision': route['state_revision'],
                'operation': operation}

    def ask(self, root, *, targets=None, paths=None, identifier='Q-001'):
        operation = self.api()
        question = {'id': identifier, 'question': 'Which count should A return?',
                    'targets': targets or ['AC-001'], 'paths': ['src/a.py'] if paths is None else paths,
                    'source_ref': 'human-task:missing-count'}
        return operation(root, self.request(root, {'kind': 'ask', 'question': question}, 'ask-' + identifier))

    def answer(self, root, *, identifier='Q-001', source_kind='human', operation_id='answer-1'):
        operation = self.api()
        from getzilla.task_intent import target_digest
        route = state.get_active_route(root)
        question = next(q for q in route['intent_state']['questions'] if q['id'] == identifier)
        answer = {'text': 'A returns the count of active rows.', 'source_kind': source_kind,
                  'source_ref': 'fixture-human-event:answer-1', 'principal': 'owner',
                  'event_id': 'fixture-human-event-1', 'target_digest': target_digest(root, route, question)}
        return operation(root, self.request(root, {'kind': 'answer', 'id': identifier, 'answer': answer}, operation_id))

    def test_open_question_refuses_affected_edit_but_allows_independent_edit_read_and_test(self):
        with project_copy(git=True) as root:
            self.task(root)
            self.ask(root)
            allowed, reason = evaluate_pre_tool(root, {'tool_name': 'Edit', 'tool_input': {'file_path': str(root / 'src/a.py')}})
            self.assertFalse(allowed)
            self.assertIn('Q-001', reason)
            for event in (
                {'tool_name': 'Edit', 'tool_input': {'file_path': str(root / 'src/b.py')}},
                {'tool_name': 'Read', 'tool_input': {'file_path': str(root / 'src/a.py')}},
                {'tool_name': 'Bash', 'tool_input': {'command': 'python3 -m unittest tests.test_intent_contract'}},
            ):
                self.assertTrue(evaluate_pre_tool(root, event)[0], event)

    def test_restored_open_intent_cannot_be_ignored_by_existing_write_consumer(self):
        with project_copy(git=True) as root:
            route = self.task(root)
            restored = copy.deepcopy(route)
            restored['intent_state'] = {'schema_version': 1, 'revision': 1, 'questions': [{
                'id': 'Q-001', 'question': 'Which count?', 'targets': ['AC-001'],
                'paths': ['src/a.py'], 'source_ref': 'human-task:count',
                'opened_digest': '0' * 64, 'answer': None}], 'operations': []}
            state._commit_route(root, restored, expected=route)
            allowed, reason = evaluate_pre_tool(root, {'tool_name': 'Edit', 'tool_input': {'file_path': 'src/a.py'}})
            self.assertFalse(allowed, 'A restored unanswered question was silently ignored.')
            self.assertIn('Q-001', reason)

    def test_question_added_after_writer_start_blocks_next_affected_shell_write(self):
        with project_copy(git=True) as root:
            self.task(root)
            from getzilla.agent_lifecycle import start_agent
            route = state.get_active_route(root)
            start_agent(root, 'fixture-native-writer', route['write_agent'])
            self.ask(root)
            for command in ('printf changed > src/a.py', 'cd src && printf changed > a.py'):
                allowed, reason = evaluate_pre_tool(root, {'tool_name': 'Bash', 'tool_input': {'command': command}})
                self.assertFalse(allowed, command)
                self.assertIn('Q-001', reason)
            self.assertTrue(evaluate_pre_tool(root, {'tool_name': 'Bash', 'tool_input': {'command': 'printf changed > src/b.py'}})[0])

    def test_answer_binds_only_affected_requirement_and_invalidates_old_receipt_context(self):
        with project_copy(git=True) as root:
            self.task(root)
            before = continuity.context_binding(root)
            self.ask(root)
            self.assertNotEqual(continuity.context_binding(root), before)
            self.answer(root)
            from getzilla.task_intent import intent_gaps
            self.assertEqual(intent_gaps(root, state.get_active_route(root)), [])
            directory = root / state.get_active_change(root)['path']
            spec = load_spec(directory / 'change-spec.yaml')
            spec['acceptance_criteria'][1]['statement'] = 'B returns the revised independent total.'
            (directory / 'change-spec.yaml').write_text(dump_canonical_spec(spec))
            self.assertEqual(intent_gaps(root, state.get_active_route(root)), [])
            spec['acceptance_criteria'][0]['statement'] = 'A now counts archived rows.'
            (directory / 'change-spec.yaml').write_text(dump_canonical_spec(spec))
            self.assertTrue(any('Q-001' in gap and 'stale' in gap for gap in intent_gaps(root, state.get_active_route(root))))

    def test_exact_retry_is_idempotent_and_colliding_or_stale_transition_cannot_clear_question(self):
        with project_copy(git=True) as root:
            self.task(root)
            operation = self.api()
            request = self.request(root, {'kind': 'ask', 'question': {'id': 'Q-001', 'question': 'Which count?',
                'targets': ['AC-001'], 'paths': ['src/a.py'], 'source_ref': 'human-task:count'}}, 'op-1')
            result = operation(root, request)
            self.assertEqual(operation(root, request), result)
            altered = copy.deepcopy(request)
            altered['operation']['question']['question'] = 'A different question'
            with self.assertRaisesRegex(ValueError, 'collision'):
                operation(root, altered)
            stale = self.request(root, {'kind': 'ask', 'question': {'id': 'Q-002', 'question': 'Which total?',
                'targets': ['AC-002'], 'paths': ['src/b.py'], 'source_ref': 'human-task:total'}}, 'op-2')
            stale['authority_epoch'] += 1
            with self.assertRaises(ValueError):
                operation(root, stale)
            with self.assertRaisesRegex(ValueError, 'immutable'):
                state.update_route(root, intent_state=None)
            self.assertEqual(len(state.get_active_route(root)['intent_state']['questions']), 1)

    def test_repository_quote_is_not_a_human_answer(self):
        with project_copy(git=True) as root:
            self.task(root)
            self.ask(root)
            with self.assertRaisesRegex(ValueError, 'human'):
                self.answer(root, source_kind='repository')
            self.assertFalse(evaluate_pre_tool(root, {'tool_name': 'Edit', 'tool_input': {'file_path': 'src/a.py'}})[0])

    def test_light_without_package_keeps_question_and_has_no_legacy_evidence_escape(self):
        with project_copy(git=True) as root:
            self.task(root, light=True)
            self.assertIsNone(state.get_active_change(root))
            self.ask(root, targets=['original'], paths=['README.md'])
            route = state.get_active_route(root)
            self.assertTrue(any('Q-001' in gap for gap in continuity.scope_gaps(root, route)))
            self.assertFalse(continuity.receipt_context_current(root, route, {}))
            self.answer(root)
            self.assertIsNone(state.get_active_change(root))
            self.assertFalse(any('Q-001' in gap for gap in continuity.scope_gaps(root)))

    def test_unknown_mutation_scope_does_not_claim_independence(self):
        with project_copy(git=True) as root:
            self.task(root)
            self.ask(root)
            allowed, reason = evaluate_pre_tool(root, {'tool_name': 'Write', 'tool_input': {'content': 'unspecified target'}})
            self.assertFalse(allowed)
            self.assertIn('intent', reason)

    def test_write_worker_scope_is_checked_but_analysis_remains_available(self):
        with project_copy(git=True) as root:
            self.task(root)
            self.ask(root)
            from getzilla.agent_lifecycle import start_agent
            route = state.get_active_route(root)
            start_agent(root, 'fixture-analyst', route['analysis_agents'][0])
            with self.assertRaisesRegex(ValueError, 'Q-001'):
                start_agent(root, 'fixture-writer', route['write_agent'])
            # This worker explicitly owns only the independent criterion.
            started = start_agent(root, 'fixture-writer-independent', route['write_agent'], requirement_ids=('AC-002',))
            self.assertEqual(started['task_id'], route['logical_task_id'])

    def test_cli_record_and_restart_preserve_question(self):
        with project_copy(git=True) as root:
            self.task(root)
            self.ask(root)
            saved = json.loads((root / '.getzilla/runtime/routes' / (state.get_active_route(root)['route_id'] + '.json')).read_text())
            state.bind_session(None)
            state.bind_session('intent-owner')
            self.assertEqual(state.get_active_route(root)['intent_state'], saved['intent_state'])
            self.assertFalse(evaluate_pre_tool(root, {'tool_name': 'Edit', 'tool_input': {'file_path': 'src/a.py'}})[0])

    def test_route_classification_remains_a_string_and_context_displays_the_human_answer(self):
        with project_copy(git=True) as root:
            route = self.task(root)
            self.ask(root)
            self.answer(root)
            current = state.get_active_route(root)
            self.assertEqual(current['intent'], route['intent'])
            self.assertIsInstance(current['intent'], str)
            rendered = continuity.render_context(root, current)
            self.assertIn('Q-001', rendered)
            self.assertIn('A returns the count of active rows.', rendered)

    def test_windows_separator_cannot_hide_affected_shell_write(self):
        with project_copy(git=True) as root:
            self.task(root)
            self.ask(root)
            with windows_command_parser():
                allowed, reason = evaluate_pre_tool(root, {'tool_name': 'Bash', 'tool_input': {'command': 'echo changed > src\\a.py'}})
            self.assertFalse(allowed)
            self.assertIn('Q-001', reason)

    def test_human_can_explicitly_withdraw_a_question_after_requirement_removal(self):
        with project_copy(git=True) as root:
            self.task(root)
            self.ask(root)
            directory = root / state.get_active_change(root)['path']
            spec = load_spec(directory / 'change-spec.yaml')
            spec['acceptance_criteria'] = [spec['acceptance_criteria'][1]]
            (directory / 'change-spec.yaml').write_text(dump_canonical_spec(spec))
            from getzilla.task_intent import intent_gaps, target_digest
            route = state.get_active_route(root)
            question = route['intent_state']['questions'][0]
            try:
                binding = target_digest(root, route, question, allow_missing=True)
            except TypeError:
                self.fail('A human cannot withdraw a question whose affected requirement was removed.')
            answer = {'text': 'Remove A from the task; this count is no longer required.', 'source_kind': 'human',
                      'source_ref': 'fixture-human-event:remove-A', 'principal': 'owner',
                      'event_id': 'fixture-remove-A', 'target_digest': binding}
            self.api()(root, self.request(root, {'kind': 'withdraw', 'id': 'Q-001', 'answer': answer}, 'withdraw-A'))
            self.assertEqual(intent_gaps(root, state.get_active_route(root)), [])
            self.assertEqual(len(state.get_active_route(root)['intent_state']['questions']), 1)

    def test_native_worker_and_package_transition_can_name_independent_requirement(self):
        from getzilla.change import transition
        with project_copy(git=True) as root:
            route = self.task(root)
            change_id = route['change_id']
            for target in ('scoped', 'approved'):
                transition(root, change_id, target, 'Fixture implements an already delegated task.')
            self.ask(root)
            with self.assertRaisesRegex(ValueError, 'Q-001'):
                transition(root, change_id, 'implementing', 'Implement the whole task.')
            try:
                transition(root, change_id, 'implementing', 'Implement independent B.', requirement_ids=('AC-002',))
                worker = state.record_agent_start(root, 'fixture-independent-B', route['write_agent'], requirement_ids=('AC-002',))
            except TypeError:
                self.fail('Native lifecycle and package operations cannot express an independent implementation scope.')
            self.assertEqual(worker['requirement_ids'], ['AC-002'])

    def test_handoff_preserves_question_and_revokes_old_answer_request(self):
        with project_copy(git=True) as root:
            self.task(root, light=True)
            self.ask(root, targets=['original'], paths=['README.md'])
            route = state.get_active_route(root)
            old_request = self.request(root, {'kind': 'answer', 'id': 'Q-001', 'answer': {}}, 'old-owner-answer')
            current = continuity.submit(root, '', 'next-intent-owner', continue_route=route['route_id'],
                expected_epoch=route['authority_epoch'], expected_revision=route['state_revision'], request_id='intent-handoff')
            self.assertEqual(current['intent_state'], route['intent_state'])
            with self.assertRaises(ValueError):
                self.api()(root, old_request)
            self.assertIn('Q-001', continuity.render_context(root, current))

    def test_missing_meaning_can_be_registered_while_typed_package_is_still_a_draft(self):
        with project_copy(git=True) as root:
            state.bind_session('intent-owner')
            continuity.submit(root, 'Implement API count A; its exact count needs a human answer.', 'intent-owner', new_task=True)
            start_change(root)
            try:
                self.ask(root, targets=['OBJ-001'], paths=['src/a.py'])
            except ValueError as exc:
                self.fail('Draft requirements must permit recording the missing meaning before implementation: ' + str(exc))
            allowed, reason = evaluate_pre_tool(root, {'tool_name': 'Edit', 'tool_input': {'file_path': 'src/a.py'}})
            self.assertFalse(allowed)
            self.assertIn('Q-001', reason)

    def test_unsynchronized_amendment_blocks_product_write_and_preserves_analysis(self):
        with project_copy(git=True) as root:
            self.task(root)
            continuity.submit(root, 'Amendment: A must include archived rows, subject to the retention rule.',
                              'intent-owner', event_id='new-A')
            for path in ('src/a.py', 'src/b.py'):
                allowed, reason = evaluate_pre_tool(root, {'tool_name': 'Edit', 'tool_input': {'file_path': path}})
                self.assertFalse(allowed)
                self.assertIn('scope_sync_required', reason)
            for event in (
                {'tool_name': 'Read', 'tool_input': {'file_path': 'src/a.py'}},
                {'tool_name': 'Bash', 'tool_input': {'command': 'python3 -m unittest tests.test_intent_contract'}},
            ):
                self.assertTrue(evaluate_pre_tool(root, event)[0], event)
            from getzilla.task_intent import mutation_block_reason
            report = {'tool_name': 'Write', 'tool_input': {'file_path': '.getzilla/runtime/audit/inspection.md'}}
            self.assertIsNone(mutation_block_reason(root, report, execution_cwd=root))
            self.assertIn('cannot establish independence', mutation_block_reason(root, report, execution_cwd=None))
            self.assertIn('scope_sync_required', mutation_block_reason(root, report, execution_cwd=root / 'src'))
            nested_report = {'tool_name': 'Write', 'tool_input': {'file_path': '../.getzilla/runtime/audit/inspection.md'}}
            self.assertIsNone(mutation_block_reason(root, nested_report, execution_cwd=root / 'src'))

    def test_explicit_amendment_impact_preserves_independent_path_and_worker(self):
        with project_copy(git=True) as root:
            self.task(root)
            route = continuity.submit(root, 'Amendment: A must include archived rows; B is unchanged.',
                                      'intent-owner', event_id='new-A')
            pending = route['context']['pending'][0]['id']
            self.ask(root, targets=[pending, 'AC-001'], paths=['src/a.py'])
            self.assertTrue(evaluate_pre_tool(root, {'tool_name': 'Edit', 'tool_input': {'file_path': 'src/b.py'}})[0])
            self.assertFalse(evaluate_pre_tool(root, {'tool_name': 'Edit', 'tool_input': {'file_path': 'src/a.py'}})[0])
            worker = state.record_agent_start(root, 'fixture-amendment-B', route['write_agent'], requirement_ids=('AC-002',))
            self.assertEqual(worker['requirement_ids'], ['AC-002'])

    def test_unadmitted_input_does_not_allow_product_writes(self):
        with project_copy(git=True) as root:
            self.task(root, light=True)
            with self.assertRaises(ValueError):
                continuity.submit(root, 'Amendment ' + 'x' * 9000, 'intent-owner', event_id='too-large')
            allowed, reason = evaluate_pre_tool(root, {'tool_name': 'Edit', 'tool_input': {'file_path': 'src/a.py'}})
            self.assertFalse(allowed)
            self.assertIn('scope_sync_required', reason)

    def test_configured_tool_criterion_is_not_duplicated_by_the_native_python_runner(self):
        from getzilla.verification_plan import _native_obligations
        with project_copy(git=True) as root:
            route = self.task(root)
            (root / '.getzilla-verification.json').write_text(json.dumps({'schema_version': 1, 'checks': [{
                'id': 'browser-contract', 'tool': 'playwright', 'commands': [['node', 'run-browser-tests.js']],
                'criteria': {'AC-001': ['tests/test_intent_contract.py']}}]}))
            obligations = _native_obligations(root, 'pr', route, {})
            named = {item['id']: item for item in obligations}
            self.assertNotIn('AC-001:tests', named)
            self.assertIn('AC-002:tests', named)
            self.assertEqual(named['tool:browser-contract']['expected_tests'], ['tests/test_intent_contract.py'])
            self.assertEqual(named['tool:browser-contract']['requirement_ids'], ['AC-001'])

    def test_absolute_windows_question_path_cannot_masquerade_as_relative_scope(self):
        with project_copy(git=True) as root:
            self.task(root)
            for path in ('C:/project/src/a.py', 'src//'):
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'affected paths'):
                    self.ask(root, paths=[path])

    def test_deleting_parent_directory_is_an_affected_mutation(self):
        from getzilla.task_intent import mutation_block_reason
        with project_copy(git=True) as root:
            self.task(root)
            self.ask(root, paths=['src/a.py'])
            event = {'tool_name': 'Bash', 'tool_input': {'command': 'rm -rf src'}}
            # Evaluate only: no command from this test is executed. An unknown cwd would
            # refuse the write before checking overlap and conceal the ancestor regression.
            reason = mutation_block_reason(root, event, execution_cwd=root)
            self.assertIsNotNone(reason)
            self.assertIn('Q-001', reason)
            allowed, reason = evaluate_pre_tool(root, event, execution_cwd=root)
            self.assertFalse(allowed)
            self.assertIn('Q-001', reason)

    def _assert_intent_decision(self, root, event, *, execution_cwd, expected):
        """Exercise both native consumers with a known cwd; never execute shell text."""
        from getzilla.task_intent import mutation_block_reason
        reason = mutation_block_reason(root, event, execution_cwd=execution_cwd)
        allowed, policy_reason = evaluate_pre_tool(root, event, execution_cwd=execution_cwd)
        if expected is None:
            self.assertIsNone(reason, event)
            self.assertTrue(allowed, (event, policy_reason))
        else:
            self.assertIsNotNone(reason, event)
            self.assertIn(expected, reason)
            self.assertFalse(allowed, event)
            self.assertIn(expected, policy_reason)

    def test_affected_path_overlap_preserves_component_boundaries(self):
        cases = (
            ('src/a.py', ('src/a.py', 'src', '.', 'src/../src/a.py'),
             ('src/b.py', 'src/a.py.backup', 'src/ab.py', 'src2/a.py')),
            ('src/', ('src', 'src/', 'src/a.py', 'src/nested/item.py', '.'),
             ('src2', 'src2/a.py', 'src-backup/a.py')),
            ('src/components', ('src/components', 'src/components/item.py', 'src', '.'),
             ('src/component', 'src/components-extra/item.py', 'src2/components')),
        )
        for affected, blocked, independent in cases:
            with self.subTest(affected=affected), project_copy(git=True) as root:
                self.task(root)
                (root / 'src/components').mkdir()
                self.ask(root, paths=[affected])
                for expected, paths in (('Q-001', blocked), (None, independent)):
                    for path in paths:
                        for target in (path, str(root / path)):
                            with self.subTest(target=target, expected=expected):
                                event = {'tool_name': 'Write', 'tool_input': {'file_path': target, 'content': 'changed'}}
                                self._assert_intent_decision(root, event, execution_cwd=root, expected=expected)

    def test_structural_targets_use_resolved_relative_and_absolute_execution_paths(self):
        with project_copy(git=True) as root:
            self.task(root)
            self.ask(root, paths=['src/a.py'])
            candidates = (
                (root, 'mv src renamed', 'Q-001'),
                (root, 'mv ./src/../src renamed', 'Q-001'),
                (root, 'mv ' + shlex.quote(str(root / 'src')) + ' renamed', 'Q-001'),
                (root / 'src', 'mv . ../renamed', 'Q-001'),
                (root / 'src', 'mv a.py ../renamed.py', 'Q-001'),
                (root, 'mv src/b.py independent.py', None),
                (root, 'mv src2 renamed', None),
                (root / 'src', 'mv b.py ../independent.py', None),
            )
            for cwd, command, expected in candidates:
                with self.subTest(cwd=cwd, command=command):
                    event = {'tool_name': 'Bash', 'tool_input': {'command': command}}
                    self._assert_intent_decision(root, event, execution_cwd=cwd, expected=expected)

    def test_pending_amendment_regions_keep_ancestor_boundaries_after_question_answer(self):
        from getzilla.task_intent import intent_gaps
        for affected, blocked, independent in (
            ('src/a.py', ('src/a.py', 'src', '.'), ('src/b.py', 'src2/a.py')),
            ('src/', ('src', 'src/', 'src/nested/a.py', '.'), ('src2', 'src2/a.py')),
        ):
            with self.subTest(affected=affected), project_copy(git=True) as root:
                self.task(root)
                route = continuity.submit(root, 'Amendment: A must include archived rows; B is unchanged.',
                                          'intent-owner', event_id='ancestor-amendment')
                pending = route['context']['pending'][0]['id']
                self.ask(root, targets=[pending, 'AC-001'], paths=[affected])
                self.answer(root)
                self.assertEqual(intent_gaps(root, state.get_active_route(root)), [])
                self.assertTrue(state.get_active_route(root)['context']['pending'])
                for expected, paths in (('scope_sync_required', blocked), (None, independent)):
                    for target in paths:
                        with self.subTest(target=target, expected=expected):
                            event = {'tool_name': 'Write', 'tool_input': {'file_path': target, 'content': 'changed'}}
                            self._assert_intent_decision(root, event, execution_cwd=root, expected=expected)
                event = {'tool_name': 'Bash', 'tool_input': {'command': 'mv src renamed'}}
                self._assert_intent_decision(root, event, execution_cwd=root, expected='scope_sync_required')

    def test_answered_question_allows_parent_until_its_answer_becomes_stale(self):
        with project_copy(git=True) as root:
            self.task(root)
            self.ask(root, paths=['src/'])
            event = {'tool_name': 'Bash', 'tool_input': {'command': 'mv src renamed'}}
            self._assert_intent_decision(root, event, execution_cwd=root, expected='Q-001')
            self.answer(root)
            self._assert_intent_decision(root, event, execution_cwd=root, expected=None)
            spec_path = root / state.get_active_change(root)['path'] / 'change-spec.yaml'
            spec = load_spec(spec_path)
            spec['acceptance_criteria'][0]['statement'] = 'A now counts archived rows.'
            spec_path.write_text(dump_canonical_spec(spec))
            self._assert_intent_decision(root, event, execution_cwd=root, expected='Q-001')
            sibling = {'tool_name': 'Write', 'tool_input': {'file_path': 'src2/a.py', 'content': 'changed'}}
            self._assert_intent_decision(root, sibling, execution_cwd=root, expected=None)

    def _patch_event(self, action, target, *, destination=None):
        lines = ['*** Begin Patch', f'*** {action} File: {target}']
        if destination is not None:
            lines.append(f'*** Move to: {destination}')
        if action == 'Add':
            lines.append('+value = 2')
        elif action == 'Update':
            lines.extend(['@@', '-value = 1', '+value = 2'])
        lines.append('*** End Patch')
        return {'tool_name': 'apply_patch', 'tool_input': {'patch': '\n'.join(lines) + '\n'}}

    def test_structured_targets_resolve_known_nested_cwd(self):
        with project_copy(git=True) as root:
            self.task(root)
            self.ask(root, paths=['src/a.py', 'src/new.py', 'src/locked/'])
            (root / 'src/alias.py').symlink_to(root / 'src/a.py')
            cases = []
            for target in ('a.py', './a.py', 'nested/../a.py', str(root / 'src/a.py'),
                           'alias.py', '.', 'locked', 'locked/', 'locked/nested.py'):
                cases.append(({'tool_name': 'Write', 'tool_input': {'file_path': target}}, 'Q-001'))
            for target in ('b.py', 'a.py.backup', '../src2/a.py', 'locked-extra/a.py'):
                cases.append(({'tool_name': 'Write', 'tool_input': {'file_path': target}}, None))
            cases.extend([
                ({'tool_name': 'Edit', 'tool_input': {'file_path': 'a.py'}}, 'Q-001'),
                ({'tool_name': 'MultiEdit', 'tool_input': {'edits': [{'file_path': 'b.py'}, {'file_path': 'a.py'}]}}, 'Q-001'),
                ({'tool_name': 'MultiEdit', 'tool_input': {'edits': [{'file_path': 'b.py'}]}}, None),
                (self._patch_event('Add', 'new.py'), 'Q-001'),
                (self._patch_event('Update', 'a.py'), 'Q-001'),
                (self._patch_event('Delete', 'a.py'), 'Q-001'),
                (self._patch_event('Update', 'b.py', destination='a.py'), 'Q-001'),
                (self._patch_event('Update', 'b.py', destination=str(root / 'src/new.py')), 'Q-001'),
                (self._patch_event('Update', 'a.py', destination='renamed.py'), 'Q-001'),
                (self._patch_event('Update', 'b.py', destination='renamed.py'), None),
                ({'tool_name': 'Bash', 'tool_input': {'command': 'printf changed > a.py'}}, 'Q-001'),
                ({'tool_name': 'Bash', 'tool_input': {'command': 'printf changed > b.py'}}, None),
            ])
            for event, expected in cases:
                with self.subTest(event=event, expected=expected):
                    self._assert_intent_decision(root, event, execution_cwd=root / 'src', expected=expected)

    def test_structured_relative_targets_require_trusted_execution_cwd(self):
        with project_copy(git=True) as root:
            self.task(root)
            self.ask(root)
            for cwd in (None, root.parent, root / 'missing-cwd'):
                for event in (
                    {'tool_name': 'Write', 'tool_input': {'file_path': 'b.py'}},
                    {'tool_name': 'Edit', 'tool_input': {'file_path': root.name + '/src/b.py'}},
                    {'tool_name': 'MultiEdit', 'tool_input': {'edits': [{'file_path': 'b.py'}]}},
                    self._patch_event('Add', 'unrelated.py'),
                ):
                    with self.subTest(cwd=cwd, event=event):
                        self._assert_intent_decision(root, event, execution_cwd=cwd, expected='cannot establish independence')
            for target, expected in ((root / 'src/a.py', 'Q-001'), (root / 'src/b.py', None),
                                     (root.parent / 'outside.py', 'cannot establish independence')):
                with self.subTest(absolute=target):
                    event = {'tool_name': 'Write', 'tool_input': {'file_path': str(target)}}
                    self._assert_intent_decision(root, event, execution_cwd=None, expected=expected)
            # The ordinary policy must use the same cwd even after all intent is answered.
            self.answer(root)
            (root / 'src2').mkdir()
            outside = root.parent / 'outside'
            outside.mkdir()
            (root / 'src/in-repo').symlink_to(root / 'src2', target_is_directory=True)
            (root / 'src/outside-link').symlink_to(outside, target_is_directory=True)
            (root / 'src/protected-link').symlink_to(root / '.grok', target_is_directory=True)
            cases = [
                (root / 'src', {'tool_name': 'Write', 'tool_input': {'file_path': '../src2/a.py'}}, True),
                (root / 'src', {'tool_name': 'Edit', 'tool_input': {'file_path': 'in-repo/a.py'}}, True),
                (root / 'src', {'tool_name': 'Write', 'tool_input': {'file_path': '../../outside/a.py'}}, False),
                (root / 'src', {'tool_name': 'Write', 'tool_input': {'file_path': 'outside-link/a.py'}}, False),
                (root / 'src', {'tool_name': 'Edit', 'tool_input': {'file_path': '../AGENTS.md'}}, False),
                (root / '.grok', {'tool_name': 'Write', 'tool_input': {'file_path': 'hooks/pre_tool_use.py'}}, False),
                (root / 'src', {'tool_name': 'Write', 'tool_input': {'file_path': 'protected-link/hooks/pre_tool_use.py'}}, False),
                (root / 'src', {'tool_name': 'MultiEdit', 'tool_input': {'edits': [{'file_path': 'b.py'}, {'file_path': '../AGENTS.md'}]}}, False),
                (root / 'src', self._patch_event('Update', 'b.py', destination='../AGENTS.md'), False),
                (root / 'src', self._patch_event('Update', '../AGENTS.md', destination='b.py'), False),
                (root / 'src', self._patch_event('Update', 'b.py', destination='../src2/a.py'), True),
                (root / 'src', self._patch_event('Update', 'b.py', destination='../../outside/a.py'), False),
                (None, {'tool_name': 'Write', 'tool_input': {'file_path': 'b.py'}}, False),
                (root.parent, {'tool_name': 'Write', 'tool_input': {'file_path': root.name + '/src/b.py'}}, False),
            ]
            for cwd, event, expected in cases:
                with self.subTest(cwd=cwd, event=event, allowed=expected):
                    allowed, reason = evaluate_pre_tool(root, event, execution_cwd=cwd)
                    self.assertEqual(allowed, expected, reason)

    def test_nested_structured_targets_preserve_pending_and_answer_freshness(self):
        with project_copy(git=True) as root:
            self.task(root)
            self.ask(root)
            event = {'tool_name': 'Edit', 'tool_input': {'file_path': 'a.py'}}
            self._assert_intent_decision(root, event, execution_cwd=root / 'src', expected='Q-001')
            self.answer(root)
            self._assert_intent_decision(root, event, execution_cwd=root / 'src', expected=None)
            spec_path = root / state.get_active_change(root)['path'] / 'change-spec.yaml'
            spec = load_spec(spec_path)
            spec['acceptance_criteria'][0]['statement'] = 'A now counts archived rows.'
            spec_path.write_text(dump_canonical_spec(spec))
            self._assert_intent_decision(root, event, execution_cwd=root / 'src', expected='Q-001')
            sibling = {'tool_name': 'Edit', 'tool_input': {'file_path': 'b.py'}}
            self._assert_intent_decision(root, sibling, execution_cwd=root / 'src', expected=None)
        with project_copy(git=True) as root:
            from getzilla.task_intent import intent_gaps
            self.task(root)
            route = continuity.submit(root, 'Amendment: A changes while B remains independent.',
                                      'intent-owner', event_id='nested-amendment')
            pending = route['context']['pending'][0]['id']
            self.ask(root, targets=[pending, 'AC-001'], paths=['src/a.py'])
            self.answer(root)
            self.assertEqual(intent_gaps(root, state.get_active_route(root)), [])
            for event, expected in (
                ({'tool_name': 'Write', 'tool_input': {'file_path': 'a.py'}}, 'scope_sync_required'),
                (self._patch_event('Update', 'b.py', destination='a.py'), 'scope_sync_required'),
                ({'tool_name': 'Write', 'tool_input': {'file_path': 'b.py'}}, None),
                (self._patch_event('Update', 'b.py', destination='renamed.py'), None),
            ):
                with self.subTest(event=event):
                    self._assert_intent_decision(root, event, execution_cwd=root / 'src', expected=expected)

    def test_native_nested_patch_checks_intent_and_pending_amendment(self):
        from getzilla.hook_health import route_degraded_events
        from tests._support import run_hook
        with project_copy(git=True) as root:
            self.task(root)
            self.ask(root, paths=['src/a.py', 'src/new.py'])
            (root / 'src2').mkdir()
            original = {name: (root / 'src' / name).read_bytes() for name in ('a.py', 'b.py')}

            def observe(event, expected):
                inputs = event['tool_input']
                if event['tool_name'] == 'apply_patch':
                    inputs = {'input': inputs['patch']}
                code, result, stderr = run_hook(root, 'pre_tool_use.py', {
                    'cwd': str(root / 'src'), 'session_id': 'intent-owner',
                    'tool_name': event['tool_name'], 'tool_input': inputs,
                }, harness='codex')
                self.assertEqual(code, 0, stderr)
                self.assertEqual(stderr, '')
                if expected is None:
                    self.assertEqual(result, {})
                else:
                    decision = result.get('hookSpecificOutput', {})
                    self.assertEqual(decision.get('permissionDecision'), 'deny', result)
                    self.assertIn(expected, decision.get('permissionDecisionReason', ''))

            self.assertEqual(route_degraded_events(root, state.get_active_route(root)), [])
            for event in (
                {'tool_name': 'Write', 'tool_input': {'file_path': 'a.py'}},
                {'tool_name': 'Write', 'tool_input': {'file_path': str(root / 'src/a.py')}},
                {'tool_name': 'Edit', 'tool_input': {'file_path': 'a.py'}},
                {'tool_name': 'MultiEdit', 'tool_input': {'file_path': 'a.py', 'edits': []}},
                {'tool_name': 'Bash', 'tool_input': {'command': 'printf changed > a.py'}},
                self._patch_event('Add', 'new.py'),
                self._patch_event('Update', 'b.py', destination='new.py'),
            ):
                with self.subTest(event=event):
                    observe(event, 'Q-001')
            observe({'tool_name': 'Write', 'tool_input': {'file_path': 'b.py'}}, None)
            observe({'tool_name': 'Write', 'tool_input': {'file_path': '../src2/a.py'}}, None)
            observe({'tool_name': 'Bash', 'tool_input': {'command': 'printf changed > b.py'}}, None)
            self.answer(root)
            route = continuity.submit(root, 'Amendment: define the new A endpoint; B is unchanged.',
                                      'intent-owner', event_id='native-nested-amendment')
            pending = route['context']['pending'][0]['id']
            self.ask(root, targets=[pending, 'AC-001'], paths=['src/new.py'], identifier='Q-PENDING')
            self.answer(root, identifier='Q-PENDING', operation_id='answer-pending')
            observe(self._patch_event('Add', 'new.py'), 'scope_sync_required')
            observe(self._patch_event('Update', 'b.py', destination='new.py'), 'scope_sync_required')
            observe({'tool_name': 'Write', 'tool_input': {'file_path': 'b.py'}}, None)
            self.assertEqual(route_degraded_events(root, state.get_active_route(root)), [])
            self.assertEqual({name: (root / 'src' / name).read_bytes() for name in original}, original)
            self.assertFalse((root / 'src/new.py').exists())

    def test_new_human_resolution_changes_completion_context_even_with_same_missing_receipt(self):
        from getzilla.completion import observe_remaining
        with project_copy(git=True) as root:
            self.task(root)
            self.ask(root)
            self.answer(root)
            before = observe_remaining(state.get_active_route(root), None, [], ['verification: missing receipt'])
            route = state.get_active_route(root)
            answer = copy.deepcopy(route['intent_state']['questions'][0]['answer'])
            answer.pop('resolution')
            answer.update(text='Count only archived rows, per the revised human decision.', source_ref='fixture:revised-answer')
            self.api()(root, self.request(root, {'kind': 'answer', 'id': 'Q-001', 'answer': answer}, 'revised-answer'))
            after = observe_remaining(state.get_active_route(root), None, [], ['verification: missing receipt'])
            self.assertNotEqual(before['fingerprint'], after['fingerprint'])


if __name__ == '__main__':
    unittest.main()
