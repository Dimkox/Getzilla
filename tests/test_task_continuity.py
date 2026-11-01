"""Behavioral continuity controls: real hooks, CLI, package and worker consumers."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

from tests._support import PROJECT, project_copy, run_hook

sys.path.insert(0, str(PROJECT / '.getzilla'))
from getzilla import state
from getzilla.agent_lifecycle import start_agent, update_agent
from getzilla.change import start_change
from getzilla.router import build_route

ORIGINAL = 'Fix API authentication, database migration and PDF catalogue. Preserve every acceptance criterion.'


class ContinuityTests(unittest.TestCase):
    def setUp(self):
        state.bind_session(None)

    def tearDown(self):
        state.bind_session(None)

    def route(self, root, session='s1'):
        route = build_route(root, ORIGINAL, session).to_dict()
        state.bind_session(session)
        state.set_active_route(root, route)
        state.bind_session(session)
        return state.get_active_route(root)

    def cli(self, root, *args):
        return subprocess.run([sys.executable, str(PROJECT / 'scripts/getzilla_route.py'), *args],
                              cwd=root, env={**os.environ, 'GETZILLA_SESSION_ID': ''},
                              capture_output=True, text=True, timeout=20)

    def submit(self, root, text, **kwargs):
        from getzilla.continuity import submit
        return submit(root, text, 's1', **kwargs)

    def light_route(self, root):
        route = build_route(root, 'Fix a typo in README documentation.', 's1').to_dict()
        state.bind_session('s1')
        state.set_active_route(root, route)
        state.bind_session('s1')
        return route

    def package(self, root):
        from getzilla.spec import load_spec, dump_canonical_spec
        (root / 'tests').mkdir(exist_ok=True)
        shutil.copyfile(__file__, root / 'tests/test_task_continuity.py')
        package = start_change(root)
        path = root / state.get_active_change(root)['path']
        spec = load_spec(path / 'change-spec.yaml')
        spec['objective'].update(success_metric='behavior controls', target='all admitted scope retained')
        spec['acceptance_criteria'] = [{'id': 'AC-001', 'statement': ORIGINAL,
                                       'evidence': [{'test': 'tests/test_task_continuity.py'}]}]
        spec['forbidden_outcomes'] = [{'id': 'FORBID-001', 'statement': 'No lost requirement.',
                                      'evidence': [{'test': 'tests/test_task_continuity.py'}]}]
        spec['approvals']['required_scopes'] = ['scope_and_design_approval']
        (path / 'change-spec.yaml').write_text(dump_canonical_spec(spec))
        (path / 'requirements.md').write_text(ORIGINAL + '\nAmendments A and B are retained in typed AC-001.\n')
        return package, path

    def ack_request(self, root, ids=()):
        from getzilla.continuity import context_binding
        route = state.get_active_route(root)
        binding = context_binding(root)
        return {'version': 1, 'operation_id': 'ack-' + str(route['context']['revision']),
                'route_id': route['route_id'], 'logical_task_id': route['logical_task_id'],
                'authority_epoch': route['authority_epoch'], 'revision': route['context']['revision'],
                'spec_digest': binding['spec_digest'], 'requirements_digest': binding['requirements_digest'],
                'items': {'original': ['OBJ-001'], **{item: ['AC-001'] for item in ids}}}

    def test_hook_keeps_original_and_qualified_followup_as_pending(self):
        with project_copy(git=True) as root:
            original = self.route(root)
            code, data, err = run_hook(root, 'user_prompt_submit.py', {
                'cwd': str(root), 'session_id': 's1',
                'prompt': 'Продолжай работу по текущему ТЗ до полного завершения.'})
            self.assertEqual(code, 0, err)
            current = state.get_active_route(root)
            self.assertEqual(current['route_id'], original['route_id'])
            self.assertEqual(current['task'], ORIGINAL)
            self.assertEqual(current['risk'], original['risk'])
            self.assertIn(ORIGINAL, data['hookSpecificOutput']['additionalContext'])

    def test_cli_continuation_keeps_original_and_show_selects_session(self):
        with project_copy(git=True) as root:
            first = self.route(root)
            self.route(root, 's2')
            result = self.cli(root, '--show', '--session', 's1', '--json')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['route_id'], first['route_id'])
            result = self.cli(root, 'continue', '--session', 's1', '--json')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['task'], ORIGINAL)

    def test_agent_and_progress_identity_survive_real_package_attachment(self):
        from getzilla.session_progress import scope_id
        with project_copy(git=True) as root:
            route = self.route(root)
            record = start_agent(root, 'child', route['write_agent'])
            scope = scope_id(root, 's1', 'child', record['generation'])
            start_change(root)
            current = update_agent(root, 'child', record['generation'], record['route_id'],
                                   record['task_id'], 'progress', checkpoint='implementation')
            self.assertEqual(current['task_id'], record['task_id'])
            self.assertEqual(scope_id(root, 's1', 'child', record['generation']), scope)

    def test_original_a_b_restart_exact_replay_and_collision(self):
        with project_copy(git=True) as root:
            original = self.route(root)
            self.submit(root, 'Amendment A: keep access controls.', event_id='a')
            current = self.submit(root, 'Amendment B: retain Unicode.', event_id='b')
            replay = self.submit(root, 'Amendment A: keep access controls.', event_id='a')
            self.assertEqual(replay, current)
            with self.assertRaises(ValueError):
                self.submit(root, 'Changed bytes.', event_id='a')
            result = self.cli(root, '--show', '--session', 's1', '--json')
            self.assertEqual(result.returncode, 0, result.stderr)
            stored = json.loads(result.stdout)
            self.assertEqual(stored['task'], ORIGINAL)
            self.assertEqual(stored['route_id'], original['route_id'])
            self.assertEqual([item['text'] for item in stored['context']['pending']],
                             ['Amendment A: keep access controls.', 'Amendment B: retain Unicode.'])

    def test_same_text_explicit_new_task_is_fresh_and_ready_continues(self):
        with project_copy(git=True) as root:
            route = self.light_route(root)
            state.update_route(root, status='ready')
            current = self.submit(root, 'continue')
            self.assertEqual(current['route_id'], route['route_id'])
            result = self.cli(root, '--new-task', route['task'], '--session', 's1', '--json')
            self.assertEqual(result.returncode, 0, result.stderr)
            fresh = json.loads(result.stdout)
            self.assertNotEqual(fresh['route_id'], route['route_id'])
            self.assertNotEqual(fresh['logical_task_id'], route['logical_task_id'])

    def test_oversized_first_amendment_latches_without_losing_prior_scope(self):
        from getzilla.continuity import scope_gaps
        with project_copy(git=True) as root:
            original = self.light_route(root)
            text = 'я' * 4097
            with self.assertRaisesRegex(ValueError, 'scope_sync_required'):
                self.submit(root, text)
            current = state.get_active_route(root)
            self.assertEqual(current['route_id'], original['route_id'])
            self.assertEqual(current['context']['pending'], [])
            self.assertEqual(current['context']['rejected']['digest'], hashlib.sha256(text.encode()).hexdigest())
            self.assertTrue(scope_gaps(root))

    def test_scope_ack_strict_revision_mapping_and_document_drift(self):
        from getzilla.continuity import ack_scope, scope_gaps
        with project_copy(git=True) as root:
            self.route(root)
            self.submit(root, 'Amendment A: retain original scope.', event_id='a')
            self.submit(root, 'Amendment B: preserve the negative controls.', event_id='b')
            _, path = self.package(root)
            original = state.get_active_route(root)
            first, second = [item['id'] for item in original['context']['pending']]
            request = self.ack_request(root, [first])
            with self.assertRaises(ValueError):
                ack_scope(root, {**request, 'revision': request['revision'] - 1})
            with self.assertRaises(ValueError):
                ack_scope(root, {**request, 'items': {'original': ['OBJ-404']}})
            self.assertEqual(state.get_active_route(root), original)
            current = ack_scope(root, request)
            self.assertEqual([item['id'] for item in current['context']['pending']], [second])
            self.assertTrue(scope_gaps(root))
            final = ack_scope(root, self.ack_request(root, [second]))
            self.assertFalse(scope_gaps(root))
            self.assertEqual(ack_scope(root, self.ack_request(root, []))['task'], ORIGINAL)
            (path / 'requirements.md').write_text(ORIGINAL + '\nchanged bytes\n')
            self.assertTrue(scope_gaps(root))
            self.assertEqual(final['logical_task_id'], original['logical_task_id'])

    def test_scope_ack_package_first_crash_and_exact_retry(self):
        from getzilla.continuity import ack_scope
        with project_copy(git=True) as root:
            self.route(root)
            current = self.submit(root, 'Amendment A: preserve retry recovery.', event_id='a')
            _, path = self.package(root)
            request = self.ack_request(root, [current['context']['pending'][0]['id']])
            before = state.get_active_route(root)
            with patch('getzilla.state._commit_route', side_effect=OSError('injected canonical publication failure')):
                with self.assertRaises(OSError):
                    ack_scope(root, request)
            self.assertEqual(state.get_active_route(root), before)
            self.assertIn('scope_ack', json.loads((path / 'state.json').read_text()))
            with self.assertRaises(ValueError):
                ack_scope(root, {**request, 'operation_id': 'another-operation'})
            after = ack_scope(root, request)
            self.assertEqual(ack_scope(root, request), after)
            self.assertEqual(after['context']['pending'], [])

    def test_handoff_revokes_old_pointer_and_repairs_publication_without_rerotation(self):
        from getzilla.continuity import submit
        with project_copy(git=True) as root:
            before = self.light_route(root)
            args = {'continue_route': before['route_id'], 'expected_epoch': before['authority_epoch'],
                    'expected_revision': before['state_revision'], 'request_id': 'handoff-1'}
            with patch('getzilla.state._publish_route_projections', side_effect=OSError('projection failed')):
                with self.assertRaises(OSError):
                    submit(root, '', 's2', **args)
            moved = state.canonical_route(root, before['route_id'])
            self.assertEqual(moved['authority_epoch'], 1)
            retry = submit(root, '', 's2', **args)
            self.assertEqual(retry, moved)
            state.bind_session('s1')
            self.assertIsNone(state.get_active_route(root))
            with self.assertRaises(ValueError):
                start_agent(root, 'late-child', before['write_agent'])

    def test_metadata_setters_cannot_erase_context_or_rebind_package(self):
        with project_copy(git=True) as root:
            route = self.route(root)
            for updates in ({'task': 'replacement'}, {'context': {}}, {'authority_epoch': 2}, {'change_id': 'alien'}):
                with self.subTest(updates=updates), self.assertRaises(ValueError):
                    state.update_route(root, **updates)
            self.assertEqual(state.get_active_route(root), route)

    def test_unbound_global_discovery_cannot_spend_or_create_grants(self):
        with project_copy(git=True) as root:
            route = self.light_route(root)
            subprocess.run(['git', 'remote', 'add', 'origin', 'https://github.com/example/fixture.git'], cwd=root, check=True)
            state.add_approval(root, 'protected-path', 'explicit fixture consent', actions=['protected-path-write'], resources=['AGENTS.md'])
            before = state.approvals_path(root).read_bytes()
            state.bind_session(None)
            self.assertEqual(state.get_active_route(root)['route_id'], route['route_id'])
            with self.assertRaises(ValueError):
                start_agent(root, 'unbound', route['write_agent'])
            self.assertFalse(state.has_valid_approval(root, 'protected-path', action='protected-path-write', resource='AGENTS.md'))
            with self.assertRaises(ValueError):
                state.add_approval(root, 'protected-path', 'unbound fixture', actions=['protected-path-write'], resources=['AGENTS.md'])
            self.assertEqual(state.approvals_path(root).read_bytes(), before)

    def test_grants_reject_old_epoch_for_old_and_new_callers(self):
        from getzilla.continuity import submit
        with project_copy(git=True) as root:
            before = self.light_route(root)
            subprocess.run(['git', 'remote', 'add', 'origin', 'https://github.com/example/fixture.git'], cwd=root, check=True)
            state.add_approval(root, 'protected-path', 'explicit fixture consent', actions=['protected-path-write'], resources=['AGENTS.md'])
            self.assertTrue(state.has_valid_approval(root, 'protected-path', action='protected-path-write', resource='AGENTS.md'))
            submit(root, '', 's2', continue_route=before['route_id'], expected_epoch=0,
                   expected_revision=before['state_revision'], request_id='handoff-grant')
            for owner in ('s1', 's2', None):
                state.bind_session(owner)
                self.assertFalse(state.has_valid_approval(root, 'protected-path', action='protected-path-write', resource='AGENTS.md'))

    def test_receipt_requires_observed_context_and_rejects_new_scope(self):
        from getzilla.continuity import context_binding
        from getzilla.receipts import write_receipt
        with project_copy(git=True) as root:
            self.light_route(root)
            state.update_route(root, risk_assessment=None)
            with self.assertRaisesRegex((ValueError, RuntimeError), 'observed|context'):
                write_receipt(root, 'verification', 'pass')
            observed = context_binding(root)
            self.submit(root, 'Add a substantive acceptance criterion.')
            with self.assertRaisesRegex((ValueError, RuntimeError), 'context|scope'):
                write_receipt(root, 'verification', 'pass', expected_context=observed)

    def test_malformed_session_locator_never_falls_back_to_global_authority(self):
        with project_copy(git=True) as root:
            route = self.light_route(root)
            pointer = root / '.getzilla/runtime/sessions/s1.json'
            pointer.write_text('{broken')
            self.assertIsNone(state.get_active_route(root))
            with self.assertRaises(ValueError):
                start_agent(root, 'child', route['write_agent'])

    def test_review_report_requires_exact_single_context_marker(self):
        from getzilla.continuity import context_binding
        from getzilla.review_source import review_source_binding
        with project_copy(git=True) as root:
            route = self.light_route(root)
            observed = context_binding(root)
            head = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=root, check=True,
                                  capture_output=True, text=True).stdout.strip()
            relative = f".getzilla/runtime/reviews/{route['route_id']}/code-review.md"
            report = root / relative
            report.parent.mkdir(parents=True)
            report.write_text('Independent review.\n')
            with self.assertRaisesRegex(ValueError, 'context|marker'):
                review_source_binding(root, head, relative)
            report.write_text('Independent review.\nreviewed-context-digest: ' + observed['digest'] + '\n')
            result = review_source_binding(root, head, relative, reviewed_context=observed['digest'])
            self.assertEqual(result['reviewed_context'], observed['digest'])
            report.write_text(report.read_text() + 'reviewed-context-digest: ' + observed['digest'] + '\n')
            with self.assertRaises(ValueError):
                review_source_binding(root, head, relative, reviewed_context=observed['digest'])

    def test_verifier_captures_before_work_and_refuses_scope_mutation(self):
        from getzilla import verification
        with project_copy(git=True, minimal_runtime=True) as root:
            self.light_route(root)
            def mutate(*args, **kwargs):
                self.submit(root, 'New acceptance condition while verifier is working.')
                return []
            with patch.object(verification, '_python', side_effect=mutate):
                report = verification.verify(root, mode='fast', record=False)
            context_checks = [item for item in report['checks'] if item['name'] == 'task-context']
            self.assertEqual(len(context_checks), 1)
            self.assertEqual(context_checks[0]['status'], 'fail')
            self.assertNotEqual(report['status'], 'pass')

    def test_unreadable_worker_state_cannot_prove_idle(self):
        with project_copy(git=True) as root:
            route = self.light_route(root)
            state.agent_state_path(root).write_text('{broken')
            result = self.cli(root, '--new-task', 'New explicit task', '--session', 's1', '--json')
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(state.get_active_route(root), route)

    def test_display_utf8_bound_discloses_recovery_and_stop_keeps_ready(self):
        from getzilla.router import route_context
        with project_copy(git=True) as root:
            self.light_route(root)
            for index in range(5):
                self.submit(root, f'{index}: ' + 'я' * 4000)
            current = state.get_active_route(root)
            rendered = route_context(current, root)
            self.assertLessEqual(len(rendered.encode()), 16384)
            self.assertIn('omitted', rendered)
            self.assertIn(current['route_id'] + '.json', rendered)
            state.update_route(root, status='ready')
            code, _, err = run_hook(root, 'stop_gate.py', {'cwd': str(root), 'session_id': 's1'})
            self.assertEqual(code, 0, err)
            self.assertEqual(state.get_active_route(root)['status'], 'ready')


if __name__ == '__main__':
    unittest.main()
