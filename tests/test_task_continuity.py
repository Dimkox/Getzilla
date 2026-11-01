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

    def test_package_retry_repairs_missing_route_attachment(self):
        with project_copy(git=True) as root:
            route = self.route(root)
            record = start_agent(root, 'child', route['write_agent'])
            with patch('getzilla.continuity.attach_package', side_effect=OSError('attachment interrupted')):
                with self.assertRaises(OSError):
                    start_change(root)
            self.assertNotIn('change_id', state.get_active_route(root))
            package = start_change(root)
            self.assertEqual(state.get_active_route(root)['change_id'], package['change_id'])
            self.assertEqual(update_agent(root, 'child', record['generation'], record['route_id'],
                                         record['task_id'], 'heartbeat')['task_id'], record['task_id'])

    def test_full_unicode_intake_survives_package_and_workflow_authority(self):
        from getzilla.continuity import submit
        from getzilla.workflow_artifacts import load_runtime_authority
        with project_copy(git=True) as root:
            original = 'я' * 32000
            route = submit(root, original, 's1', new_task=True)
            for index in range(8):
                submit(root, str(index) + 'я' * 4000, 's1')
            package = start_change(root)
            current = state.get_active_route(root)
            self.assertEqual(current['task'], original)
            self.assertEqual(current['logical_task_id'], route['logical_task_id'])
            self.assertEqual(len(current['context']['pending']), 8)
            self.assertEqual(load_runtime_authority(root, 'route'), current)
            self.assertEqual(load_runtime_authority(root, 'change')['change_id'], package['change_id'])

    def test_handoff_request_identity_collision_is_not_repaired_as_replay(self):
        from getzilla.continuity import submit
        with project_copy(git=True) as root:
            before = self.light_route(root)
            args = {'continue_route': before['route_id'], 'expected_epoch': 0,
                    'expected_revision': before['state_revision'], 'request_id': 'handoff-one'}
            moved = submit(root, '', 's2', **args)
            with self.assertRaises(ValueError):
                submit(root, '', 's2', **{**args, 'request_id': 'different-operation'})
            self.assertEqual(state.get_active_route(root), moved)

    def test_count_and_total_bounds_keep_prior_bytes_and_allow_exact_retry(self):
        from getzilla.continuity import ack_scope, submit
        for texts in ([f'Accepted amendment {index}' for index in range(16)],
                      [str(index) + 'я' * 4095 for index in range(8)]):
            with self.subTest(bound=len(texts)), project_copy(git=True) as root:
                self.route(root)
                for text in texts:
                    self.submit(root, text)
                before = state.get_active_route(root)
                rejected = 'n' * (8192 if len(texts) == 8 else 1)
                with self.assertRaisesRegex(ValueError, 'scope_sync_required'):
                    self.submit(root, rejected, event_id='overflow')
                latched = state.get_active_route(root)
                self.assertEqual(latched['context']['pending'], before['context']['pending'])
                self.package(root)
                ack_scope(root, self.ack_request(root, [item['id'] for item in before['context']['pending']]))
                retried = submit(root, rejected, 's1', event_id='overflow')
                self.assertIsNone(retried['context']['rejected'])
                self.assertEqual(retried['context']['pending'][0]['text'], rejected)

    def test_large_rejection_requires_exact_safe_file_bytes_for_incorporation(self):
        from getzilla.continuity import ack_scope, scope_gaps
        with project_copy(git=True) as root:
            self.route(root)
            raw = 'я' * 4097
            with self.assertRaises(ValueError):
                self.submit(root, raw)
            _, path = self.package(root)
            source = path / 'rejected-input.txt'
            source.write_text(raw, encoding='utf-8')
            request = self.ack_request(root)
            request['resolve_rejected'] = {'id': state.get_active_route(root)['context']['rejected']['id'],
                                          'action': 'incorporated', 'targets': ['AC-001'],
                                          'text_path': source.relative_to(root).as_posix()}
            source.write_text(raw + 'changed', encoding='utf-8')
            with self.assertRaises(ValueError):
                ack_scope(root, request)
            source.write_text(raw, encoding='utf-8')
            request_path = path / 'ack-request.json'
            request_path.write_text(json.dumps(request), encoding='utf-8')
            result = self.cli(root, '--ack-scope', request_path.relative_to(root).as_posix(), '--session', 's1', '--json')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(scope_gaps(root))
            source.write_text(raw + 'changed', encoding='utf-8')
            with self.assertRaises(ValueError):
                ack_scope(root, request)

    def test_ack_flush_failure_preserves_route_and_package(self):
        from getzilla.continuity import ack_scope
        with project_copy(git=True) as root:
            self.route(root)
            _, path = self.package(root)
            request = self.ack_request(root)
            route = state.get_active_route(root)
            package_before = (path / 'state.json').read_bytes()
            with patch('getzilla.package_status.os.fsync', side_effect=OSError('document fsync failed')):
                with self.assertRaises((OSError, ValueError)):
                    ack_scope(root, request)
            self.assertEqual(state.get_active_route(root), route)
            self.assertEqual((path / 'state.json').read_bytes(), package_before)

    def test_corrupt_canonical_cannot_be_unrouted_or_silently_recreated(self):
        with project_copy(git=True) as root:
            route = self.light_route(root)
            canonical = root / '.getzilla/runtime/routes' / (route['route_id'] + '.json')
            canonical.write_text('{broken')
            self.assertIsNone(state.get_active_route(root))
            with self.assertRaises(ValueError):
                state.set_active_route(root, route)
            with self.assertRaises(ValueError):
                start_agent(root, 'child', route['write_agent'])
            canonical.unlink()
            with self.assertRaises(ValueError):
                state.set_active_route(root, route)

    def test_legacy_unicode_identity_freezes_once_and_inconsistent_workers_refuse(self):
        from getzilla.continuity import normalize_route, task_identity
        with project_copy(git=True) as root:
            legacy = {'route_id': 'legacy', 'task': ORIGINAL, 'session_id': 's1',
                      'change_id': '20261101-исправить', 'created_at': '2026-11-01T00:00:00+00:00'}
            state.bind_session('s1')
            state.set_active_route(root, legacy)
            expected = task_identity(legacy)
            active = {'agent_type': 'repo_explorer', 'route_id': 'legacy', 'task_id': expected,
                      'workspace': str(root.resolve()), 'generation': 'gen', 'lifecycle': 'running'}
            state.durable_json(root, state.agent_state_path(root), {'active': {'child': active}, 'history': []})
            before = state.agent_state_path(root).read_bytes()
            route = normalize_route(root)
            self.assertEqual(route['logical_task_id'], expected)
            self.assertEqual(normalize_route(root), route)
            self.assertEqual(state.agent_state_path(root).read_bytes(), before)
        with project_copy(git=True) as root:
            state.bind_session('s1')
            state.set_active_route(root, legacy)
            active['workspace'] = str(root.resolve())
            active['task_id'] = 'wrong-task'
            state.durable_json(root, state.agent_state_path(root), {'active': {'child': active}, 'history': []})
            before = state.agent_state_path(root).read_bytes()
            with self.assertRaisesRegex(ValueError, 'inconsistent'):
                normalize_route(root)
            self.assertEqual(state.agent_state_path(root).read_bytes(), before)
            self.assertNotIn('logical_task_id', state.get_active_route(root))

    def test_manual_session_does_not_inherit_environment_owner(self):
        with project_copy(git=True) as root:
            route = self.light_route(root)
            with patch.dict(os.environ, {'GETZILLA_SESSION_ID': 's1'}):
                state.bind_session('manual')
                self.assertIsNone(state.current_session())
                self.assertEqual(state.get_active_route(root)['route_id'], route['route_id'])
                with self.assertRaises(ValueError):
                    start_agent(root, 'unbound-child', route['write_agent'])

    def test_read_only_discovery_does_not_create_missing_runtime(self):
        with project_copy() as root:
            empty = root / 'empty-workspace'
            empty.mkdir()
            state.bind_session('s1')
            self.assertIsNone(state.get_active_route(empty))
            self.assertFalse(state.route_authority_present(empty))
            self.assertEqual(list(empty.iterdir()), [])

    def test_invalid_modern_version_cannot_receive_legacy_evidence(self):
        from getzilla.continuity import legacy_evidence_allowed
        with project_copy(git=True) as root:
            route = self.light_route(root)
            for value in (False, None, 0, '1'):
                corrupted = {**route, 'task_context_version': value}
                self.assertFalse(legacy_evidence_allowed(corrupted))
            partial = {'route_id': route['route_id'], 'task_context_version': 1, 'authority_epoch': 0,
                       'context': {'legacy_compatible': True, 'revision': 0, 'pending': [],
                                   'rejected': None, 'last_ack': None}}
            self.assertFalse(legacy_evidence_allowed(partial))

    def test_queue_drain_never_restores_legacy_receipt_eligibility(self):
        from getzilla.continuity import ack_scope, legacy_evidence_allowed
        with project_copy(git=True) as root:
            self.route(root)
            current = self.submit(root, 'Amendment A must remain in scope.')
            self.package(root)
            route = ack_scope(root, self.ack_request(root, [current['context']['pending'][0]['id']]))
            self.assertEqual(route['context']['pending'], [])
            self.assertFalse(legacy_evidence_allowed(route))

    def test_worker_start_and_handoff_share_one_outer_transition(self):
        import threading
        from concurrent.futures import ThreadPoolExecutor
        from getzilla.continuity import submit
        with project_copy(git=True) as root:
            route = self.light_route(root)
            waiting = threading.Event()
            def old_worker():
                state.bind_session('s1')
                waiting.set()
                return start_agent(root, 'late-child', route['write_agent'])
            with ThreadPoolExecutor(max_workers=1) as pool:
                with state.task_transition(root):
                    future = pool.submit(old_worker)
                    self.assertTrue(waiting.wait(2))
                    moved = submit(root, '', 's2', continue_route=route['route_id'], expected_epoch=0,
                                   expected_revision=route['state_revision'], request_id='serialized-handoff')
                with self.assertRaises(ValueError):
                    future.result(timeout=5)
            self.assertEqual(moved['authority_epoch'], 1)
            self.assertEqual(state.get_agent_state(root)['active'], {})
            worker = start_agent(root, 'new-child', route['write_agent'])
            with self.assertRaises(ValueError):
                submit(root, '', 's3', continue_route=route['route_id'], expected_epoch=1,
                       expected_revision=moved['state_revision'], request_id='blocked-handoff')
            self.assertEqual(state.get_agent_state(root)['active']['new-child']['generation'], worker['generation'])

    def test_direct_metadata_cannot_close_pending_scope_or_mutate_foreign_package(self):
        with project_copy(git=True) as root:
            route = self.light_route(root)
            pending = self.submit(root, 'A substantive acceptance condition.')
            with self.assertRaises(ValueError):
                state.update_route(root, status='completed')
            self.assertEqual(state.get_active_route(root), pending)
            state.bind_session('foreign')
            with self.assertRaises(ValueError):
                state.set_active_change(root, {'change_id': 'foreign', 'path': '.getzilla/runtime/changes/foreign'})
            self.assertEqual(state.canonical_route(root, route['route_id']), pending)

    def test_new_task_after_closed_package_has_explicit_no_package_context(self):
        from getzilla.change import transition
        from getzilla.continuity import context_binding, submit
        with project_copy(git=True) as root:
            self.light_route(root)
            package = start_change(root)
            transition(root, package['change_id'], 'cancelled', 'explicit fixture cancellation')
            fresh = submit(root, 'Fix a README typo.', 's1', new_task=True)
            self.assertNotEqual(fresh.get('change_id'), package['change_id'])
            self.assertEqual(context_binding(root)['variant'], 'no-package')

    def test_large_hook_refusal_is_bounded_and_exposes_not_admitted(self):
        from getzilla.continuity import submit
        with project_copy(git=True) as root:
            submit(root, 'я' * 20000, 's1', new_task=True)
            code, data, err = run_hook(root, 'user_prompt_submit.py', {'cwd': str(root), 'session_id': 's1',
                                                                      'prompt': 'x' * 8193})
            self.assertEqual(code, 0, err)
            rendered = data['hookSpecificOutput']['additionalContext']
            self.assertLessEqual(len(rendered.encode('utf-8')), 16384)
            self.assertIn('NOT admitted', rendered)
            self.assertIn('.json', rendered)

    def test_verifier_refuses_unavailable_authority_without_recording(self):
        from getzilla import verification
        with project_copy(git=True, minimal_runtime=True) as root:
            route = self.light_route(root)
            canonical = root / '.getzilla/runtime/routes' / (route['route_id'] + '.json')
            canonical.write_text('{broken')
            with patch.object(verification, '_python', return_value=[]):
                report = verification.verify(root, mode='fast', record=False)
            self.assertEqual(report['status'], 'fail')
            self.assertTrue(any(item['name'] == 'task-context' and item['status'] == 'fail' for item in report['checks']))

    def test_same_head_old_review_report_stays_stale_after_scope_ack(self):
        from getzilla.continuity import ack_scope, context_binding
        from getzilla.review_source import review_source_binding
        with project_copy(git=True) as root:
            self.route(root)
            _, path = self.package(root)
            ack_scope(root, self.ack_request(root))
            subprocess.run(['git', 'add', '.'], cwd=root, check=True)
            subprocess.run(['git', 'commit', '-qm', 'fixture scope source'], cwd=root, check=True)
            observed = context_binding(root)
            head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
            report = path / 'evidence/code-review.md'
            report.write_text('Independent report.\nreviewed-context-digest: ' + observed['digest'] + '\n')
            relative = report.relative_to(root).as_posix()
            review_source_binding(root, head, relative, reviewed_context=observed['digest'])
            amended = self.submit(root, 'Amendment A: add one acceptance condition.')
            ack_scope(root, self.ack_request(root, [amended['context']['pending'][0]['id']]))
            self.assertEqual(subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(), head)
            with self.assertRaises(ValueError):
                review_source_binding(root, head, relative, reviewed_context=observed['digest'])
            with self.assertRaises(ValueError):
                review_source_binding(root, head, relative, reviewed_context=context_binding(root)['digest'])

    def test_spilled_verification_refuses_scope_change_during_publication(self):
        from getzilla import receipts
        from getzilla.continuity import context_binding
        with project_copy(git=True) as root:
            route = self.light_route(root)
            state.update_route(root, risk_assessment=None)
            observed = context_binding(root)
            publish = receipts._publish_verification_report
            def mutate(*args, **kwargs):
                result = publish(*args, **kwargs)
                self.submit(root, 'New acceptance after report spill.')
                return result
            with patch.object(receipts, '_publish_verification_report', side_effect=mutate):
                with self.assertRaisesRegex(ValueError, 'context|scope'):
                    receipts.write_receipt(root, 'verification', 'pass', expected_context=observed,
                                           details={'stdout': 'x' * receipts.MAX_RECEIPT_BYTES})
            self.assertIsNone(receipts.get_receipt(root, route['route_id'], 'verification'))
            self.assertFalse(list((root / '.getzilla/runtime/receipts').rglob('reports/*.json')))

    def test_all_grant_kinds_and_legacy_records_reject_pre_handoff_authority(self):
        from getzilla.continuity import submit
        with project_copy(git=True) as root:
            route = self.light_route(root)
            subprocess.run(['git', 'remote', 'add', 'origin', 'https://github.com/example/fixture.git'], cwd=root, check=True)
            cases = [('protected-path', 'protected-path-write', 'AGENTS.md'),
                     ('production', 'git-push-branch', 'feature-x'),
                     ('external-write', 'external-write', 'https://example.com/api')]
            grants = []
            for scope, action, resource in cases:
                grant = state.add_approval(root, scope, 'explicit fixture authority', actions=[action], resources=[resource])
                grants.append(grant)
                self.assertTrue(state.has_valid_approval(root, scope, action=action, resource=resource))
            moved = submit(root, '', 's2', continue_route=route['route_id'], expected_epoch=0,
                           expected_revision=route['state_revision'], request_id='all-grants')
            for legacy in (False, True):
                values = [{key: value for key, value in grant.items()
                           if not legacy or key not in {'logical_task_id', 'authority_epoch', 'owner_session_id'}}
                          for grant in grants]
                state.durable_json(root, state.approvals_path(root), values)
                for session in ('s1', 's2', None):
                    state.bind_session(session)
                    for scope, action, resource in cases:
                        self.assertFalse(state.has_valid_approval(root, scope, action=action, resource=resource))
            self.assertEqual(state.canonical_route(root, route['route_id'])['authority_epoch'], moved['authority_epoch'])

    def test_ack_cannot_inherit_original_mapping_to_removed_typed_target(self):
        from getzilla.continuity import ack_scope, scope_gaps
        from getzilla.spec import load_spec, dump_canonical_spec
        with project_copy(git=True) as root:
            self.route(root)
            _, path = self.package(root)
            ack_scope(root, self.ack_request(root))
            spec = load_spec(path / 'change-spec.yaml')
            spec['objective']['id'] = 'OBJ-002'
            (path / 'change-spec.yaml').write_text(dump_canonical_spec(spec))
            route = self.submit(root, 'A new requirement on the updated objective.')
            request = self.ack_request(root, [route['context']['pending'][0]['id']])
            del request['items']['original']
            before = (path / 'state.json').read_bytes()
            with self.assertRaisesRegex(ValueError, 'original|typed|mapping'):
                ack_scope(root, request)
            self.assertEqual(state.get_active_route(root), route)
            self.assertEqual((path / 'state.json').read_bytes(), before)
            request['items']['original'] = ['OBJ-002']
            ack_scope(root, request)
            self.assertEqual(scope_gaps(root), [])

    def test_malformed_package_state_never_acknowledges_pending_scope(self):
        from getzilla.continuity import ack_scope
        with project_copy(git=True) as root:
            self.route(root)
            _, path = self.package(root)
            route = self.submit(root, 'A pending condition must not be lost.')
            request = self.ack_request(root, [route['context']['pending'][0]['id']])
            original = json.loads((path / 'state.json').read_text())
            for key, value in (('schema_version', 99), ('schema_version', True), ('status', None), ('history', 'invalid')):
                with self.subTest(key=key, value=value):
                    malformed = {**original, key: value}
                    (path / 'state.json').write_text(json.dumps(malformed))
                    before = (path / 'state.json').read_bytes()
                    with self.assertRaises(ValueError):
                        ack_scope(root, request)
                    self.assertEqual(state.get_active_route(root), route)
                    self.assertEqual((path / 'state.json').read_bytes(), before)

    def test_malformed_ack_mirror_cannot_qualify(self):
        from getzilla.continuity import ack_scope, scope_gaps, validate_route
        import copy
        with project_copy(git=True) as root:
            self.route(root)
            _, path = self.package(root)
            route = ack_scope(root, self.ack_request(root))
            package_state = json.loads((path / 'state.json').read_text())
            for key, value in (('items', {'original': None}), ('version', 99),
                               ('logical_task_id', 'foreign'), ('route_id', 'foreign'),
                               ('acknowledged', [{}] * 17)):
                with self.subTest(field=key):
                    malformed = copy.deepcopy(route)
                    malformed['context']['last_ack'][key] = value
                    package_state['scope_ack'] = malformed['context']['last_ack']
                    (path / 'state.json').write_text(json.dumps(package_state))
                    state.durable_json(root, root / '.getzilla/runtime/routes' / (route['route_id'] + '.json'), malformed)
                    with self.assertRaises(ValueError):
                        validate_route(root, malformed)
                    self.assertTrue(scope_gaps(root, malformed))

    def test_failed_terminal_package_transition_preserves_prior_state(self):
        from getzilla.change import transition
        from getzilla.continuity import ack_scope
        with project_copy(git=True) as root:
            route = self.light_route(root)
            package, path = self.package(root)
            before = (path / 'state.json').read_bytes()
            prior_route = state.get_active_route(root)
            worker = start_agent(root, 'active-child', route['write_agent'])
            with self.assertRaisesRegex(ValueError, 'worker'):
                transition(root, package['change_id'], 'cancelled', 'explicit cancellation')
            self.assertEqual((path / 'state.json').read_bytes(), before)
            self.assertEqual(state.get_active_route(root), prior_route)
            from getzilla.agent_lifecycle import stop_agent
            self.assertTrue(stop_agent(root, 'active-child', route['write_agent'], generation=worker['generation'], final=True))
            ack_scope(root, self.ack_request(root))
            for target in ('scoped', 'approved', 'implementing', 'verifying', 'reviewing', 'ready'):
                transition(root, package['change_id'], target, 'fixture lifecycle')
            before = (path / 'state.json').read_bytes()
            route = state.get_active_route(root)
            with self.assertRaises(ValueError):
                transition(root, package['change_id'], 'released', 'evidence is intentionally absent')
            self.assertEqual((path / 'state.json').read_bytes(), before)
            self.assertEqual(state.get_active_route(root), route)

    def test_small_receipt_postpublication_scope_mutation_retires_pass(self):
        from getzilla import receipts
        from getzilla.continuity import context_binding
        with project_copy(git=True) as root:
            route = self.light_route(root)
            state.update_route(root, risk_assessment=None)
            observed = context_binding(root)
            publish = receipts._publish_receipt
            def mutate(*args, **kwargs):
                result = publish(*args, **kwargs)
                self.submit(root, 'New acceptance during small receipt publication.')
                return result
            with patch.object(receipts, '_publish_receipt', side_effect=mutate):
                with self.assertRaisesRegex(ValueError, 'context|scope'):
                    receipts.write_receipt(root, 'verification', 'pass', expected_context=observed)
            self.assertIsNone(receipts.get_receipt(root, route['route_id'], 'verification'))

    def test_terminal_package_projection_failure_has_exact_retry(self):
        from getzilla import change
        with project_copy(git=True) as root:
            self.light_route(root)
            package = start_change(root)
            path = root / state.get_active_change(root)['path']
            with patch.object(change, 'update_route', side_effect=OSError('publication fault')):
                with self.assertRaises(OSError):
                    change.transition(root, package['change_id'], 'cancelled', 'explicit fixture decision')
            self.assertEqual(json.loads((path / 'state.json').read_text())['status'], 'cancelled')
            self.assertNotEqual(state.get_active_route(root)['status'], 'cancelled')
            change.transition(root, package['change_id'], 'cancelled', 'explicit fixture decision')
            self.assertEqual(state.get_active_route(root)['status'], 'cancelled')

    def test_new_route_refuses_symlinked_publication_parent(self):
        with project_copy(git=True) as root:
            runtime = root / '.getzilla/runtime'
            routes = runtime / 'routes'
            outside = root / 'unrelated-route-store'
            outside.mkdir()
            routes.symlink_to(outside, target_is_directory=True)
            with self.assertRaises((ValueError, OSError)):
                self.light_route(root)
            self.assertEqual(list(outside.iterdir()), [])
            self.assertFalse((runtime / 'active-route.json').exists())

    def test_valid_owner_is_independent_of_unsafe_global_discovery(self):
        from getzilla.continuity import submit
        with project_copy(git=True) as root:
            route = self.light_route(root)
            global_path = root / '.getzilla/runtime/active-route.json'
            outside = root / 'unrelated.json'
            outside.write_text(json.dumps(route))
            global_path.unlink()
            global_path.symlink_to(outside)
            self.assertEqual(state.get_active_route(root), route)
            state.bind_session(None)
            self.assertIsNone(state.discovered_route(root))
            with self.assertRaises(ValueError):
                state.add_approval(root, 'protected-path', 'unbound', actions=['protected-path-write'], resources=['AGENTS.md'])
            self.assertEqual(json.loads(outside.read_text()), route)
            state.bind_session('s1')
            with self.assertRaises((ValueError, OSError)):
                submit(root, 'Pending despite refused unsafe projection.', 's1')
            # Canonical commit may precede projection refusal; the owned session
            # still reads authoritative scope and no external target is touched.
            self.assertEqual(len(state.get_active_route(root)['context']['pending']), 1)
            self.assertEqual(json.loads(outside.read_text()), route)

    def test_new_same_session_task_rejects_old_grant(self):
        from getzilla.continuity import submit, finish_task
        with project_copy(git=True) as root:
            route = self.light_route(root)
            subprocess.run(['git', 'remote', 'add', 'origin', 'https://github.com/example/fixture.git'], cwd=root, check=True)
            state.add_approval(root, 'protected-path', 'explicit fixture authority',
                               actions=['protected-path-write'], resources=['AGENTS.md'])
            finish_task(root, cancel=True)
            fresh = submit(root, route['task'], 's1', new_task=True)
            self.assertNotEqual(fresh['logical_task_id'], route['logical_task_id'])
            self.assertFalse(state.has_valid_approval(root, 'protected-path', action='protected-path-write', resource='AGENTS.md'))

    def test_legacy_large_original_and_consistent_selected_package_migrate_once(self):
        from getzilla.continuity import normalize_route, task_identity
        from tests._support import activate_owned_route
        with project_copy(git=True) as root:
            route = {'route_id': 'legacy-open-package', 'session_id': 's1', 'task': 'я' * 40000,
                     'created_at': '2026-11-01T00:00:00+00:00', 'status': 'implementing'}
            activate_owned_route(root, route)
            path = root / '.getzilla/runtime/changes/legacy-package'
            path.mkdir(parents=True)
            package = {'schema_version': 1, 'change_id': 'legacy-package', 'route_id': route['route_id'],
                       'status': 'implementing', 'history': []}
            state.durable_json(root, path / 'state.json', package)
            state.set_active_change(root, {'change_id': 'legacy-package', 'path': path.relative_to(root).as_posix()})
            identity = task_identity(route)
            migrated = normalize_route(root)
            self.assertEqual(migrated['logical_task_id'], identity)
            self.assertEqual(migrated['task'], route['task'])
            self.assertEqual(migrated['change_id'], 'legacy-package')
            self.assertEqual(normalize_route(root), migrated)

    def test_resume_and_stop_disclose_unavailable_authority(self):
        with project_copy(git=True) as root:
            route = self.light_route(root)
            canonical = root / '.getzilla/runtime/routes' / (route['route_id'] + '.json')
            canonical.write_text('{broken')
            for hook in ('session_start.py', 'user_prompt_submit.py', 'stop_gate.py'):
                with self.subTest(hook=hook):
                    code, data, err = run_hook(root, hook, {'cwd': str(root), 'session_id': 's1',
                        'prompt': '<system-reminder>Harness observation.</system-reminder>', 'stop_hook_active': False})
                    self.assertEqual(code, 0, err)
                    output = json.dumps(data, ensure_ascii=False)
                    self.assertIn('authority unavailable', output)
                    self.assertIn('--continue', output)
                    self.assertEqual(canonical.read_text(), '{broken')

    def test_manual_discovery_cannot_reconcile_complete_or_cancel(self):
        from getzilla.review_plan import reconcile_route
        from getzilla.continuity import finish_task
        with project_copy(git=True) as root:
            route = self.light_route(root)
            state.bind_session(None)
            self.assertEqual(state.get_active_route(root), route)
            before = (root / '.getzilla/runtime/routes' / (route['route_id'] + '.json')).read_bytes()
            for operation in (lambda: reconcile_route(root), lambda: finish_task(root),
                              lambda: finish_task(root, cancel=True)):
                with self.assertRaises(ValueError):
                    operation()
            self.assertEqual((root / '.getzilla/runtime/routes' / (route['route_id'] + '.json')).read_bytes(), before)

    def test_context_capture_refuses_route_change_between_document_reads(self):
        from getzilla import continuity
        with project_copy(git=True) as root:
            self.route(root)
            self.package(root)
            continuity.ack_scope(root, self.ack_request(root))
            read = continuity.package_documents
            changed = False
            def interleave(*args, **kwargs):
                nonlocal changed
                documents = read(*args, **kwargs)
                if not changed:
                    changed = True
                    self.submit(root, 'New scope during context capture.')
                return documents
            with patch.object(continuity, 'package_documents', side_effect=interleave):
                with self.assertRaisesRegex(ValueError, 'context|changed'):
                    continuity.context_binding(root)
            self.assertEqual(len(state.get_active_route(root)['context']['pending']), 1)

    def test_context_capture_refuses_document_change_without_route_change(self):
        from getzilla import continuity
        with project_copy(git=True) as root:
            self.route(root)
            _, path = self.package(root)
            continuity.ack_scope(root, self.ack_request(root))
            read = continuity.package_documents
            changed = False
            before = state.get_active_route(root)
            def interleave(*args, **kwargs):
                nonlocal changed
                documents = read(*args, **kwargs)
                if not changed:
                    changed = True
                    (path / 'requirements.md').write_text(ORIGINAL + '\nA concurrent document amendment.\n')
                return documents
            with patch.object(continuity, 'package_documents', side_effect=interleave):
                with self.assertRaisesRegex(ValueError, 'context|changed'):
                    continuity.context_binding(root, discovery=True)
            self.assertEqual(state.get_active_route(root), before)


if __name__ == '__main__':
    unittest.main()
