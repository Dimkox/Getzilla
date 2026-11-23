"""GitHub CI interactions: advisory early stop without progress, stale evidence excluded (#153)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla import ci_progress as ci  # noqa: E402
from getzilla import session_progress as progress  # noqa: E402

SCOPE = 'c' * 64
HEAD = '1' * 40
OLD = '2' * 40
T0 = 1_800_000_000


def run_json(run_id=7, attempt=1, head=HEAD, status='completed', conclusion='failure', updated='2026-11-23T10:00:00Z',
             jobs=None):
    item = {'databaseId': run_id, 'attempt': attempt, 'headSha': head, 'status': status,
            'conclusion': conclusion, 'updatedAt': updated}
    if jobs is not None:
        item['jobs'] = jobs
    return json.dumps(item)


def failed_jobs(step='Import OCI layers'):
    return [{'name': 'security-expanded', 'conclusion': 'failure',
             'steps': [{'name': 'Set up', 'conclusion': 'success'}, {'name': step, 'conclusion': 'failure'}]}]


class ClassificationTests(unittest.TestCase):
    def test_supported_shapes(self):
        cases = {
            'gh run view 7 --json databaseId,attempt,headSha,status,conclusion,updatedAt': ('poll', 'run', '7', None, True),
            'gh run view 7': ('poll', 'run', '7', None, False),
            'gh run view 7 --log-failed': ('log', 'run', '7', None, False),
            'gh run view 7 --attempt 2 --log': ('log', 'run', '7', None, False),
            'gh run list --json databaseId,status': ('poll', 'runs', None, None, True),
            'gh run watch 7 --exit-status --interval 30': ('wait', 'run', '7', None, False),
            'gh pr checks 446 --watch': ('wait', 'pr', '446', None, False),
            'gh pr checks 446': ('poll', 'pr', '446', None, False),
            'gh run rerun 7': ('mutation', 'run', '7', 'rerun', False),
            'gh run rerun 7 --failed': ('mutation', 'run', '7', 'rerun', False),
            'gh -R Dimkox/Getzilla run cancel 7': ('mutation', 'run', '7', 'cancel', False),
            'gh api repos/Dimkox/Getzilla/actions/runs/7': ('poll', 'run', '7', None, True),
            'gh api repos/{owner}/{repo}/actions/runs/7/jobs': ('poll', 'run', '7', None, True),
            'gh api repos/Dimkox/Getzilla/actions/runs/7/logs': ('log', 'run', '7', None, False),
            'gh api -X POST repos/Dimkox/Getzilla/actions/runs/7/rerun': ('mutation', 'run', '7', 'rerun', False),
            'gh api --method POST repos/Dimkox/Getzilla/actions/runs/7/rerun-failed-jobs': ('mutation', 'run', '7', 'rerun', False),
            'gh api -X POST repos/Dimkox/Getzilla/actions/runs/7/cancel': ('mutation', 'run', '7', 'cancel', False),
        }
        for command, expected in cases.items():
            with self.subTest(command=command):
                found = ci.classify(command)
                self.assertIsNotNone(found)
                self.assertEqual((found.kind, found.target, found.ident, found.op, found.structured), expected)
        self.assertEqual(ci.classify('gh -R Dimkox/Getzilla run cancel 7').repo, 'Dimkox/Getzilla')
        self.assertEqual(ci.classify('gh api repos/Dimkox/Getzilla/actions/runs/7').repo, 'Dimkox/Getzilla')
        self.assertEqual(ci.classify('gh api repos/{owner}/{repo}/actions/runs/7').repo, '.')

    def test_unsupported_or_ambiguous_forms_are_not_classified(self):
        for command in ('gh run view', 'gh run rerun', 'gh run view 7 --json x | jq .', 'gh run view $RUN',
                        'gh run view 7 --json status --jq .status', 'gh api repos/o/r/actions/runs/7 --jq .status',
                        'gh run view 7 --web', 'gh alias run', 'gh workflow run getzilla.yml', 'gh run view 7 --unknown',
                        'gh api repos/o/r/issues/1', 'gh api -X DELETE repos/o/r/actions/runs/7', 'gh run view 7x',
                        'echo gh run rerun 7', 'GH=1 gh run rerun 7 && gh run rerun 7', 'gh run rerun 7\n',
                        'gh --repo=o/r run rerun 7 extra', 'gh run delete 7', 'gh pr checks 446 --json name'):
            with self.subTest(command=command):
                found = ci.classify(command)
                self.assertTrue(found is None or found.kind in {'poll', 'log'} and not found.structured)


class TokenTests(unittest.TestCase):
    def test_object_array_wrapper_and_json_lines(self):
        one = ci.parse_runs(run_json())
        self.assertEqual([(run.ident, run.attempt, run.head, run.status) for run in one], [('7', 1, HEAD, 'completed')])
        rest = json.dumps({'total_count': 1, 'workflow_runs': [
            {'id': 8, 'run_attempt': 2, 'head_sha': OLD, 'status': 'in_progress', 'conclusion': None,
             'updated_at': '2026-11-23T10:00:00Z'}]})
        self.assertEqual([(run.ident, run.attempt, run.status) for run in ci.parse_runs(rest)], [('8', 2, 'in_progress')])
        lines = run_json(run_id=1) + '\n' + run_json(run_id=2)
        self.assertEqual([run.ident for run in ci.parse_runs(lines)], ['1', '2'])
        self.assertEqual(len(ci.parse_runs(json.dumps([json.loads(run_json(run_id=n)) for n in (1, 2, 3)]))), 3)

    def test_failure_signature_from_jobs(self):
        first = ci.parse_runs(run_json(jobs=failed_jobs()))[0].signature
        same = ci.parse_runs(run_json(attempt=2, jobs=failed_jobs()))[0].signature
        other = ci.parse_runs(run_json(jobs=failed_jobs('Upload')))[0].signature
        self.assertIsNotNone(first)
        self.assertEqual(first, same)
        self.assertNotEqual(first, other)

    def test_untrusted_shapes_give_no_token(self):
        for text in ('', 'not json', '{"databaseId": 1, "databaseId": 2}', run_json()[:-1], '[' + run_json() * 2 + ']',
                     json.dumps({'databaseId': 'x', 'status': 'completed'}), json.dumps({'databaseId': 1, 'headSha': 'zz'}),
                     json.dumps({'databaseId': 1, 'status': 'exploded'}), 'x' * 70_000, json.dumps({'value': float('inf')})):
            with self.subTest(text=text[:40]):
                self.assertEqual(ci.parse_runs(text), [])


class GuardTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='getzilla-ci-progress-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / '.getzilla/runtime').mkdir(parents=True)

    def observe(self, command, code=0, output='', now=T0, head=HEAD):
        return ci.observe(self.root, SCOPE, {'command': command}, {'exit_code': code, 'stdout': output}, head, now=now)

    def refuse(self, command, now=T0 + 1, head=HEAD):
        return ci.refusal(self.root, SCOPE, {'command': command}, head, now=now)

    def test_failed_rerun_waits_for_a_fresh_completed_observation(self):
        poll = 'gh run view 7 --json databaseId,attempt,headSha,status,conclusion,updatedAt'
        self.observe(poll, output=run_json(status='in_progress', conclusion=None), now=T0)
        self.assertIsNone(self.refuse('gh run rerun 7', now=T0 + 1))
        self.observe('gh run rerun 7', code=1, output='run 7 cannot be rerun; it is still in progress', now=T0 + 2)
        refused = self.refuse('gh run rerun 7', now=T0 + 60)
        self.assertIn('gh-run:.:7:attempt>=1:completed', refused)
        self.assertIn('gh run watch 7 --exit-status', refused)
        self.assertIn('progress-recover', refused)
        # A historical observation (another head) does not satisfy the condition.
        self.observe(poll, output=run_json(head=OLD, updated='2026-11-23T10:05:00Z'), now=T0 + 70)
        self.assertIsNotNone(self.refuse('gh run rerun 7', now=T0 + 71))
        self.observe('gh run watch 7 --exit-status', now=T0 + 80)
        self.observe(poll, output=run_json(updated='2026-11-23T10:06:00Z'), now=T0 + 90)
        self.assertIsNone(self.refuse('gh run rerun 7', now=T0 + 91))

    def test_successful_rerun_blocks_a_duplicate_until_the_new_attempt_completes(self):
        self.observe('gh run rerun 7 --failed', now=T0)
        self.assertIn('attempt>=2:completed', self.refuse('gh run rerun 7 --failed', now=T0 + 5))
        old = 'gh run view 7 --json databaseId,attempt,headSha,status,conclusion,updatedAt'
        note = self.observe(old, output=run_json(attempt=1), now=T0 + 6)
        self.assertIn('historical', note)
        self.assertIsNotNone(self.refuse('gh run rerun 7 --failed', now=T0 + 7))
        self.observe(old, output=run_json(attempt=2, updated='2026-11-23T11:00:00Z'), now=T0 + 8)
        self.assertIsNone(self.refuse('gh run rerun 7 --failed', now=T0 + 9))

    def test_same_failure_in_the_two_newest_attempts_refuses_another_rerun(self):
        poll = 'gh run view 7 --json databaseId,attempt,headSha,status,conclusion,updatedAt,jobs'
        self.observe(poll, output=run_json(attempt=1, jobs=failed_jobs()), now=T0)
        self.assertIsNone(self.refuse('gh run rerun 7', now=T0 + 1))
        self.observe(poll, output=run_json(attempt=2, updated='2026-11-23T11:00:00Z', jobs=failed_jobs()), now=T0 + 2)
        refused = self.refuse('gh run rerun 7', now=T0 + 3)
        self.assertIn('same failure', refused)
        self.assertIn('progress-recover', refused)
        # A different head means a new candidate: no deterministic stop.
        self.assertIsNone(self.refuse('gh run rerun 7', now=T0 + 4, head=OLD))
        block = next(row for row in ci.inspect(self.root, SCOPE, now=T0 + 5) if row['class'] == 'deterministic')
        result = ci.recover(self.root, SCOPE, block['loop_id'], block['revision'], 'changed-hypothesis',
                            'checker image digest changed', now=T0 + 6)
        self.assertTrue(result['retry_available'])
        self.assertIsNone(self.refuse('gh run rerun 7', now=T0 + 7))
        self.assertIsNotNone(self.refuse('gh run rerun 7', now=T0 + 8))
        with self.assertRaises(ValueError):
            ci.recover(self.root, SCOPE, block['loop_id'], ci.inspect(self.root, SCOPE, now=T0 + 9)[0]['revision'],
                       'changed-hypothesis', 'checker image digest changed', now=T0 + 9)

    def test_transient_budget_and_deterministic_precedence(self):
        command = 'gh run view 7 --json databaseId,status'
        self.observe(command, code=1, output='error connecting to api.github.com: connection reset by peer', now=T0)
        self.assertIn('retry after', self.refuse(command, now=T0 + 10))
        self.assertIsNone(self.refuse(command, now=T0 + 31))
        self.observe(command, code=1, output='read: connection reset by peer', now=T0 + 31)
        self.assertIsNotNone(self.refuse(command, now=T0 + 31 + 119))
        self.assertIsNone(self.refuse(command, now=T0 + 31 + 120))
        self.observe(command, code=1, output='connection reset by peer', now=T0 + 160)
        self.assertIn('transient retry budget', self.refuse(command, now=T0 + 1000))
        limited = 'gh run view 8 --json databaseId,status'
        self.observe(limited, code=1, output='HTTP 429: API rate limit exceeded', now=T0)
        self.assertIsNotNone(self.refuse(limited, now=T0 + 59))
        self.assertIsNone(self.refuse(limited, now=T0 + 60))
        deterministic = 'gh run view 9 --json databaseId,status'
        self.observe(deterministic, code=1, output='HTTP 404: Not Found (connection reset by peer?)', now=T0)
        self.assertIsNone(self.refuse(deterministic, now=T0 + 1))

    def test_unchanged_polls_stop_at_the_fourth_and_wait_resets(self):
        poll = 'gh run view 7 --json databaseId,attempt,headSha,status,conclusion,updatedAt'
        state = run_json(status='in_progress', conclusion=None)
        for number in range(3):
            self.assertIsNone(self.refuse(poll, now=T0 + number * 60))
            note = self.observe(poll, output=state, now=T0 + number * 60 + 1)
        self.assertIn('gh run watch 7 --exit-status', note)
        refused = self.refuse(poll, now=T0 + 200)
        self.assertIn('gh run watch 7 --exit-status', refused)
        self.assertIsNone(self.refuse('gh run watch 7 --exit-status', now=T0 + 201))
        self.observe('gh run watch 7 --exit-status', code=1, now=T0 + 400)
        self.assertIsNone(self.refuse(poll, now=T0 + 401))
        # A changed token is progress, and a completed token never blocks.
        for number in range(4):
            self.observe(poll, output=run_json(updated=f'2026-11-23T10:0{number}:00Z'), now=T0 + 500 + number)
        self.assertIsNone(self.refuse(poll, now=T0 + 600))

    def test_logs_of_old_attempts_or_heads_are_historical_and_count_nothing(self):
        poll = 'gh run view 7 --json databaseId,attempt,headSha,status,conclusion,updatedAt'
        self.assertIn('not observed', self.observe('gh run view 7 --log-failed', code=0, output='old log', now=T0))
        self.observe(poll, output=run_json(attempt=2), now=T0 + 1)
        self.assertIn('historical', self.observe('gh run view 7 --attempt 1 --log', output='TAR record 100001', now=T0 + 2))
        self.assertEqual(self.observe('gh run view 7 --log-failed', output='TAR record 100001', now=T0 + 3), '')
        self.assertIn('historical', self.observe('gh run view 7 --log-failed', output='x', now=T0 + 4, head=OLD))
        self.assertEqual([row for row in ci.inspect(self.root, SCOPE, now=T0 + 5) if row['status'] == 'blocked'], [])

    def test_state_file_is_separate_and_bounded(self):
        self.observe('gh run rerun 7', code=1, output='refused', now=T0)
        runtime = self.root / '.getzilla/runtime'
        self.assertTrue((runtime / ci.STATE_NAME).is_file())
        self.assertFalse((runtime / Path(progress.STATE).name).exists())
        raw = (runtime / ci.STATE_NAME).read_text()
        self.assertNotIn('rerun', raw)
        self.assertNotIn('refused', raw)
        for number in range(200):
            self.observe(f'gh run rerun {number + 100}', code=1, output='refused', now=T0 + number)
        state = json.loads((runtime / ci.STATE_NAME).read_text())
        self.assertLessEqual(len(state['blocks']), ci.MAX_BLOCKS)
        self.assertLessEqual(len(state['runs']), ci.MAX_RUNS)

    def test_unknown_scope_head_or_corrupt_state_never_blocks(self):
        self.assertEqual(ci.observe(self.root, None, {'command': 'gh run rerun 7'}, {'exit_code': 1}, HEAD, now=T0), '')
        self.assertEqual(ci.observe(self.root, SCOPE, {'command': 'gh run rerun 7'}, {'exit_code': 1}, None, now=T0), '')
        self.assertIsNone(self.refuse('gh run rerun 7'))
        (self.root / '.getzilla/runtime' / ci.STATE_NAME).write_text('{"version": 9}')
        with self.assertRaises(ValueError):
            self.refuse('gh run rerun 7')

    def test_recovery_allows_one_paced_transient_retry_and_success_resets_the_budget(self):
        command = 'gh run view 7 --json databaseId,status'
        self.observe(command, code=1, output='connection reset by peer', now=T0)
        block = next(row for row in ci.inspect(self.root, SCOPE, now=T0 + 1) if row['class'] == 'transient')
        ci.recover(self.root, SCOPE, block['loop_id'], block['revision'], 'new-evidence', 'proxy restarted', now=T0 + 2)
        self.assertIsNone(self.refuse(command, now=T0 + 3))
        self.assertIsNotNone(self.refuse(command, now=T0 + 4))
        self.observe(command, output=run_json(), now=T0 + 40)
        self.observe(command, code=1, output='connection reset by peer', now=T0 + 41)
        self.assertEqual(next(row['count'] for row in ci.inspect(self.root, SCOPE, now=T0 + 42)
                              if row['class'] == 'transient'), 1)

    def test_rate_limit_second_step_and_http_4xx_are_deterministic(self):
        command = 'gh run view 8 --json databaseId,status'
        self.observe(command, code=1, output='HTTP 429: API rate limit exceeded', now=T0)
        self.observe(command, code=1, output='HTTP 429: API rate limit exceeded', now=T0 + 60)
        self.assertIsNotNone(self.refuse(command, now=T0 + 60 + 299))
        self.assertIsNone(self.refuse(command, now=T0 + 60 + 300))
        for status in ('405', '410', '451'):
            other = f'gh run view {status} --json databaseId,status'
            self.observe(other, code=1, output=f'HTTP {status}: connection reset', now=T0)
            self.assertIsNone(self.refuse(other, now=T0 + 1), status)

    def test_rerun_rule_needs_two_consecutive_completed_failed_attempts(self):
        poll = 'gh run view 7 --json databaseId,attempt,headSha,status,conclusion,updatedAt,jobs'
        for between in ('success', 'cancelled'):
            with self.subTest(between=between):
                self.setUp()
                self.observe(poll, output=run_json(attempt=1, jobs=failed_jobs()), now=T0)
                self.observe(poll, output=run_json(attempt=2, conclusion=between, updated='2026-11-23T10:30:00Z',
                                                   jobs=[]), now=T0 + 1)
                self.observe(poll, output=run_json(attempt=3, updated='2026-11-23T11:00:00Z', jobs=failed_jobs()),
                             now=T0 + 2)
                self.assertIsNone(self.refuse('gh run rerun 7', now=T0 + 3))

    def test_a_failed_attempt_polled_without_jobs_keeps_the_failure_history(self):
        jobs = 'gh run view 7 --json databaseId,attempt,headSha,status,conclusion,updatedAt,jobs'
        lean = 'gh run view 7 --json databaseId,attempt,headSha,status,conclusion,updatedAt'
        self.observe(jobs, output=run_json(attempt=1, jobs=failed_jobs()), now=T0)
        self.observe(jobs, output=run_json(attempt=2, updated='2026-11-23T11:00:00Z', jobs=failed_jobs()), now=T0 + 1)
        self.observe(lean, output=run_json(attempt=2, updated='2026-11-23T11:00:00Z'), now=T0 + 2)
        self.assertIn('same failure', self.refuse('gh run rerun 7', now=T0 + 3))

    def test_poll_omitting_conclusion_preserves_known_failures(self):
        poll = 'gh run view 7 --json databaseId,attempt,headSha,status,conclusion,updatedAt,jobs'
        for attempt in (1, 2):
            self.observe(poll, output=run_json(attempt=attempt, jobs=failed_jobs()), now=T0 + attempt)
        lean = json.loads(run_json(attempt=2))
        del lean['conclusion']
        self.observe('gh run view 7 --json databaseId,attempt,headSha,status,updatedAt',
                     output=json.dumps(lean), now=T0 + 3)
        self.assertIn('same failure', self.refuse('gh run rerun 7', now=T0 + 4))

    def test_only_a_successful_or_run_failure_watch_resets_polls(self):
        poll = 'gh run view 9 --json databaseId,attempt,headSha,status,conclusion,updatedAt'
        state = run_json(run_id=9, status='in_progress', conclusion=None)
        for number in range(3):
            self.observe(poll, output=state, now=T0 + number)
        for output in ('connection reset by peer', 'HTTP 404: Not Found'):
            self.observe('gh run watch 9 --exit-status', code=1, output=output, now=T0 + 10)
            self.assertIsNotNone(self.refuse(poll, now=T0 + 11), output)
        self.observe('gh run watch 9 --exit-status', code=1, output='run 9 completed with failure', now=T0 + 20)
        self.assertIsNone(self.refuse(poll, now=T0 + 21))

    def test_older_replay_of_the_same_attempt_is_historical_and_cannot_resume(self):
        poll = 'gh run view 7 --json databaseId,attempt,headSha,status,conclusion,updatedAt'
        self.observe(poll, output=run_json(status='in_progress', conclusion=None, updated='2026-11-23T10:10:00Z'), now=T0)
        self.observe('gh run cancel 7', code=1, output='refused', now=T0 + 1)
        note = self.observe(poll, output=run_json(updated='2026-11-23T10:00:00Z'), now=T0 + 2)
        self.assertIn('older than the last recorded state', note)
        self.assertIsNotNone(self.refuse('gh run cancel 7', now=T0 + 3))

    def test_invalid_repository_values_are_not_classified(self):
        for command in ('gh -R github.com/o/r run rerun 7', 'gh run rerun 7 --repo github.com/o/r',
                        'gh --repo=a/b/c run view 7', 'gh api repos/o/r%2F/actions/runs/7'):
            with self.subTest(command=command):
                self.assertIsNone(ci.classify(command))

    def test_deep_json_and_large_lists_fail_closed_without_evicting_referenced_runs(self):
        self.assertEqual(ci.parse_runs('[' * 5000 + ']' * 5000), [])
        self.observe('gh run rerun 7', code=1, output='refused', now=T0)
        listing = json.dumps({'workflow_runs': [json.loads(run_json(run_id=1000 + n)) for n in range(100)]})
        self.observe('gh run list --json databaseId,attempt,headSha,status,conclusion,updatedAt', output=listing, now=T0 + 1)
        state = json.loads((self.root / '.getzilla/runtime' / ci.STATE_NAME).read_text())
        block = next(row for row in state['blocks'].values() if row['cls'] == 'external-pending')
        self.assertIn(block['run'], state['runs'])

    def test_base_engine_state_keeps_loading_next_to_external_state(self):
        from getzilla.state import bind_session
        from tests._support import activate_owned_route
        bind_session('session-coexist')
        self.addCleanup(bind_session, None)
        activate_owned_route(self.root, {'route_id': 'coexist', 'session_id': 'session-coexist'})
        scope = progress.scope_id(self.root, 'session-coexist')
        for number in range(3):
            progress.observe(self.root, scope, {'command': 'pytest'}, self.root, {'exit_code': 1}, 'a' * 64,
                             event_id=str(number), now=T0 + number)
        ci.observe(self.root, scope, {'command': 'gh run rerun 7'}, {'exit_code': 1, 'stdout': 'refused'}, HEAD, now=T0 + 5)
        raw = json.loads((self.root / progress.STATE).read_text())
        self.assertEqual(set(raw), {'version', 'records'})
        self.assertEqual(raw['version'], 1)
        report = progress.inspect(self.root, scope, now=T0 + 6)
        self.assertEqual(len(report['loops']), 1)
        self.assertEqual([row['class'] for row in report['external']], ['external-pending'])

    def test_expired_blocks_do_not_refuse(self):
        self.observe('gh run rerun 7', code=1, output='refused', now=T0)
        self.assertIsNotNone(self.refuse('gh run rerun 7', now=T0 + 10))
        self.assertIsNone(self.refuse('gh run rerun 7', now=T0 + ci.TTL + 10))


class HookTests(unittest.TestCase):
    def test_real_hooks_stop_unchanged_polls_allow_wait_and_keep_policy(self):
        import subprocess
        from tests._support import activate_owned_route, project_copy, run_hook
        with project_copy(git=True) as root:
            activate_owned_route(root, {'route_id': 'ci-hook', 'session_id': 'ci-hook', 'change_id': 'ci-task'})
            head = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=root, check=True, capture_output=True,
                                  text=True).stdout.strip()
            poll = 'gh run view 7 --json databaseId,attempt,headSha,status,conclusion,updatedAt'
            payload = {'cwd': str(root), 'session_id': 'ci-hook', 'tool_name': 'Bash', 'tool_input': {'command': poll},
                       'tool_response': {'exit_code': 0, 'stdout': run_json(head=head, status='in_progress', conclusion=None)}}
            for number in range(1, 4):
                self.assertEqual(run_hook(root, 'pre_tool_use.py', payload)[1]['decision'], 'allow')
                code, response, stderr = run_hook(root, 'post_tool_use.py', {**payload, 'tool_use_id': str(number)})
                self.assertEqual(code, 0, stderr)
            self.assertIn('gh run watch 7', response['hookSpecificOutput']['additionalContext'])
            denied = run_hook(root, 'pre_tool_use.py', payload)[1]
            self.assertEqual(denied['decision'], 'deny')
            self.assertIn('gh run watch 7 --exit-status', json.dumps(denied))
            wait = {**payload, 'tool_input': {'command': 'gh run watch 7 --exit-status --interval 30'},
                    'tool_response': {'exit_code': 0, 'stdout': 'done'}}
            self.assertEqual(run_hook(root, 'pre_tool_use.py', wait)[1]['decision'], 'allow')
            run_hook(root, 'post_tool_use.py', {**wait, 'tool_use_id': 'wait'})
            self.assertEqual(run_hook(root, 'pre_tool_use.py', payload)[1]['decision'], 'allow')
            # Policy still applies first: a workflow dispatch stays denied whatever the progress state.
            dispatch = {**payload, 'tool_input': {'command': 'gh workflow run getzilla.yml'}}
            self.assertEqual(run_hook(root, 'pre_tool_use.py', dispatch)[1]['decision'], 'deny')
            # A log of a run on the current head is current evidence, not historical.
            stale = {**payload, 'tool_input': {'command': 'gh run view 7 --log-failed'},
                     'tool_response': {'exit_code': 0, 'stdout': 'old failure'}}
            note = run_hook(root, 'post_tool_use.py', {**stale, 'tool_use_id': 'log'})[1]
            self.assertNotIn('historical', json.dumps(note))
            (root / '.getzilla/runtime' / ci.STATE_NAME).write_text('{broken')
            self.assertEqual(run_hook(root, 'pre_tool_use.py', payload)[1]['decision'], 'allow')


if __name__ == '__main__':
    unittest.main()
