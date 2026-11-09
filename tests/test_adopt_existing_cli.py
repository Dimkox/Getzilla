"""Z15 CLI contract; Z17 adversarial flow checks; Z18 end-to-end acceptance scenarios."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from tests.zero_git_support import (  # noqa: E402
    FAKE_GITHUB_TOKEN, FAKE_KEY_MARKER, FAKE_PRIVATE_KEY, clean_source, git_objects, plan_and_adopt, tree_state, write_tree,
)

CLI = ROOT / 'scripts/adopt_existing.py'


def cli(*args: str, env: dict | None = None) -> tuple[int, dict]:
    proc = subprocess.run([sys.executable, str(CLI), *args], capture_output=True, timeout=300, check=False,
                          env={**os.environ, 'GETZILLA_HOME': str(ROOT), **(env or {})})
    return proc.returncode, json.loads(proc.stdout.decode('utf-8'))


def assert_no_adoption_refusal(case: unittest.TestCase, code: int, record: object) -> None:
    if type(code) is int and code == 0:
        return
    category = 'UNKNOWN'
    if type(record) is dict:
        reason = record.get('reason_code')
        if type(reason) is str and reason in {
            'INVALID_ARGUMENTS', 'QUIESCENCE_REQUIRED', 'PLAN_DIGEST_MISMATCH', 'BLOCKED_SECURITY',
            'BLOCKED_UNSAFE_SOURCE', 'BLOCKED_UNSUPPORTED_FS', 'GIT_PRESENT', 'STALE_PLAN',
            'PLAN_NOT_READY', 'PLAN_TAMPERED', 'TARGET_CONFLICT', 'TARGET_EXISTS', 'OPERATION_LOCKED',
            'UNKNOWN_OPERATION', 'PUBLISHED', 'VERIFICATION_FAILED', 'STORE_OBJECT_MODIFIED',
            'STORE_OBJECT_MISSING', 'TOOL_ERROR', 'STATE_CORRUPT', 'ERROR',
        }:
            category = reason
    # Each closed category has its own source location in sanitized failure reports.
    case.assertNotEqual(category, 'INVALID_ARGUMENTS', 'adoption refusal: INVALID_ARGUMENTS')
    case.assertNotEqual(category, 'QUIESCENCE_REQUIRED', 'adoption refusal: QUIESCENCE_REQUIRED')
    case.assertNotEqual(category, 'PLAN_DIGEST_MISMATCH', 'adoption refusal: PLAN_DIGEST_MISMATCH')
    case.assertNotEqual(category, 'BLOCKED_SECURITY', 'adoption refusal: BLOCKED_SECURITY')
    case.assertNotEqual(category, 'BLOCKED_UNSAFE_SOURCE', 'adoption refusal: BLOCKED_UNSAFE_SOURCE')
    case.assertNotEqual(category, 'BLOCKED_UNSUPPORTED_FS', 'adoption refusal: BLOCKED_UNSUPPORTED_FS')
    case.assertNotEqual(category, 'GIT_PRESENT', 'adoption refusal: GIT_PRESENT')
    case.assertNotEqual(category, 'STALE_PLAN', 'adoption refusal: STALE_PLAN')
    case.assertNotEqual(category, 'PLAN_NOT_READY', 'adoption refusal: PLAN_NOT_READY')
    case.assertNotEqual(category, 'PLAN_TAMPERED', 'adoption refusal: PLAN_TAMPERED')
    case.assertNotEqual(category, 'TARGET_CONFLICT', 'adoption refusal: TARGET_CONFLICT')
    case.assertNotEqual(category, 'TARGET_EXISTS', 'adoption refusal: TARGET_EXISTS')
    case.assertNotEqual(category, 'OPERATION_LOCKED', 'adoption refusal: OPERATION_LOCKED')
    case.assertNotEqual(category, 'UNKNOWN_OPERATION', 'adoption refusal: UNKNOWN_OPERATION')
    case.assertNotEqual(category, 'PUBLISHED', 'adoption refusal: PUBLISHED')
    case.assertNotEqual(category, 'VERIFICATION_FAILED', 'adoption refusal: VERIFICATION_FAILED')
    case.assertNotEqual(category, 'STORE_OBJECT_MODIFIED', 'adoption refusal: STORE_OBJECT_MODIFIED')
    case.assertNotEqual(category, 'STORE_OBJECT_MISSING', 'adoption refusal: STORE_OBJECT_MISSING')
    case.assertNotEqual(category, 'TOOL_ERROR', 'adoption refusal: TOOL_ERROR')
    case.assertNotEqual(category, 'STATE_CORRUPT', 'adoption refusal: STATE_CORRUPT')
    case.assertNotEqual(category, 'ERROR', 'adoption refusal: ERROR')
    case.assertNotEqual(category, 'UNKNOWN', 'adoption refusal: UNKNOWN')


class ClosedAdoptionDiagnosticTests(unittest.TestCase):
    """Pure dictionary/trace controls; no adoption fixture, CLI or payload is used."""

    def refusal(self, code, record):
        try:
            assert_no_adoption_refusal(self, code, record)
        except self.failureException as failure:
            location = None
            trace = failure.__traceback__
            while trace is not None:
                if trace.tb_frame.f_code.co_name == 'assert_no_adoption_refusal':
                    location = trace.tb_lineno
                trace = trace.tb_next
            self.assertIsNotNone(location)
            return str(failure), location
        self.fail('nonzero adoption result has no closed diagnostic')

    def test_success_never_inspects_private_record(self):
        class Unreadable:
            def __repr__(self):
                raise AssertionError('private record was inspected')
        assert_no_adoption_refusal(self, 0, Unreadable())
        assert_no_adoption_refusal(self, 0, {'details': Unreadable()})

    def test_tool_and_conflict_have_distinct_fixed_trace_lines(self):
        tool, tool_line = self.refusal(8, {'reason_code': 'TOOL_ERROR', 'details': 'PRIVATE-CANARY'})
        conflict, conflict_line = self.refusal(6, {'reason_code': 'TARGET_CONFLICT'})
        self.assertIn('adoption refusal: TOOL_ERROR', tool)
        self.assertIn('adoption refusal: TARGET_CONFLICT', conflict)
        self.assertNotEqual(tool_line, conflict_line)
        self.assertNotIn('PRIVATE-CANARY', tool)

    def test_stale_and_integrity_have_distinct_fixed_trace_lines(self):
        stale, stale_line = self.refusal(5, {'reason_code': 'STALE_PLAN'})
        integrity, integrity_line = self.refusal(7, {'reason_code': 'VERIFICATION_FAILED'})
        self.assertIn('adoption refusal: STALE_PLAN', stale)
        self.assertIn('adoption refusal: VERIFICATION_FAILED', integrity)
        self.assertNotEqual(stale_line, integrity_line)

    def test_unknown_private_reason_and_details_are_never_disclosed(self):
        class Unreadable:
            def __repr__(self):
                raise AssertionError('private details were inspected')
        message, unknown_line = self.refusal(8, {'reason_code': 'PRIVATE-CANARY-REASON',
                                               'details': Unreadable(), 'PRIVATE-CANARY-KEY': 'private'})
        missing, missing_line = self.refusal(2, {})
        self.assertIn('adoption refusal: UNKNOWN', message)
        self.assertNotIn('PRIVATE', message)
        self.assertNotIn('private', message)
        self.assertEqual(unknown_line, missing_line)
        self.assertIn('adoption refusal: UNKNOWN', missing)

    def test_non_string_or_non_dictionary_reason_is_fixed_unknown(self):
        for record in ({'reason_code': None}, {'reason_code': 7}, {'reason_code': {'private': 'value'}}, None):
            with self.subTest():
                message, _line = self.refusal(8, record)
                self.assertIn('adoption refusal: UNKNOWN', message)
                self.assertNotIn('private', message)


class _Case(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix='zg-cli-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.source = clean_source(self.base / 'src')
        self.target = self.base / 'adopted'
        self.state = self.base / 'state'
        self.plan_file = self.base / 'plan.json'

    def plan(self, *extra: str) -> tuple[int, dict]:
        return cli('plan', '--source', str(self.source), '--target', str(self.target), '--output', str(self.plan_file),
                   '--state-root', str(self.state), *extra)

    def apply(self, digest: str | None = None, *extra: str) -> tuple[int, dict]:
        digest = digest or json.loads(self.plan_file.read_text(encoding='utf-8'))['plan_id']
        return cli('apply', '--plan', str(self.plan_file), '--plan-digest', digest, '--state-root', str(self.state), *extra)


class CliTests(_Case):
    def test_cli_plan_has_no_source_side_effect(self) -> None:
        before = tree_state(self.source)
        code, record = self.plan()
        self.assertEqual(code, 0, record)
        self.assertEqual(record['status'], 'plan_ready')
        self.assertEqual(tree_state(self.source), before)
        self.assertFalse(self.target.exists())

    def test_apply_requires_matching_digest(self) -> None:
        self.plan()
        code, record = self.apply('0' * 64, '--writers-stopped')
        self.assertEqual((code, record['reason_code']), (2, 'PLAN_DIGEST_MISMATCH'))
        code, record = self.apply(None)
        self.assertEqual((code, record['reason_code']), (2, 'QUIESCENCE_REQUIRED'))
        self.assertFalse(self.target.exists())

    def test_exit_code_contract(self) -> None:
        write_tree(self.source, {'.env': 'X=1'})
        code, record = self.plan()
        self.assertEqual((code, record['reason_code']), (3, 'BLOCKED_SECURITY'))
        code, record = cli('status', '--operation-id', 'not-an-op', '--state-root', str(self.state))
        self.assertEqual(code, 2)
        code, record = cli('frobnicate')
        self.assertEqual((code, record['reason_code']), (2, 'INVALID_ARGUMENTS'))

    def test_parent_git_or_gitfile_is_not_zero_git(self) -> None:
        write_tree(self.source, {'.git': 'gitdir: /elsewhere/.git/worktrees/x\n'})
        code, record = self.plan()
        self.assertEqual((code, record['reason_code']), (4, 'GIT_PRESENT'))
        nested = write_tree(self.base / 'repo/sub', {'a.txt': 'a'})
        (self.base / 'repo/.git').mkdir()
        code, record = cli('plan', '--source', str(nested), '--target', str(self.target))
        self.assertEqual((code, record['reason_code']), (4, 'GIT_PRESENT'))

    def test_missing_git_reports_tool_error(self) -> None:
        self.plan()
        bin_dir = self.base / 'nogit'
        bin_dir.mkdir()
        digest = json.loads(self.plan_file.read_text(encoding='utf-8'))['plan_id']
        code, record = cli('apply', '--plan', str(self.plan_file), '--plan-digest', digest, '--writers-stopped',
                           '--state-root', str(self.state), env={'PATH': str(bin_dir)})
        self.assertEqual((code, record['reason_code']), (8, 'TOOL_ERROR'))
        self.assertFalse(self.target.exists())

    def test_remote_push_flags_not_available(self) -> None:
        self.plan()
        for flag in ('--push', '--remote', '--create-repo'):
            with self.subTest(flag=flag):
                code, record = self.apply(None, '--writers-stopped', flag, 'x')
                self.assertEqual(code, 2)

    def test_status_failed_operation_has_successful_query_envelope(self) -> None:
        write_tree(self.source, {'AGENTS.md': '# mine\n'})
        self.plan()
        code, record = self.apply(None, '--writers-stopped')
        self.assertEqual((code, record['reason_code']), (6, 'TARGET_CONFLICT'))
        operation = 'op-' + json.loads(self.plan_file.read_text(encoding='utf-8'))['plan_id'][:32]
        code, status = cli('status', '--operation-id', operation, '--state-root', str(self.state))
        self.assertEqual(code, 0)
        self.assertEqual(status['reason_code'], 'TARGET_CONFLICT')

    def test_full_cli_round_trip(self) -> None:
        self.plan()
        code, record = self.apply(None, '--writers-stopped')
        assert_no_adoption_refusal(self, code, record)
        self.assertEqual(code, 0, record)
        self.assertEqual(record['details']['integrity_status'], 'verified')
        self.assertTrue((self.target / '.git').is_dir())


class AdversarialTests(_Case):
    def test_no_network_during_any_ingest_stage(self) -> None:
        def refuse(*args, **kwargs):
            raise AssertionError('network access attempted')

        with mock.patch.object(socket.socket, 'connect', refuse), mock.patch.object(socket, 'create_connection', refuse):
            plan_and_adopt(self.source, self.target, self.state)

    def test_no_client_process_exec(self) -> None:
        sentinel = self.base / 'client-ran'
        write_tree(self.source, {'setup.py': f'open({str(sentinel)!r}, "w")\n',
                                 'package.json': json.dumps({'scripts': {'postinstall': f'touch {sentinel}'}}),
                                 'Makefile': f'all:\n\ttouch {sentinel}\n'})
        plan_and_adopt(self.source, self.target, self.state)
        self.assertFalse(sentinel.exists())

    def test_secret_absent_from_snapshot_git_logs_and_index(self) -> None:
        write_tree(self.source, {'.env': f'TOKEN={FAKE_GITHUB_TOKEN}\n', 'keys/id_ed25519': FAKE_PRIVATE_KEY})
        policy_file = self.base / 'policy.json'
        policy_file.write_text(json.dumps({'exclude': ['.env', 'keys']}), encoding='utf-8')
        code, record = cli('plan', '--source', str(self.source), '--target', str(self.target),
                           '--output', str(self.plan_file), '--policy', str(policy_file))
        self.assertEqual(code, 0, record)
        code, applied = self.apply(None, '--writers-stopped')
        self.assertEqual(code, 0, applied)
        marker = FAKE_GITHUB_TOKEN.encode()
        for content in git_objects(self.target):
            self.assertNotIn(marker, content)
            self.assertNotIn(FAKE_KEY_MARKER.encode(), content)
        for path in self.state.rglob('*'):
            if path.is_file():
                self.assertNotIn(marker, path.read_bytes())
        self.assertNotIn(FAKE_GITHUB_TOKEN, json.dumps(record) + json.dumps(applied))
        self.assertFalse((self.target / '.env').exists())

    def test_approved_path_replacement_is_stale(self) -> None:
        self.plan()
        (self.source / 'app/main.py').write_text(f'K = "{FAKE_GITHUB_TOKEN}"\n', encoding='utf-8')
        code, record = self.apply(None, '--writers-stopped')
        self.assertEqual((code, record['reason_code']), (5, 'STALE_PLAN'))
        self.assertFalse(self.target.exists())
        for path in self.state.rglob('*'):
            if path.is_file():
                self.assertNotIn(FAKE_GITHUB_TOKEN.encode(), path.read_bytes())

    def test_materialize_existing_guard_survives_adoption(self) -> None:
        plan_and_adopt(self.source, self.target, self.state)
        proc = subprocess.run([sys.executable, str(ROOT / 'scripts/install_into.py'), '--materialize-new', str(self.target)],
                              capture_output=True, text=True, check=False, timeout=300)
        self.assertNotEqual(proc.returncode, 0)

    def test_partial_git_objects_do_not_contain_excluded_bytes(self) -> None:
        write_tree(self.source, {'secret.env': f'T={FAKE_GITHUB_TOKEN}\n', 'AGENTS.md': '# mine\n'})
        from getzilla.project_adoption import run_adoption
        from getzilla.source_admission import plan_source
        from getzilla.source_models import IngestPolicy
        from getzilla.source_snapshot import AdoptionError
        plan = plan_source(self.source, self.target, IngestPolicy(exclude=('secret.env',)))
        with self.assertRaises(AdoptionError):  # AGENTS.md collides after the source commit exists
            run_adoption(plan, plan.plan_id, quiesced=True, home=ROOT, state_root=self.state)
        for path in self.base.rglob('*'):
            if path.is_file() and path != self.source / 'secret.env':
                self.assertNotIn(FAKE_GITHUB_TOKEN.encode(), path.read_bytes(), path)


class EndToEndTests(_Case):
    def test_clean_python_source_end_to_end(self) -> None:
        before = tree_state(self.source)
        plan, receipt = plan_and_adopt(self.source, self.target, self.state)
        self.assertEqual(receipt['state'], 'PUBLISHED_LOCAL')
        self.assertEqual(tree_state(self.source), before)  # test_e2e_original_before_after_equal
        self.assertEqual((self.target / 'app/main.py').read_bytes(), (self.source / 'app/main.py').read_bytes())

    def test_js_folder_adopts_without_running_npm(self) -> None:
        sentinel = self.base / 'npm-ran'
        source = write_tree(self.base / 'js', {
            'package.json': json.dumps({'name': 'demo', 'scripts': {'prepare': f'touch {sentinel}'}}),
            'src/index.js': 'export const x = 1;\n'})
        target = self.base / 'js-adopted'
        plan_and_adopt(source, target, self.base / 'js-state')
        self.assertFalse(sentinel.exists())
        self.assertFalse((target / 'node_modules').exists())

    def test_env_excluded_and_reported(self) -> None:
        write_tree(self.source, {'.env': 'X=1'})
        from getzilla.source_models import IngestPolicy
        _plan, receipt = plan_and_adopt(self.source, self.target, self.state, IngestPolicy(exclude=('.env',)))
        self.assertEqual(receipt['excluded'], [{'path': '.env', 'reason_code': 'POLICY_EXCLUDED', 'policy_ref': 'exclude:.env'}])

    def test_existing_git_routes_away_from_zero_git(self) -> None:
        subprocess.run(['git', 'init', '-q', str(self.source)], check=True)
        code, record = self.plan()
        self.assertEqual((code, record['reason_code']), (4, 'GIT_PRESENT'))


if __name__ == '__main__':
    unittest.main()
