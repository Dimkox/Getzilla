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
                          env={**os.environ, **(env or {})})
    return proc.returncode, json.loads(proc.stdout.decode('utf-8'))


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
