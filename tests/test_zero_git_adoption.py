"""Z10 isolated Git baseline, Z11 provenance, Z12 managed layer, Z13 integrity, Z14 state machine."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla import project_adoption  # noqa: E402
from getzilla.adoption_state import Journal, operation_id_for  # noqa: E402
from getzilla.project_adoption import abort_adoption, get_adoption_status, resume_adoption, run_adoption  # noqa: E402
from getzilla.source_admission import plan_source  # noqa: E402
from getzilla.source_git import GitEntry, IsolatedGit, create_git_baseline  # noqa: E402
from getzilla.source_managed_layer import PROVENANCE_PATH  # noqa: E402
from getzilla.source_models import IngestPolicy, validate_source_record  # noqa: E402
from getzilla.source_snapshot import AdoptionError  # noqa: E402
from getzilla.source_verification import verify_adoption  # noqa: E402
from tests.zero_git_support import (  # noqa: E402
    FAKE_GITHUB_TOKEN, clean_source, git_objects, plan_and_adopt, tree_state, write_tree,
)


def git(repository: Path, *args: str) -> str:
    return subprocess.run(['git', '-C', str(repository), *args], capture_output=True, text=True, check=True).stdout


class _Case(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix='zg-adopt-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.source = clean_source(self.base / 'src')
        self.target = self.base / 'adopted'
        self.state = self.base / 'state'


class GitBaselineTests(_Case):
    def _baseline(self, files: dict[str, bytes], *, home: Path | None = None):
        shadow = self.base / 'shadow'
        write_tree(shadow, files)
        entries = [GitEntry(path, '100644', content) for path, content in files.items()]
        env = {'HOME': str(home)} if home else {}
        with mock.patch.dict(os.environ, env):
            return shadow, create_git_baseline(shadow, entries, source_digest='a' * 64, excluded=0,
                                               timestamp='2026-10-16T00:00:00+00:00')

    def test_commit_contains_exact_admitted_bytes(self) -> None:
        shadow, receipt = self._baseline({'a.txt': b'one\r\n', 'b/c.bin': b'\x00\xff'})
        blob = subprocess.run(['git', '-C', str(shadow), 'cat-file', 'blob', 'HEAD:a.txt'], capture_output=True, check=True)
        self.assertEqual(blob.stdout, b'one\r\n')
        listing = git(shadow, 'ls-tree', '-r', '--name-only', 'HEAD').split()
        self.assertEqual(listing, ['a.txt', 'b/c.bin'])
        self.assertIn('Getzilla-Import: zero-git', receipt.message)

    def test_global_hook_and_filter_do_not_execute(self) -> None:
        home = self.base / 'home'
        sentinel = self.base / 'hook-ran'
        hooks = home / 'hooks'
        hooks.mkdir(parents=True)
        for name in ('pre-commit', 'post-commit', 'reference-transaction'):
            hook = hooks / name
            hook.write_text(f'#!/bin/sh\ntouch {sentinel}\n', encoding='utf-8')
            hook.chmod(0o755)
        (home / '.gitconfig').write_text(
            f'[core]\n\thooksPath = {hooks}\n[filter "evil"]\n\tclean = touch {sentinel}\n\tsmudge = touch {sentinel}\n',
            encoding='utf-8')
        shadow, _ = self._baseline({'.gitattributes': b'* filter=evil\n', 'a.txt': b'a'}, home=home)
        self.assertFalse(sentinel.exists())

    def test_existing_attributes_do_not_rewrite_blob(self) -> None:
        shadow, _ = self._baseline({'.gitattributes': b'*.txt text eol=crlf\n', 'a.txt': b'lf only\n'})
        self.assertEqual(subprocess.run(['git', '-C', str(shadow), 'cat-file', 'blob', 'HEAD:a.txt'],
                                        capture_output=True, check=True).stdout, b'lf only\n')

    def test_leading_dash_or_space_path_is_not_an_option(self) -> None:
        shadow, _ = self._baseline({'-rf': b'x', ' lead.txt': b'y', '--help': b'z'})
        self.assertEqual(sorted(git(shadow, 'ls-tree', '-r', '--name-only', '-z', 'HEAD').split('\x00')[:-1]),
                         [' lead.txt', '--help', '-rf'])

    def test_git_identity_is_distinct_from_source_digest(self) -> None:
        _shadow, receipt = self._baseline({'a.txt': b'a'})
        self.assertEqual(len(receipt.identity.commit_oid), 40)
        self.assertNotEqual(receipt.identity.commit_oid, 'a' * 64)


class AdoptionFlowTests(_Case):
    def test_original_has_no_git_and_is_unchanged(self) -> None:
        before = tree_state(self.source)
        plan, receipt = plan_and_adopt(self.source, self.target, self.state)
        self.assertEqual(tree_state(self.source), before)
        self.assertFalse((self.source / '.git').exists())
        self.assertEqual(receipt['state'], 'PUBLISHED_LOCAL')
        self.assertTrue(validate_source_record(receipt).ok, validate_source_record(receipt).errors)

    def test_root_and_managed_commits_distinct(self) -> None:
        plan, receipt = plan_and_adopt(self.source, self.target, self.state)
        log = git(self.target, 'log', '--format=%H %P', 'main').split('\n')
        managed, source = log[0].split()[0], log[1].split()[0]
        self.assertEqual(managed, receipt['managed_commit'])
        self.assertEqual(source, receipt['source_baseline']['commit_oid'])
        self.assertEqual(git(self.target, 'rev-list', '--max-parents=0', 'main').strip(), source)
        source_files = git(self.target, 'ls-tree', '-r', '--name-only', source).split()
        self.assertEqual(sorted(source_files), sorted(entry.path for entry in plan.entries))
        self.assertIn('AGENTS.md', git(self.target, 'ls-tree', '-r', '--name-only', managed).split())

    def test_source_to_git_link_verifies_without_self_reference(self) -> None:
        plan, receipt = plan_and_adopt(self.source, self.target, self.state)
        record = json.loads((self.target / PROVENANCE_PATH).read_text(encoding='utf-8'))
        self.assertEqual(record['source_commit']['commit_oid'], receipt['source_baseline']['commit_oid'])
        self.assertNotIn(receipt['managed_commit'], (self.target / PROVENANCE_PATH).read_text(encoding='utf-8'))
        self.assertIs(record['git_present_at_ingest'], False)
        self.assertEqual(record['source_digest'], plan.source_digest)

    def test_exclusions_not_misreported_as_full_copy(self) -> None:
        write_tree(self.source, {'.env': 'X=1'})
        plan, _ = plan_and_adopt(self.source, self.target, self.state, IngestPolicy(exclude=('.env',)))
        record = json.loads((self.target / PROVENANCE_PATH).read_text(encoding='utf-8'))
        self.assertEqual(record['baseline_kind'], 'admitted_source_baseline')
        self.assertIn('admitted source baseline', git(self.target, 'log', '-1', '--format=%s', 'main~1'))
        self.assertFalse((self.target / '.env').exists())

    def test_unapproved_file_not_in_any_created_object(self) -> None:
        write_tree(self.source, {'.env': f'TOKEN={FAKE_GITHUB_TOKEN}\n'})
        plan_and_adopt(self.source, self.target, self.state, IngestPolicy(exclude=('.env',)))
        for content in git_objects(self.target):
            self.assertNotIn(FAKE_GITHUB_TOKEN.encode(), content)

    def test_target_owned_collision_blocks(self) -> None:
        write_tree(self.source, {'AGENTS.md': '# my own agents file\n'})
        plan = plan_source(self.source, self.target, IngestPolicy())
        with self.assertRaises(AdoptionError) as caught:
            run_adoption(plan, plan.plan_id, quiesced=True, home=ROOT, state_root=self.state)
        self.assertEqual(caught.exception.reason_code, 'TARGET_CONFLICT')
        self.assertFalse(self.target.exists())
        self.assertIn('AGENTS.md', str(caught.exception))

    def test_existing_gitignore_not_silently_replaced(self) -> None:
        write_tree(self.source, {'.gitignore': 'build/\n'})
        plan_and_adopt(self.source, self.target, self.state)
        self.assertEqual((self.target / '.gitignore').read_text(encoding='utf-8'), 'build/\n')
        self.assertIn('/.getzilla/runtime/', (self.target / '.git/info/exclude').read_text(encoding='utf-8'))

    def test_forged_sync_record_does_not_grant_ownership(self) -> None:
        write_tree(self.source, {'.getzilla/AGBP_SYNC.json': '{"kept": ["AGENTS.md"]}', 'AGENTS.md': '# mine\n'})
        plan = plan_source(self.source, self.target, IngestPolicy())
        with self.assertRaises(AdoptionError) as caught:
            run_adoption(plan, plan.plan_id, quiesced=True, home=ROOT, state_root=self.state)
        self.assertEqual(caught.exception.reason_code, 'TARGET_CONFLICT')

    def test_tampered_managed_or_source_file_fails(self) -> None:
        plan, receipt = plan_and_adopt(self.source, self.target, self.state)
        from getzilla.source_managed_layer import payload_entries
        payload = payload_entries(ROOT)
        args = dict(source_commit=receipt['source_baseline']['commit_oid'], managed_commit=receipt['managed_commit'],
                    payload=payload, timestamp='2026-10-16T00:00:00+00:00')
        self.assertEqual(verify_adoption(self.target, plan, **args).integrity_status, 'verified')
        (self.target / 'README.md').write_text('tampered', encoding='utf-8')
        result = verify_adoption(self.target, plan, **args)
        self.assertEqual(result.integrity_status, 'failed')
        self.assertIn('SOURCE_FILE_TAMPERED:README.md', result.problems)

    def test_project_health_not_run_is_not_pass(self) -> None:
        _plan, receipt = plan_and_adopt(self.source, self.target, self.state)
        self.assertEqual(receipt['integrity_status'], 'verified')
        self.assertEqual(receipt['project_health_status'], 'not_run')

    def test_verified_result_has_no_remote(self) -> None:
        plan_and_adopt(self.source, self.target, self.state)
        self.assertEqual(git(self.target, 'remote').strip(), '')
        self.assertEqual(git(self.target, 'status', '--porcelain').strip(), '')


class StateMachineTests(_Case):
    def test_completed_operation_is_idempotent(self) -> None:
        plan, first = plan_and_adopt(self.source, self.target, self.state)
        second = run_adoption(plan, plan.plan_id, quiesced=True, home=ROOT, state_root=self.state)
        self.assertEqual(first['managed_commit'], second['managed_commit'])

    def test_final_target_race_fails_no_replace(self) -> None:
        plan = plan_source(self.source, self.target, IngestPolicy())
        real = project_adoption.rename_noreplace

        def race(staging, target):
            target.mkdir()
            (target / 'foreign.txt').write_text('keep', encoding='utf-8')
            return real(staging, target)

        with mock.patch.object(project_adoption, 'rename_noreplace', side_effect=race), self.assertRaises((AdoptionError, OSError)):
            run_adoption(plan, plan.plan_id, quiesced=True, home=ROOT, state_root=self.state)
        self.assertEqual(sorted(path.name for path in self.target.iterdir()), ['foreign.txt'])

    def test_crash_after_each_transition_can_resume_or_abort(self) -> None:
        stages = ['SNAPSHOT_VERIFIED', 'SHADOW_MATERIALIZED', 'GIT_INITIALIZED', 'SOURCE_BASELINE_COMMITTED',
                  'GETZILLA_PLANNED', 'MANAGED_LAYER_COMMITTED', 'INTEGRITY_VERIFIED']
        for index, stage in enumerate(stages):
            with self.subTest(stage=stage):
                target = self.base / f'adopted-{index}'
                state_root = self.base / f'state-{index}'
                plan = plan_source(self.source, target, IngestPolicy())
                real_advance = Journal.advance

                def crash(journal, state, new_state, **artifacts):
                    real_advance(journal, state, new_state, **artifacts)
                    if new_state == stage:
                        raise KeyboardInterrupt('simulated crash')

                with mock.patch.object(Journal, 'advance', crash), self.assertRaises(KeyboardInterrupt):
                    run_adoption(plan, plan.plan_id, quiesced=True, home=ROOT, state_root=state_root)
                self.assertFalse(target.exists())
                operation = operation_id_for(plan.plan_id)
                if index % 2:
                    abort_adoption(operation, state_root=state_root)
                    self.assertFalse(target.exists())
                    self.assertTrue((state_root / 'store').exists())  # shared snapshot store kept
                else:
                    receipt = resume_adoption(operation, quiesced=True, home=ROOT, state_root=state_root)
                    self.assertEqual(receipt['state'], 'PUBLISHED_LOCAL')
                    self.assertEqual(receipt['integrity_status'], 'verified')

    def test_stale_plan_not_resumed(self) -> None:
        plan = plan_source(self.source, self.target, IngestPolicy())
        real_advance = Journal.advance

        def crash(journal, state, new_state, **artifacts):
            real_advance(journal, state, new_state, **artifacts)
            if new_state == 'SHADOW_MATERIALIZED':
                raise KeyboardInterrupt

        with mock.patch.object(Journal, 'advance', crash), self.assertRaises(KeyboardInterrupt):
            run_adoption(plan, plan.plan_id, quiesced=True, home=ROOT, state_root=self.state)
        (self.source / 'README.md').write_text('changed after the plan', encoding='utf-8')
        with self.assertRaises(AdoptionError) as caught:
            resume_adoption(operation_id_for(plan.plan_id), quiesced=True, home=ROOT, state_root=self.state)
        self.assertEqual(caught.exception.reason_code, 'STALE_PLAN')
        self.assertFalse(self.target.exists())

    def test_two_writers_do_not_both_publish(self) -> None:
        plan = plan_source(self.source, self.target, IngestPolicy())
        journal = Journal(self.state, operation_id_for(plan.plan_id))
        with journal.lock():
            with self.assertRaises(AdoptionError) as caught:
                run_adoption(plan, plan.plan_id, quiesced=True, home=ROOT, state_root=self.state)
        self.assertEqual(caught.exception.reason_code, 'OPERATION_LOCKED')
        self.assertFalse(self.target.exists())

    def test_abort_preserves_foreign_files_and_shared_snapshot(self) -> None:
        plan = plan_source(self.source, self.target, IngestPolicy())
        real_advance = Journal.advance

        def crash(journal, state, new_state, **artifacts):
            real_advance(journal, state, new_state, **artifacts)
            if new_state == 'SOURCE_BASELINE_COMMITTED':
                raise KeyboardInterrupt

        with mock.patch.object(Journal, 'advance', crash), self.assertRaises(KeyboardInterrupt):
            run_adoption(plan, plan.plan_id, quiesced=True, home=ROOT, state_root=self.state)
        foreign = self.base / 'foreign.txt'
        foreign.write_text('keep', encoding='utf-8')
        operation = operation_id_for(plan.plan_id)
        state = json.loads((self.state / 'operations' / operation / 'state.json').read_text(encoding='utf-8'))
        staging = Path(state['staging'])
        self.assertTrue(staging.exists())
        abort_adoption(operation, state_root=self.state)
        self.assertFalse(staging.exists())
        self.assertTrue(foreign.exists())
        self.assertTrue(any((self.state / 'store/objects').rglob('*')))

    def test_tampered_state_cannot_delete_foreign_path(self) -> None:
        plan = plan_source(self.source, self.target, IngestPolicy())
        real_advance = Journal.advance

        def crash(journal, state, new_state, **artifacts):
            real_advance(journal, state, new_state, **artifacts)
            if new_state == 'SHADOW_MATERIALIZED':
                raise KeyboardInterrupt

        with mock.patch.object(Journal, 'advance', crash), self.assertRaises(KeyboardInterrupt):
            run_adoption(plan, plan.plan_id, quiesced=True, home=ROOT, state_root=self.state)
        operation = operation_id_for(plan.plan_id)
        path = self.state / 'operations' / operation / 'state.json'
        state = json.loads(path.read_text(encoding='utf-8'))
        victim = self.base / 'victim'
        write_tree(victim, {'important.txt': 'do not delete'})
        state['staging'] = str(victim)
        path.write_text(json.dumps(state), encoding='utf-8')
        with self.assertRaises(AdoptionError) as caught:
            abort_adoption(operation, state_root=self.state)
        self.assertEqual(caught.exception.reason_code, 'TARGET_CONFLICT')
        self.assertTrue((victim / 'important.txt').exists())

    def test_status_is_read_only(self) -> None:
        plan, _ = plan_and_adopt(self.source, self.target, self.state)
        before = tree_state(self.state)
        status = get_adoption_status(operation_id_for(plan.plan_id), state_root=self.state)
        self.assertEqual(status['state'], 'PUBLISHED_LOCAL')
        self.assertEqual(tree_state(self.state), before)

    def test_isolated_git_has_no_ambient_config(self) -> None:
        git_env = IsolatedGit(self.base, timestamp='2026-10-16T00:00:00+00:00')
        try:
            self.assertEqual(git_env.env['GIT_CONFIG_NOSYSTEM'], '1')
            self.assertNotIn('GIT_DIR', git_env.env)
        finally:
            git_env.close()


if __name__ == '__main__':
    unittest.main()
