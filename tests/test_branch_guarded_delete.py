"""B03: guarded delete re-checks refs and deletes only under an exact-OID lease, on a temporary bare remote."""
from __future__ import annotations

import sys
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.branch_lifecycle import (  # noqa: E402
    BranchPolicy, LocalGitRefBackend, apply_branch_plan, build_branch_plan, classify_branches,
)
from tests.branch_support import commit, git, make_remote, merged_prs  # noqa: E402

POLICY = BranchPolicy(default_branch='main', deletion_enabled=True)
NOW = datetime(2026, 2, 1, tzinfo=timezone.utc)


class GuardedDeleteTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.remote, self.oids = make_remote(self.base)
        self.prs = merged_prs(self.oids)

    def backend(self, prs=None, **kwargs) -> LocalGitRefBackend:
        return LocalGitRefBackend(self.remote, 'main', pull_requests=self.prs if prs is None else prs, **kwargs)

    def plan(self, policy=POLICY):
        return build_branch_plan(classify_branches(self.backend().snapshot(), policy), policy, NOW)

    def heads(self) -> set[str]:
        return set(git(self.remote, 'for-each-ref', '--format=%(refname:strip=2)', 'refs/heads').split())

    def test_allowed_exact_ref_deleted_in_fixture(self) -> None:
        plan = self.plan()
        self.assertEqual({entry.name for entry in plan.eligible}, {'merged', 'squashed'})
        receipt = apply_branch_plan(plan, self.backend(), POLICY, capability_granted=True, now=NOW)
        self.assertEqual(receipt.status, 'applied')
        self.assertEqual({item['oid'] for item in receipt.deleted}, {self.oids['merged'], self.oids['squashed']})
        self.assertEqual(self.heads(), {'main', 'unmerged', 'newer', 'release/2.2'})
        self.assertNotEqual(receipt.refs_before, receipt.refs_after)

    def test_disabled_capability_is_dry_run(self) -> None:
        before = self.heads()
        for policy, granted in ((POLICY, False), (replace(POLICY, deletion_enabled=False), True)):
            receipt = apply_branch_plan(self.plan(policy), self.backend(), policy, capability_granted=granted, now=NOW)
            self.assertEqual(receipt.status, 'dry_run')
        self.assertEqual(self.heads(), before)

    def test_no_atomic_lease_backend_blocks(self) -> None:
        backend = self.backend()
        backend.supports_atomic_lease = False
        receipt = apply_branch_plan(self.plan(), backend, POLICY, capability_granted=True, now=NOW)
        self.assertEqual(receipt.reasons, ('BACKEND_HAS_NO_ATOMIC_LEASE',))
        self.assertIn('merged', self.heads())

    def test_ref_moved_after_plan_not_deleted(self) -> None:
        plan = self.plan()
        work = self.base / 'work'
        git(work, 'switch', '-q', 'squashed')
        moved = commit(work, 'late.txt', 'late\n', 'pushed after the plan')
        git(work, 'push', '-q', str(self.remote), 'squashed')
        self.assertEqual(git(self.remote, 'rev-parse', 'refs/heads/squashed'), moved)
        receipt = apply_branch_plan(plan, self.backend(), POLICY, capability_granted=True, now=NOW)
        self.assertIn({'name': 'squashed', 'reason': 'REF_MOVED_AFTER_PLAN'}, receipt.skipped)
        self.assertIn('squashed', self.heads())

    def test_lease_rejects_concurrent_move(self) -> None:
        backend = self.backend()
        self.assertFalse(backend.delete_ref('merged', self.oids['unmerged']))
        self.assertIn('merged', self.heads())

    def test_new_open_pr_preserves_ref(self) -> None:
        plan = self.plan()
        prs = {**self.prs, 'merged': {'state': 'open', 'head_oid': self.oids['merged']}}
        receipt = apply_branch_plan(plan, self.backend(prs), POLICY, capability_granted=True, now=NOW)
        self.assertTrue(any(item['name'] == 'merged' and 'OPEN_PULL_REQUEST' in item['reason'] for item in receipt.skipped))
        self.assertIn('merged', self.heads())

    def test_policy_change_after_plan_blocks(self) -> None:
        plan = self.plan()
        receipt = apply_branch_plan(plan, self.backend(), replace(POLICY, keep=('merged',)), capability_granted=True, now=NOW)
        self.assertEqual(receipt.reasons, ('POLICY_CHANGED_AFTER_PLAN',))

    def test_protected_default_never_deleted(self) -> None:
        old = {'state': 'merged', 'head_oid': self.oids['main'], 'merged_at': '2020-01-01T00:00:00Z'}
        prs = {**self.prs, 'main': old, 'release/2.2': {**old}}
        backend = self.backend(prs)
        plan = build_branch_plan(classify_branches(backend.snapshot(), POLICY), POLICY, NOW)
        self.assertFalse({'main', 'release/2.2'} & {entry.name for entry in plan.eligible})
        apply_branch_plan(plan, backend, POLICY, capability_granted=True, now=NOW)
        self.assertTrue({'main', 'release/2.2'} <= self.heads())


if __name__ == '__main__':
    unittest.main()
