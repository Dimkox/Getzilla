"""B02: the retention plan is a report bound to the policy and refs snapshot; nothing is deleted."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.branch_lifecycle import (  # noqa: E402
    BranchLifecycleError, BranchPolicy, BranchRetentionPlan, RefInfo, build_branch_plan, classify_branches,
)
from tests.branch_support import OID, git, make_remote, merged, synthetic  # noqa: E402

POLICY = BranchPolicy(default_branch='main')
NOW = datetime(2026, 2, 1, tzinfo=timezone.utc)


def plan_for(refs, policy=POLICY, now=NOW, **kwargs):
    return build_branch_plan(classify_branches(synthetic(refs, **kwargs), policy), policy, now)


def actions(plan):
    return {entry.name: entry for entry in plan.entries}


class RetentionPlanTests(unittest.TestCase):
    def test_default_dry_run_changes_no_ref(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            remote, _ = make_remote(Path(tmp))
            before = git(remote, 'for-each-ref')
            policy = Path(tmp) / 'policy.json'
            policy.write_text(json.dumps({'default_branch': 'main'}), encoding='utf-8')
            result = subprocess.run([sys.executable, str(ROOT / 'scripts' / 'branch_lifecycle.py'), 'report',
                                     '--repo', str(remote), '--policy', str(policy)],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertTrue(report['plan']['dry_run'])
            self.assertEqual(git(remote, 'for-each-ref'), before)

    def test_before_14_days_not_eligible(self) -> None:
        entry = actions(plan_for([merged('x', OID['b'], '2026-01-25T00:00:00Z')]))['x']
        self.assertEqual(entry.action, 'wait')
        self.assertEqual(entry.eligible_at, '2026-02-08T00:00:00Z')
        self.assertEqual(actions(plan_for([merged('x', OID['b'], '2026-01-10T00:00:00Z')]))['x'].action,
                         'eligible_for_delete')

    def test_unknown_merge_time_kept(self) -> None:
        old_commit = RefInfo('x', OID['b'], committed_at='2020-01-01T00:00:00Z',
                             merge_proof=merged('x', OID['b'], None).merge_proof)
        entry = actions(plan_for([old_commit]))['x']
        self.assertEqual(entry.action, 'keep')
        self.assertIn('MERGE_TIME_UNKNOWN', entry.reasons)

    def test_ttl_without_owner_does_not_delete(self) -> None:
        entry = actions(plan_for([RefInfo('experiment/x', OID['b'], created_at='2020-01-01T00:00:00Z')]))['experiment/x']
        self.assertEqual(entry.action, 'notice')
        self.assertIn('EXPERIMENTAL_TTL_NO_OWNER', entry.reasons)
        self.assertEqual(plan_for([RefInfo('experiment/x', OID['b'])]).eligible, ())

    def test_policy_or_ref_change_invalidates_plan(self) -> None:
        base = plan_for([merged('x', OID['b'])])
        self.assertNotEqual(base.plan_id, plan_for([merged('x', OID['c'])]).plan_id)
        self.assertNotEqual(base.plan_id, plan_for([merged('x', OID['b'])], policy=BranchPolicy('main', retention_days=7)).plan_id)
        data = base.to_dict()
        data['entries'][1]['expected_oid'] = OID['c']
        with self.assertRaises(BranchLifecycleError):
            BranchRetentionPlan.from_dict(data)
        with self.assertRaises(BranchLifecycleError):
            build_branch_plan(classify_branches(synthetic([]), POLICY), BranchPolicy('main', retention_days=1), NOW)

    def test_incomplete_snapshot_plans_nothing(self) -> None:
        plan = plan_for([merged('x', OID['b'], '2025-01-01T00:00:00Z')], complete=False)
        self.assertEqual(plan.eligible, ())


if __name__ == '__main__':
    unittest.main()
