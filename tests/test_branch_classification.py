"""B01: branches are classified by ancestry or proven tree equality, never by commit date."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.branch_lifecycle import (  # noqa: E402
    BranchLifecycleError, BranchPolicy, LocalGitRefBackend, MergeProof, RefInfo, classify_branches,
)
from tests.branch_support import OID, make_remote, merged, merged_prs, synthetic  # noqa: E402

POLICY = BranchPolicy(default_branch='main')


class GitClassificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.remote, cls.oids = make_remote(Path(cls.tmp.name))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def inventory(self, **kwargs):
        backend = LocalGitRefBackend(self.remote, 'main', pull_requests=merged_prs(self.oids), **kwargs)
        return {record.name: record for record in classify_branches(backend.snapshot(), POLICY).branches}

    def test_old_unmerged_branch_preserved(self) -> None:
        record = self.inventory()['unmerged']
        self.assertEqual(record.state, 'unmerged')
        self.assertFalse(record.deletable_candidate)

    def test_merged_by_ancestry_has_evidence(self) -> None:
        record = self.inventory()['merged']
        self.assertEqual((record.state, record.merge_proof.kind), ('merged', 'ancestor'))
        self.assertEqual(record.expected_oid, self.oids['merged'])
        self.assertEqual(record.merge_proof.target_commit, self.oids['main'])

    def test_newer_date_not_selected_as_main(self) -> None:
        records = self.inventory()
        self.assertIn('DEFAULT_BRANCH', records['main'].keep_reasons)
        self.assertNotIn('DEFAULT_BRANCH', records['newer'].keep_reasons)
        self.assertEqual(records['newer'].state, 'unmerged')
        with self.assertRaises(BranchLifecycleError):
            BranchPolicy.from_dict({'retention_days': 14})

    def test_squash_with_tree_equality_proof(self) -> None:
        self.assertEqual(self.inventory()['squashed'].merge_proof.kind, 'tree_equal')

    def test_squash_without_proof_not_deletable(self) -> None:
        backend = LocalGitRefBackend(self.remote, 'main', pull_requests=merged_prs(self.oids), equivalence_depth=0)
        records = {r.name: r for r in classify_branches(backend.snapshot(), POLICY).branches}
        self.assertEqual(records['squashed'].state, 'unmerged')
        self.assertFalse(records['squashed'].deletable_candidate)

    def test_protected_and_open_pr_kept(self) -> None:
        prs = {**merged_prs(self.oids), 'merged': {'state': 'open', 'head_oid': self.oids['merged']}}
        records = {r.name: r for r in classify_branches(
            LocalGitRefBackend(self.remote, 'main', pull_requests=prs).snapshot(), POLICY).branches}
        self.assertIn('PROTECTED', records['release/2.2'].keep_reasons)
        self.assertIn('OPEN_PULL_REQUEST', records['merged'].keep_reasons)
        self.assertFalse(records['merged'].deletable_candidate)

    def test_partial_pagination_not_clean_inventory(self) -> None:
        backend = LocalGitRefBackend(self.remote, 'main', pull_requests=merged_prs(self.oids), complete=False)
        inventory = classify_branches(backend.snapshot(), POLICY)
        self.assertFalse(inventory.clean)
        self.assertIn('INCOMPLETE_REFS_SNAPSHOT', inventory.unknown_coverage)
        self.assertFalse(any(record.deletable_candidate for record in inventory.branches))


class SyntheticClassificationTests(unittest.TestCase):
    def test_proof_for_other_target_is_unknown(self) -> None:
        stale = RefInfo('x', OID['b'], merge_proof=MergeProof('ancestor', OID['c']))
        record = classify_branches(synthetic([stale]), POLICY).branches[1]
        self.assertEqual(record.state, 'unknown')
        self.assertFalse(record.deletable_candidate)

    def test_snapshot_target_must_be_policy_default(self) -> None:
        with self.assertRaises(BranchLifecycleError):
            classify_branches(synthetic([merged('x', OID['b'])]), BranchPolicy(default_branch='develop'))


if __name__ == '__main__':
    unittest.main()
