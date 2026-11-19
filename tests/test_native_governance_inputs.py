"""Governance loader provenance must retain the same live native resource."""
import os
import shutil
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from tests import test_governance as fixtures
from getzilla import governance
from getzilla.trace_storage import native_root

NOW = datetime(2026,11,5,tzinfo=timezone.utc)


class NativeGovernanceInputTests(unittest.TestCase):
    def setUp(self):
        saved = os.open('.',os.O_RDONLY|os.O_DIRECTORY)
        self.addCleanup(os.close,saved)
        self.root = fixtures._make_fixture(self)
        self.addCleanup(os.fchdir,saved)
        self.root.chmod(0o755)
        os.chdir(self.root)
        for relative in ('schemas','governance','governance/rules','governance/debt','governance/canonical-examples'):
            (self.root/relative).chmod(0o755)
        for relative in (*governance._GOVERNANCE_SCHEMA_DIGESTS,
                         governance.RULES_PATH,governance.DEBT_PATH,governance.EXAMPLES_PATH):
            (self.root/relative).chmod(0o644)

    def test_original_loader_and_summary_values_match_in_same_native_scope(self):
        expected = governance.governance_summary(governance.load_governance(self.root),now=NOW)
        with native_root(self.root) as anchor:
            snapshot = governance.load_governance(self.root,anchor=anchor)
            self.assertEqual(governance.governance_summary(snapshot,now=NOW),expected)

    def test_original_summary_cannot_reopen_a_foreign_replacement_root(self):
        expected = governance.governance_summary(governance.load_governance(self.root),now=NOW)
        moved = self.root.with_name(self.root.name+'-moved')
        with native_root(self.root) as anchor:
            snapshot = governance.load_governance(self.root,anchor=anchor)
            self.root.rename(moved)
            try:
                self.root.mkdir(mode=0o755)
                sentinel = self.root/'foreign-governance'
                sentinel.write_text('foreign')
                self.assertEqual(governance.governance_summary(snapshot,now=NOW),expected)
                self.assertEqual(sentinel.read_text(),'foreign')
            finally:
                shutil.rmtree(self.root)
                moved.rename(self.root)

    def test_private_authority_member_refuses_before_any_source_bytes(self):
        (self.root/governance.RULES_PATH).chmod(0o600)
        with native_root(self.root) as anchor:
            with patch('os.read',side_effect=AssertionError('unadmitted inventory consumed')):
                with self.assertRaises(governance.GovernanceError):
                    governance.load_governance(self.root,anchor=anchor)

    def test_hardlinked_schema_refuses_whole_native_inventory(self):
        path = self.root/governance.RULES_SCHEMA_PATH
        os.link(path,path.with_name('alias.json'))
        with native_root(self.root) as anchor:
            with self.assertRaises(governance.GovernanceError):
                governance.load_governance(self.root,anchor=anchor)

    def test_closed_native_resource_cannot_restore_snapshot_provenance(self):
        with native_root(self.root) as anchor:
            snapshot = governance.load_governance(self.root,anchor=anchor)
        with self.assertRaises(governance.GovernanceError):
            governance.governance_summary(snapshot,now=NOW)
