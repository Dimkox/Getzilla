"""Scoped cleanup evidence is recoverable and read-only. All assets synthetic."""

from datetime import datetime, timezone
from pathlib import Path
import json
import os
import tempfile
import unittest

from getzilla_factory import landing_backup

RUNTIME = Path(os.environ.get("GETZILLA_TEST_RUNTIME", Path(__file__).resolve().parents[2] / ".getzilla/runtime/tests"))
RUNTIME.mkdir(mode=0o700, parents=True, exist_ok=True)


class IncidentEvidencePlanTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(dir=RUNTIME)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.source = self.root / "source"
        self.backup = self.root / "backup"
        self.quarantine = self.root / "quarantine"
        for path in (self.source, self.backup, self.quarantine):
            path.mkdir(mode=0o700)
        self.asset = self.source / "incident.log"
        self.saved = self.backup / "incident.log"
        for path in (self.asset, self.saved):
            path.write_text("synthetic original evidence")
            path.chmod(0o600)
        self.now = datetime(2026, 10, 13, tzinfo=timezone.utc)

    def plan(self, assets=None):
        return landing_backup.plan_incident_cleanup(
            incident_id="incident-76",
            source_root=self.source,
            backup_root=self.backup,
            quarantine_root=self.quarantine,
            assets=assets or ["incident.log"],
            retention_seconds=86400,
            source_identity="a" * 64,
            clock=lambda: self.now,
        )

    def test_plan_binds_original_backup_restore_and_retention_without_mutation(self):
        before = {str(path): path.read_bytes() for path in (self.asset, self.saved)}
        plan = self.plan()
        self.assertEqual(plan["schema_version"], 1)
        self.assertEqual(plan["action"], "plan-only")
        self.assertEqual(plan["mutations_performed"], 0)
        row = plan["assets"][0]
        self.assertEqual(row["source_sha256"], row["backup_sha256"])
        self.assertEqual(row["restore_destination"], "incident.log")
        self.assertEqual(row["restore_policy"], "refuse-clobber")
        self.assertEqual(plan["retention_seconds"], 86400)
        self.assertNotIn("synthetic original evidence", json.dumps(plan))
        self.assertEqual(before, {str(path): path.read_bytes() for path in (self.asset, self.saved)})
        self.assertEqual(list(self.quarantine.iterdir()), [])

    def test_missing_or_changed_backup_denies(self):
        self.saved.unlink()
        with self.assertRaises(landing_backup.BackupError):
            self.plan()
        self.saved.write_text("different bytes")
        self.saved.chmod(0o600)
        with self.assertRaisesRegex(landing_backup.BackupError, "backup_binding"):
            self.plan()

    def test_unsafe_scope_credentials_and_links_deny(self):
        for asset in ["../incident.log", "*", ".env", "secret.pem", "incident.log", "incident.log"]:
            if asset == "incident.log":
                self.saved.unlink(missing_ok=True)
                self.saved.symlink_to(self.asset)
            with self.subTest(asset=asset), self.assertRaises(landing_backup.BackupError):
                self.plan([asset])
