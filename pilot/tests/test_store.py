from __future__ import annotations

import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest

from pilot.store import PilotStore, PilotStoreError
from pilot.tests.support import candidate_change, issue_snapshot, make_control, utc_time


class PilotStoreTests(unittest.TestCase):
    def test_state_rejects_control_paths_and_symlink_alias(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            control = make_control(root)
            alias = root / "control-alias"
            alias.symlink_to(control, target_is_directory=True)
            for state_root, reason in (
                (control, "state_root_repository"),
                (control / "state", "state_root_repository"),
                (alias, "state_root_mode"),
            ):
                with self.subTest(state_root=state_root):
                    with self.assertRaisesRegex(PilotStoreError, reason):
                        PilotStore(state_root, control_repository=control)
            self.assertFalse((control / "pilot.sqlite3").exists())
            self.assertFalse((control / "state").exists())

    def test_replay_is_exact_and_candidate_survives_close_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            state_root = root / "state"
            issue = issue_snapshot()
            store = PilotStore(
                state_root,
                control_repository=make_control(root),
                clock=lambda: utc_time(4),
            )
            job, created = store.create_or_replay(issue, command_key="submit-1")
            replay, replay_created = store.create_or_replay(issue, command_key="submit-1")
            self.assertTrue(created)
            self.assertFalse(replay_created)
            self.assertEqual(job, replay)
            job = store.mark_workspace_ready(issue.job_id, workspace_digest="3" * 64)
            job = store.begin_invocation(issue.job_id, command_key="codex-1")
            candidate = candidate_change(issue)
            job = store.store_candidate(issue.job_id, candidate)
            self.assertEqual(job.state, "candidate_sealed")
            store.close()

            reopened = PilotStore(
                state_root,
                control_repository=make_control(root),
                clock=lambda: utc_time(5),
            )
            self.assertEqual(reopened.get(issue.job_id).candidate, candidate)
            self.assertEqual(state_root.stat().st_mode & 0o777, 0o700)
            self.assertEqual(reopened.database_path.stat().st_mode & 0o777, 0o600)
            reopened.close()

    def test_conflicting_replay_and_tampered_record_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            state_root = root / "state"
            issue = issue_snapshot()
            store = PilotStore(state_root, control_repository=make_control(root))
            store.create_or_replay(issue, command_key="submit-1")
            with self.assertRaisesRegex(PilotStoreError, "command_conflict"):
                store.create_or_replay(
                    issue_snapshot(body="different"), command_key="submit-1"
                )
            store.close()

            connection = sqlite3.connect(state_root / "pilot.sqlite3")
            connection.execute(
                "UPDATE jobs SET snapshot_json = ? WHERE job_id = ?",
                (b"{}", issue.job_id),
            )
            connection.commit()
            connection.close()
            reopened = PilotStore(state_root, control_repository=make_control(root))
            with self.assertRaises(PilotStoreError):
                reopened.get(issue.job_id)
            reopened.close()

    def test_read_only_status_does_not_recover_or_change_database(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            state_root = root / "state"
            issue = issue_snapshot()
            store = PilotStore(state_root, control_repository=make_control(root))
            store.create_or_replay(issue, command_key="submit-1")
            store.mark_workspace_ready(issue.job_id, workspace_digest="3" * 64)
            store.begin_invocation(issue.job_id, command_key="codex-1")
            store.close()
            database = state_root / "pilot.sqlite3"
            before = hashlib.sha256(database.read_bytes()).hexdigest()

            status = PilotStore(
                state_root,
                control_repository=make_control(root),
                read_only=True,
            )
            self.assertEqual(status.get(issue.job_id).state, "invocation_intent")
            status.close()

            self.assertEqual(hashlib.sha256(database.read_bytes()).hexdigest(), before)


if __name__ == "__main__":
    unittest.main()
