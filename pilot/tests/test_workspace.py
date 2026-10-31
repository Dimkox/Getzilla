from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from pilot.workspace import ExactGitWorkspace, WorkspaceError, WorkspacePolicy
from pilot.tests.support import issue_snapshot, make_control, make_source, run_git


class ExactGitWorkspaceTests(unittest.TestCase):
    def test_workspace_rejects_control_paths_and_symlink_alias(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            control = make_control(root)
            source, base_sha, base_tree = make_source(root)
            alias = root / "control-alias"
            alias.symlink_to(control, target_is_directory=True)
            for workspace_root, reason in (
                (control, "workspace_root_boundary"),
                (control / "workspaces", "workspace_root_boundary"),
                (alias, "workspace_root_mode"),
            ):
                with self.subTest(workspace_root=workspace_root):
                    with self.assertRaisesRegex(WorkspaceError, reason):
                        ExactGitWorkspace(
                            source,
                            workspace_root,
                            control_repository=control,
                            policy=WorkspacePolicy("a" * 64, base_sha, base_tree, ("index.html",), 4096),
                        )
            self.assertFalse((control / "workspaces").exists())

    def test_private_no_local_clone_has_no_remote_and_seals_one_parent_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source, base_sha, base_tree = make_source(root)
            policy = WorkspacePolicy(
                profile_digest="a" * 64,
                base_sha=base_sha,
                base_tree=base_tree,
                allowed_write_paths=("index.html",),
                max_diff_bytes=4096,
            )
            manager = ExactGitWorkspace(
                source,
                root / "private-workspaces",
                control_repository=make_control(root),
                policy=policy,
            )
            prepared = manager.prepare("pilot-job-1")
            (prepared.worktree / "index.html").write_text("v2.0.14\n", encoding="utf-8")

            candidate = manager.seal(
                prepared,
                issue_snapshot(
                    profile_digest=policy.profile_digest,
                    base_sha=base_sha,
                    base_tree=base_tree,
                ),
                sandbox_evidence_digest="d" * 64,
                model_id="gpt-5.3-codex",
                executable_version="0.153.4",
                executable_sha256="e" * 64,
                prompt_digest="f" * 64,
                tool_policy_digest="1" * 64,
                output_schema_digest="2" * 64,
                started_at="2026-09-05T12:00:02Z",
                completed_at="2026-09-05T12:00:03Z",
            )

            self.assertFalse((prepared.worktree / ".git").exists())
            self.assertEqual(run_git(prepared.git_dir, "remote"), b"")
            self.assertFalse((prepared.git_dir / "objects/info/alternates").exists())
            self.assertEqual(candidate.base_sha, base_sha)
            self.assertEqual(
                run_git(prepared.git_dir, "rev-list", "--parents", "-n", "1", candidate.candidate_sha).decode().split(),
                [candidate.candidate_sha, base_sha],
            )
            self.assertEqual(tuple(item.path for item in candidate.changed_files), ("index.html",))
            self.assertEqual((prepared.root.stat().st_mode & 0o777), 0o700)

    def test_disallowed_or_special_change_is_rejected_without_commit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source, base_sha, base_tree = make_source(root)
            manager = ExactGitWorkspace(
                source,
                root / "private-workspaces",
                control_repository=make_control(root),
                policy=WorkspacePolicy("a" * 64, base_sha, base_tree, ("index.html",), 4096),
            )
            prepared = manager.prepare("pilot-job-1")
            (prepared.worktree / "not-allowed.txt").write_text("no", encoding="utf-8")
            with self.assertRaisesRegex(WorkspaceError, "changed_paths"):
                manager.seal(
                    prepared,
                    issue_snapshot(profile_digest="a" * 64, base_sha=base_sha, base_tree=base_tree),
                    sandbox_evidence_digest="d" * 64,
                    model_id="gpt-5.3-codex",
                    executable_version="0.153.4",
                    executable_sha256="e" * 64,
                    prompt_digest="f" * 64,
                    tool_policy_digest="1" * 64,
                    output_schema_digest="2" * 64,
                    started_at="2026-09-05T12:00:02Z",
                    completed_at="2026-09-05T12:00:03Z",
                )
            self.assertEqual(run_git(prepared.git_dir, "rev-parse", "HEAD").decode().strip(), base_sha)

    def test_sealed_workspace_recovers_by_job_and_rejects_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source, base_sha, base_tree = make_source(root)
            manager = ExactGitWorkspace(
                source,
                root / "private-workspaces",
                control_repository=make_control(root),
                policy=WorkspacePolicy("a" * 64, base_sha, base_tree, ("index.html",), 4096),
            )
            prepared = manager.prepare("pilot-job-1")
            (prepared.worktree / "index.html").write_text("v2.0.14\n", encoding="utf-8")
            candidate = manager.seal(
                prepared,
                issue_snapshot(profile_digest="a" * 64, base_sha=base_sha, base_tree=base_tree),
                sandbox_evidence_digest="d" * 64,
                model_id="gpt-5.3-codex",
                executable_version="0.153.4",
                executable_sha256="e" * 64,
                prompt_digest="f" * 64,
                tool_policy_digest="1" * 64,
                output_schema_digest="2" * 64,
                started_at="2026-09-05T12:00:02Z",
                completed_at="2026-09-05T12:00:03Z",
            )

            recovered = manager.recover("pilot-job-1", candidate)

            self.assertEqual(recovered, prepared)
            self.assertEqual(run_git(recovered.git_dir, "remote"), b"")
            self.assertEqual(
                run_git(recovered.git_dir, "rev-parse", "HEAD").decode().strip(),
                candidate.candidate_sha,
            )
            (recovered.worktree / "unexpected.txt").write_text("tamper", encoding="utf-8")
            with self.assertRaisesRegex(WorkspaceError, "workspace_tamper"):
                manager.recover("pilot-job-1", candidate)
            (recovered.worktree / "unexpected.txt").unlink()
            recovered.root.chmod(0o755)
            with self.assertRaisesRegex(WorkspaceError, "workspace_tamper"):
                manager.recover("pilot-job-1", candidate)
            recovered.root.chmod(0o700)
            real_worktree = recovered.root / "app-real"
            recovered.worktree.rename(real_worktree)
            recovered.worktree.symlink_to(real_worktree, target_is_directory=True)
            with self.assertRaisesRegex(WorkspaceError, "workspace_tamper"):
                manager.recover("pilot-job-1", candidate)


if __name__ == "__main__":
    unittest.main()
