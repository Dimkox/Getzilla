"""General nonpaid task admission binds actual args and finite owner delegation."""

from datetime import datetime, timedelta, timezone
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

from tests._support import PROJECT, project_copy, run_hook

sys.path.insert(0, str(PROJECT / ".getzilla"))
from getzilla.router import build_route
from getzilla.state import add_approval, set_active_route


class TaskExecutionAdmissionTests(unittest.TestCase):
    def fixture(self, root):
        subprocess.run(["git", "remote", "add", "origin", "https://github.com/example/task.git"], cwd=root, check=True)
        set_active_route(root, build_route(root, "Fix a local source defect", "task-admission").to_dict())

    def test_ordinary_source_write_needs_exact_task_scope(self):
        with project_copy(git=True) as root:
            self.fixture(root)
            code, data, _ = run_hook(
                root,
                "pre_tool_use.py",
                {
                    "cwd": str(root),
                    "tool_name": "Write",
                    "tool_input": {"file_path": "source.py", "content": "approved"},
                },
            )
            self.assertEqual(code, 0)
            self.assertEqual(data["decision"], "deny")
            self.assertIn("task", data["reason"].lower())

    def test_exact_authorized_action_works_and_changed_args_deny(self):
        from getzilla.execution_admission import task_execution_resource

        with project_copy(git=True) as root:
            self.fixture(root)
            inputs = {"file_path": "source.py", "content": "approved"}
            add_approval(
                root,
                "task-execution",
                "Owner delegated this exact task action",
                5,
                actions=["task-tool-execute"],
                resources=[task_execution_resource("Write", inputs)],
                source="explicit-user-consent",
            )
            self.assertEqual(
                run_hook(root, "pre_tool_use.py", {"cwd": str(root), "tool_name": "Write", "tool_input": inputs})[1][
                    "decision"
                ],
                "allow",
            )
            for changed in ({**inputs, "content": "outside scope"}, {**inputs, "file_path": "other.py"}):
                self.assertEqual(
                    run_hook(root, "pre_tool_use.py", {"cwd": str(root), "tool_name": "Write", "tool_input": changed})[
                        1
                    ]["decision"],
                    "deny",
                )

    def test_elapsed_window_expiry_denies_even_with_matching_args(self):
        from getzilla.execution_admission import evaluate_task_execution, task_execution_resource

        with project_copy(git=True) as root:
            self.fixture(root)
            inputs = {"file_path": "source.py", "content": "approved"}
            add_approval(
                root,
                "task-execution",
                "Owner exact delegation",
                1,
                actions=["task-tool-execute"],
                resources=[task_execution_resource("Write", inputs)],
                source="explicit-user-consent",
            )
            future = datetime.now(timezone.utc) + timedelta(minutes=2)
            with patch("getzilla.state.datetime") as clock:
                clock.now.return_value = future
                clock.fromisoformat.side_effect = datetime.fromisoformat
                self.assertFalse(evaluate_task_execution(root, "Write", inputs)[0])

    def test_shell_must_fit_remaining_time_and_cannot_extend_with_grant(self):
        from getzilla.execution_admission import evaluate_task_execution, task_execution_resource

        with project_copy(git=True) as root:
            self.fixture(root)
            for command, expected in [
                ("/usr/bin/timeout --signal=KILL 5s python3 -m unittest tests.test_structure", True),
                ("python3 -m unittest tests.test_structure", False),
                ("/usr/bin/timeout --signal=KILL 3600s python3 -m unittest tests.test_structure", False),
            ]:
                inputs = {"command": command}
                add_approval(
                    root,
                    "task-execution",
                    "Owner exact bounded command",
                    1,
                    actions=["task-tool-execute"],
                    resources=[task_execution_resource("Bash", inputs)],
                    source="explicit-user-consent",
                )
                self.assertEqual(evaluate_task_execution(root, "Bash", inputs)[0], expected)

    def test_safe_observation_and_readonly_bootstrap_stay_usable(self):
        from getzilla.execution_admission import evaluate_task_execution

        with project_copy(git=True) as root:
            self.fixture(root)
            for tool, inputs in [
                ("Read", {"path": "README.md"}),
                ("Bash", {"command": "git status --short"}),
                ("Bash", {"command": "python3 scripts/getzilla_status.py"}),
            ]:
                self.assertTrue(evaluate_task_execution(root, tool, inputs)[0])
            self.assertFalse(
                evaluate_task_execution(root, "Bash", {"command": "git status --short; python3 attacker.py"})[0]
            )
            self.assertFalse(evaluate_task_execution(root, "Read", {"path": "../outside.txt"})[0])

    def test_runtime_claims_and_source_change_cannot_mint_or_reuse_authority(self):
        from getzilla.execution_admission import evaluate_task_execution, task_execution_resource

        with project_copy(git=True) as root:
            self.fixture(root)
            inputs = {"file_path": "source.py", "content": "approved"}
            (root / ".getzilla/runtime/task-authority.json").write_text(
                json.dumps({"approved": True, "deadline": 9999999999})
            )
            self.assertFalse(evaluate_task_execution(root, "Write", inputs)[0])
            add_approval(
                root,
                "task-execution",
                "Owner exact delegation",
                5,
                actions=["task-tool-execute"],
                resources=[task_execution_resource("Write", inputs)],
                source="explicit-user-consent",
            )
            (root / "source.py").write_text("changed source")
            self.assertFalse(evaluate_task_execution(root, "Write", inputs)[0])

    def test_exact_task_action_is_one_shot(self):
        from getzilla.execution_admission import evaluate_task_execution, task_execution_resource

        with project_copy(git=True) as root:
            self.fixture(root)
            inputs = {"file_path": "source.py", "content": "approved"}
            add_approval(
                root,
                "task-execution",
                "Owner delegated one exact action",
                5,
                actions=["task-tool-execute"],
                resources=[task_execution_resource("Write", inputs)],
                source="explicit-user-consent",
            )
            self.assertTrue(evaluate_task_execution(root, "Write", inputs)[0])
            self.assertFalse(evaluate_task_execution(root, "Write", inputs)[0])
