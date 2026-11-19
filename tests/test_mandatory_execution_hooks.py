"""Mandatory hook controls use synthetic fixtures and no external side effects."""

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import os
import unittest

PROJECT = Path(__file__).resolve().parents[1]
SCRATCH = Path(
    os.environ.get(
        "GETZILLA_TEST_RUNTIME",
        Path(__file__).resolve().parents[1 if __name__.startswith("tests.") else 2] / ".getzilla/runtime/tests",
    )
)
SCRATCH.mkdir(mode=0o700, parents=True, exist_ok=True)


class MandatoryHookTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=SCRATCH)
        self.root = Path(self.tmp.name)
        shutil.copytree(PROJECT / ".getzilla/hooks", self.root / ".getzilla/hooks")
        shutil.copytree(
            PROJECT / ".getzilla/getzilla",
            self.root / ".getzilla/getzilla",
            ignore=shutil.ignore_patterns("__pycache__"),
        )
        shutil.copytree(PROJECT / ".getzilla/config", self.root / ".getzilla/config")
        self.addCleanup(self.tmp.cleanup)

    def hook(self, tool="functions.exec_command", inputs=None, raw=None):
        result = subprocess.run(
            ["python3", str(self.root / ".getzilla/hooks/pre_tool_use.py")],
            cwd=self.root,
            input=raw
            if raw is not None
            else json.dumps(
                {
                    "cwd": str(self.root),
                    "tool_name": tool,
                    "tool_input": inputs if inputs is not None else {"cmd": "terraform destroy"},
                }
            ),
            text=True,
            capture_output=True,
            timeout=10,
        )
        data = json.loads(result.stdout)
        self.assertEqual(data.get("decision"), "deny", (result.returncode, data, result.stderr))
        return result

    def test_namespaced_actual_arguments(self):
        self.hook()
        self.hook(
            "functions.apply_patch", {"input": "*** Begin Patch\n*** Update File: AGENTS.md\n@@\n-a\n+b\n*** End Patch"}
        )

    def test_opaque_nested_dispatch_denied(self):
        self.hook("functions.exec", {"code": 'await tools.exec_command({cmd: "terraform destroy"})'})
        self.hook("functions.exec", {"code": "text(1)"})

    def test_missing_bootstrap_rejects_nonzero(self):
        (self.root / ".getzilla/hooks/_lib.py").unlink()
        self.assertNotEqual(self.hook().returncode, 0)

    def test_missing_policy_rejects(self):
        (self.root / ".getzilla/getzilla/policy.py").unlink()
        self.hook("Bash", {"command": "ls"})

    def test_malformed_payload_rejects(self):
        self.hook(raw="not-json")
        self.hook(raw="[]")

    def test_outer_exception_rejects(self):
        p = self.root / ".getzilla/hooks/_lib.py"
        p.write_text(p.read_text() + "\ndef root_context(*args):\n    raise RuntimeError('injected')\n")
        self.hook("Bash", {"command": "ls"})

    def test_unknown_executable_transport_rejects(self):
        self.hook("functions.launch_runtime", {"code": "anything"})

    def test_conflicting_envelopes_reject(self):
        self.hook(
            raw=json.dumps(
                {
                    "cwd": str(self.root),
                    "tool_name": "Read",
                    "toolName": "exec_command",
                    "tool_input": {"path": "README.md"},
                    "toolArgs": json.dumps({"cmd": "terraform destroy"}),
                }
            )
        )

    def test_installation_and_self_reports_do_not_prove_host_enforcement(self):
        import sys

        sys.path.insert(0, str(PROJECT / ".getzilla"))
        from getzilla.doctor import execution_control_status

        runtime = self.root / ".getzilla/runtime"
        runtime.mkdir(exist_ok=True)
        (runtime / "native-enforcement.json").write_text(json.dumps({"loaded": True, "verified": True}))
        status = execution_control_status(self.root)
        self.assertTrue(status["installed"])
        self.assertEqual(status["loaded"], "not-observed")
        self.assertEqual(status["host_verified"], "not-observed")

    def test_freeform_patch_and_namespaced_mcp_actual_inputs(self):
        patch = "*** Begin Patch\n*** Update File: AGENTS.md\n@@\n-a\n+b\n*** End Patch"
        self.hook("functions.apply_patch", patch)
        self.hook("functions.mcp__openai__create_image", {"prompt": "synthetic"})
        self.hook("functions.mcp__github__create_issue", {"title": "synthetic"})

    def test_missing_or_corrupt_policy_configuration_denies(self):
        p = self.root / ".getzilla/config/policy.json"
        p.write_text("invalid-json")
        self.hook("Bash", {"command": "ls"})
        p.unlink()
        self.hook("Bash", {"command": "ls"})

    def test_missing_agent_route_denies(self):
        self.hook("collaboration.spawn_agent", {"agent_type": "ai_implementer", "message": "synthetic"})

    def test_generic_external_grant_cannot_authorize_paid_http(self):
        import sys
        from unittest.mock import patch

        sys.path.insert(0, str(PROJECT / ".getzilla"))
        from getzilla._policy_legacy import evaluate_pre_tool

        with (
            patch("getzilla._policy_legacy.has_valid_approval", return_value=True),
            patch("getzilla.human_gates.gate_block_reason", return_value=None),
        ):
            allowed, reason = evaluate_pre_tool(
                self.root,
                {
                    "tool_name": "Bash",
                    "tool_input": {"command": "curl -X POST https://api.openai.com/v1/chat/completions -d synthetic"},
                },
            )
        self.assertFalse(allowed)
        self.assertIn("paid", reason.lower())

    def test_root_shim_missing_guard_rejects(self):
        shim = self.root / "pre_tool_use.py"
        shutil.copyfile(PROJECT / ".getzilla/templates/hook_root_shim.py", shim)
        (self.root / ".getzilla/hooks/pre_tool_use.py").unlink()
        for harness in ("grok", "claude", "codex", "qwen", "gemini", "copilot"):
            result = subprocess.run(
                ["python3", str(shim), "--harness", harness],
                cwd=self.root,
                input="{}",
                text=True,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 2)
            data = json.loads(result.stdout)
            if harness in {"claude", "codex", "qwen"}:
                self.assertEqual(data["hookSpecificOutput"]["permissionDecision"], "deny")
                self.assertNotIn("decision", data)
            elif harness == "copilot":
                self.assertEqual(data["permissionDecision"], "deny")
            else:
                self.assertEqual(data["decision"], "deny")

    def test_root_shim_failure_discards_partial_allow(self):
        shim = self.root / "pre_tool_use.py"
        shutil.copyfile(PROJECT / ".getzilla/templates/hook_root_shim.py", shim)
        (self.root / ".getzilla/hooks/pre_tool_use.py").write_text(
            'print("' + json.dumps({"decision": "allow"}).replace('"', '\\"') + '")\nraise RuntimeError("fault")\n'
        )
        result = subprocess.run(
            ["python3", str(shim)], cwd=self.root, input="{}", text=True, capture_output=True, timeout=10
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["decision"], "deny")

    def test_control_status_keeps_tests_gate_and_delivery_distinct(self):
        import sys

        sys.path.insert(0, str(PROJECT / ".getzilla"))
        from getzilla.doctor import execution_control_status

        runtime = self.root / ".getzilla/runtime"
        runtime.mkdir(exist_ok=True)
        (runtime / "native-enforcement.json").write_text(
            json.dumps({"loaded": True, "bounded_tests": "pass", "full_gate": "pass", "delivery": "pass"})
        )
        status = execution_control_status(self.root)
        for stage in ("loaded", "host_verified", "bounded_tests", "full_gate", "delivery"):
            self.assertEqual(status[stage], "not-observed")
        self.assertIn("source_identity", status)
        self.assertIn("git_head", status["source_identity"])
        self.assertIn("tree_fingerprint", status["source_identity"])
