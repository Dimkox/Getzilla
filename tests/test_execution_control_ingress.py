"""STOP admits only bounded literal native observation/cancel forms, then normal policy."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from getzilla import execution, policy, state
from tests.execution_contract_support import owned_route

ROOT = Path(__file__).resolve().parents[1]


class ExecutionControlIngressTests(unittest.TestCase):
    def setUp(self):
        base = ROOT / ".getzilla/runtime"
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=base)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.enterContext(patch.dict(os.environ, {"GETZILLA_SESSION_ID": "stop-ingress-fixture"}))
        self.addCleanup(state.bind_session, None)
        config = self.root / ".getzilla/config"
        config.mkdir(parents=True)
        (config / "policy.json").write_text('{"schema_version": 2}')
        owned_route(self.root, session="stop-ingress-fixture")
        execution.stop(self.root, execution.trusted_caller(self.root))
        self.identity = "a" * 32

    def evaluate(self, command):
        return policy.evaluate_pre_tool(
            self.root, {"tool_name": "Bash", "tool_input": {"command": command}}, execution_cwd=self.root
        )

    def test_stopped_native_get_wait_and_cancel_still_pass_the_actual_policy(self):
        suffixes = [
            f"get {self.identity}",
            f"cancel {self.identity}",
            f"wait {self.identity}",
            f"wait {self.identity} --seconds 0.125",
            f"wait {self.identity} --seconds 30",
        ]
        prefixes = [
            "getzilla execution",
            "python3 scripts/getzilla_execution.py",
            f"python3 {self.root}/scripts/getzilla_execution.py",
        ]
        for prefix in prefixes:
            for suffix in suffixes:
                with self.subTest(command=prefix + " " + suffix):
                    allowed, reason = self.evaluate(prefix + " " + suffix)
                    self.assertTrue(allowed, reason)

    def test_stop_does_not_admit_start_shell_tails_bad_ids_or_unbounded_waits(self):
        forms = [
            "start --tool fixture --intent forbidden --timeout 5",
            f"get {self.identity} && true",
            f"get {self.identity}; true",
            f"cancel {self.identity} extra",
            "get not-an-id",
            f"wait {self.identity} --seconds nan",
            f"wait {self.identity} --seconds inf",
            f"wait {self.identity} --seconds 0",
            f"wait {self.identity} --seconds -1",
            f"wait {self.identity} --seconds 30.1",
            f"wait {self.identity} --seconds 1e300",
            f"wait {self.identity} --seconds 1 --extra file",
            f"wait {self.identity} --seconds $(echo 1)",
        ]
        for form in forms:
            with self.subTest(form=form):
                allowed, reason = self.evaluate("getzilla execution " + form)
                self.assertFalse(allowed)
                self.assertIn("execution_stopped", reason)

    def test_admitted_control_still_runs_the_secret_read_guard(self):
        scripts = self.root / "scripts"
        scripts.mkdir()
        secret = self.root / ".env"
        secret.write_text("SYNTHETIC_FIXTURE_ONLY=not-a-credential\n")
        (scripts / "getzilla_execution.py").symlink_to(secret)
        allowed, reason = self.evaluate(f"python3 scripts/getzilla_execution.py get {self.identity}")
        self.assertFalse(allowed)
        self.assertIn("secret", reason.lower())
