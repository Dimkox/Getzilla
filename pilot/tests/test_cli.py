from __future__ import annotations

import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pilot.cli import main
from pilot.tests.support import posix_runtime


def write_config(root: Path, *, provider_mode: str = "app_server_chatgpt") -> Path:
    config = root / "pilot.json"
    config.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "job_id": "pilot-job-1",
                "issue_number": 1,
                "state_root": str(root / "state"),
                "workspace_root": str(root / "workspaces"),
                "validation_root": str(root / "validation"),
                "source_repository": str(root / "landing-source"),
                "provider_mode": provider_mode,
                "codex_executable": "/opt/pilot/bin/codex",
                "codex_sha256": "a" * 64,
                "codex_version": "0.153.4",
                "model_id": "gpt-6-astra",
                "python_executable": "/usr/bin/python3",
                "python_sha256": "b" * 64,
                "git_executable": "/usr/bin/git",
                "git_sha256": "c" * 64,
                "gh_executable": "/snap/gh/751/gh",
                "gh_sha256": "d" * 64,
                "bwrap_executable": "/usr/bin/bwrap",
                "bwrap_sha256": "e" * 64,
            }
        ),
        encoding="utf-8",
    )
    config.chmod(0o600)
    return config


class PilotCliTests(unittest.TestCase):
    def test_effect_phases_are_disabled_without_live_flag_or_config(self) -> None:
        for phase in ("prepare", "publish-branch", "publish-proposal"):
            output = io.StringIO()
            self.assertEqual(main([phase], stdout=output), 2)
            self.assertEqual(json.loads(output.getvalue())["reason"], "live_disabled")
            output = io.StringIO()
            self.assertEqual(main([phase, "--live"], stdout=output), 2)
            self.assertEqual(json.loads(output.getvalue())["reason"], "live_config_required")

    @posix_runtime
    def test_closed_config_dispatches_three_live_phases_and_read_only_status(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            config = write_config(root)
            calls = []

            def fake_runner(phase, runtime):
                calls.append((phase, runtime))
                return {"status": phase, "external_effect": phase.startswith("publish-")}

            for phase in ("prepare", "publish-branch", "publish-proposal"):
                output = io.StringIO()
                self.assertEqual(
                    main(
                        [phase, "--live", "--config", str(config)],
                        phase_runner=fake_runner,
                        stdout=output,
                    ),
                    0,
                )
            output = io.StringIO()
            self.assertEqual(
                main(
                    ["status", "--config", str(config)],
                    phase_runner=fake_runner,
                    stdout=output,
                ),
                0,
            )

            self.assertEqual([item[0] for item in calls], ["prepare", "publish-branch", "publish-proposal", "status"])
            self.assertEqual(calls[0][1].profile.provider_mode, "app_server_chatgpt")
            self.assertFalse(calls[0][1].profile.live_default)
            self.assertEqual(calls[0][1].validation_root, root / "validation")

    @posix_runtime
    def test_main_has_a_built_in_host_runner_not_an_adapter_placeholder(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            config = write_config(root)
            output = io.StringIO()

            self.assertEqual(
                main(["prepare", "--live", "--config", str(config)], stdout=output),
                2,
            )

            self.assertEqual(
                json.loads(output.getvalue())["reason"],
                "runtime_path_unavailable",
            )


    def test_non_posix_host_is_refused_before_the_config_is_read(self) -> None:
        calls = []
        with tempfile.TemporaryDirectory() as raw, patch("pilot.cli.POSIX_HOST", False):
            missing = str(Path(raw) / "absent.json")
            for argv in (
                ["prepare", "--live", "--config", missing],
                ["publish-branch", "--live", "--config", missing],
                ["publish-proposal", "--live", "--config", missing],
                ["status", "--config", missing],
            ):
                output = io.StringIO()
                self.assertEqual(main(argv, phase_runner=lambda *call: calls.append(call) or {}, stdout=output), 2)
                self.assertEqual(json.loads(output.getvalue()), {"status": "unavailable", "reason": "posix_host_required"})
        self.assertEqual(calls, [])

if __name__ == "__main__":
    unittest.main()
