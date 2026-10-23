"""Consumer policy ported from Pulse: Bitrix local modules, explicit infrastructure skips."""
import importlib
import importlib.util
import os
import tempfile
import unittest
from unittest import mock
import sys
from pathlib import Path


class GetzillaConsumerPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".getzilla"))
        cls.checks = importlib.import_module("getzilla.bitrix_checks")
        cls.gates = importlib.import_module("getzilla.quality_gates")
        cls.verification = importlib.import_module("getzilla.verification")

    def test_bitrix_local_module_is_not_core(self):
        findings = self.checks.check_bitrix(Path("."), ["bitrix/local/modules/puls.x/lib/a.php"])
        self.assertFalse(any(f.code == "core-modification" for f in findings))

    def test_bitrix_locality_remains_core(self):
        findings = self.checks.check_bitrix(Path("."), ["bitrix/locality/a.php"])
        self.assertTrue(any(f.code == "core-modification" for f in findings))

    def test_bitrix_module_root_is_discovered(self):
        roots = self.checks._module_roots(Path("/tmp"), ["bitrix/local/modules/puls.x/lib/a.php"])
        self.assertEqual(roots, [Path("/tmp/bitrix/local/modules/puls.x")])

    def test_unknown_factory_skip_is_not_allowed(self):
        self.assertFalse(self.gates._allowed_skip("factory-postgres-exit", "arbitrary", None))

    def test_consumer_factory_skip_is_allowed(self):
        self.assertTrue(
            self.gates._allowed_skip(
                "factory-postgres-exit",
                "consumer source-only/unit-only policy prohibits infrastructure execution",
                None,
            )
        )

    def test_repository_sandbox_skip_remains_allowed(self):
        self.assertTrue(
            self.gates._allowed_skip(
                "factory-postgres-exit", "repository-sandbox has no nested-container/database capability", None
            )
        )

    def test_other_skip_is_not_authorized(self):
        self.assertFalse(
            self.gates._allowed_skip(
                "python-unittest", "consumer source-only/unit-only policy prohibits infrastructure execution", None
            )
        )

    def test_factory_unit_dispatch_is_behavioral_and_never_starts_exit(self):
        class Dispatch:
            def __init__(self):
                self.batches = []
                self.runs = []

            def batch(self, names, callback):
                self.batches.append((names, callback()))

            def run(self, name, callback):
                self.runs.append((name, callback()))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "factory/tests").mkdir(parents=True)
            (root / "factory/pyproject.toml").write_text("[project]\n")
            (root / "factory/tests/test_contracts.py").write_text("")
            dispatch = Dispatch()
            with mock.patch.object(self.verification, "_factory_unit", return_value=["unit-pass"]):
                self.verification._dispatch_factory_unit(root, dispatch)
            self.assertEqual(dispatch.batches[0][0], ["factory-unit"])
            self.assertEqual(dispatch.batches[0][1], ["unit-pass"])
            self.assertEqual(dispatch.runs, [])

    def test_installed_project_records_the_infrastructure_skip_in_pr(self):
        for pytest_runner in (False, True):
            with self.subTest(pytest_runner=pytest_runner), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / ".getzilla").mkdir()
                (root / ".getzilla/AGBP_SYNC.json").write_text('{"kept_local": [], "kept_local_sha256": {}, "schema_version": 1}\n')
                (root / "tests").mkdir()
                (root / "tests/test_contract.py").write_text("")
                (root / "factory/tests").mkdir(parents=True)
                (root / "factory/pyproject.toml").write_text("[project]\n")
                (root / "factory/tests/run_disposable_exit.py").write_text("raise SystemExit(1)\n")
                results = []
                with (
                    mock.patch.object(self.verification, "_ruff", return_value=self.verification.CheckResult("ruff", "pass", "fixture")),
                    mock.patch.object(self.verification, "_bandit", return_value=self.verification.CheckResult("bandit", "pass", "fixture")),
                    mock.patch.object(self.verification, "_core_python_checks", return_value=[]),
                    mock.patch.object(self.verification, "_factory_unit", return_value=[]),
                    mock.patch.object(self.verification, "command_exists", side_effect=lambda name: name == "pytest" and pytest_runner),
                    mock.patch.object(self.verification, "_command_check", side_effect=AssertionError("the exit must never start")),
                ):
                    self.verification._python_checks(root, "pr", None, results)
                exit_check = next(item for item in results if item.name == "factory-postgres-exit")
                self.assertEqual((exit_check.status, exit_check.summary),
                                 ("skip", self.verification.CONSUMER_INFRA_SKIP))
                self.assertTrue(self.gates._allowed_skip(exit_check.name, exit_check.summary, None))

    def test_the_getzilla_source_still_runs_the_infrastructure_exit(self):
        self._check_source_infrastructure('infrastructure', True)

    def test_repository_sandbox_skips_without_starting_infrastructure_exit(self):
        self._check_source_infrastructure('repository-sandbox', False)

    def _check_source_infrastructure(self, capability, executes):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "factory/tests").mkdir(parents=True)
            (root / "factory/pyproject.toml").write_text("[project]\n")
            (root / "factory/tests/run_disposable_exit.py").write_text("raise SystemExit(0)\n")
            results = []
            ran = []
            with (
                mock.patch.dict(os.environ, {'GETZILLA_VERIFY_CAPABILITY': capability}),
                mock.patch.object(self.verification, "_ruff", return_value=self.verification.CheckResult("ruff", "pass", "fixture")),
                mock.patch.object(self.verification, "_bandit", return_value=self.verification.CheckResult("bandit", "pass", "fixture")),
                mock.patch.object(self.verification, "_factory_unit", return_value=[]),
                mock.patch.object(self.verification, "command_exists", return_value=False),
                mock.patch.object(self.verification, "_command_check",
                                  side_effect=lambda *args, **kwargs: ran.append(args[1]) or self.verification.CheckResult(args[1], "pass", "ran")),
            ):
                self.verification._python_checks(root, "pr", None, results)
            if executes:
                self.assertIn("factory-postgres-exit", ran)
            else:
                self.assertEqual(ran, [])
                exit_check = next(item for item in results if item.name == 'factory-postgres-exit')
                self.assertEqual(exit_check.status, 'skip')
                self.assertIn('repository-sandbox', exit_check.summary)


if __name__ == "__main__":
    unittest.main()
