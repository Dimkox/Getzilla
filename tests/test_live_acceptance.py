"""Contract probes for the real disposable acceptance entrypoints."""
from __future__ import annotations
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / ".getzilla"), str(ROOT / "factory/src")]


class FactoryLiveContractTests(unittest.TestCase):
    def test_live_suite_cannot_admit_a_skipped_database_case(self):
        import importlib.util
        self.assertIsNotNone(importlib.util.find_spec("factory.tests.run_live_suite"))
        from factory.tests.run_live_suite import accepted
        result = unittest.TestResult()
        result.testsRun = 4
        result.skipped.append((unittest.FunctionTestCase(lambda: None), "FACTORY_TEST_DATABASE_URL missing"))
        self.assertFalse(accepted(result, ["some.test", "FreshClusterArtifactAttestorMigrationTests.test_fresh"]))

    def test_exit_cleanup_requires_observed_absence(self):
        from factory.tests import run_disposable_exit as runner
        identifier = "a" * 64
        def boundary(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, identifier + "\n")
        with patch.object(runner, "_binding_matches", return_value=True), \
                patch.object(runner.subprocess, "run", side_effect=boundary):
            with self.assertRaises(RuntimeError):
                runner._remove_bound_container(identifier, "gz-test-db", "b" * 32)


class ObserverTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "linux", "POSIX observer")
    def test_observer_keeps_a_raw_digest_but_redacts_database_credentials_from_exported_log(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = "print('postgresql://user:public-test-sentinel@127.0.0.1:5432/database')"
            result = module.observe([sys.executable, "-c", source], root=root, environment={}, output=root, timeout=2, grace=1)
            self.assertNotIn("public-test-sentinel", (root / "command.log").read_text())
            self.assertEqual(len(result["raw_log_sha256"]), 64)

    @unittest.skipUnless(sys.platform == "linux", "POSIX cancellation contract")
    def test_verifier_gives_live_child_time_to_acknowledge_cleanup(self):
        from getzilla.python_test_runner import execute
        import inspect
        self.assertIn("termination_grace", inspect.signature(execute).parameters)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            ack = root / "ack"
            source = ("import signal,time,pathlib\n"
                      "def stop(*args):\n time.sleep(.4)\n pathlib.Path('ack').write_text('removed')\n raise SystemExit(130)\n"
                      "signal.signal(signal.SIGTERM,stop)\nwhile True: time.sleep(.02)\n")
            result = execute([sys.executable, "-c", source], root, {}, timeout=.2, termination_grace=1)
            self.assertEqual(ack.read_text(), "removed")
            self.assertEqual(result.returncode, 124)
            self.assertFalse(result.cleanup_error)

    def module(self):
        import importlib
        import importlib.util
        self.assertIsNotNone(importlib.util.find_spec("getzilla.live_acceptance"))
        return importlib.import_module("getzilla.live_acceptance")

    @unittest.skipUnless(sys.platform == "linux", "POSIX cancellation contract")
    def test_timeout_retains_primary_result_and_allows_bounded_cleanup_ack(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw)
            child = path / "child.py"
            child.write_text("import signal,time,pathlib,sys\n"
                             "def stop(*args):\n time.sleep(.4)\n pathlib.Path(sys.argv[1]).write_text('ack')\n raise SystemExit(130)\n"
                             "signal.signal(signal.SIGTERM,stop)\nwhile True: time.sleep(.02)\n")
            ack = path / "ack"
            result = module.observe([sys.executable, str(child), str(ack)], root=path,
                                    environment={}, output=path, timeout=.2, grace=1)
            self.assertEqual(ack.read_text(), "ack")
            self.assertEqual(result["primary_outcome"], "timed_out")
            self.assertEqual(result["child_returncode"], 130)
            self.assertTrue(result["child_exit_confirmed"])
            self.assertFalse(result["escalated"])

    @unittest.skipUnless(sys.platform != "win32", "POSIX-only live observer")
    def test_missing_resource_evidence_cannot_make_a_live_cell_pass(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw)
            result = module.observe([sys.executable, "-c", "pass"], root=path,
                                    environment={}, output=path, timeout=2, grace=1,
                                    namespace="gz-missing", require_resources=True)
            self.assertEqual(result["primary_outcome"], "passed")
            self.assertEqual(result["cleanup_outcome"], "unknown")
            self.assertEqual(result["status"], "fail")


if __name__ == "__main__":
    unittest.main()
