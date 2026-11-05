"""Public acceptance evidence and observer controls; no real Docker in unit cases."""

from __future__ import annotations
import hashlib
import importlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".getzilla"))


class ComponentAdmissionTests(unittest.TestCase):
    def module(self):
        self.assertIsNotNone(
            importlib.util.find_spec("getzilla.live_acceptance"), "two isolated PostgreSQL cell observer must exist"
        )
        return importlib.import_module("getzilla.live_acceptance")

    def factory(self, root):
        ids = [
            "factory.tests.test_postgres_integration.FreshClusterArtifactAttestorMigrationTests.test_fresh",
            "factory.tests.test_postgres_integration.ApiTests.test_runtime",
        ]
        suite = {"status": "pass", "tests_run": 2, "executed": ids, "failures": 0, "errors": 0, "skipped": []}
        restart = {
            "status": "pass",
            "restarts": [
                {"before": "2026-01-01T00:00:00", "after": "2026-01-01T00:00:01"},
                {"before": "2026-01-01T00:00:01", "after": "2026-01-01T00:00:02"},
            ],
        }
        (root / "factory-suite.json").write_text(json.dumps(suite))
        (root / "factory-restart.json").write_text(json.dumps(restart))
        return suite, restart

    def test_factory_requires_counted_real_database_and_two_restarts(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            suite, restart = self.factory(root)
            self.assertTrue(module.validate_components(root, "factory"))
            for change in ("missing", "skip", "zero", "partial", "duplicate", "restart"):
                with self.subTest(change=change):
                    s = json.loads(json.dumps(suite))
                    r = json.loads(json.dumps(restart))
                    if change == "missing":
                        s["executed"] = ["public.other"]
                        s["tests_run"] = 1
                    elif change == "skip":
                        s["skipped"] = [{"id": s["executed"][0], "reason": "required DB fixture missing"}]
                    elif change == "zero":
                        s["tests_run"] = 0
                    elif change == "partial":
                        s["tests_run"] = 3
                    elif change == "duplicate":
                        s["executed"][1] = s["executed"][0]
                    else:
                        r["restarts"][1]["after"] = r["restarts"][1]["before"]
                    (root / "factory-suite.json").write_text(json.dumps(s))
                    (root / "factory-restart.json").write_text(json.dumps(r))
                    self.assertFalse(module.validate_components(root, "factory"))

    def test_factory_conditional_skip_keeps_a_complete_disjoint_census(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            suite, _restart = self.factory(root)
            skipped = {
                "id": "factory.tests.test_landing_pdf_worker.PdfWorkerWithoutParser.test_worker_executes_and_reports_parser_unavailable",
                "reason": "pypdf present; unavailable branch cannot run",
            }
            suite["tests_run"] = 3
            suite["skipped"] = [skipped]
            (root / "factory-suite.json").write_text(json.dumps(suite))
            self.assertTrue(module.validate_components(root, "factory"))
            for change in ("duplicate", "overlap", "partial", "required", "unknown"):
                changed = json.loads(json.dumps(suite))
                if change == "duplicate":
                    changed["skipped"].append(skipped)
                    changed["tests_run"] = 4
                elif change == "overlap":
                    changed["executed"].append(skipped["id"])
                    changed["tests_run"] = 4
                elif change == "partial":
                    changed["tests_run"] = 4
                elif change == "required":
                    changed["skipped"][0]["id"] = "factory.tests.test_postgres_integration.Required.test_database"
                else:
                    changed["skipped"][0]["id"] = "factory.tests.public_unknown.test_skipped"
                with self.subTest(change=change):
                    (root / "factory-suite.json").write_text(json.dumps(changed))
                    self.assertFalse(module.validate_components(root, "factory"))

    def test_trust_ci_requires_complete_ten_and_restart_identity(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            suite = {
                "status": "pass",
                "tests_run": 10,
                "executed": ["test_postgres_integration.PublicDb.test_" + str(i) for i in range(10)],
                "failures": 0,
                "errors": 0,
                "skipped": 0,
            }
            restart = {
                "status": "pass",
                "postmaster_before": "before",
                "postmaster_after": "after",
                "cluster_identity_preserved": True,
                "seed_verified": True,
            }
            for change in ("valid", "partial", "skip", "restart"):
                s = json.loads(json.dumps(suite))
                r = json.loads(json.dumps(restart))
                if change == "partial":
                    s["tests_run"] = 1
                    s["executed"] = s["executed"][:1]
                elif change == "skip":
                    s["skipped"] = 1
                elif change == "restart":
                    r["postmaster_after"] = r["postmaster_before"]
                (root / "trust-ci-suite.json").write_text(json.dumps(s))
                (root / "trust-ci-restart.json").write_text(json.dumps(r))
                self.assertEqual(module.validate_components(root, "trust-ci"), change == "valid")

    def test_unknown_or_missing_evidence_never_passes(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.assertFalse(module.validate_components(root, "factory"))
            self.assertFalse(module.validate_components(root, "trust-ci"))
            self.assertFalse(module.validate_components(root, "lifecycle"))


class ObserverControls(unittest.TestCase):
    def module(self):
        self.assertIsNotNone(
            importlib.util.find_spec("getzilla.live_acceptance"), "bounded PostgreSQL observer must exist"
        )
        return importlib.import_module("getzilla.live_acceptance")

    @unittest.skipUnless(sys.platform == "linux", "actual POSIX process session control")
    def test_missing_journal_blocks_even_when_child_exits_zero(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            result = module.observe(
                [sys.executable, "-c", "pass"],
                root=root,
                environment={},
                output=root,
                timeout=2,
                grace=1,
                namespace="gz-public",
                require_resources=True,
            )
            self.assertEqual(result["primary_outcome"], "passed")
            self.assertEqual(result["cleanup_outcome"], "unknown")
            self.assertEqual(result["status"], "fail")
            self.assertTrue(result["child_exit_confirmed"])

    @unittest.skipUnless(sys.platform == "linux", "actual POSIX process session control")
    def test_timeout_keeps_primary_and_reaps_after_cleanup_ack(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = "import signal,time,pathlib\ndef stop(*args):\n pathlib.Path('ack').write_text('done')\n raise SystemExit(130)\nsignal.signal(signal.SIGTERM,stop)\nwhile True:time.sleep(.01)\n"
            result = module.observe(
                [sys.executable, "-c", source], root=root, environment={}, output=root, timeout=0.25, grace=1
            )
            self.assertEqual(result["primary_outcome"], "timed_out")
            self.assertEqual((root / "ack").read_text(), "done")
            self.assertEqual(result["child_returncode"], 130)
            self.assertTrue(result["child_exit_confirmed"])

    def test_failed_subcommand_never_echoes_captured_output(self):
        module = self.module()
        command = ["docker", "exec", "public-argument-sentinel"]
        result = subprocess.CompletedProcess(command, 19, "public-output-sentinel", "public-error-sentinel")
        output = io.StringIO()
        with (
            patch.object(module.subprocess, "run", return_value=result),
            redirect_stderr(output),
            self.assertRaises(subprocess.CalledProcessError),
        ):
            module._run(command)
        self.assertNotIn("sentinel", output.getvalue())

    def test_expired_main_budget_does_not_prepare_images(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            with (
                patch.object(module, "_git", return_value="a" * 40),
                patch.object(module, "ensure_images") as prepare,
                self.assertRaises(ValueError),
            ):
                module.main(
                    [
                        "--cell",
                        "factory",
                        "--root",
                        str(root),
                        "--output",
                        str(root / "observations"),
                        "--timeout-seconds",
                        "0",
                    ]
                )
            prepare.assert_not_called()


class PublicWorkflowControls(unittest.TestCase):
    def test_counted_trust_ci_driver_is_a_separate_public_acceptance_harness(self):
        driver = ROOT / 'scripts/getzilla_trust_ci_postgres_suite.py'
        self.assertTrue(driver.is_file(), 'public acceptance orchestration belongs outside trust-ci product source')
        result = subprocess.run([sys.executable, '-B', str(driver), '--help'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--tests', result.stdout)

    def test_two_pg_cells_join_required_linux_without_replacing_native_jobs(self):
        import yaml

        document = yaml.safe_load((ROOT / ".github/workflows/getzilla.yml").read_text())
        jobs = document["jobs"]
        self.assertIn("postgres-acceptance", jobs)
        self.assertEqual(
            {v["cell"] for v in jobs["postgres-acceptance"]["strategy"]["matrix"]["include"]}, {"factory", "trust-ci"}
        )
        self.assertEqual(set(jobs["linux"]["needs"]), {"linux-core", "postgres-acceptance"})
        self.assertEqual(jobs["linux"]["if"], "always()")
        self.assertIn("windows", jobs)
        self.assertIn("macos", jobs)
        self.assertEqual(document["permissions"], {"contents": "read"})
        steps = jobs["postgres-acceptance"]["steps"]
        self.assertTrue(any("getzilla_live.py" in step.get("run", "") for step in steps))
        self.assertTrue(any("--live-source" in step.get("run", "") and step.get("if") == "always()" for step in steps))
        self.assertNotIn("workflow_dispatch", document.get("on", {}))

    def exporter(self):
        from getzilla import ci_evidence

        self.assertTrue(
            hasattr(ci_evidence, "export_live_evidence"), "bounded live observations must use the existing CI exporter"
        )
        return ci_evidence.export_live_evidence

    def manifest(self, root):
        data = b"public synthetic failure observation\n"
        (root / "observer.json").write_bytes(data)
        (root / "unrelated.txt").write_text("public data not selected for export")
        manifest = {
            "schema": "getzilla-live-acceptance-v1",
            "cell": "factory",
            "source": {"head": "a" * 40, "tree": "b" * 40},
            "run_id": "public-synthetic",
            "attempt": "1",
            "status": "fail",
            "files": [{"path": "observer.json", "sha256": hashlib.sha256(data).hexdigest()}],
        }
        (root / "manifest.json").write_text(json.dumps(manifest))
        return manifest

    def test_export_only_exact_hash_bound_public_observations(self):
        export = self.exporter()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.manifest(root)
            export(root, root / "export")
            self.assertEqual({p.name for p in (root / "export").iterdir()}, {"manifest.json", "observer.json"})
            self.assertEqual((root / "export/observer.json").read_bytes(), (root / "observer.json").read_bytes())

    def test_export_refuses_tampering_duplicates_and_unselected_paths_before_publication(self):
        export = self.exporter()
        for failure in ("tampered", "duplicate", "unselected", "traversal"):
            with tempfile.TemporaryDirectory() as raw, self.subTest(failure=failure):
                root = Path(raw)
                manifest = self.manifest(root)
                if failure == "tampered":
                    (root / "observer.json").write_text("different public bytes")
                elif failure == "duplicate":
                    manifest["files"] *= 2
                elif failure == "unselected":
                    manifest["files"][0]["path"] = "unrelated.txt"
                else:
                    manifest["files"][0]["path"] = "../public-other.txt"
                (root / "manifest.json").write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    export(root, root / "export")
                self.assertFalse((root / "export").exists())
