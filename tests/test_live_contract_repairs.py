"""NEW owned pure/data/AST contracts; no old body, evaluator or producer runs."""

import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

W = Path(__file__).resolve().parents[1]
E = W / ".getzilla/runtime/scratch/new-live-contract-controls"


class NewContracts(unittest.TestCase):
    def setUp(self):
        E.mkdir(parents=True, exist_ok=True, mode=0o700)

    def api(self):
        p = W / ".getzilla/getzilla/live_contracts.py"
        self.assertTrue(p.is_file(), "missing pure live contract adapter")
        spec = importlib.util.spec_from_file_location("new_owned_live_contracts", p)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def binding(self, api):
        return api.ci_binding(
            head="a" * 40, tree="b" * 40, run_id="4321", attempt="2", cell="factory", producer_sha256="c" * 64
        )

    def test_ci_invocation_is_derived_from_expected_context(self):
        a = self.api()
        b = self.binding(a)
        self.assertEqual(b, self.binding(a))
        self.assertEqual(b["cell"], "factory")
        self.assertEqual(len(b["nonce"]), 32)
        other = a.ci_binding(
            head="a" * 40, tree="b" * 40, run_id="4321", attempt="3", cell="factory", producer_sha256="c" * 64
        )
        self.assertNotEqual(b["nonce"], other["nonce"])

    def test_nested_manifest_cannot_renew_or_replace_expected_identity(self):
        a = self.api()
        b = self.binding(a)
        r = {
            "schema": "getzilla-live-acceptance-v1",
            "binding": b,
            "status": "pass",
            "checks": [{"id": "factory-postgres-exit", "status": "pass"}],
            "primary_outcome": "passed",
            "cleanup_outcome": "confirmed",
        }
        actual = a.normalize_live_record(r, b, b)
        self.assertEqual(actual["source"], {"head": "a" * 40, "tree": "b" * 40})
        self.assertFalse(actual["fresh_execution_credit"])
        mutated = {**b, "attempt": "1"}
        with self.assertRaises(ValueError):
            a.normalize_live_record({**r, "binding": mutated}, mutated, b)

    def test_all_100_cycle_journals_fit_one_bounded_ledger_inventory(self):
        a = self.api()
        b = self.binding(a)
        entries = {}
        for n in range(1, 96):
            entries[b["namespace"] + f"-c{n}-ack.json"] = (
                json.dumps({"cleanup": "removed", "namespace": b["namespace"] + f"-c{n}", "nonce": "d" * 32}) + "\n"
            )
        entries["protected-ack.json"] = (
            json.dumps({"cleanup": "removed", "namespace": b["namespace"] + "-protected", "nonce": "e" * 32}) + "\n"
        )
        ledger = a.cleanup_ledger(b, entries)
        self.assertEqual(len(ledger["acks"]), 96)
        self.assertLess(len(json.dumps(ledger).encode()), 32768)
        with tempfile.TemporaryDirectory(dir=E) as raw:
            p = Path(raw)
            for n in range(1, 101):
                (p / (b["namespace"] + f"-c{n}-resources.json")).write_text("{}")
            for name in (
                "protected-resources.json",
                "protected-evidence.txt",
                "invocation.json",
                "observer.json",
                "lifecycle.json",
                "lifecycle.json.envelope.json",
                "lifecycle-resource-index.json",
                "lifecycle-cleanup-ledger.json",
                "controller-validation.json",
                "command.log",
            ):
                (p / name).write_text("{}")
            for n in range(96, 101):
                (p / (b["namespace"] + f"-c{n}-sample.json")).write_text("{}")
            for n in range(96, 101):
                (p / (b["namespace"] + f"-c{n}-ack.json")).write_text("{}")
            inventory = a.evidence_inventory(p)
            self.assertEqual(len(inventory), 120)
            self.assertLessEqual(len(inventory) + 1, 128)
            self.assertEqual(sum(name["path"].endswith("-resources.json") for name in inventory), 101)
            for n in range(20):
                (p / (b["namespace"] + f"-extra{n}-ack.json")).write_text("{}")
            with self.assertRaises(ValueError):
                a.evidence_inventory(p)

    def test_ledger_preserves_raw_ack_and_rejects_wrong_owner(self):
        a = self.api()
        b = self.binding(a)
        raw = json.dumps({"cleanup": "removed", "namespace": b["namespace"] + "-c1", "nonce": "d" * 32}) + "\n"
        name = b["namespace"] + "-c1-ack.json"
        ledger = a.cleanup_ledger(b, {name: raw})
        self.assertEqual(ledger["acks"][name], raw)
        actual = a.ledger_ack(ledger, b, name, {"namespace": b["namespace"] + "-c1", "nonce": "d" * 32})
        self.assertEqual(actual["cleanup"], "removed")
        with self.assertRaises(ValueError):
            a.ledger_ack(ledger, b, name, {"namespace": "gz-foreign", "nonce": "d" * 32})

    def test_cycle_cleanup_is_reserved_inside_existing_total(self):
        a = self.api()
        for mode, total in [("sigint", 45), ("sigterm", 45), ("timeout", 35), ("kill", 45), ("failure", 45)]:
            active, cleanup = a.cycle_budget(mode)
            self.assertEqual(active + cleanup, total)
            self.assertEqual(cleanup, 10)

    def test_cleanup_preserves_primary_and_reports_real_cleanup_failure(self):
        a = self.api()
        calls = []
        primary = RuntimeError("primary owned fixture")

        class Owner:
            def cleanup(self):
                calls.append("cleanup")
                raise OSError("owned fixture failure")

        actual = a.finish_owned(Owner(), primary, lambda owner: calls.append("ack"))
        self.assertIs(actual, primary)
        self.assertEqual(calls, ["cleanup"])
        self.assertTrue(actual.__notes__)

    def test_architecture_has_one_truthful_owner_for_each_exact_path(self):
        model = json.loads((W / "architecture/system.yaml").read_bytes())
        owners = {}
        for n in model["nodes"]:
            for p in n["repository_paths"]:
                owners.setdefault(p, []).append(n["id"])
        self.assertFalse({p: n for p, n in owners.items() if len(n) > 1})

    def test_receipt_runs_current_plan_validation_once(self):
        t = ast.parse((W / ".getzilla/getzilla/receipts.py").read_bytes())
        f = next(n for n in t.body if isinstance(n, ast.FunctionDef) and n.name == "validate_evidence")
        calls = [
            n
            for n in ast.walk(f)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "report_gaps"
        ]
        self.assertEqual(len(calls), 1)

    def test_legacy_fixture_has_complete_current_assurance_marker(self):
        t = ast.parse((W / "trust-ci/tests/test_public_admission.py").read_bytes())
        dictionaries = [
            n
            for n in ast.walk(t)
            if isinstance(n, ast.Dict)
            and any(
                isinstance(k, ast.Constant)
                and k.value == "kind"
                and isinstance(v, ast.Constant)
                and v.value == "security-result"
                for k, v in zip(n.keys, n.values)
            )
        ]
        self.assertTrue(dictionaries)
        for d in dictionaries:
            self.assertTrue(any(isinstance(k, ast.Constant) and k.value == "assurance" for k in d.keys))

    def test_live_exports_keep_historical_measurement_separate(self):
        a = self.api()
        self.assertTrue(callable(getattr(a, "read_live_record", None)))
        self.assertTrue(callable(getattr(a, "controller_observation", None)))

    def test_alias_rejection_detail_is_closed_and_never_logs_raw_values(self):
        p = W / ".getzilla/getzilla/security_osv_diagnostics.py"
        self.assertTrue(p.is_file(), "missing closed alias rejection shape diagnostic")
        spec = importlib.util.spec_from_file_location("new_owned_alias_diagnostic", p)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        d = module.alias_rejection(
            {"id": "PRIVATE_MEMBER_SENTINEL", "aliases": ["CVE-2026-123", "PRIVATE_VALUE/SENTINEL"]}, 1
        )
        self.assertEqual(d["reason"], "charset")
        self.assertEqual(d["index"], 1)
        self.assertEqual(d["count"], 2)
        self.assertEqual(len(d["value_sha256"]), 64)
        encoded = json.dumps(d)
        self.assertNotIn("PRIVATE", encoded)
        self.assertLess(len(encoded), 512)

    def test_complete_current_shaped_artifact_reads_without_fresh_measurement_credit(self):
        a = self.api()
        b = self.binding(a)
        ids = [
            "factory.tests.test_postgres_integration.Case.test_owned",
            "factory.tests.test_migrations.FreshClusterArtifactAttestorMigrationTests.test_owned",
        ]
        source = {"owned-source.py": "e" * 64}
        with tempfile.TemporaryDirectory(dir=E) as raw:
            p = Path(raw)

            def write(name, value):
                (p / name).write_text(json.dumps(value, sort_keys=True) + "\n")

            write("invocation.json", b)
            write("observer.json", {"primary_outcome": "passed", "cleanup_outcome": "confirmed"})
            suite = {
                "schema": "getzilla-live-suite-v1",
                "binding": b,
                "status": "pass",
                "expected_ids": ids,
                "collected_ids": ids,
                "required_ids": ids,
                "started": ids,
                "executed": ids,
                "missing_required": [],
                "inapplicable_ids": [],
                "tests_run": 2,
                "failures": 0,
                "errors": 0,
                "loader_errors": 0,
                "problems": [],
                "source_stable": True,
                "requirements_complete": True,
                "skipped": [],
                "allowed_skips": {},
                "applicability": None,
                "source_inventory": source,
            }
            write("factory-suite.json", suite)
            write(
                "factory-resources.json",
                {
                    "namespace": b["namespace"],
                    "nonce": "f" * 32,
                    "cleanup_status": "removed",
                    "resources": [{"status": "removed", "kind": "container"}],
                },
            )
            write(
                "factory-restart.json",
                {
                    "binding": b,
                    "status": "pass",
                    "restarts": [
                        {
                            "before": "2026-11-01T00:00:00+00:00",
                            "after": "2026-11-01T00:00:01+00:00",
                            "cluster": "123",
                            "synthetic_job_id": None,
                        }
                    ]
                    * 2,
                },
            )
            for name in ("factory-suite.json", "factory-restart.json"):
                write(
                    name + ".envelope.json",
                    {
                        "binding": b,
                        "report": {"path": name, "sha256": hashlib.sha256((p / name).read_bytes()).hexdigest()},
                        "journal": {
                            "path": "factory-resources.json",
                            "sha256": hashlib.sha256((p / "factory-resources.json").read_bytes()).hexdigest(),
                        },
                    },
                )
            files = {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in p.iterdir()
                if path.name not in ("observer.json", "invocation.json")
            }
            write(
                "controller-validation.json",
                a.controller_observation(b, files, parser_evidence_sha256=a.digest(suite["applicability"])),
            )
            record = {
                "schema": "getzilla-live-acceptance-v1",
                "binding": b,
                "status": "pass",
                "checks": [{"id": "factory-postgres-exit", "status": "pass"}],
                "primary_outcome": "passed",
                "cleanup_outcome": "confirmed",
                "files": a.evidence_inventory(p),
            }
            write("manifest.json", record)
            loaded = a.read_live_record(p, b, expected_source_inventory=source, expected_ids=ids,
                expected_factory_applicability={"policy": None, "allowances_by_version": {}})
            self.assertFalse(loaded["fresh_execution_credit"])
            self.assertEqual(loaded["source"]["head"], "a" * 40)
            with self.assertRaises(ValueError):
                a.read_live_record(p, {**b, "run_id": "999"}, expected_source_inventory=source, expected_ids=ids,
                expected_factory_applicability={"policy": None, "allowances_by_version": {}})
            with self.assertRaises(ValueError):
                a.read_live_record(p, b, expected_source_inventory=source, expected_ids=ids + ["owned.case.omitted"],
                    expected_factory_applicability={"policy": None, "allowances_by_version": {}})


if __name__ == "__main__":
    unittest.main(verbosity=2)
