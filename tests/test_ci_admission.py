"""Fail-closed required Linux aggregation across jobs and source identities."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import importlib
import importlib.util
from pathlib import Path
import sys
import unittest
import re

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".getzilla"))
HEAD, TREE, CHECKER = "a" * 40, "b" * 40, "c" * 40
INVENTORY, POLICY = "d" * 64, "e" * 64
NOW = datetime(2026, 11, 3, 12, tzinfo=timezone.utc)
NAMES = ("security-inventory", "known-vulnerabilities", "security-kev", "security-epss",
         "security-malicious-packages", "security-licenses", "security-container-images", "opengrep",
         "secret-scan", "bandit", "trivy-config")


class CiAdmissionTests(unittest.TestCase):
    def test_required_linux_depends_on_every_new_mandatory_job(self):
        source = (Path(__file__).resolve().parents[1] / ".github/workflows/getzilla.yml").read_text()
        jobs = dict(re.findall(r"^  ([a-z-]+):\n(.*?)(?=^  [a-z-]+:|\Z)", source, re.M | re.S))
        self.assertIn("linux-core", jobs)
        self.assertIn("live-acceptance", jobs)
        self.assertIn("security-expanded", jobs)
        self.assertIn("needs: [linux-core, live-acceptance, security-expanded]", jobs["linux"])
        self.assertIn("if: always()", jobs["linux"])
        self.assertIn("getzilla_ci_admission.py", jobs["linux"])
        self.assertIn("fail-fast: false", jobs["live-acceptance"])
        self.assertIn("GETZILLA_SECURITY_CHECKER_SHA", jobs["security-expanded"])
        self.assertIn("--provision-tools", jobs["security-expanded"])
        self.assertIn("python -I trusted-checker/scripts/getzilla_security.py", jobs["security-expanded"])
        self.assertNotIn("continue-on-error", source)

    def module(self):
        self.assertIsNotNone(importlib.util.find_spec("getzilla.ci_admission"))
        return importlib.import_module("getzilla.ci_admission")

    def records(self):
        common = {"source": {"head": HEAD, "tree": TREE}, "run_id": "123", "attempt": "2", "status": "pass"}
        records = {name: deepcopy(common) for name in ("linux-core", "factory", "trust-ci", "lifecycle", "security-expanded")}
        records["linux-core"]["unit"] = {"status": "pass", "collected": 2, "tests_run": 2,
            "failures": 0, "errors": 0, "skipped": [], "database_obligations": "not_run_in_unit_mode",
            "executed": ["factory.tests.test_disposable_exit.DisposableExitTests.test_cleanup",
                         "factory.tests.test_postgres_fixture_reset.FixtureResetTests.test_reset"]}
        for cell, names in (("factory", ["factory-postgres-exit"]), ("trust-ci", ["trust-ci-postgres", "trust-ci-postgres-restart"]),
                            ("lifecycle", ["factory-lifecycle"])):
            records[cell].update(primary_outcome="passed", cleanup_outcome="confirmed",
                                 checks=[{"id": name, "status": "pass"} for name in names])
        records["security-expanded"]["checker"] = {"head": CHECKER, "tree": TREE, "selected_ref": CHECKER,
            "selection": "operator-variable", "boundary": "separate-checkout"}
        records["security-expanded"]["report"] = {"schema_version": 1, "kind": "security-expanded", "status": "pass",
            "source": {"head_sha": HEAD, "tree_sha": TREE, "checker_sha": CHECKER, "checker_tree_sha": TREE,
                       "candidate_clean": True, "checker_clean": True, "same_project": True},
            "assurance": "local-input-integrity-only",
            "created_at_utc": NOW.isoformat(), "valid_until_utc": (NOW + timedelta(hours=72)).isoformat(),
            "policy_sha256": POLICY, "inventory_sha256": INVENTORY,
            "checks": [{"name": name, "status": "pass", "details": [{"kind": "security-result", "schema_version": 1,
                "outcome": "pass"}]} for name in NAMES]}
        return records

    def evaluate(self, records=None, needs=None, now=NOW):
        module = self.module()
        return module.evaluate(needs or {name: "success" for name in ("linux-core", "live-acceptance", "security-expanded")},
            records or self.records(), head=HEAD, tree=TREE, run_id="123", attempt="2", now=now)

    def test_all_required_evidence_passes_on_the_exact_source(self):
        self.assertEqual(self.evaluate(), [])

    def test_required_unit_classes_cannot_be_counted_as_executed_when_skipped(self):
        records = self.records()
        records['linux-core']['unit']['skipped'] = [{"id": records['linux-core']['unit']['executed'][0], "reason": "unavailable"}]
        self.assertTrue(self.evaluate(records))

    def test_missing_skipped_cancelled_or_failed_job_cannot_admit(self):
        for state in ("skipped", "cancelled", "failure", None):
            needs = {name: "success" for name in ("linux-core", "live-acceptance", "security-expanded")}
            needs["live-acceptance"] = state
            self.assertTrue(self.evaluate(needs=needs), state)

    def test_wrong_source_or_attempt_or_missing_cell_is_rejected(self):
        for key, value in (("source", {"head": "f" * 40, "tree": TREE}), ("attempt", "1")):
            records = self.records()
            records["factory"][key] = value
            self.assertTrue(self.evaluate(records))
        records = self.records()
        del records["lifecycle"]
        self.assertTrue(self.evaluate(records))

    def test_security_missing_duplicate_or_summary_only_na_is_rejected(self):
        for mutation in ("missing", "duplicate", "na"):
            records = self.records()
            checks = records["security-expanded"]["report"]["checks"]
            if mutation == "missing":
                checks.pop()
            elif mutation == "duplicate":
                checks.append(deepcopy(checks[0]))
            else:
                checks[-1].update(status="skip", summary="not applicable", details=[])
            self.assertTrue(self.evaluate(records), mutation)

    def test_security_unknown_extra_pass_is_rejected_and_named_ruff_is_optional(self):
        records = self.records()
        records["security-expanded"]["report"]["checks"].append({"name": "unexpected-check", "status": "pass"})
        self.assertTrue(self.evaluate(records))
        records["security-expanded"]["report"]["checks"][-1]["name"] = "ruff"
        self.assertEqual(self.evaluate(records), [])

    def test_security_cannot_invent_assurance_or_omit_source_cleanliness(self):
        for value in (None, "externally-qualified"):
            records = self.records()
            records["security-expanded"]["report"]["assurance"] = value
            self.assertTrue(self.evaluate(records), value)
        for field in ("candidate_clean", "checker_clean", "same_project"):
            for value in (None, False, "true", 1):
                records = self.records()
                records["security-expanded"]["report"]["source"][field] = value
                self.assertTrue(self.evaluate(records), (field, value))

    def test_security_structural_na_is_inventory_bound(self):
        records = self.records()
        check = records["security-expanded"]["report"]["checks"][-1]
        check.update(status="skip", details=[{"kind": "security-result", "schema_version": 1, "outcome": "not_applicable",
            "applicability_evidence": {"complete": True, "inventory_sha256": INVENTORY, "reason": "complete-inventory-no-objects"}}])
        self.assertEqual(self.evaluate(records), [])
        check["details"][0]["applicability_evidence"]["inventory_sha256"] = "0" * 64
        self.assertTrue(self.evaluate(records))

    def test_security_expires_strictly_after_72_hours(self):
        self.assertEqual(self.evaluate(now=NOW + timedelta(hours=72)), [])
        self.assertTrue(self.evaluate(now=NOW + timedelta(hours=72, microseconds=1)))
        records = self.records()
        records["security-expanded"]["report"]["valid_until_utc"] = None
        self.assertTrue(self.evaluate(records))


if __name__ == "__main__":
    unittest.main()
