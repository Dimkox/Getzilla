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


def unit_fixture(*, include_skip=False):
    """New tiny public sources; these records never represent a real CI run."""
    import hashlib
    from getzilla.factory_tests import declared_ids, skip_allowance
    contents = {
        "factory/tests/test_disposable_exit.py": b"class DisposableExitTests:\n def test_cleanup(self): pass\n",
        "factory/tests/test_postgres_fixture_reset.py": b"class FixtureResetTests:\n def test_reset(self): pass\n",
    }
    if include_skip:
        contents["factory/tests/test_postgres_integration.py"] = b"class PostgresFactoryTests:\n def test_public_fixture_skip(self): pass\n"
    identifiers = declared_ids(Path("/owned-fixture"), contents=contents)
    context = {"unit_database_bindings": "scrubbed", "host_supported": False,
               "procfs_descriptor_reopen": False, "pypdf_version": None, "jsonschema_cli": None}
    expected_source = {"source_inventory": {name: hashlib.sha256(raw).hexdigest() for name, raw in contents.items()},
                       "declared_ids": identifiers, "engine_sha256": "f" * 64}
    binding = {**expected_source, "root": "/owned-fixture", "python": "/fixture/python",
               "invocation_id": "0" * 32, "source_bindings": {"ancestry": {}, "directories": {}, "files": {}},
               "context": context}
    skipped = [{"id": item, "reason": skip_allowance(item, context)[1],
                "applicability": skip_allowance(item, context)[0]}
               for item in identifiers if skip_allowance(item, context)]
    executed = [item for item in identifiers if not skip_allowance(item, context)]
    unit = {"schema_version": 3, "check_id": "factory-unit", "status": "pass", "binding": binding,
            "collected": len(identifiers), "collected_ids": identifiers, "expected_ids": identifiers,
            "required_ids": executed, "tests_run": len(identifiers), "started": identifiers,
            "executed": executed, "failures": 0, "errors": 0, "loader_errors": 0, "skipped": skipped,
            "unqualified_skips": [], "missing_required": [], "source_stable": True,
            "database_obligations": "not_run_in_unit_mode", "problems": []}
    return unit, expected_source


class CiSchema3RepairTests(unittest.TestCase):
    def test_owned_three_started_two_executed_one_qualified_skip(self):
        from getzilla.ci_admission import _factory_unit_valid
        unit, source = unit_fixture(include_skip=True)
        self.assertTrue(_factory_unit_valid(unit, source))

    def test_owned_accounting_and_skip_provenance_refuse(self):
        from getzilla.ci_admission import _factory_unit_valid
        unit, source = unit_fixture(include_skip=True)
        changed = deepcopy(unit)
        changed["executed"].append(changed["skipped"][0]["id"])
        self.assertFalse(_factory_unit_valid(changed, source))
        changed = deepcopy(unit)
        changed["skipped"][0]["reason"] = "unmeasured skip"
        self.assertFalse(_factory_unit_valid(changed, source))
        changed = deepcopy(unit)
        changed["started"].append("factory.tests.test_owned.Unaccounted.test_case")
        self.assertFalse(_factory_unit_valid(changed, source))

    def test_owned_source_and_missing_evidence_refuse(self):
        from getzilla.ci_admission import _factory_unit_valid
        unit, source = unit_fixture()
        self.assertTrue(_factory_unit_valid(unit, source))
        changed = deepcopy(source)
        changed["engine_sha256"] = "e" * 64
        self.assertFalse(_factory_unit_valid(unit, changed))
        changed = deepcopy(source)
        changed["source_inventory"][next(iter(changed["source_inventory"]))] = "d" * 64
        self.assertFalse(_factory_unit_valid(unit, changed))
        self.assertFalse(_factory_unit_valid(unit, None))


class CiAdmissionTests(unittest.TestCase):
    def test_required_linux_depends_on_every_new_mandatory_job(self):
        source = (Path(__file__).resolve().parents[1] / ".github/workflows/getzilla.yml").read_text()
        jobs = dict(re.findall(r"^  ([a-z-]+):\n(.*?)(?=^  [a-z-]+:|\Z)", source, re.M | re.S))
        self.assertIn("linux-core", jobs)
        self.assertIn("live-acceptance", jobs)
        self.assertIn("security-expanded", jobs)
        self.assertIn("needs: [linux-core, linux-core-tests, live-acceptance, security-expanded]", jobs["linux"])
        self.assertIn("if: always()", jobs["linux"])
        self.assertIn("getzilla_ci_admission.py", jobs["linux"])
        self.assertIn("fail-fast: false", jobs["live-acceptance"])
        self.assertIn("GETZILLA_SECURITY_CHECKER_SHA", jobs["security-expanded"])
        producer = jobs['security-expanded']
        self.assertIn('trusted-checker/.getzilla/getzilla/security_image_provision.py', producer)
        self.assertIn('from getzilla.security_image_provision import provision;provision(sys.argv[2])', producer)
        self.assertIn('from getzilla.security_cli import main;raise SystemExit(main())', producer)
        self.assertIn('\"$selected_python\" -I -S -B', producer)
        self.assertIn('--produce-images --ci-image-corpus', producer)
        self.assertIn('--backend-tool-pins', producer)
        self.assertIn('candidate HEAD is never selected automatically', producer)
        self.assertNotIn('--provision-tools', producer)
        self.assertNotIn("continue-on-error", source)

    def module(self):
        self.assertIsNotNone(importlib.util.find_spec("getzilla.ci_admission"))
        return importlib.import_module("getzilla.ci_admission")

    def records(self):
        common = {"source": {"head": HEAD, "tree": TREE}, "run_id": "123", "attempt": "2", "status": "pass"}
        records = {name: deepcopy(common) for name in ("linux-core", "factory", "trust-ci", "lifecycle", "security-expanded")}
        unit, source = unit_fixture()
        records["linux-core"].update(unit=unit, unit_source=source)
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
        return module.evaluate(needs or {name: "success" for name in ("linux-core", "linux-core-tests", "live-acceptance", "security-expanded")},
            records or self.records(), head=HEAD, tree=TREE, run_id="123", attempt="2", now=now)

    def test_waiver_is_limited_to_bound_security_failure_before_expiry(self):
        module = self.module()
        config = module.read_waiver(Path(__file__).resolve().parents[1])
        needs = dict.fromkeys(("linux-core", "linux-core-tests", "live-acceptance", "security-expanded"), "success")
        records = self.records()
        args = dict(waiver=config, repository="Dimkox/Getzilla", head=HEAD, tree=TREE,
                    run_id="123", attempt="2", now=NOW)
        def decision(**changes):
            from unittest.mock import patch
            with patch.dict("os.environ", {"GETZILLA_OPERATOR_CHECKER": CHECKER}):
                return module.admission_result(needs, records, **(args | changes))
        self.assertEqual(decision()["status"], "pass")
        self.assertFalse(decision()["waiver"]["used"])
        needs["security-expanded"] = "failure"
        security = records["security-expanded"]
        security.update(schema="getzilla-security-ci-v1", status="fail", primary_phase="scan",
                        event_provenance={"repository": "Dimkox/Getzilla"}, report={"kind": "public-security-input-refusal", "status": "fail"})
        self.assertEqual(decision()["status"], "pass-with-waiver")
        self.assertEqual(decision()["waiver"]["issue"], 456)
        original = security["report"]
        for status in ("fail", "fail-for-selected-run"):
            with self.subTest(scan_status=status):
                security["report"] = {"kind": "security-expanded", "status": status,
                                      "checks": [{"name": "known-vulnerabilities", "status": "fail"}]}
                result = decision()
                self.assertEqual(result["status"], "fail")
                self.assertFalse(result["waiver"]["used"])
        security["report"] = original
        self.assertEqual(decision(now=datetime(2026,12,8,tzinfo=timezone.utc))["status"], "fail")
        self.assertEqual(decision(repository="Fork/Getzilla")["status"], "fail")
        for job in ("linux-core", "linux-core-tests", "live-acceptance"):
            needs[job] = "failure"
            self.assertEqual(decision()["status"], "fail")
            needs[job] = "success"
        for result in ("cancelled", "skipped"):
            needs["security-expanded"] = result
            self.assertEqual(decision()["status"], "fail")
        needs["security-expanded"] = "failure"
        security["attempt"] = "1"
        self.assertEqual(decision()["status"], "fail")
        del records["security-expanded"]
        self.assertEqual(decision()["status"], "fail")

    def test_waiver_configuration_is_closed(self):
        import json
        import tempfile
        module = self.module()
        entry = module.read_waiver(Path(__file__).resolve().parents[1])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / ".getzilla/config/ci-waivers.json"
            path.parent.mkdir(parents=True)
            self.assertIsNone(module.read_waiver(root))
            for rows in ([dict(entry, check="linux-core")], [entry, entry],
                         [dict(entry, unexpected=True)], [dict(entry, expires="2027-01-01")]):
                path.write_text(json.dumps({"schema_version": 1, "waivers": rows}))
                with self.assertRaises(ValueError):
                    module.read_waiver(root)
            path.write_text("{")
            with self.assertRaises(ValueError):
                module.read_waiver(root)

    def test_all_required_evidence_passes_on_the_exact_source(self):
        self.assertEqual(self.evaluate(), [])

    def test_required_unit_classes_cannot_be_counted_as_executed_when_skipped(self):
        records = self.records()
        records['linux-core']['unit']['skipped'] = [{"id": records['linux-core']['unit']['executed'][0], "reason": "unavailable"}]
        self.assertTrue(self.evaluate(records))

    def test_missing_skipped_cancelled_or_failed_job_cannot_admit(self):
        for state in ("skipped", "cancelled", "failure", None):
            needs = {name: "success" for name in ("linux-core", "linux-core-tests", "live-acceptance", "security-expanded")}
            needs["live-acceptance"] = state
            self.assertTrue(self.evaluate(needs=needs), state)

    def test_missing_skipped_cancelled_or_failed_core_test_shards_cannot_admit(self):
        self.assertFalse(self.evaluate())
        for state in ("skipped", "cancelled", "failure", None):
            needs = {name: "success" for name in ("linux-core", "linux-core-tests", "live-acceptance", "security-expanded")}
            needs["linux-core-tests"] = state
            self.assertIn("required job linux-core-tests did not succeed", self.evaluate(needs=needs), state)

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
