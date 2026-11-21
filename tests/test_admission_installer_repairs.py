"""NEW owned data/AST controls; no existing workload or producer is executed."""

import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

W = Path(__file__).resolve().parents[1]
E = W / ".getzilla/runtime/scratch/new-admission-installer-controls"


def module(name):
    p = W / ".getzilla/getzilla" / (name + ".py")
    spec = importlib.util.spec_from_file_location("new_" + name, p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class AdmissionInstallerRepairs(unittest.TestCase):
    def setUp(self):
        E.mkdir(parents=True, exist_ok=True, mode=0o700)

    def api(self):
        return module("live_contracts")

    def binding(self, a, cell="trust-ci"):
        return a.ci_binding(head="a" * 40, tree="b" * 40, run_id="72", attempt="1", cell=cell, producer_sha256="c" * 64)

    def suite(self, b):
        ids = ["owned.Case.test_database", "owned.Case.test_second"]
        return dict(
            schema="getzilla-live-suite-v1",
            binding=b,
            status="pass",
            expected_ids=ids,
            collected_ids=ids,
            required_ids=ids,
            started=ids,
            executed=ids,
            missing_required=[],
            inapplicable_ids=[],
            tests_run=2,
            failures=0,
            errors=0,
            loader_errors=0,
            problems=[],
            source_stable=True,
            requirements_complete=True,
            skipped=[],
            allowed_skips={},
            applicability=None,
            source_inventory={"owned.py": "d" * 64},
        )

    def skip(self, suite, ids):
        suite["executed"] = [v for v in suite["expected_ids"] if v not in ids]
        suite["required_ids"] = list(suite["executed"])
        suite["inapplicable_ids"] = ids
        suite["skipped"] = [dict(id=v, reason="invented", applicability="invented") for v in ids]
        suite["allowed_skips"] = {v: dict(reason="invented", rule="invented") for v in ids}

    def test_managed_declarations_are_unique_and_both_apis_ship(self):
        tree = ast.parse((W / "scripts/install_into.py").read_bytes())
        node = next(
            n
            for n in tree.body
            if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "MANAGED_FILES" for t in n.targets)
        )
        names = [n.value for n in node.value.elts if isinstance(n, ast.Constant)]
        scripts = json.loads((W / ".getzilla/config/managed.json").read_bytes())["scripts"]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(len(scripts), len(set(scripts)))
        for name in ("getzilla_live.py", "getzilla_live_lifecycle.py"):
            self.assertEqual(names.count("scripts/" + name), 1)
            self.assertEqual(scripts.count(name), 1)
        self.assertIn("duplicate managed path:", (W / "scripts/install_into.py").read_text())

    def test_trust_all_skipped_and_mixed_invented_allowances_refuse(self):
        a = self.api()
        b = self.binding(a)
        for count in (1, 2):
            s = self.suite(b)
            self.skip(s, s["expected_ids"][:count])
            self.assertFalse(a.recorded_suite_valid(s, b))
        self.assertTrue(a.recorded_suite_valid(self.suite(b), b))

    def test_consumer_refuses_bound_all_skipped_artifact(self):
        a = self.api()
        b = self.binding(a)
        s = self.suite(b)
        self.skip(s, s["expected_ids"])
        with tempfile.TemporaryDirectory(dir=E) as raw:
            p = Path(raw)

            def write(name, value):
                (p / name).write_text(json.dumps(value, sort_keys=True))
                (p / name).chmod(0o600)

            write("invocation.json", b)
            write("observer.json", {})
            write("trust-ci-suite.json", s)
            write("trust-ci-resources.json", dict(cleanup_status="removed", resources=[dict(status="removed")]))
            write(
                "trust-ci-restart.json",
                dict(
                    binding=b,
                    status="pass",
                    restarts=[
                        dict(
                            before="2026-11-01T00:00:00+00:00",
                            after="2026-11-01T00:00:01+00:00",
                            cluster="123",
                            synthetic_job_id="owned",
                        )
                    ],
                ),
            )

            def sha(name):
                return hashlib.sha256((p / name).read_bytes()).hexdigest()

            for name in ("trust-ci-suite.json", "trust-ci-restart.json"):
                write(
                    name + ".envelope.json",
                    dict(
                        binding=b,
                        report=dict(path=name, sha256=sha(name)),
                        journal=dict(path="trust-ci-resources.json", sha256=sha("trust-ci-resources.json")),
                    ),
                )
            files = {v.name: sha(v.name) for v in p.iterdir() if v.name not in ("invocation.json", "observer.json")}
            write("controller-validation.json", a.controller_observation(b, files))
            write(
                "manifest.json",
                dict(schema="getzilla-live-acceptance-v1", binding=b, status="pass", files=a.evidence_inventory(p)),
            )
            with self.assertRaises(ValueError):
                a.read_live_record(
                    p, b, expected_source_inventory=s["source_inventory"], expected_ids=s["expected_ids"]
                )

    def test_factory_requires_independent_canonical_allowances(self):
        a = self.api()
        b = self.binding(a, "factory")
        s = self.suite(b)
        s["expected_ids"][0] = "factory.tests.test_landing_pdf_worker.PdfWorkerWithPinnedParser.test_owned"
        self.assertIn("expected_allowances", __import__("inspect").signature(a.recorded_suite_valid).parameters)
        self.skip(s, [s["expected_ids"][0]])
        canonical = {
            s["expected_ids"][0]: dict(
                rule="parser-absent", reason="requires pypdf installed for the child interpreter"
            )
        }
        s["allowed_skips"] = copy.deepcopy(canonical)
        s["skipped"] = [dict(id=k, applicability=v["rule"], reason=v["reason"]) for k, v in canonical.items()]
        self.assertTrue(a.recorded_suite_valid(s, b, expected_allowances=canonical))
        self.assertFalse(a.recorded_suite_valid(s, b))
        s["allowed_skips"][s["expected_ids"][0]]["reason"] = "invented"
        s["skipped"][0]["reason"] = "invented"
        self.assertFalse(a.recorded_suite_valid(s, b, expected_allowances=canonical))
        s["allowed_skips"][s["expected_ids"][0]]["rule"] = "invented"
        s["skipped"][0]["applicability"] = "invented"
        self.assertFalse(a.recorded_suite_valid(s, b, expected_allowances=canonical))

    def test_parser_cases_cannot_use_absent_independent_policy(self):
        a = self.api()
        b = self.binding(a, "factory")
        s = self.suite(b)
        s["expected_ids"][0] = "factory.tests.test_landing_pdf_worker.PdfWorkerWithPinnedParser.test_owned"
        with self.assertRaises(ValueError):
            a.retained_parser_allowances(s, b, {"policy": None, "allowances_by_version": {}})

    def test_original_parser_facts_use_source_policy_and_canonical_reason(self):
        a = self.api()
        b = self.binding(a, "factory")
        s = self.suite(b)
        ident = "factory.tests.test_landing_pdf_worker.PdfWorkerWithoutParser.test_worker_executes_and_reports_parser_unavailable"
        s["expected_ids"][0] = ident
        policy = {"eligible_ids": [ident], "parser_pin": "6.12.0", "required_parser": False, "digest": "e" * 64}
        canonical = {ident: {"rule": "parser-present", "reason": "pypdf present; unavailable branch cannot run"}}
        contract = {"policy": policy, "allowances_by_version": {"pinned": canonical, "absent": {}}}
        fact = {
            "module": "factory.tests.test_landing_pdf_worker",
            "path": "/original/factory/tests/test_landing_pdf_worker.py",
            "pypdf_version": "6.12.0",
            "observed": True,
        }
        row = {
            "binding": b,
            "python": "/original/venv/python",
            "python_identity": {"named": [1] * 7, "target": [2] * 7},
            "policy_digest": "e" * 64,
            "pypdf_version": "6.12.0",
            "observed_ns": 1,
        }
        s["applicability"] = {
            "policy": copy.deepcopy(policy),
            "observations": [dict(row, observed_ns=n) for n in (1, 2, 3)],
            "module_fact": {"discovery": dict(fact), "after": dict(fact)},
        }
        self.assertEqual(a.retained_parser_allowances(s, b, contract), canonical)
        for key, value in [
            ("policy", dict(policy, required_parser=True)),
            ("observations", [dict(row, pypdf_version=None)] * 3),
        ]:
            bad = copy.deepcopy(s)
            bad["applicability"][key] = value
            with self.assertRaises(ValueError):
                a.retained_parser_allowances(bad, b, contract)
        consumer = (W / ".getzilla/getzilla/ci_admission.py").read_text()
        self.assertIn("applicability = retained_parser_contract(root)", consumer)
        self.assertIn(
            "factory_tests.skip_allowance(identifier, context)",
            (W / ".getzilla/getzilla/live_acceptance.py").read_text(),
        )

    def context(self):
        self.assertTrue((W / ".getzilla/getzilla/ci_security_context.py").is_file())
        return module("ci_security_context")

    def test_pr_and_push_selected_identity_preserve_real_event(self):
        a = self.context()
        for event, merge, head in [("pull_request", "b" * 40, "a" * 40), ("push", "a" * 40, "a" * 40)]:
            env = dict(
                GITHUB_SHA=merge,
                GITHUB_EVENT_NAME=event,
                GITHUB_RUN_ID="72",
                GITHUB_RUN_ATTEMPT="2",
                GITHUB_REPOSITORY="Dimkox/Getzilla",
            )
            selected, provenance = a.selected_run_environment(env, head)
            self.assertEqual(selected["GITHUB_SHA"], head)
            self.assertEqual(provenance["event_sha"], merge)
            self.assertEqual(provenance["source_head"], head)
            self.assertEqual(selected["GITHUB_RUN_ATTEMPT"], "2")
            self.assertEqual(env["GITHUB_SHA"], merge)
            with self.assertRaises(ValueError):
                a.selected_run_environment(env, "unbound")

    def test_workflow_supplies_selected_head_and_primary_refusal_survives(self):
        a = self.context()
        workflow = (W / ".github/workflows/getzilla.yml").read_text()
        self.assertIn("SELECTED_SOURCE_SHA: ${{ github.event.pull_request.head.sha || github.sha }}", workflow)
        self.assertIn("security-event.json", workflow)
        refusal = dict(
            kind="public-security-input-refusal",
            status="fail",
            qualification="UNVERIFIED",
            gaps=["input-preparation-unavailable"],
            reason="selected public input/profile/source validation refused",
        )
        phase, report = a.primary_report(None, refusal, None)
        self.assertEqual(phase, "declaration")
        self.assertEqual(report, refusal)
        self.assertNotIn("bootstrap", json.dumps(report))
        self.assertEqual(a.primary_report(None, {}, refusal)[0], "preparation")

    def test_primary_refusal_projection_never_exports_private_values(self):
        a = self.context()
        self.assertTrue(hasattr(a, "closed_phase_report"))
        raw = b"PRIVATE_BODY"
        projected = a.closed_phase_report(
            {
                "kind": "public-security-input-refusal",
                "status": "fail",
                "qualification": "UNVERIFIED",
                "gaps": ["input-preparation-unavailable", "PRIVATE_GAP"],
                "reason": "PRIVATE_REASON",
            },
            raw,
        )
        self.assertEqual(projected["gaps"], ["input-preparation-unavailable"])
        self.assertEqual(projected["omitted"], {"gap_values": 1, "reason": True})
        self.assertEqual(projected["original_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertNotIn("PRIVATE", json.dumps(projected))

    def test_empty_report_and_all_eight_expectations_share_truthful_refusal(self):
        # This refusal must occur before any current plan producer is reached.
        tree = ast.parse((W / ".getzilla/getzilla/verification_plan.py").read_bytes())
        selected = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in ("_finding", "report_gaps")]
        scope = {
            "Path": Path,
            "Any": object,
            "datetime": object,
            "current_required_plan": lambda *a, **k: self.fail("producer reached"),
        }
        exec(compile(ast.Module(body=selected, type_ignores=[]), "<new-empty-report-control>", "exec"), scope)
        gaps = scope["report_gaps"](Path("/unexecuted-owned-root"), {})
        text = (W / "tests/test_change_receipts.py").read_text()
        node = next(
            n
            for n in ast.parse(text).body
            if isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "_MISSING_REQUIRED_PLAN" for t in n.targets)
        )
        expected = ast.literal_eval(node.value)
        self.assertEqual(
            expected, ["verification: " + gaps[0]["code"] + ": " + gaps[0]["path"] + ": " + gaps[0]["message"]]
        )
        self.assertEqual(text.count("_MISSING_REQUIRED_PLAN"), 9)

    def test_alias_reason_type_count_index_survive_existing_200_byte_message(self):
        a = module("security_osv_diagnostics")
        self.assertTrue(hasattr(a, "bounded_alias_message"))
        d = a.alias_rejection(dict(id="PRIVATE_MEMBER", aliases=["PRIVATE/BAD"]), 0)
        error = ValueError("PRIVATE_RAW_NEVER_EXPORT")
        error.osv_alias_detail = d
        message = a.bounded_alias_message(error)
        self.assertLessEqual(len(message), 200)
        compact = json.loads(message)
        self.assertEqual(compact["reason"], "charset")
        self.assertEqual(compact["type"], "array/string")
        self.assertEqual((compact["count"], compact["index"]), (1, 0))
        self.assertEqual(compact["omitted"], ["sha256"])
        self.assertNotIn("PRIVATE", message)
        self.assertEqual(len(d["value_sha256"]), 64)


if __name__ == "__main__":
    unittest.main(verbosity=2)
