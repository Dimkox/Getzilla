"""Actual owned native sources and fixed local reader, no supplied cost authority."""

import copy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".getzilla"))
from tests import test_trace_observation as trace_fixtures
from tests._native_public_fixture import project_copy
from getzilla import state, task_budget, route_metrics
from getzilla.observation_privacy import local_identity, load_local


class EconomicsProtectedReaderTests(unittest.TestCase):
    def setUp(self):
        self.fixture = trace_fixtures.TraceObservationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.addCleanup(state.bind_session, None)

    def query(self, root, route):
        binding = local_identity(root)
        now = datetime.now(timezone.utc) + timedelta(seconds=1)

        def stamp(value):
            return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        return {
            "scope_ids": [binding["repository_digest"]],
            "as_of": stamp(now),
            "cohort": {
                "kind": "task_ids",
                "tasks": [
                    {
                        "domain": "core_native",
                        "project_digest": binding["repository_digest"],
                        "task_id": route["logical_task_id"],
                    }
                ],
            },
            "accounting_interval": {"start": stamp(now - timedelta(days=1)), "end_exclusive": stamp(now)},
            "views": ["task_lifetime", "period_spend"],
            "group_by": ["task"],
            "money_bases": ["confirmed_billed", "tariff_estimate"],
            "fx_refs": [],
            "cache_pair_refs": [],
            "snapshot_ref": None,
        }

    def test_real_protected_partial_report_has_measured_elapsed_and_unknown_money_acceptance(self):
        from getzilla.economics_reader import local_report_reader, is_protected_report

        with project_copy(git=True, minimal_runtime=True) as root:
            route = self.fixture.setup_native(root)
            task_budget.execute_local(root, "economic-reader-one", [sys.executable, "--version"], timeout=1)
            query = self.query(root, route)
            with local_report_reader(root) as handle:
                result = route_metrics.read_report(query, handle=handle)
                self.assertTrue(is_protected_report(result, handle=handle))
                value = result.as_dict()
                repeated = route_metrics.read_report(query, handle=handle)
                self.assertEqual(result.canonical, repeated.canonical)
                self.assertFalse(is_protected_report(result, handle=handle, purpose="review-experiment"))
            report = value["report"]
            self.assertEqual(report["status"], "partial")
            self.assertIsNone(report["ratios"]["accepted_tasks"])
            usage = next(r for r in report["tasks"][0]["usage"] if r["category"] == "elapsed")
            self.assertGreaterEqual(int(usage["known_subtotal"]["numerator"]), 0)
            self.assertTrue(usage["source_refs"])
            self.assertTrue(all(r["value"] is None for r in report["totals"]["task_lifetime"]))
            self.assertFalse(value["private_egress_authorized"])
            self.assertNotIn("Fix a README typo", json.dumps(value))
            self.assertNotIn("--version", json.dumps(value))
            self.assertFalse(is_protected_report(result, handle=handle))
            self.assertEqual(route_metrics.read_report(query, handle=handle).as_dict()["status"], "unavailable")

    def test_same_native_duplicate_does_not_double_charge_or_count_usage(self):
        from getzilla.economics_reader import local_report_reader

        with project_copy(git=True, minimal_runtime=True) as root:
            route = self.fixture.setup_native(root)
            task_budget.execute_local(root, "economic-duplicate", [sys.executable, "--version"], timeout=1)
            query = self.query(root, route)

            def report():
                with local_report_reader(root) as handle:
                    return route_metrics.read_report(query, handle=handle).as_dict()["report"]

            first = report()
            economic = next(r for r in load_local(root)["events"] if r.get("kind") == "economics_observation")
            with (root / ".getzilla/runtime/metrics.jsonl").open("a") as output:
                output.write(json.dumps(economic) + "\n")
            second = report()
            self.assertEqual(first["tasks"][0]["usage"], second["tasks"][0]["usage"])
            self.assertEqual(first["totals"], second["totals"])

    def test_stale_journal_or_policy_before_final_admission_does_not_return_qualified_data(self):
        from getzilla.economics_reader import local_report_reader, is_protected_report

        with project_copy(git=True, minimal_runtime=True) as root:
            route = self.fixture.setup_native(root)
            query = self.query(root, route)
            original = route_metrics.compute_economics

            def changed(*args, **kwargs):
                result = original(*args, **kwargs)
                with (root / ".getzilla/runtime/metrics.jsonl").open("a") as output:
                    output.write("{}\n")
                return result

            with (
                local_report_reader(root) as handle,
                mock.patch.object(route_metrics, "compute_economics", side_effect=changed),
            ):
                result = route_metrics.read_report(query, handle=handle)
                self.assertFalse(is_protected_report(result, handle=handle))
                self.assertEqual(result.as_dict()["status"], "unavailable")

    def test_foreign_scope_session_truncated_input_and_dto_are_not_authority(self):
        from getzilla.economics_reader import local_report_reader, is_protected_report

        with project_copy(git=True, minimal_runtime=True) as root:
            route = self.fixture.setup_native(root)
            query = self.query(root, route)
            foreign = copy.deepcopy(query)
            foreign["scope_ids"] = ["f" * 64]
            with local_report_reader(root) as handle:
                result = route_metrics.read_report(foreign, handle=handle)
                self.assertFalse(is_protected_report(result, handle=handle))
            state.bind_session("foreign-session")
            with self.assertRaises(ValueError):
                with local_report_reader(root):
                    pass
            state.bind_session(trace_fixtures.SESSION)
            with (root / ".getzilla/runtime/metrics.jsonl").open("a") as output:
                output.write('{"private":"not a full line"}')
            with local_report_reader(root) as handle:
                result = route_metrics.read_report(query, handle=handle)
                self.assertFalse(is_protected_report(result, handle=handle))
                self.assertEqual(result.as_dict()["status"], "unavailable")
            self.assertEqual(
                route_metrics.read_report(query, handle={"uid": os.getuid(), "purpose": "economics"}).as_dict()[
                    "status"
                ],
                "unavailable",
            )

    def test_actual_report_cli_typed_read_and_write_attempt_never_imports(self):
        import subprocess

        with project_copy(git=True, minimal_runtime=True) as root:
            route = self.fixture.setup_native(root)
            task_budget.execute_local(root, "economic-cli", [sys.executable, "--version"], timeout=1)
            request = json.dumps(self.query(root, route))
            command = [
                sys.executable,
                "-B",
                str(ROOT / "scripts/getzilla_report.py"),
                "--economics-query-stdin",
                "--json",
            ]
            environment = {**os.environ, "GETZILLA_SESSION_ID": trace_fixtures.SESSION}
            result = subprocess.run(
                command, input=request, capture_output=True, text=True, cwd=root, env=environment, timeout=10
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            value = json.loads(result.stdout)
            self.assertEqual(value["qualification"], "native_local_protected_read")
            self.assertEqual(value["report"]["status"], "partial")
            text_result = subprocess.run(
                command[:-1], input=request, capture_output=True, text=True, cwd=root, env=environment, timeout=10
            )
            self.assertEqual(text_result.returncode, 0, text_result.stdout + text_result.stderr)
            self.assertIn("Source coverage gaps:", text_result.stdout)
            self.assertIn("history_gap", text_result.stdout)
            before = (root / ".getzilla/runtime/metrics.jsonl").read_bytes()
            rejected = subprocess.run(
                command + ["--import-observations", "never-import.json"],
                input=request,
                capture_output=True,
                text=True,
                cwd=root,
                env=environment,
                timeout=10,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertEqual(before, (root / ".getzilla/runtime/metrics.jsonl").read_bytes())

    def test_review_experiment_consumes_only_live_canonical_protected_results(self):
        from getzilla.economics_reader import local_report_reader
        from getzilla.review_experiment import assess_experiment
        from tests.test_review_experiment import protocol

        with project_copy(git=True, minimal_runtime=True) as root:
            route = self.fixture.setup_native(root)
            task_budget.execute_local(root, "economic-review", [sys.executable, "--version"], timeout=1)
            query = self.query(root, route)
            p = protocol()
            rows = {
                "c0": {
                    "actor": "reviewer",
                    "decision": "accepted",
                    "candidate": "head",
                    "requirements": "v1",
                    "checks": True,
                    "at": 300,
                    "defects": 0,
                }
            }
            with local_report_reader(root, purpose="review-experiment") as handle:
                result = assess_experiment(
                    p,
                    rows,
                    as_of=600,
                    economics_queries={"control": query, "experiment": query},
                    economics_handle=handle,
                )
                self.assertEqual(result["economics_qualified_sides"], ["control", "experiment"])
                self.assertNotIn("economics_unavailable", result["gaps"])
                self.assertIn("economics_incomplete", result["gaps"])
                self.assertIn("independent_human_acceptance_unbound", result["gaps"])
                self.assertIsNone(result["cost_per_accepted"])
                self.assertEqual(result["decision"], "indeterminate")

    def test_canonical_conflict_is_not_counted_and_concurrent_census_change_refuses(self):
        from getzilla.economics_reader import local_report_reader, is_protected_report

        with project_copy(git=True, minimal_runtime=True) as root:
            route = self.fixture.setup_native(root)
            task_budget.execute_local(root, "economic-conflict", [sys.executable, "--version"], timeout=1)
            query = self.query(root, route)
            economic = next(r for r in load_local(root)["events"] if r.get("kind") == "economics_observation")
            changed = copy.deepcopy(economic)
            changed["payload"]["elapsed"]["value"] += 1
            with (root / ".getzilla/runtime/metrics.jsonl").open("a") as output:
                output.write(json.dumps(changed) + "\n")
            with local_report_reader(root) as handle:
                result = route_metrics.read_report(query, handle=handle)
                self.assertTrue(is_protected_report(result, handle=handle))
                value = result.as_dict()
                self.assertIn("conflicted", value["source_coverage"]["gaps"])
                self.assertFalse(value["report"]["coverage"]["complete"])
                self.assertFalse(value["report"]["tasks"][0]["usage"])
            original = route_metrics.compute_economics

            def add_route(*args, **kwargs):
                result = original(*args, **kwargs)
                target = root / ".getzilla/runtime/routes" / ("f" * 12 + ".json")
                target.write_text("{}")
                target.chmod(0o600)
                return result

            with (
                local_report_reader(root) as handle,
                mock.patch.object(route_metrics, "compute_economics", side_effect=add_route),
            ):
                result = route_metrics.read_report(query, handle=handle)
                self.assertFalse(is_protected_report(result, handle=handle))
                self.assertEqual(result.as_dict()["status"], "unavailable")

    def test_typed_read_keeps_existing_journal_routes_registry_and_lock_namespace_unchanged(self):
        from getzilla.economics_reader import local_report_reader, is_protected_report

        with project_copy(git=True, minimal_runtime=True) as root:
            route = self.fixture.setup_native(root)
            task_budget.execute_local(root, "economic-readonly", [sys.executable, "--version"], timeout=1)
            query = self.query(root, route)

            def snapshot():
                return {
                    str(p.relative_to(root)): p.read_bytes()
                    for p in (root / ".getzilla/runtime").rglob("*")
                    if p.is_file()
                }

            before = snapshot()
            with local_report_reader(root) as handle:
                result = route_metrics.read_report(query, handle=handle)
                self.assertTrue(is_protected_report(result, handle=handle))
            self.assertEqual(before, snapshot())

    def test_existing_journal_byte_bound_is_not_replaced_by_generic_metadata_limit(self):
        from getzilla.economics_reader import local_report_reader, is_protected_report
        from getzilla.metrics_journal import digest, validate

        with project_copy(git=True, minimal_runtime=True) as root:
            route = self.fixture.setup_native(root)
            task_budget.execute_local(root, "economic-large-journal", [sys.executable, "--version"], timeout=1)
            query = self.query(root, route)
            raw = (root / ".getzilla/runtime/metrics.jsonl").read_bytes()
            rows = []
            for index in range(1200):
                row = {
                    "schema_version": 2,
                    "event": "cost",
                    "event_id": digest({"storage_only": index}),
                    "at": "2026-01-01T00:00:00Z",
                    "route_id": None,
                    "session_id": None,
                    "head": None,
                    "base": None,
                    "tree": None,
                    "amount": None,
                    "currency": None,
                    "source": "x" * 256,
                    "scope": "x" * 256,
                    "kind": "x" * 256,
                }
                validate(row)
                rows.append((json.dumps(row) + "\n").encode())
            (root / ".getzilla/runtime/metrics.jsonl").write_bytes(raw + b"".join(rows))
            self.assertGreater((root / ".getzilla/runtime/metrics.jsonl").stat().st_size, 1048576)
            with local_report_reader(root) as handle:
                result = route_metrics.read_report(query, handle=handle)
                if is_protected_report(result, handle=handle):
                    self.assertEqual(result.as_dict()["report"]["status"], "partial")
                else:
                    self.assertEqual(result.as_dict()["reason"], "input_limit")

    def test_live_reader_refuses_named_root_replacement(self):
        from getzilla.economics_reader import local_report_reader, is_protected_report

        with project_copy(git=True, minimal_runtime=True) as root:
            route = self.fixture.setup_native(root)
            query = self.query(root, route)
            moved = root.with_name("displaced-economics-root")
            with local_report_reader(root) as handle:
                root.rename(moved)
                root.mkdir(mode=0o700)
                try:
                    result = route_metrics.read_report(query, handle=handle)
                    self.assertFalse(is_protected_report(result, handle=handle))
                    self.assertEqual(result.as_dict()["status"], "unavailable")
                finally:
                    root.rmdir()
                    moved.rename(root)
