"""NEW guarded producer fixtures. No real checker/scanner, acquisition or signing."""

import importlib.util
import os
import tempfile
import contextlib
import sys
from pathlib import Path
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from datetime import datetime, timezone, timedelta

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from adaptive_trust_ci.public_admission import Authority, Selector
from adaptive_trust_ci import security_bundle as bundle
from adaptive_trust_ci import public_runtime as runtime
from adaptive_trust_ci import public_process as process
from adaptive_trust_ci.public_publisher import PublisherConfig, Publication
import json

if importlib.util.find_spec("adaptive_trust_ci.public_producer"):
    from adaptive_trust_ci import public_producer as producer
else:
    producer = None
_installer_spec = importlib.util.spec_from_file_location(
    "owned_new_checker_installer", Path(__file__).resolve().parents[1] / "scripts/install_public_checker.py"
)
installer = importlib.util.module_from_spec(_installer_spec)
_installer_spec.loader.exec_module(installer)
ACTIVE = False
OWNED = None


def deny(event, args):
    if not ACTIVE:
        return
    if event.startswith(("socket.", "subprocess.", "ctypes.")) or event in ("os.system", "os.posix_spawn", "os.fork"):
        raise AssertionError("new fixture denies native/network")
    if event == "open" or event.startswith(("os.", "shutil.")):
        paths = args[:2] if event in ("os.rename", "os.replace") else args[:1]
        if (
            OWNED is None
            or not paths
            or any(
                not isinstance(value, (str, bytes, os.PathLike))
                or not Path(os.fsdecode(value)).absolute().is_relative_to(OWNED)
                for value in paths
            )
        ):
            raise AssertionError("new fixture denies outside I/O")


sys.addaudithook(deny)


class ProducerControls(unittest.TestCase):
    def setUp(self):
        self.cleanup_latch = producer.check_cleanup_latch if producer is not None else None
        if producer is not None:
            latch = patch.object(producer, 'check_cleanup_latch', return_value=None)
            latch.start()
            self.addCleanup(latch.stop)
        self.now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.selector = Selector("owned/fixture", 7, 5, "a" * 40, "b" * 40, "c" * 40, 31, 2)
        self.authority = Authority(
            "owned/fixture",
            7,
            "owned/runner",
            8,
            "d" * 40,
            "e" * 40,
            9,
            ".github/workflows/public.yml",
            "f" * 40,
            "1" * 40,
            "2" * 40,
            81,
            "workflow_dispatch",
            "main",
            b"owned-public-fixture",
            "3" * 64,
            required_jobs=("check",),
        )
        self.report = {
            "schema_version": 1,
            "kind": "security-expanded",
            "status": "pass",
            "source": {
                "head_sha": "b" * 40,
                "tree_sha": "c" * 40,
                "checker_sha": "f" * 40,
                "checker_tree_sha": "1" * 40,
                "candidate_clean": True,
                "checker_clean": True,
                "same_project": True,
            },
            "created_at_utc": self.now.isoformat(),
            "valid_until_utc": (self.now + timedelta(seconds=60)).isoformat(),
            "inventory_sha256": "4" * 64,
            "policy_sha256": "3" * 64,
            "qualification_gaps": [],
            "checks": [
                {
                    "name": "security-inventory",
                    "status": "pass",
                    "details": [
                        {"kind": "security-result", "outcome": "pass", "findings": [], "gaps": [], "data_sources": []}
                    ],
                }
            ],
        }
        self.integration = {
            "merge_sha": "5" * 40,
            "tree_sha": "6" * 40,
            "parents": ["a" * 40, "b" * 40],
            "strategy": "merge",
        }

    def guarded(self, callback):
        global ACTIVE
        ACTIVE = True
        try:
            return callback()
        finally:
            ACTIVE = False

    def require(self):
        self.assertIsNotNone(producer, "missing shipped producer")

    def call(self, sign):
        record = producer._signing_plan(
            self.selector,
            self.authority,
            self.report,
            self.integration,
            candidate_root=Path("/UNREAD/candidate"),
            snapshot_root=Path("/UNREAD/snapshots"),
            core=object(),
            client=object(),
            now=self.now,
        )
        return producer._finish_signature(record, self.authority, sign=sign, now=self.now)

    def facts(self):
        return SimpleNamespace(
            source_validated=True,
            blockers=(),
            checker_source=("f" * 40, "1" * 40),
            required=(bundle.Requirement("security-inventory", True, (), "4" * 64),),
            sources=(),
            inventory_digest="4" * 64,
            integration_validated=True,
            valid_until=(self.now + timedelta(seconds=60)).isoformat(),
        )

    def observed(self):
        return SimpleNamespace(
            validated=True,
            blockers=(),
            source_digest=bundle.digest(self.selector.source().as_dict()),
            authority_digest=self.authority.as_policy().authority_digest,
            jobs=("check",),
        )

    def test_failed_checker_never_reaches_signer(self):
        self.require()
        self.report["status"] = "fail"
        calls = []
        with self.assertRaises(ValueError):
            self.guarded(lambda: self.call(lambda payload: calls.append(payload)))
        self.assertEqual(calls, [])

    def test_missing_canonical_facts_never_reaches_signer(self):
        self.require()
        calls = []
        with (
            patch.object(producer, "observe", return_value=self.observed()),
            patch.object(
                producer,
                "validate_local_inputs",
                return_value=SimpleNamespace(source_validated=False, blockers=("missing",)),
            ),
        ):
            with self.assertRaises(ValueError):
                self.guarded(lambda: self.call(lambda payload: calls.append(payload)))
        self.assertEqual(calls, [])

    def test_changed_provider_identity_never_reaches_signer(self):
        self.require()
        calls = []
        bad = SimpleNamespace(validated=False, blockers=("changed",))
        with (
            patch.object(producer, "observe", return_value=bad),
            patch.object(producer, "validate_local_inputs", return_value=self.facts()),
        ):
            with self.assertRaises(ValueError):
                self.guarded(lambda: self.call(lambda payload: calls.append(payload)))
        self.assertEqual(calls, [])

    def test_current_complete_result_reaches_machine_binding_only(self):
        self.require()
        calls = []
        with (
            patch.object(producer, "observe", return_value=self.observed()),
            patch.object(producer, "validate_local_inputs", return_value=self.facts()),
            patch.object(producer, "binding_valid", return_value=True),
        ):
            result = self.guarded(
                lambda: self.call(lambda payload: calls.append(payload) or "OWNED-NOT-A-REAL-SIGNATURE")
            )
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["selector"], self.selector.__dict__)
        self.assertEqual(calls[0]["kind"], "getzilla-security-bundle-binding")
        self.assertEqual(calls[0]["source_sha256"], bundle.digest(self.selector.source().as_dict()))
        self.assertEqual(result["evidence"]["binding"]["signature"], "OWNED-NOT-A-REAL-SIGNATURE")

    def test_wrong_checker_source_never_reaches_signer(self):
        self.require()
        self.report["source"]["checker_sha"] = "0" * 40
        calls = []
        with self.assertRaises(ValueError):
            self.guarded(lambda: self.call(lambda payload: calls.append(payload)))
        self.assertEqual(calls, [])

    def test_selector_comes_from_current_provider_not_payload(self):
        self.require()
        calls = []

        def get(path):
            calls.append(path)
            if "/pulls/" in path:
                return {
                    "number": 5,
                    "state": "open",
                    "head": {"sha": "b" * 40, "ref": "feature", "repo": {"id": 7}},
                    "base": {"sha": "a" * 40, "ref": "main", "repo": {"id": 7}},
                }
            if "/git/commits/" in path:
                return {"sha": "b" * 40, "tree": {"sha": "c" * 40}}
            return {
                "total_count": 1,
                "workflow_runs": [
                    {
                        "id": 31,
                        "run_attempt": 2,
                        "workflow_id": 9,
                        "head_sha": "d" * 40,
                        "head_branch": "main",
                        "event": "workflow_dispatch",
                        "status": "completed",
                        "conclusion": "success",
                    }
                ],
            }

        client = SimpleNamespace(_request=lambda method, path: get(path))
        result = self.guarded(lambda: producer.select_current(client, self.authority, 5))
        self.assertEqual(result, self.selector)
        self.assertEqual(len(calls), 3)

    def test_installed_checker_pin_refuses_before_import(self):
        self.require()
        calls = []
        with (
            patch.object(producer, "checker_identity", return_value=("0" * 40, "1" * 40)),
            patch.object(producer, "import_core", side_effect=lambda root: calls.append(root)),
        ):
            with self.assertRaises(ValueError):
                self.guarded(lambda: producer.load_checker(self.authority))
        self.assertEqual(calls, [])

    def test_worker_consumes_refreshed_record_and_keeps_unknown_without_refresh(self):
        self.require()
        calls = []
        config = SimpleNamespace(
            publisher=PublisherConfig("owned/fixture", 7, 81, 91, "3" * 64),
            authority=self.authority,
            input_root=Path("/OWNED"),
            producer_key_path=Path("/UNREAD-public"),
            app_key_path=Path("/UNREAD-app"),
            producer={"snapshot_root": "/UNREAD-snapshots"},
        )
        root = Path("/OWNED/public-ownedfixture")
        record = {"selector": self.selector.__dict__, "evidence": {"binding": {}, "report": {}}}
        worker = runtime.PublicWorker(
            config, SimpleNamespace(require_refresh_safe=lambda current: None), journal=object(), clock=lambda: 1.0
        )
        with (
            patch.object(
                runtime, "refresh_for_pr", side_effect=lambda *args, **kwargs: calls.append("refresh") or producer.PreparedRecord(root, object())
            ),
            patch.object(
                runtime,
                "read_file",
                side_effect=lambda path, maximum: (
                    json.dumps(record).encode() if path.name == "record.json" else b"owned-public"
                ),
            ),
            patch.object(runtime, "load_checker", return_value=object()),
            patch.object(runtime, "issue_scoped_token", return_value="owned-token"),
            patch.object(runtime, "BoundPublicVerifier", return_value=SimpleNamespace(owned=True)),
            patch.object(runtime, "publish", return_value=Publication("unknown", "owned-unconfirmed")),
        ):
            first = self.guarded(lambda: worker.publish_for_pr(5))
            parts = worker._pending_parts
            second = self.guarded(lambda: worker.publish_for_pr(5))
        self.assertEqual(calls, ["refresh"])
        self.assertIs(worker._pending_parts, parts)
        self.assertEqual(first.state, "unknown")
        self.assertEqual(second.state, "unknown")

    def test_refresh_launches_fixed_producer_and_rejects_foreign_result(self):
        self.require()
        config = SimpleNamespace(
            producer={"configured": True, "cgroup_root": "/UNREAD-cgroup"},
            config_path=Path("/UNREAD-config"),
            input_root=Path("/OWNED"),
        )
        with (
            patch.object(
                producer,
                "ProducerEnvelope",
                side_effect=lambda *a, **k: contextlib.nullcontext(SimpleNamespace(empty_confirmed=True)),
            ),
            patch.object(
                producer, "_run_owned", return_value=b'{"root":"/OWNED/public-12345678","ready":false,"facts":{}}'
            ) as owned,
            patch.object(producer.public_preparation, "from_owned", return_value="owned-mocked-capability"),
        ):
            root = self.guarded(lambda: producer.refresh_for_pr(config, 5, clock=lambda: 1.0))
        self.assertEqual(root.root, Path("/OWNED/public-12345678"))
        self.assertEqual(root.measurement, "owned-mocked-capability")
        self.assertEqual(owned.call_args.args[0][-1], "--produce")
        self.assertEqual(json.loads(owned.call_args.args[1])["pr"], 5)
        with (
            patch.object(
                producer,
                "ProducerEnvelope",
                side_effect=lambda *a, **k: contextlib.nullcontext(SimpleNamespace(empty_confirmed=True)),
            ),
            patch.object(producer, "_run_owned", return_value=b'{"root":"/FOREIGN/public-12345678","ready":false,"facts":{}}'),
        ):
            with self.assertRaises(ValueError):
                self.guarded(lambda: producer.refresh_for_pr(config, 5, clock=lambda: 1.0))

    def test_expired_report_never_reaches_signer(self):
        self.require()
        calls = []
        self.report["valid_until_utc"] = (self.now - timedelta(seconds=1)).isoformat()
        with (
            patch.object(producer, "observe", return_value=self.observed()),
            patch.object(producer, "validate_local_inputs", return_value=self.facts()),
        ):
            with self.assertRaises(ValueError):
                self.guarded(lambda: self.call(lambda payload: calls.append(payload)))
        self.assertEqual(calls, [])

    def test_restart_unresolved_fence_prevents_any_refresh(self):
        self.require()
        calls = []

        def refuse(current):
            raise ValueError("prior-public-operation-unresolved")

        config = SimpleNamespace(publisher=PublisherConfig("owned/fixture", 7, 81, 91, "3" * 64))
        worker = runtime.PublicWorker(config, SimpleNamespace(require_refresh_safe=refuse))

        def attempt():
            try:
                worker.publish_for_pr(5)
            except Exception as error:
                return type(error).__name__
            return "accepted"

        with patch.object(runtime, "refresh_for_pr", side_effect=lambda *a, **k: calls.append("refresh")):
            result = self.guarded(attempt)
        self.assertEqual(calls, [])
        self.assertEqual(result, "ValueError")

    def test_runner_completion_uses_durable_blocked_targets_not_body_evidence(self):
        self.require()
        import hmac
        import hashlib

        calls = []
        config = SimpleNamespace(
            publisher=PublisherConfig("owned/fixture", 7, 81, 91, "3" * 64), authority=self.authority
        )
        queue = SimpleNamespace(
            blocked_targets=lambda: (5,), enqueue=lambda delivery, targets: calls.append(targets) or ["owned-job"]
        )
        ingress = runtime.PublicIngress(config, queue, b"owned-fixture-not-a-real-key-" * 2)
        raw = json.dumps(
            {
                "repository": {"full_name": "owned/runner", "id": 8},
                "workflow_run": {"pull_requests": []},
                "report": {"pass": True},
            }
        ).encode()
        signature = "sha256=" + hmac.new(ingress.secret, raw, hashlib.sha256).hexdigest()

        def attempt():
            try:
                return ingress.accept(raw, signature, "workflow_run", "owned-completed")
            except Exception as error:
                return {"exception": type(error).__name__}

        result = self.guarded(attempt)
        self.assertEqual(result.get("job_ids"), ["owned-job"])
        self.assertEqual(calls, [(5,)])

    def test_required_skip_cannot_reach_machine_signer(self):
        self.require()
        calls = []
        self.report["checks"][0]["status"] = "skip"
        self.report["checks"][0]["details"][0]["outcome"] = "not_applicable"
        with (
            patch.object(producer, "observe", return_value=self.observed()),
            patch.object(producer, "validate_local_inputs", return_value=self.facts()),
            patch.object(producer, "binding_valid", return_value=True),
        ):
            try:
                self.guarded(lambda: self.call(lambda payload: calls.append(payload) or "OWNED-NOT-A-SIGNATURE"))
            except ValueError:
                pass
        self.assertEqual(calls, [])

    def test_cached_execution_uses_canonical_revalidation_without_resigning(self):
        self.require()
        record = {
            "selector": self.selector.__dict__,
            "evidence": {"binding": {"original": True}, "report": {"original_time": "unchanged"}},
        }
        with patch.object(producer, "evaluate", return_value=SimpleNamespace(eligible=True)) as canonical:
            result = self.guarded(
                lambda: producer.reuse_record(
                    record,
                    self.selector,
                    self.authority,
                    root=Path("/UNREAD"),
                    snapshot=Path("/UNREAD-snapshots"),
                    client=object(),
                    now=self.now,
                )
            )
        self.assertIs(result, record)
        self.assertEqual(result["evidence"]["report"]["original_time"], "unchanged")
        self.assertEqual(canonical.call_count, 1)
        with patch.object(producer, "evaluate", return_value=SimpleNamespace(eligible=False)):
            with self.assertRaises(ValueError):
                self.guarded(
                    lambda: producer.reuse_record(
                        record,
                        self.selector,
                        self.authority,
                        root=Path("/UNREAD"),
                        snapshot=Path("/UNREAD-snapshots"),
                        client=object(),
                        now=self.now,
                    )
                )

    def test_machine_signer_refuses_other_role_before_private_key_read(self):
        self.require()
        with patch.object(producer, "_read_app_key", side_effect=AssertionError("private seam must stay closed")):
            with self.assertRaises(ValueError):
                self.guarded(lambda: producer.machine_sign(Path("/UNREAD"), b"owned", {"kind": "human-owner-decision"}))

    def test_closed_step_log_rotates_inside_owned_fixture(self):
        if sys.platform != "linux" or not hasattr(os, "O_NOFOLLOW"):
            with self.assertRaises(ValueError):
                self.guarded(lambda: producer.retain_step(Path("/UNREAD-unsupported"), "checker", "complete"))
            return
        self.require()
        self.assertTrue(callable(getattr(producer, "retain_step", None)), "missing bounded step retention")
        global OWNED
        base = Path(
            os.environ.get(
                "GETZILLA_PUBLIC_FIXTURE_BASE",
                str(Path(__file__).resolve().parents[2] / ".getzilla/runtime/test-fixtures"),
            )
        )
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="producer-owned-", dir=base) as directory:
            OWNED = Path(directory)
            try:
                for _ in range(100):
                    self.guarded(lambda: producer.retain_step(OWNED, "checker", "complete"))
                self.assertLessEqual((OWNED / "producer.log").stat().st_size, 2048)
                self.assertLessEqual((OWNED / "producer.previous.log").stat().st_size, 2048)
                for row in (OWNED / "producer.log").read_text().splitlines():
                    self.assertEqual(json.loads(row), {"step": "checker", "state": "complete"})
                with self.assertRaises(ValueError):
                    self.guarded(lambda: producer.retain_step(OWNED, "private-value", "complete"))
            finally:
                OWNED = None

    def test_measured_target_source_capacity_and_exact_boundaries(self):
        self.require()
        function = getattr(bundle, "source_size_ok", None)
        self.assertTrue(callable(function), "missing explicit source capacity profile")
        with_values = ((64781565, 6810, True), (67108864, 8192, True), (67108865, 8192, False), (67108864, 8193, False))
        for size, count, expected in with_values:
            with self.subTest(size=size, count=count):
                self.assertIs(self.guarded(lambda: function(size, count)), expected)
        self.assertEqual(bundle.SNAPSHOT_BYTES, 33554432)
        self.assertEqual(bundle.BUNDLE_BYTES, 2097152)

    def test_preparation_entry_transfers_only_actual_read_only_workflow_context(self):
        self.require()
        environment = {
            "GITHUB_TOKEN": "owned-fixture-token",
            "GITHUB_SHA": "d" * 40,
            "GITHUB_RUN_ID": "31",
            "GITHUB_RUN_ATTEMPT": "2",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
        }
        with (
            patch.object(
                producer, "workflow_config", return_value=SimpleNamespace(producer={"cgroup_root": "/UNREAD-cgroup"})
            ),
            patch.object(
                producer,
                "ProducerEnvelope",
                side_effect=lambda *a, **k: contextlib.nullcontext(SimpleNamespace(empty_confirmed=True)),
            ),
            patch.object(producer, "_run_owned", return_value=b"prepared") as owned,
        ):
            self.guarded(
                lambda: producer.prepare_workflow(Path("/UNREAD-config"), 5, environ=environment, clock=lambda: 1.0)
            )
        self.assertEqual(owned.call_args.args[0][-1], "--prepare")
        request = json.loads(owned.call_args.args[1])
        self.assertEqual(request["run"], [31, 2, "d" * 40])
        self.assertNotIn("machine_key", request)
        self.assertNotIn("app_key", request)

    def owned_cgroup(self, callback):
        if sys.platform != "linux" or not hasattr(os, "O_NOFOLLOW"):
            with self.assertRaises(ValueError):
                self.guarded(lambda: process.ProducerEnvelope(Path("/UNREAD-unsupported"), 3.0, clock=lambda: 1.0))
            return
        global OWNED
        base = Path(
            os.environ.get(
                "GETZILLA_PUBLIC_FIXTURE_BASE",
                str(Path(__file__).resolve().parents[2] / ".getzilla/runtime/test-fixtures"),
            )
        )
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="cgroup-shaped-owned-", dir=base) as directory:
            OWNED = Path(directory)
            for name, value in (
                ("cgroup.type", "domain"),
                ("cgroup.controllers", "pids"),
                ("cgroup.subtree_control", "pids"),
            ):
                (OWNED / name).write_text(value)

            def create(path):
                path.mkdir(mode=0o700)
                for name, value in (
                    ("cgroup.procs", ""),
                    ("cgroup.events", "populated 0\n"),
                    ("cgroup.kill", ""),
                    ("pids.max", ""),
                ):
                    (path / name).write_text(value)

            def remove(path):
                for entry in path.iterdir():
                    entry.unlink()
                path.rmdir()

            try:
                with (
                    patch.object(process, "_cgroup2", return_value=True),
                    patch.object(process, "_create_leaf", side_effect=create),
                    patch.object(process, "_remove_leaf", side_effect=remove),
                ):
                    self.guarded(lambda: callback(OWNED))
            finally:
                OWNED = None

    def test_owned_cgroup_shaped_lifecycle_closes_fds_and_requires_empty_group(self):
        def ordinary(root):
            envelope = process.ProducerEnvelope(root, 3.0, clock=lambda: 1.0)
            envelope.attach(SimpleNamespace(pid=123))
            self.assertEqual((envelope.path / "cgroup.procs").read_bytes(), b"123")
            (envelope.path / "cgroup.procs").write_bytes(b"")
            envelope.close()
            self.assertTrue(envelope.empty_confirmed)
            self.assertEqual(envelope.descriptors, {})
            self.assertFalse(envelope.path.exists())

        self.owned_cgroup(ordinary)

    def test_populated_group_cannot_be_declared_clean(self):
        def ordinary(root):
            time = [1.0]
            envelope = process.ProducerEnvelope(root, 3.0, clock=lambda: time[0])
            (envelope.path / "cgroup.events").write_text("populated 1\n")
            time[0] = 4.0
            with self.assertRaises(ValueError):
                envelope.close()
            self.assertFalse(envelope.empty_confirmed)
            self.assertEqual(envelope.descriptors, {})

        self.owned_cgroup(ordinary)

    def test_no_cleanup_confirmation_prevents_parent_signature_phase(self):
        self.require()
        config = SimpleNamespace(
            producer={"cgroup_root": "/UNREAD-cgroup"}, config_path=Path("/UNREAD-config"), input_root=Path("/OWNED")
        )
        with (
            patch.object(
                producer,
                "ProducerEnvelope",
                side_effect=lambda *a, **k: contextlib.nullcontext(SimpleNamespace(empty_confirmed=False)),
            ),
            patch.object(producer, "_run_owned", return_value=b'{"root":"/OWNED/public-12345678","ready":true}'),
            patch.object(producer, "_finish_signature", side_effect=AssertionError("no signature before group empty")),
        ):
            with self.assertRaises(ValueError):
                self.guarded(lambda: producer.refresh_for_pr(config, 5, clock=lambda: 1.0))

    def test_checker_build_pins_and_lock_are_explicit_data_only(self):
        with self.assertRaises(ValueError):
            self.guarded(lambda: installer.selection("owned/fixture", "", "a" * 40))
        self.assertIsNone(self.guarded(lambda: installer.selection("", "", "")))
        lock = (
            "bandit==1.9.4 --hash=sha256:" + "a" * 64 + "\n" + "PyYAML==6.0.3 --hash=sha256:" + "b" * 64 + "\n"
        ).encode()
        result = self.guarded(lambda: installer.checker_requirements(lock, "1.9.4"))
        self.assertEqual(result, {"bandit": "1.9.4", "pyyaml": "6.0.3"})
        for bad in (
            b"bandit @ https://invalid.example/wheel",
            b"-r outside.txt",
            b"bandit==1.9.4",
            lock.replace(b"1.9.4", b"1.9.3"),
        ):
            with self.subTest(kind="closed-invalid-lock"), self.assertRaises(ValueError):
                self.guarded(lambda: installer.checker_requirements(bad, "1.9.4"))

    def test_regular_filesystem_cannot_claim_kernel_cgroup_qualification(self):
        def ordinary(root):
            with (
                patch.object(process, "_cgroup2", return_value=False),
                patch.object(process, "_create_leaf", side_effect=AssertionError("no leaf on wrong filesystem")),
            ):
                with self.assertRaises(ValueError):
                    process.ProducerEnvelope(root, 3.0, clock=lambda: 1.0)

        self.owned_cgroup(ordinary)

    def test_cleanup_uncertainty_becomes_durable_unknown(self):
        events = []
        queue = SimpleNamespace(
            claim=lambda: ("a" * 64, 5), finish=lambda key, state, reason: events.append((state, reason))
        )

        def uncertain(pr):
            raise process.ProducerCleanupUnknown("owned-cleanup-unconfirmed")

        worker = runtime.PublicWorker(SimpleNamespace(), queue, operation=uncertain)
        result = self.guarded(worker.run_once)
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(events, [("unknown", "producer-cleanup-unconfirmed")])


if __name__ == "__main__":
    unittest.main()
