"""Owned integer/ordinary-file controls. Processes, network and real producers denied."""

from contextlib import ExitStack, redirect_stdout
import ast
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".getzilla"))
from getzilla import security_image_authority as image_authority
from getzilla import security_oci as oci, security_image_backend as native
from getzilla import security_image_producer as producer, security_cli as cli


def closed_detail():
    return dict(
        dimension="entries",
        oci_phase="tar-entries",
        limit_name="max_tar_entries",
        before=100000,
        charge=1,
        attempted=100001,
        limit=100000,
        profile_compressed=536870912,
        profile_unpacked=536870912,
        profile_storage=536870912,
        image_ordinal=0,
    )


def owned_error():
    error = oci.OCIError("Aggregate OCI resource bound exceeded")
    error.detail = closed_detail()
    return error


class BudgetFaultControls(unittest.TestCase):
    def setUp(self):
        effects = ExitStack()
        self.addCleanup(effects.close)
        for port in ("socket.socket", "socket.getaddrinfo", "subprocess.Popen", "subprocess.run"):
            effects.enter_context(mock.patch(port, side_effect=AssertionError("outside effects denied")))

    def test_actual_dimensions_keep_exact_ceiling_and_failed_charge_totals(self):
        profile = dict(
            oci.LIMITS,
            max_compressed_bytes=7,
            max_unpacked_bytes=7,
            max_storage_bytes=7,
            max_layers=2,
            images=[],
            platform="linux/amd64",
        )
        for dimension, ceiling in [
            ("compressed", 7),
            ("unpacked", 7),
            ("storage", 7),
            ("expanded", 7),
            ("layers", 2),
            ("entries", 100000),
        ]:
            with self.subTest(dimension=dimension):
                ledger = oci._Budget(profile)
                phase = {
                    "compressed": "blob-compressed",
                    "unpacked": "layer-decoded",
                    "storage": "blob-storage",
                    "expanded": "tar-expanded",
                    "layers": "layer-count",
                    "entries": "tar-entries",
                }[dimension]
                ledger.image_ordinal = 2
                ledger.charge(dimension, ceiling, phase=phase)
                self.assertEqual(ledger.totals[dimension], ceiling)
                with self.assertRaises(oci.OCIError) as caught:
                    ledger.charge(dimension, 1, phase=phase)
                detail = getattr(caught.exception, "detail", {})
                self.assertTrue(detail, "actual bound must name the refused dimension and actual counters")
                self.assertEqual(detail["dimension"], dimension)
                self.assertEqual((detail["oci_phase"], detail["image_ordinal"]), (phase, 2))
                self.assertEqual(
                    (detail["before"], detail["charge"], detail["attempted"], detail["limit"]),
                    (ceiling, 1, ceiling + 1, ceiling),
                )
                self.assertEqual(ledger.totals[dimension], ceiling)
                self.assertIn(str(ceiling + 1), str(caught.exception))

    def test_all_charge_sites_name_a_closed_phase(self):
        tree = ast.parse((ROOT / ".getzilla/getzilla/security_oci.py").read_bytes())
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "charge"
        ]
        self.assertEqual(len(calls), 14)
        phases = []
        for call in calls:
            phase = next((value.value for value in call.keywords if value.arg == "phase"), None)
            self.assertIsInstance(phase, ast.Constant, "each actual accounting site needs a fixed source phase")
            phases.append(phase.value)
        self.assertEqual(
            set(phases),
            {
                "layout-json",
                "blob-storage",
                "blob-compressed",
                "layer-count",
                "layer-decoded",
                "tar-entries",
                "tar-expanded",
                "attestation-count",
                "attestation-bytes",
                "scanner-entrypoint",
                "layer-cached-unpacked",
                "layer-cached-expanded",
            },
        )

    def test_live_ci_profile_and_lifetime_never_silently_become_default(self):
        guard = object()
        with (
            mock.patch.object(image_authority, "_GUARD", guard),
            mock.patch.object(image_authority, "measured_ci_profile", return_value=True),
        ):
            profile = dict(oci.active_limits(), images=[], platform="linux/amd64")
            self.assertEqual(profile["max_storage_bytes"], 8 * 1024**3)
            ledger = oci._Budget(profile)
            ledger.charge("storage", 8 * 1024**3)
            with self.assertRaises(oci.OCIError) as caught:
                ledger.charge("storage", 1)
            self.assertEqual(getattr(caught.exception, "detail", {}).get("limit"), 8 * 1024**3)
            with mock.patch.object(image_authority, "_GUARD", object()), self.assertRaisesRegex(oci.OCIError, "lifetime"):
                ledger.charge("entries", 1)
        with mock.patch.object(image_authority, "measured_ci_profile", side_effect=native.BackendUnavailable("owned proof refusal")
        ):
            with self.assertRaises(native.BackendUnavailable):
                oci.active_limits()

    def test_closed_fault_rejects_extra_secret_invalid_and_inconsistent_fields(self):
        self.assertTrue(callable(getattr(oci, "bound_fault", None)))
        self.assertEqual(oci.bound_fault(owned_error()), closed_detail())
        changes = [
            dict(secret="PRIVATE_MARKER"),
            dict(dimension="PRIVATE_MARKER"),
            dict(oci_phase="https://PRIVATE_MARKER"),
            dict(limit_name="PRIVATE_MARKER"),
            dict(before=True),
            dict(charge=-1),
            dict(attempted=100002),
            dict(limit=99999),
            dict(profile_storage=2**100),
            dict(image_ordinal=512),
        ]
        for change in changes:
            with self.subTest(change=list(change)):
                error = owned_error()
                error.detail.update(change)
                self.assertEqual(oci.bound_fault(error), {})
                with self.assertRaises(ValueError):
                    oci.OCIError("owned", detail=error.detail)
        self.assertEqual(oci.bound_fault(oci.OCIError("ordinary")), {})
        self.assertEqual(oci.OCIError("first", "second").args, ("first", "second"))

    def test_producer_retains_only_closed_bound_fields(self):
        for bad in (False, True):
            with self.subTest(bad=bad):
                error = owned_error()
                if bad:
                    error.detail["secret"] = "PRIVATE_MARKER"
                with mock.patch.object(producer.os, "write") as write:
                    producer._fault(error)
                report = json.loads(write.call_args.args[1])["fault"]
                self.assertNotIn("PRIVATE_MARKER", json.dumps(report))
                self.assertEqual(report.get("dimension"), None if bad else "entries")
                self.assertEqual(report.get("attempted"), None if bad else 100001)

    def test_normal_cli_retains_bound_fault_without_success_credit(self):
        with tempfile.TemporaryDirectory(dir=ROOT / ".getzilla/runtime") as raw:
            root = Path(raw)
            output = root / "report.json"
            arguments = []
            for key in ("root", "database", "artifacts", "tools"):
                arguments += ["--" + key, str(root)]
            arguments += ["--json-out", str(output)]
            with (
                mock.patch.object(cli, "ci_run_context", return_value={}),
                mock.patch.object(cli, "evaluate", side_effect=owned_error()),
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(cli.main(arguments), 1)
            body = json.loads(output.read_bytes())
            self.assertEqual(body["status"], "fail")
            self.assertEqual(body["qualification"], "UNVERIFIED")
            self.assertEqual(body.get("fault"), closed_detail())

    def test_supervisor_requires_fresh_closed_failed_child_output(self):
        with tempfile.TemporaryDirectory(dir=ROOT / ".getzilla/runtime") as raw:
            root = Path(raw)
            output = root / "report.json"
            args = SimpleNamespace(
                root=root,
                database=root,
                artifacts=root,
                tools=root / "tools",
                input_profile=root / "profile",
                json_out=output,
                refresh=False,
                provision_tools=False,
                family_records=None,
            )
            child = dict(
                kind="public-security-input-refusal",
                status="fail",
                qualification="UNVERIFIED",
                gaps=["input-preparation-unavailable"],
                fault=closed_detail(),
            )
            process = SimpleNamespace(returncode=1, terminal_state="completed", cleanup_error=None)
            for variant in ("fresh", "stale", "secret", "malformed", "timeout", "cleanup", "changed-read"):
                with self.subTest(variant=variant):
                    cli._atomic(output, oci.canonical(child))

                    def execute(command, selected, environment, **options):
                        self.assertEqual(options["timeout"], 600)
                        self.assertEqual(selected, root)
                        self.assertEqual(command[command.index("--json-out") + 1], str(output))
                        if variant != "stale":
                            value = copy.deepcopy(child)
                            if variant == "secret":
                                value["fault"]["secret"] = "PRIVATE_MARKER"
                            cli._atomic(output, b"not JSON" if variant == "malformed" else oci.canonical(value))
                        return SimpleNamespace(
                            **{
                                **vars(process),
                                "terminal_state": "timeout" if variant == "timeout" else "completed",
                                "cleanup_error": "owned cleanup incomplete" if variant == "cleanup" else None,
                            }
                        )

                    original_read = cli.read_file

                    def read(*arguments, **options):
                        value = original_read(*arguments, **options)
                        if variant == "changed-read":
                            cli._atomic(output, value)
                        return value

                    with (
                        mock.patch.object(cli, "execute", side_effect=execute),
                        mock.patch.object(cli, "_environment", return_value={}),
                        mock.patch.object(cli, "read_file", side_effect=read),
                    ):
                        body = cli._supervised_preparation(args, {})
                    self.assertEqual(body["status"], "unavailable")
                    self.assertEqual(body["qualification"], "UNVERIFIED")
                    self.assertEqual(body.get("fault"), closed_detail() if variant == "fresh" else None)
                    self.assertNotIn("PRIVATE_MARKER", json.dumps(body))
