"""Owned native-run applicability fixtures; never provider or runtime qualification."""

import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".getzilla"))
from getzilla import security_licenses as licenses, security_cli as cli, security_image_producer as producer
from getzilla import security_image_backend as native, security_python_target as target
from tests.test_security_licenses import artifact, wheel, manifest, inventory, dependency, POLICY

NOW = datetime(2026, 11, 18, 21, 0, tzinfo=timezone.utc)


class SelectedRunLicenseTests(unittest.TestCase):
    def test_preparation_uses_sealed_current_run_not_global_future_coverage(self):
        from getzilla.expanded_security import CHECK_FAMILIES

        host, future, inactive, inv, source, run, binding = self.fixture()
        context = self.live(inv, source, run, binding)
        self.catalog(host, inv, binding)
        result = licenses.evaluate_artifacts(
            inv, self.root, POLICY, now=NOW, target_binding=binding, run_context=context
        )
        profile = dict(
            profile_sha256=binding["profile_sha256"],
            source=source,
            inventory_sha256=inv["digest"],
            policy_sha256="f" * 64,
            observed_counts=dict(dependencies=3, tools=0, images=0),
            required_sources={key: [] for key in CHECK_FAMILIES},
        )
        obligations = [
            dict(
                check_id=key,
                applicability="required" if key == "security-inventory" else "not_applicable",
                evidence=dict(inventory_sha256=inv["digest"], policy_sha256="f" * 64, complete=True),
                data_sources=[],
            )
            for key in CHECK_FAMILIES
        ]
        prepared = cli.preparation_result(profile, source, source, obligations, [], result, now=NOW)
        self.assertEqual(prepared["status"], "prepared", prepared["gaps"])
        self.assertIs(prepared["overall_coverage_complete"], False)
        self.assertEqual(prepared["preparation_scope"], "selected-native-security-run")
        forged = copy.deepcopy(result)
        forged["selected_run"]["conditions"] = []
        refused = cli.preparation_result(profile, source, source, obligations, [], forged, now=NOW)
        self.assertEqual(refused["status"], "unavailable")
        for field in ("gaps", "raw_coverage"):
            with self.subTest(field=field):
                forged = copy.deepcopy(result)
                forged[field] = [] if field == "gaps" else {"complete": True}
                refused = cli.preparation_result(profile, source, source, obligations, [], forged, now=NOW)
                self.assertEqual(refused["status"], "unavailable")

    def test_finalizer_names_scoped_pass_and_keeps_raw_global_incomplete(self):
        from tests.test_security_cli import SecurityCliTests

        host, future, inactive, inv, source, run, binding = self.fixture()
        context = self.live(inv, source, run, binding)
        self.catalog(host, inv, binding)
        result = licenses.evaluate_artifacts(
            inv, self.root, POLICY, now=NOW, target_binding=binding, run_context=context
        )
        _source, checks = SecurityCliTests().report()
        for check in checks:
            detail = check["details"][0]
            detail["inventory_sha256"] = inv["digest"]
            for proof in detail["data_sources"]:
                proof["acquisition"]["last_verified_sync_utc"] = NOW.isoformat()
                proof["acquisition"]["source_published_at"] = NOW.isoformat()
        detail = next(check["details"][0] for check in checks if check["name"] == "security-licenses")
        detail.update(
            findings=result["selected_run"]["details"],
            selected_run=result["selected_run"],
            raw_coverage=result["raw_coverage"],
            raw_license_diagnostics=result["gaps"],
        )
        report = cli.finalize_report(source, source, checks, inv["digest"], "f" * 64, now=NOW)
        self.assertEqual(report["status"], "pass-for-selected-run", report["qualification_gaps"])
        self.assertIs(report["overall_coverage_complete"], False)
        detail["selected_run"]["status"] = "pass"
        self.assertNotEqual(
            cli.finalize_report(source, source, checks, inv["digest"], "f" * 64, now=NOW)["status"],
            "pass-for-selected-run",
        )

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=ROOT / ".getzilla/runtime")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def module(self):
        self.assertIsNotNone(
            importlib.util.find_spec("getzilla.security_license_scope"),
            "missing privately bound selected-run license applicability",
        )
        from getzilla import security_license_scope

        return security_license_scope

    def fixture(self):
        host = dependency(manifest=".getzilla/config/python-quality-requirements.txt", usage="build-ci")
        future = dependency(name="future", manifest="future/requirements.txt", usage="runtime")
        future.pop("distribution")
        inactive = dependency(name="inactive", manifest=host["manifest"], usage="build-ci")
        inv = inventory(host, future, inactive, builds=[])
        declarations = {
            host["manifest"]: 'example==1.0.0\ninactive==1.0.0; python_version < "0"\n',
            future["manifest"]: "future==1.0.0\n",
        }
        inv["manifests"] = []
        for name, text in declarations.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8", newline="\n")
            inv["manifests"].append(dict(path=name, sha256=hashlib.sha256(text.encode()).hexdigest()))
        inv["digest"] = target.digest({k: v for k, v in inv.items() if k != "digest"})
        source = dict(
            head_sha="a" * 40,
            tree_sha="b" * 40,
            checker_sha="c" * 40,
            checker_tree_sha="d" * 40,
            candidate_clean=True,
            checker_clean=True,
            same_project=True,
        )
        run = dict(
            provider="github-actions", repository="owned/project", run_id="42", run_attempt="1", head_sha="a" * 40
        )
        observed = target.observe_target()
        pins = target.source_pins(self.root, inv, observed)
        binding = dict(
            target=observed,
            source=source,
            run=run,
            inventory_sha256=inv["digest"],
            profile_sha256="e" * 64,
            source_pins=pins,
        )
        return host, future, inactive, inv, source, run, binding

    def test_activation_reobserves_source_pins_and_needs_private_native_entry(self):
        module = self.module()
        host, future, inactive, inv, source, run, binding = self.fixture()
        guard = object()
        state = dict(source=source, run=run, native_guard=guard, root=self.root, declared_inventory=inv)
        profile = dict(
            python_target=binding["target"],
            python_source_pins=binding["source_pins"],
            source=source,
            run=run,
            inventory_sha256=inv["digest"],
        )
        profile["profile_sha256"] = target.digest(profile)
        with mock.patch.object(producer, "_LIVE", state), mock.patch.object(native, "_GUARD", guard):
            with self.assertRaises(Exception):
                module.activate(self.root, profile)
            module.activate(self.root, profile, _entry=producer._LICENSE_ENTRY)
            self.assertIsNotNone(module.current(self.root, inv, target.binding(profile)))
            wrong = copy.deepcopy(profile)
            wrong["python_source_pins"][target.digest(target._subject(inactive))]["marker_active"] = True
            wrong["profile_sha256"] = target.digest({k: v for k, v in wrong.items() if k != "profile_sha256"})
            with self.assertRaises(Exception):
                module.activate(self.root, wrong, _entry=producer._LICENSE_ENTRY)

    def live(self, inv, source, run, binding):
        module = self.module()
        guard = object()
        state = dict(
            source=source,
            run=run,
            builds={},
            build_inputs=[],
            native_guard=guard,
            root=self.root,
            declared_inventory=copy.deepcopy(inv),
            license_entry=producer._LICENSE_ENTRY,
            license_binding=copy.deepcopy(binding),
            license_profile=dict(profile_sha256=binding["profile_sha256"], source=source),
        )
        effects = mock.patch.multiple(producer, _LIVE=state)
        effects.start()
        self.addCleanup(effects.stop)
        effect = mock.patch.object(native, "_GUARD", guard)
        effect.start()
        self.addCleanup(effect.stop)
        return module.current(self.root, inv, binding)

    def catalog(self, host, inv, binding):
        payload = wheel(
            extra_files={
                "example-1.0.0.dist-info/WHEEL": "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n"
            }
        )
        record = artifact(self.root, host, payload)
        record["context"] = target.artifact_context(host)
        record["python_target"] = target.wheel_observation(
            record["filename"], target.archive_files(payload, record["filename"]), binding, dependency=host
        )
        manifest(self.root, inv, [record], acquired=NOW)

    def test_default_global_result_remains_incomplete_and_json_cannot_select_run(self):
        module = self.module()
        host, future, inactive, inv, source, run, binding = self.fixture()
        self.catalog(host, inv, binding)
        with mock.patch.object(producer, "_LIVE", None):
            self.assertIsNone(module.current(self.root, inv, binding))
            result = licenses.evaluate_artifacts(inv, self.root, POLICY, now=NOW, target_binding=binding)
        self.assertEqual(result["status"], "fail")
        self.assertNotIn("selected_run", result)
        with self.assertRaises(Exception):
            licenses.evaluate_artifacts(
                inv, self.root, POLICY, now=NOW, target_binding=binding, run_context={"status": "pass"}
            )

    def test_selected_run_keeps_future_inactive_diagnostics_but_requires_actual_host(self):
        host, future, inactive, inv, source, run, binding = self.fixture()
        context = self.live(inv, source, run, binding)
        self.catalog(host, inv, binding)
        original = copy.deepcopy(inv)
        result = licenses.evaluate_artifacts(
            inv, self.root, POLICY, now=NOW, target_binding=binding, run_context=context
        )
        self.assertEqual(result["status"], "overall-incomplete")
        self.assertEqual(result["raw_coverage"]["status"], "fail")
        self.assertFalse(result["selected_run"]["overall_coverage_complete"])
        self.assertEqual(result["selected_run"]["status"], "pass-for-selected-run", result["selected_run"]["gaps"])
        self.assertTrue(result["gaps"])
        self.assertEqual(inv, original)
        self.assertEqual(context.acquisition_dependencies(), [host])
        self.assertTrue(self.module().validate_result(result["selected_run"]))
        changed = copy.deepcopy(result["selected_run"])
        changed["context_sha256"] = "0" * 64
        self.assertFalse(self.module().validate_result(changed))
        (self.root / "manifest.json").unlink()
        failed = licenses.evaluate_artifacts(
            inv, self.root, POLICY, now=NOW, target_binding=binding, run_context=context
        )
        self.assertEqual(failed["selected_run"]["status"], "fail-for-selected-run")
        self.assertFalse(self.module().validate_result(result["selected_run"]))

    def test_missing_actual_family_and_unobserved_build_consumer_stay_mandatory(self):
        host, future, inactive, inv, source, run, binding = self.fixture()
        subject = dict(
            kind="github-action",
            reference="owned/action@" + "f" * 40,
            manifest=".github/workflows/owned.yml",
            line=1,
            source_sha256="2" * 64,
            usage="build-ci",
        )
        inv["tools"] = [subject]
        row = dict(build_sha256="3" * 64, dockerfile="trust-ci/runner.Dockerfile", recipe_sha256="4" * 64)
        inv["builds"] = [row]
        context = self.live(inv, source, run, binding)
        self.catalog(host, inv, binding)
        result = licenses.evaluate_artifacts(
            inv, self.root, POLICY, now=NOW, target_binding=binding, run_context=context
        )
        self.assertEqual(result["selected_run"]["status"], "fail-for-selected-run")
        self.assertTrue(any("family" in gap["code"] or "tool" in gap["code"] for gap in result["selected_run"]["gaps"]))
        self.assertTrue(any("consumer" in gap["code"] for gap in result["selected_run"]["gaps"]))

    def test_changed_guard_source_inventory_or_profile_cannot_reuse_scope(self):
        host, future, inactive, inv, source, run, binding = self.fixture()
        context = self.live(inv, source, run, binding)
        for variant in ("guard", "inventory", "profile"):
            with self.subTest(variant=variant):
                if variant == "guard":
                    with mock.patch.object(native, "_GUARD", object()), self.assertRaises(Exception):
                        context.validate(inv, binding)
                elif variant == "inventory":
                    changed = copy.deepcopy(inv)
                    changed["dependencies"].pop()
                    with self.assertRaises(Exception):
                        context.validate(changed, binding)
                else:
                    changed = copy.deepcopy(binding)
                    changed["profile_sha256"] = "0" * 64
                    with self.assertRaises(Exception):
                        context.validate(inv, changed)
