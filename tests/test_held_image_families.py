"""Held image family serialization in tiny real OCI contexts; no native job."""

import copy
import json
from pathlib import Path
from unittest.mock import patch

from tests import test_image_component_licenses as fixtures
from getzilla import security_image_authority as image_authority
from getzilla import security_image_licenses as image_licenses
from getzilla import security_image_producer as producer
from getzilla.security_artifacts import family_evidence, ArtifactError


class HeldFamilyTests(fixtures.ImageComponentTests):
    def fixture(self, rows=None):
        from contextlib import contextmanager

        @contextmanager
        def owned():
            a = self.api()
            inv, cat = self.image([rows if rows is not None else self.debian()])
            subject = dict(
                reference=inv["images"][0]["reference"],
                manifest="compose.yaml",
                line=1,
                source_sha256="a" * 64,
                usage="ci",
                platform="linux/amd64",
            )
            inv["images"] = [subject]
            artifacts = self.root / "artifacts"
            artifacts.mkdir(mode=0o700, exist_ok=True)
            guard = object()
            source = {"head_sha": "b" * 40}
            run = {"id": "fixture"}
            with a.import_layouts(cat, inv, self.profile, self.stage) as images:
                state = dict(
                    native_guard=guard,
                    source=source,
                    run=run,
                    declared_inventory=inv,
                    images={images[0].reference: images[0]},
                )
                with patch.object(image_authority, "_GUARD", guard), patch.object(image_authority, "_LIVE", state):
                    yield artifacts, inv, source, run, state

        return owned()

    def test_actual_family_serializes_and_reads_shared_custody(self):
        with self.fixture() as (root, inv, source, run, state):
            records = image_licenses.prepare_families(root, inv, source, run)
            self.assertEqual(len(records), 1)
            evidence = family_evidence(root, records[0])
            self.assertTrue(evidence["files"])
            self.assertEqual(evidence["components"][0]["expression"], "MIT")
            self.assertEqual(evidence["binding"]["subject"], inv["images"][0])
            self.assertNotIn("oci/", json.dumps(evidence["components"]))

    def test_copied_json_and_replaced_source_run_or_guard_cannot_restore_authority(self):
        with self.fixture() as (root, inv, source, run, state):
            record = image_licenses.prepare_families(root, inv, source, run)[0]
            for field, value in [
                ("source", {"head_sha": "c" * 40}),
                ("run", {"id": "other"}),
                ("native_guard", object()),
                ("image_families", json.loads(json.dumps(state.get("image_families", {}), default=str))),
            ]:
                before = state.get(field)
                state[field] = value
                with self.assertRaises(ValueError):
                    family_evidence(root, record)
                state[field] = before
        with self.assertRaises(ValueError):
            family_evidence(root, record)

    def test_changed_retained_term_or_other_store_cannot_receive_family_credit(self):
        with self.fixture() as (root, inv, source, run, state):
            record = image_licenses.prepare_families(root, inv, source, run)[0]
            import shutil

            other = self.root / "copy"
            shutil.copytree(root, other)
            with self.assertRaises(ValueError):
                family_evidence(other, record)
            proof = json.loads((root / record["path"]).read_text())["proofs"][0]
            (root / proof["path"]).write_bytes(b"tampered")
            with self.assertRaises(ValueError):
                family_evidence(root, record)

    def test_evaluator_joins_complete_held_family_without_legacy_zip_partition(self):
        from getzilla.security_licenses import evaluate_artifacts, load_policy
        from datetime import datetime, timezone

        with self.fixture() as (root, inv, source, run, state):
            records = image_licenses.prepare_families(root, inv, source, run)
            stamp = datetime.now(timezone.utc).isoformat()
            (root / "manifest.json").write_text(
                json.dumps(
                    dict(
                        schema_version=1,
                        inventory_digest=inv["digest"],
                        last_verified_sync_utc=stamp,
                        records=records,
                        gaps=[],
                    )
                )
            )
            inv.update(dependencies=[], tools=[], complete=True, gaps=[])
            policy = load_policy(Path(__file__).resolve().parents[1])
            policy = copy.deepcopy(policy)
            # The existing trusted policy's internal exact use selector is used;
            # this tiny observation is not an OS/GPL approval or native receipt.
            inv["images"][0]["distribution"] = "internal"
            state["declared_inventory"] = inv
            # Subject mutation invalidates the former record; reobserve exact use.
            records = image_licenses.prepare_families(root, inv, source, run)
            (root / "manifest.json").write_text(
                json.dumps(
                    dict(
                        schema_version=1,
                        inventory_digest=inv["digest"],
                        last_verified_sync_utc=stamp,
                        records=records,
                        gaps=[],
                    )
                )
            )
            result = evaluate_artifacts(inv, root, policy)
            self.assertEqual(result["status"], "pass", result["gaps"])
            self.assertEqual(result["details"][0]["kind"], "image")
            from getzilla.security_license_families import finding_consistent
            from getzilla.security_licenses import _select_expression

            self.assertTrue(finding_consistent(result["details"][0], policy["auto_allow"], _select_expression))
            changed = copy.deepcopy(result["details"][0])
            changed["license_files"][0]["sha256"] = "f" * 64
            self.assertFalse(finding_consistent(changed, policy["auto_allow"], _select_expression))

    def test_cli_automatically_prepares_images_only_under_actual_typed_scope(self):
        from getzilla import security_cli as cli, security_license_scope as scope_api

        with self.fixture() as (root, inv, source, run, state):
            inv.update(dependencies=[], tools=[])
            binding = dict(source=source, run=run, inventory_sha256=inv["digest"], profile_sha256="e" * 64)
            state.update(
                root=self.root,
                license_entry=producer._LICENSE_ENTRY,
                license_binding=binding,
                license_profile=dict(profile_sha256=binding["profile_sha256"]),
                license_checker_declarations={},
            )
            context = scope_api.current(self.root, inv, binding)
            records, preparation = cli._prepare_families(inv, root, self.stage, None, run_context=context)
            self.assertEqual(len(records), 1)
            self.assertEqual(preparation, dict(schema_version=1, providers=[]))
            with self.assertRaises(cli.SecurityDataError):
                cli._prepare_families(inv, root, self.stage, None, run_context={})

    def test_unknown_groups_persist_diagnostic_bytes_without_qualified_family(self):
        rows = self.debian()
        rows[-1] = (rows[-1][0], b"legacy unknown terms")
        with self.fixture(rows) as (root, inv, source, run, state):
            from getzilla.public_security_context import _preparation_step, _preparation_fault, _preparation_detail
            with self.assertRaises(ArtifactError) as caught, _preparation_step("package-artifacts"):
                image_licenses.prepare_families(root, inv, source, run)
            detail = _preparation_fault(caught.exception)
            self.assertEqual(detail["image_gap_counts"], {"dpkg-legacy-license-scope": 1})
            for invalid in ({"unknown": 1}, {"dpkg-legacy-license-scope": True}, {}):
                self.assertFalse(_preparation_detail(dict(detail, image_gap_counts=invalid)))
            saved = state.get("image_family_diagnostics", [])
            self.assertEqual(len(saved), 1)
            document = json.loads((root / saved[0]["path"]).read_text())
            self.assertFalse(document["observation"]["complete"])
            self.assertTrue(document["observation"]["unresolved"])
            self.assertEqual(state.get("image_families", {}), {})

    def test_internal_license_observation_reaches_evaluator_and_preserves_original_bytes(self):
        from datetime import datetime, timezone
        from getzilla.security_licenses import evaluate_artifacts, load_policy, _select_expression

        rows = self.debian()
        rows[-1] = (rows[-1][0], b"legacy text in original image")
        policy = load_policy(Path(__file__).resolve().parents[1])
        with self.fixture(rows) as (root, inv, source, run, state):
            inv["images"][0].update(manifest="trust-ci/runner.Dockerfile", distribution="internal")
            inv.update(dependencies=[], tools=[], complete=True, gaps=[])
            now = datetime.now(timezone.utc)
            records = image_licenses.prepare_families(root, inv, source, run, policy=policy, now=now)
            (root / "manifest.json").write_text(json.dumps(dict(schema_version=1,
                inventory_digest=inv["digest"], last_verified_sync_utc=now.isoformat(),
                records=records, gaps=[])))
            out = evaluate_artifacts(inv, root, policy)
            self.assertEqual((out["status"], out["gaps"]), ("pass", []))
            finding = out["details"][0]
            self.assertEqual(finding["license_observations"], {"status": "internal-report-only",
                "counts": {"dpkg-legacy-license-scope": 1}})
            self.assertTrue(image_licenses.finding_consistent(finding, policy["auto_allow"], _select_expression))
            self.assertIn(rows[-1][1], family_evidence(root, records[0])["files"].values())
            finding["license_observations"]["counts"].clear()
            self.assertFalse(image_licenses.finding_consistent(finding, policy["auto_allow"], _select_expression))

    def test_unknown_and_redistributed_images_keep_the_same_license_gap(self):
        from getzilla.security_licenses import load_policy
        policy = load_policy(Path(__file__).resolve().parents[1])
        rows = self.debian()
        rows[-1] = (rows[-1][0], b"legacy terms")
        with self.fixture(rows) as (root, inv, source, run, state):
            use = inv["images"][0]
            use["manifest"] = "trust-ci/runner.Dockerfile"
            for distribution in (None, "redistributed", "unknown"):
                if distribution is not None:
                    use["distribution"] = distribution
                with self.subTest(distribution=distribution), self.assertRaises(ArtifactError) as exc:
                    image_licenses.prepare_families(root, inv, source, run, policy=policy)
                self.assertEqual(exc.exception.image_gap_counts, {"dpkg-legacy-license-scope": 1})

    def test_internal_image_cannot_downgrade_unowned_software(self):
        from getzilla.security_licenses import load_policy
        rows = self.debian()
        rows[-1] = (rows[-1][0], b"unrecognized terms")
        rows.append(("usr/local/bin/not-owned", b"\x7fELFdata"))
        with self.fixture(rows) as (root, inv, source, run, state):
            inv["images"][0].update(manifest="trust-ci/runner.Dockerfile", distribution="internal")
            with self.assertRaises(ArtifactError) as exc:
                image_licenses.prepare_families(root, inv, source, run,
                    policy=load_policy(Path(__file__).resolve().parents[1]))
            self.assertEqual(exc.exception.image_gap_counts, {"unattributed-software": 1})
            self.assertEqual(exc.exception.license_observations["counts"], {"dpkg-legacy-license-scope": 1})

    def test_shared_image_or_recompressed_layer_stays_strict(self):
        from types import SimpleNamespace
        from getzilla.security_internal_image_scope import internal_images
        a = dict(reference="build", distribution="internal", manifest="trust-ci/runner.Dockerfile")
        b = dict(reference="shipped", distribution="redistributed", manifest="factory/compose.yaml")
        images = {"build": SimpleNamespace(layer_identities={"gzip-a", "tar-a"}),
                  "shipped": SimpleNamespace(layer_identities={"gzip-b", "tar-a"})}
        self.assertEqual(internal_images([a, b], images), set())
        images["shipped"].layer_identities = {"gzip-b", "tar-b"}
        self.assertEqual(internal_images([a, b], images), {"build"})
        self.assertEqual(internal_images([a, b, dict(b, reference="build")], images), set())

    def test_internal_image_policy_has_closed_shape_and_categories(self):
        from getzilla.security_license_contracts import _policy, load_policy
        policy = load_policy(Path(__file__).resolve().parents[1])
        policy.pop("digest")
        block = policy["image_license_scope"]
        for change in ({"report_only_gaps": block["report_only_gaps"] + ["unattributed-software"]},
                      {"report_only_gaps": []}, {"extra": True}, {"internal": "allow"}):
            with self.subTest(change=change), self.assertRaises(ArtifactError):
                _policy(dict(policy, image_license_scope={**block, **change}))

    def test_whiteout_cannot_supply_removed_lower_hardlink_target(self):
        api = self.api()
        inventory, catalog = self.linked_image(
            [
                [("usr/share/common-licenses/MIT", fixtures.MIT, 0o644)],
                [
                    ("usr/share/doc/tiny/copyright", "usr/share/common-licenses/MIT", "hardlink"),
                    ("usr/share/common-licenses/.wh.MIT", b"", 0o644),
                ],
            ]
        )
        with api.import_layouts(catalog, inventory, self.profile, self.stage) as images:
            with self.assertRaises(ValueError):
                api.observe_final_files(images[0], lambda path: True)

    def test_normal_refresh_replaces_only_reproved_same_source_use(self):
        from getzilla.security_license_acquisition import acquire_pypi
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        with self.fixture() as (root, inv, source, run, state):
            record = image_licenses.prepare_families(root, inv, source, run, now=now)[0]
            first = acquire_pypi([], root, inventory_digest=inv["digest"], families=[record], now=now)
            self.assertFalse(first["gaps"])
        with self.fixture() as (root, inv, source, run, state):
            run["id"] = "new actual fixture run"
            record = image_licenses.prepare_families(root, inv, source, run, now=now)[0]
            second = acquire_pypi([], root, inventory_digest=inv["digest"], families=[record], now=now)
            self.assertFalse(second["gaps"])
            self.assertEqual(second["records"], [record])
