"""Real tiny wheel/OCI evaluator join, no image execution or native qualification."""

import copy
import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".getzilla"))
from getzilla import security_ci_inputs as ci, security_oci as oci
from getzilla import security_licenses as licenses
from tests import test_ci_image_license_inputs as ci_fixtures
from tests import test_security_license_run_scope as scope_fixtures
from tests.test_security_licenses import artifact, wheel, manifest, inventory, POLICY, NOW


class EvaluationCreditHookTests(unittest.TestCase):
    def setUp(self):
        self.fixture = ci_fixtures.CIImageTargetBindingTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.project, _ = self.fixture.backend_context()
        self.owned = ci_fixtures.RequestedImageMembersTests()
        self.owned.setUp()
        self.addCleanup(self.owned.doCleanups)
        self.owned.api = lambda: oci
        self.root = self.owned.root / "artifacts"
        self.root.mkdir(mode=0o700)
        consumer = self.fixture.uses["consumers"][0]
        self.fixture.uses["closure_graphs_sha256"] = self.fixture.target.digest(None)
        consumer["supported_tags"].append("py3-none-any")
        consumer["target"].update(tags_sha256=self.fixture.target.digest(consumer["supported_tags"]), tag_count=2)
        self.payloads, members = {}, {}
        for dep in consumer["dependencies"]:
            key = dep["name"], dep["version"]
            if key not in self.payloads:
                stem = dep["name"] + "-" + dep["version"] + ".dist-info/"
                payload = wheel(
                    name=dep["name"],
                    version=dep["version"],
                    extra_files={stem + "WHEEL": "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n"},
                )
                self.payloads[key] = payload
                files = licenses.archive_files(payload, dep["name"] + "-" + dep["version"] + "-py3-none-any.whl")
                members.update({consumer["site_packages"][0] + "/" + path: body for path, body in files.items()})
            pin = consumer["source_pins"][self.fixture.target.digest(self.fixture.target._subject(dep))]
            if dep["manifest"] != "trust-ci/pyproject.toml":
                pin["hashes"] = [hashlib.sha256(self.payloads[key]).hexdigest()]
        self.image_inventory, self.image_catalog = self.owned.image([list(members.items())])
        consumer["image"] = self.image_inventory["images"][0]["reference"]
        self.consumer = consumer
        self.installed, self.binding = ci.scope(self.fixture.parent, 0)
        self.child = self.root / "ci-installations" / self.installed["dependencies"][0]["delivery_context"]
        self.child.mkdir(parents=True, mode=0o700)
        records = []
        for dep in self.installed["dependencies"]:
            payload = self.payloads[dep["name"], dep["version"]]
            record = artifact(self.child, dep, payload)
            record["context"] = self.fixture.target.artifact_context(dep)
            record["python_target"] = self.fixture.target.wheel_observation(
                record["filename"], licenses.archive_files(payload, record["filename"]), self.binding, dependency=dep
            )
            records.append(record)
        manifest(self.child, self.installed, records, acquired=NOW)
        self.records = records

    def live(self):
        from contextlib import contextmanager

        @contextmanager
        def held():
            with oci.import_layouts(
                self.image_catalog, self.image_inventory, self.owned.profile, self.owned.stage
            ) as images:
                self.fixture.live["images"] = {images[0].reference: images[0]}
                yield images[0]

        return held()

    def test_actual_success_is_sealed_and_copied_or_wrong_binding_cannot_credit(self):
        with self.live():
            result = licenses.evaluate_artifacts(
                self.installed, self.child, POLICY, now=NOW, target_binding=self.binding
            )
            self.assertEqual(result["status"], "pass", result["gaps"])
            self.assertEqual(ci.validated_evaluation(self.binding, result), self.consumer)
            with self.assertRaises(ValueError):
                ci.validated_evaluation(self.binding, copy.deepcopy(result))
            wrong = copy.deepcopy(self.binding)
            wrong["run"]["run_id"] = "other"
            with self.assertRaises(ValueError):
                ci.validated_evaluation(wrong, result)

    def test_parent_auxiliary_success_credits_exact_backend_and_keeps_raw_gaps(self):
        module = scope_fixtures.SelectedRunLicenseTests()
        module.root = self.owned.root
        self.addCleanup(module.doCleanups)
        parent = dict(self.fixture.parent, source_pins=self.consumer["source_pins"])
        inv = inventory(
            *self.consumer["dependencies"],
            builds=[dict(dockerfile=self.consumer["recipe"], build_sha256=self.consumer["build_sha256"])],
        )
        inv["digest"] = parent["inventory_sha256"]
        with self.live() as image:
            context = module.live(inv, self.fixture.source, self.fixture.run, parent)
            context.state.update(ci_uses=self.fixture.uses, images={image.reference: image})
            manifest(self.root, inv, self.records, acquired=NOW)
            output = licenses.evaluate_artifacts(
                inv, self.root, POLICY, now=NOW, target_binding=parent, run_context=context
            )
            key = (
                "build-input:"
                + self.consumer["build_sha256"]
                + ":"
                + self.fixture.target.digest(self.fixture.target._subject(self.project))
            )
            self.assertIn(key, context.passed, output)
            self.assertTrue(output["gaps"], "raw source gaps must remain separate")
            self.assertEqual(output["selected_run"]["status"], "pass-for-selected-run")
