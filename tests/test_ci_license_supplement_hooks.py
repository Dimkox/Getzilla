"""Actual profile term/metadata bytes and tiny held OCI custody; no execution.

Portable fixtures use a synthetic ZIP container with a test-only exact container
hash. Legal/metadata/supplement bodies and the fixed profile names stay real.
This does not qualify an actual vendor wheel or native job.
"""

import copy
from contextlib import contextmanager
import hashlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".getzilla"))
from getzilla import security_ci_inputs as ci, security_oci as oci
from getzilla import security_licenses as licenses, security_license_exceptions as ex
from getzilla import security_license_supplements as supplements
from tests import test_ci_image_license_inputs as fixtures
from tests.test_security_licenses import artifact, manifest, POLICY, NOW

ROOT = Path(__file__).resolve().parents[1]
DATA = json.loads((ROOT / "tests/fixtures/security-license-internal-profiles.json").read_text())


class SupplementHookTests(unittest.TestCase):
    @contextmanager
    def installation(self, name, *, missing_supplement=False, actual_payload=None):
        fixture = fixtures.CIImageTargetBindingTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        owned = fixtures.RequestedImageMembersTests()
        owned.setUp()
        self.addCleanup(owned.doCleanups)
        owned.api = lambda: oci
        data = DATA[name]
        profile_name = name + "-" + data["version"] + "-internal-ci-v1"
        profile = copy.deepcopy(ex.PROFILES[profile_name])
        files = {path: body.encode() for path, body in data["files"].items()}
        wheel_path = name + "-" + data["version"] + ".dist-info/WHEEL"
        files[wheel_path] = b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n"
        if actual_payload is None:
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive:
                for path, body in files.items():
                    archive.writestr(path, body)
            payload = buffer.getvalue()
            profile["artifact_sha256"] = hashlib.sha256(payload).hexdigest()
        else:
            payload = actual_payload
            self.assertEqual(hashlib.sha256(payload).hexdigest(), profile["artifact_sha256"])
            files = licenses.archive_files(payload, data["filename"], requested=set(files))
        dep = dict(
            fixture.dep,
            name=name,
            version=data["version"],
            usage="build" if name == "setuptools" else "runtime-and-development",
        )
        consumer = fixture.uses["consumers"][0]
        consumer.update(dependencies=[dep], supported_tags=["py3-none-any"])
        consumer["target"].update(
            python_version="3.13.18",
            abi="cpython-313-x86_64-linux-gnu",
            tags_sha256=fixture.target.digest(["py3-none-any"]),
            tag_count=1,
        )
        consumer["target"]["marker_environment"].update(python_version="3.13", python_full_version="3.13.18")
        consumer["source_pins"] = {
            fixture.target.digest(fixture.target._subject(dep)): dict(
                context_sha256=fixture.target._context_key(dep),
                manifest_sha256=consumer["requirements_sha256"],
                hashes=[profile["artifact_sha256"]],
                files=[],
                marker_active=True,
            )
        }
        members = {consumer["site_packages"][0] + "/" + path: body for path, body in files.items()}
        supplement_bodies = {
            "usr/share/common-licenses/GPL-3": (
                ROOT / ".getzilla/config/license-exception-inputs/factory-source-delivery-v1/GPL-3.0.txt"
            ).read_bytes(),
            "usr/share/common-licenses/MPL-2.0": (
                ROOT / ".getzilla/config/license-exception-inputs/ci-internal-v1/MPL-2.0-debian.txt"
            ).read_bytes(),
        }
        if not missing_supplement:
            members.update({path: supplement_bodies[path] for path in profile["supplements"]})
        image_inventory, catalog = owned.image([list(members.items())])
        consumer["image"] = image_inventory["images"][0]["reference"]
        installed, binding = ci.scope(fixture.parent, 0)
        installed_dep = installed["dependencies"][0]
        store = owned.root / "artifacts"
        store.mkdir(mode=0o700)
        record = artifact(store, installed_dep, payload, filename=data["filename"])
        record["context"] = fixture.target.artifact_context(installed_dep)
        record["python_target"] = fixture.target.wheel_observation(
            record["filename"], files, binding, dependency=installed_dep
        )
        scope = ex.scope_for(installed_dep, binding, dict(binding_sha256=fixture.target.digest(binding)))
        subject = dict(
            **{key: installed_dep[key] for key in ("ecosystem", "name", "version", "manifest", "usage")},
            **scope,
            distribution="internal",
            filename=record["filename"],
            artifact_sha256=record["sha256"],
            artifact_url=record["origin"]["artifact_url"],
        )
        policy = dict(POLICY, dependency_exceptions=[dict(subject=subject, condition_profile=profile_name)])
        manifest(store, installed, [record], acquired=NOW)
        with patch.dict(ex.PROFILES, {profile_name: profile}):
            with oci.import_layouts(catalog, image_inventory, owned.profile, owned.stage) as images:
                fixture.live["images"] = {images[0].reference: images[0]}
                yield dict(
                    inventory=installed,
                    binding=binding,
                    dep=installed_dep,
                    root=store,
                    record=record,
                    policy=policy,
                    scope=scope,
                    files=files,
                    profile=profile_name,
                )

    def evaluate(self, value):
        return licenses.evaluate_artifacts(
            value["inventory"], value["root"], value["policy"], target_binding=value["binding"], now=NOW
        )

    def test_exact_profiles_mint_live_proofs_and_keep_supplements_outside_wheel_retention(self):
        for name in ("setuptools", "certifi", "psycopg"):
            with self.subTest(name=name), self.installation(name) as value:
                with patch.object(supplements, "prove_ci", wraps=supplements.prove_ci) as mint:
                    result = self.evaluate(value)
                self.assertEqual(result["status"], "pass", result["gaps"])
                self.assertEqual(mint.call_count, 1)
                self.assertEqual(mint.call_args.args[-1], value["profile"])
                detail = result["details"][0]
                proof = detail["policy_exception"]
                self.assertTrue(proof["required_supplements"])
                self.assertFalse(set(proof["required_supplements"]) & set(proof["required_retention"]))
                self.assertFalse(any("common-licenses" in path for path in detail["delivery"]["members"]))
                self.assertTrue(ex.detail_consistent(detail))
                if name == "setuptools":
                    self.assertEqual(detail["expression"], "MIT")
                    self.assertEqual(len(detail["license_files"]), 17)
                    self.assertEqual(proof["original_diagnostic"]["code"], "license-text-review")

    def test_missing_actual_common_text_and_unmatched_exact_policy_refuse(self):
        with self.installation("certifi", missing_supplement=True) as value:
            self.assertEqual(self.evaluate(value)["status"], "fail")
        with self.installation("certifi") as value:
            value["policy"]["dependency_exceptions"][0]["subject"]["manifest_sha256"] = "f" * 64
            with patch.object(supplements, "prove_ci", wraps=supplements.prove_ci) as mint:
                self.assertEqual(self.evaluate(value)["status"], "fail")
            self.assertEqual(mint.call_count, 0)

    def test_copied_private_supplement_proof_cannot_pass_evaluator(self):
        with self.installation("certifi") as value:
            mint = supplements.prove_ci
            with patch.object(supplements, "prove_ci", side_effect=lambda *args: copy.deepcopy(mint(*args))):
                result = self.evaluate(value)
            self.assertEqual(result["status"], "fail")
            with self.assertRaises(ValueError):
                ci.validated_evaluation(value["binding"], result)
