"""Real retained terms with tiny owned LIVE/member ports; no image execution."""

import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".getzilla"))
from getzilla import security_license_exceptions as ex
from getzilla import security_image_producer as producer
from getzilla import security_image_backend as native
from getzilla import security_ci_inputs as ci


class InternalProfiles(unittest.TestCase):
    def values(self, name="setuptools"):
        f = json.loads((ROOT / "tests/fixtures/security-license-internal-profiles.json").read_text())[name]
        profile = name + "-" + f["version"] + "-internal-ci-v1"
        self.assertIn(profile, ex.PROFILES, "approved exact internal profile is absent")
        dep = dict(
            ecosystem="PyPI",
            name=name,
            version=f["version"],
            manifest="trust-ci/requirements-build.txt",
            usage="build" if name == "setuptools" else "runtime-and-development",
        )
        scope = dict(
            manifest_sha256="a" * 64,
            profile="ci:trust-ci/Dockerfile.api:python:cpython:3.13:linux-x86_64",
            abi="cpython-313-x86_64-linux-gnu",
            delivery_kind="installed-package",
        )
        record = dict(
            filename=f["filename"],
            sha256=f["artifact_sha256"],
            origin=dict(artifact_url="https://files.pythonhosted.org/packages/aa/" + f["filename"]),
        )
        subject = dict(
            dep,
            **scope,
            distribution="internal",
            filename=record["filename"],
            artifact_sha256=record["sha256"],
            artifact_url=record["origin"]["artifact_url"],
        )
        entry = dict(subject=subject, condition_profile=profile)
        terms = ex.PROFILES[profile]["declared_terms"]
        files = {p: b.encode() for p, b in f["files"].items()}
        meta = dict(expression=f["expression"], license_paths=terms)
        return entry, dep, record, files, meta, scope

    def environment(self, values):
        binding = dict(
            source={"head_sha": "1" * 40},
            run={"run_id": "owned-run"},
            ci_uses={"consumers": [dict(image="owned-image")]},
            ci_consumer=0,
        )
        guard = object()
        live = dict(native_guard=guard, source=binding["source"], run=binding["run"])
        self.enterContext(patch.object(native, "_GUARD", guard))
        self.enterContext(patch.object(producer, "_LIVE", live))
        self.enterContext(patch.object(ci, "validate_binding", lambda b: b))
        self.enterContext(patch.object(ex, "scope_for", lambda *a: values[-1]))
        gpl = (ROOT / ".getzilla/config/license-exception-inputs/factory-source-delivery-v1/GPL-3.0.txt").read_bytes()
        mpl = (ROOT / ".getzilla/config/license-exception-inputs/ci-internal-v1/MPL-2.0-debian.txt").read_bytes()
        self.bodies = {"usr/share/common-licenses/GPL-3": gpl, "usr/share/common-licenses/MPL-2.0": mpl}
        self.enterContext(
            patch.object(
                producer,
                "ci_member_evidence",
                lambda uses, source, run, index, paths: {p: self.bodies[p] for p in paths},
            )
        )
        return binding

    def verify(self, v, proof=None, distribution="internal"):
        return ex.verify_exception({"dependency_exceptions": [v[0]]}, *v[1:5], distribution, v[5], supplements=proof)

    def test_actual_three_profiles_and_separate_supplements(self):
        from getzilla import security_license_supplements as sup

        for name in ("setuptools", "certifi", "psycopg"):
            with self.subTest(name=name):
                v = self.values(name)
                b = self.environment(v)
                proof = sup.prove_ci(b, v[1], v[2], v[5], v[0]["condition_profile"])
                result = self.verify(v, proof)
                self.assertTrue(result["required_supplements"])
                self.assertFalse(set(result["required_retention"]) & set(self.bodies))
                self.assertEqual(len(result["license_files"]), 17 if name == "setuptools" else 1)
                self.assertTrue(set(v[3]) <= set(result["required_retention"]))

    def test_approved_exact_internal_profile_exists(self):
        self.values()

    def test_every_original_term_or_nested_metadata_change_refuses(self):
        from getzilla import security_license_supplements as sup

        v = self.values()
        b = self.environment(v)
        proof = sup.prove_ci(b, v[1], v[2], v[5], v[0]["condition_profile"])
        for path in v[3]:
            changed = copy.deepcopy(v)
            changed[3][path] += b" changed"
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.verify(changed, proof)

    def test_missing_forged_replayed_and_changed_live_text_refuse(self):
        from getzilla import security_license_supplements as sup

        v = self.values()
        b = self.environment(v)
        for proof in (None, {}, object()):
            with self.subTest(proof=type(proof).__name__), self.assertRaises(ValueError):
                self.verify(v, proof)
        proof = sup.prove_ci(b, v[1], v[2], v[5], v[0]["condition_profile"])
        original = self.bodies["usr/share/common-licenses/GPL-3"]
        self.bodies["usr/share/common-licenses/GPL-3"] = b"GPL-3.0"
        with self.assertRaises(ValueError):
            self.verify(v, proof)
        self.bodies["usr/share/common-licenses/GPL-3"] = original
        producer._LIVE["run"] = {"run_id": "other"}
        with self.assertRaises(ValueError):
            self.verify(v, proof)

    def test_private_type_alone_and_mutated_binding_are_not_proofs(self):
        from getzilla import security_license_supplements as sup

        v = self.values()
        b = self.environment(v)
        proof = sup.prove_ci(b, v[1], v[2], v[5], v[0]["condition_profile"])
        forged = sup._Proof(proof.binding, proof.subject, proof.requirements, proof.fingerprint)
        with self.assertRaises(ValueError):
            self.verify(v, forged)
        proof.binding["run"] = {"run_id": "substituted"}
        with self.assertRaises(ValueError):
            self.verify(v, proof)

    def test_supplement_details_replay_structurally_but_do_not_mint_authority(self):
        from getzilla import security_license_supplements as sup

        v = self.values()
        b = self.environment(v)
        proof = sup.prove_ci(b, v[1], v[2], v[5], v[0]["condition_profile"])
        result = self.verify(v, proof)
        finding = dict(
            ecosystem="PyPI",
            package="setuptools",
            version="84.1.0",
            manifest=v[1]["manifest"],
            distribution="internal",
            artifact_sha256=v[2]["sha256"],
            expression="MIT",
            selected_expression="MIT",
            origin=v[2]["origin"],
            policy_exception=result["detail"],
            license_files=result["license_files"],
            notice_files=result["notice_files"],
        )
        self.assertTrue(ex.detail_consistent(finding))
        for key in ("required_supplements", "supplement_custody"):
            changed = copy.deepcopy(finding)
            changed["policy_exception"].pop(key)
            self.assertFalse(ex.detail_consistent(changed))
        with self.assertRaises(ValueError):
            self.verify(v, json.loads(json.dumps(result["detail"])))

    def test_internal_profile_never_becomes_redistribution_permission(self):
        v = self.values()
        entry = copy.deepcopy(v[0])
        entry["subject"]["distribution"] = "redistributed"
        with self.assertRaises(ValueError):
            ex.validate_exceptions([entry])
        entry = copy.deepcopy(v[0])
        entry["subject"]["usage"] = "runtime"
        with self.assertRaises(ValueError):
            ex.validate_exceptions([entry])

    def test_all_terms_requested_and_no_global_allow_added(self):
        v = self.values()
        paths = ex.retention_paths({"dependency_exceptions": [v[0]]}, v[1])
        self.assertTrue(set(v[3]) <= paths)
        from getzilla import security_licenses

        self.assertEqual(
            set(security_licenses.ALLOWED), {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD"}
        )

    def test_exact_selector_and_actual_policy_are_closed(self):
        v = self.values()
        self.assertEqual(
            ex.matching_profile({"dependency_exceptions": [v[0]]}, v[1], v[2], "internal", v[5]),
            v[0]["condition_profile"],
        )
        for field in ("manifest_sha256", "profile", "abi", "delivery_kind"):
            scope = dict(v[5], **{field: "foreign"})
            with self.subTest(field=field), self.assertRaises(ValueError):
                ex.matching_profile({"dependency_exceptions": [v[0]]}, v[1], v[2], "internal", scope)
        policy = json.loads((ROOT / ".getzilla/config/license-policy.json").read_text())
        ex.validate_exceptions(policy["dependency_exceptions"])
        self.assertEqual(len(ex.PROFILES["setuptools-84.1.0-internal-ci-v1"]["terms"]), 17)
        self.assertEqual(len(ex.PROFILES["setuptools-84.1.0-internal-ci-v1"]["metadata"]), 13)
