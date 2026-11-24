"""Consume only the helper's exact complete whole-file license bundles."""

import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".getzilla"))
from getzilla.security_licenses import _license_evidence, _select_expression
from getzilla.security_artifacts import ArtifactError

DATA = json.loads((Path(__file__).parent / "fixtures/security-license-npm-bundles.json").read_text())


class BundleConsumerTests(unittest.TestCase):
    def test_every_exact_bundle_retains_whole_body_and_all_ids(self):
        for item in DATA["bundles"]:
            expression = " AND ".join(item["identifiers"])
            chosen, ids = _select_expression(expression, item["identifiers"])
            files = {"LICENSE": item["text"].encode()}
            terms, notices = _license_evidence(files, dict(license_paths=["LICENSE"]), ids, chosen)
            self.assertEqual(len(terms), 1)
            self.assertEqual(notices, [])
            self.assertEqual(terms[0]["sha256"], item["sha256"])
            self.assertEqual(terms[0]["bytes"], item["bytes"])
            observed = terms[0].get("recognized_licenses", [terms[0].get("recognized_license")])
            self.assertEqual(set(observed), set(item["identifiers"]))

    def test_missing_required_id_or_changed_grant_cannot_pass(self):
        mixed = next(v for v in DATA["bundles"] if len(v["identifiers"]) > 1)
        for text in (mixed["text"], mixed["text"] + "\nExtra terms."):
            with self.assertRaises(ArtifactError):
                _license_evidence({"LICENSE": text.encode()}, dict(license_paths=["LICENSE"]), {"MIT"}, ["MIT"])

    def test_ancillary_sibling_checks_all_bundle_ids_and_exact_bytes(self):
        item = next(v for v in DATA["bundles"] if len(v["identifiers"]) > 1)
        expression = " AND ".join(item["identifiers"])
        notice = "Exact reviewed test ancillary."
        ancillary = dict(kind="attribution", expression=expression, required_files={"LICENSE": item["sha256"]})
        with patch(
            "getzilla.security_license_contracts.reviewed_ancillary",
            side_effect=lambda text: ancillary if text == notice else None,
        ):
            terms, notices = _license_evidence(
                {"LICENSE": item["text"].encode(), "COPYING": notice.encode()},
                dict(license_paths=["LICENSE", "COPYING"], expression=expression),
                set(item["identifiers"]),
                item["identifiers"],
            )
            self.assertEqual(len(terms), 1)
            self.assertEqual(notices[0]["required_files"][0]["recognized_licenses"], item["identifiers"])

    def test_actual_release_family_finalizer_retains_every_bundle_grant(self):
        import tempfile
        import copy
        from tests import test_public_security_inputs as fixtures
        from getzilla.security_licenses import evaluate_artifacts
        from getzilla.security_license_families import finding_consistent

        item = next(value for value in DATA["bundles"] if len(value["identifiers"]) > 1)
        parent = Path(__file__).resolve().parents[1] / ".getzilla/runtime/scratch/license-bundle-consumer"
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            root = Path(directory)
            with patch.object(fixtures, "MIT", item["text"].encode()):
                inventory, record, bundle = fixtures.release_fixture(root)
            proof_path = root / record["components"]["path"]
            proof = json.loads(proof_path.read_text())
            proof["components"][0]["expression"] = " AND ".join(item["identifiers"])
            raw = fixtures.encoded(proof)
            proof_path.write_bytes(raw)
            record["components"]["sha256"] = fixtures.sha(raw)
            (root / "manifest.json").write_bytes(fixtures.encoded(bundle))
            result = evaluate_artifacts(inventory, root, fixtures.POLICY, now=fixtures.NOW)
            self.assertEqual(result["status"], "pass", result["gaps"])
            finding = result["details"][0]
            self.assertTrue(finding_consistent(finding, fixtures.POLICY["auto_allow"], _select_expression))
            reduced = copy.deepcopy(finding)
            reduced["license_files"][0]["recognized_licenses"] = ["MIT"]
            self.assertFalse(finding_consistent(reduced, fixtures.POLICY["auto_allow"], _select_expression))
