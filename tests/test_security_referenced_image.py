"""Delivery classification is derived from three actual archives and live image hashes."""
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from getzilla import security_referenced_image as scope

ROOT = Path(__file__).resolve().parents[1]


def zipped(files):
    body = io.BytesIO()
    with zipfile.ZipFile(body, "w") as output:
        for path, raw in files.items():
            output.writestr(path, raw)
    return body.getvalue()


class ReferencedImageTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        directory = Path(temp.name)
        self.outputs = {name: directory / (name + ".zip") for name in scope.PRODUCTS}
        self.proofs = {"getzilla/" + path: (ROOT / path).read_bytes() for path in scope.STANDALONE}
        for name, path in self.outputs.items():
            path.write_bytes(zipped(self.proofs if name == "source-zip" else {"factory.py": b"pass\n"}))
        self.pins = json.loads((ROOT / ".getzilla/config/ci-images.json").read_text())
        self.layer = b"held compressed layer"
        self.binary = b"held postgres executable"

    def result(self):
        return scope.distribution(scope.delivery_members(self.outputs, self.pins),
                                  {"sha256:" + hashlib.sha256(self.layer).hexdigest()},
                                  {hashlib.sha256(self.binary).hexdigest()})

    def test_pinned_proofs_and_three_complete_outputs_are_referenced(self):
        self.assertEqual(self.result(), "referenced")

    def test_pinned_manifest_rejects_inline_data_or_urls_even_with_matching_digest(self):
        path = scope.PREFIX + scope.PG + ".json"
        for field in ("data", "urls"):
            obj = json.loads(self.proofs["getzilla/" + path])
            obj["layers"][0][field] = "untrusted"
            raw = json.dumps(obj).encode()
            with self.subTest(field=field), patch("getzilla.security_referenced_image.hashlib.sha256") as sha:
                sha.return_value.hexdigest.return_value = scope.PG
                with self.assertRaises(ValueError):
                    scope._check_proof(path, raw)

    def test_unlisted_manifest_even_in_nested_archive_or_utf16_document(self):
        raw = self.proofs["getzilla/" + scope.PREFIX + scope.PG + ".json"]
        for value in (raw, raw.decode().encode("utf-16"), ("  " + raw.decode()).encode("utf-16-be"),
                      ("\n" + raw.decode()).encode("utf-32-be"), zipped({"other": raw})):
            self.outputs["factory-wheel"].write_bytes(zipped({"unlisted": value}))
            with self.subTest(size=len(value)), self.assertRaises(ValueError):
                self.result()

    def test_same_digest_with_foreign_reference_refuses(self):
        self.pins["python"]["reference"] = "different@sha256:" + scope.PYTHON
        with self.assertRaises(ValueError):
            self.result()

    def test_missing_archive_hash_cannot_establish_referenced(self):
        partial = {name: "a"*64 for name in scope.PRODUCTS - {"factory-wheel"}}
        self.assertEqual(scope.distribution((set(), partial), {"layer"}, {"binary"}), "redistributed")

    def test_single_added_byte_refused(self):
        key = next(iter(self.proofs))
        self.proofs[key] += b" "
        self.outputs["source-zip"].write_bytes(zipped(self.proofs))
        with self.assertRaises(ValueError):
            self.result()

    def test_shipped_layer_or_binary_is_redistributed(self):
        for value in (self.layer, self.binary):
            self.outputs["factory-offline"].write_bytes(zipped({"payload.whl": zipped({"payload": value})}))
            self.assertEqual(self.result(), "redistributed")

    def test_missing_unreadable_or_wrong_pin_is_strict(self):
        self.assertEqual(scope.distribution(None, {"layer"}, {"binary"}), "redistributed")
        self.outputs["factory-offline"].write_bytes(b"incomplete")
        with self.assertRaises(ValueError):
            self.result()
        with self.assertRaises(ValueError):
            scope.require_factory_pin([{"manifest":"factory/compose.yaml","source_reference":"postgres:17-alpine"}], self.pins)

    def test_exact_policy_required(self):
        from getzilla.security_license_contracts import _policy
        policy = json.loads((ROOT / ".getzilla/config/license-policy.json").read_bytes())
        self.assertEqual(_policy(policy)["referenced_image_scope"]["standalone_proofs"], scope.STANDALONE)
        policy["referenced_image_scope"]["standalone_proofs"].pop(next(iter(scope.STANDALONE)))
        with self.assertRaises(ValueError):
            _policy(policy)
