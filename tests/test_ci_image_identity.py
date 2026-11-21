"""Actual fixed pin metadata proves both Docker image-store identities; no daemon."""

import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".getzilla"))
from getzilla import disposable_resources as resources


class ImageStoreIdentityTests(unittest.TestCase):
    def test_classic_and_containerd_ids_keep_config_manifest_and_platform_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / ".getzilla/config/ci-image-blobs", root / ".getzilla/config/ci-image-blobs")
            for name in ("postgres", "python"):
                pin = resources.image_pins(ROOT)[name]
                digest = pin["reference"].split("@", 1)[1]
                raw = (root / ".getzilla/config/ci-image-blobs" / (digest[7:] + ".json")).read_bytes()
                manifest = json.loads(raw)
                common = {"RepoDigests": [pin["reference"]], "Os": "linux", "Architecture": "amd64"}
                classic = {**common, "Id": pin["image_id"]}
                current = {
                    **common,
                    "Id": digest,
                    "Descriptor": {"digest": digest, "size": len(raw), "mediaType": manifest["mediaType"]},
                }
                with (
                    self.subTest(image=name),
                    patch.object(resources, "_docker", side_effect=AssertionError("pure observation only")),
                ):
                    self.assertEqual(resources.runtime_image_id(root, pin, inspection=classic), pin["image_id"])
                    self.assertEqual(resources.runtime_image_id(root, pin, inspection=current), digest)
                    variants = []
                    for field, value in (
                        ("Id", "sha256:" + "f" * 64),
                        ("RepoDigests", []),
                        ("RepoDigests", pin["reference"]),
                        ("RepoDigests", [None]),
                        ("Os", "windows"),
                        ("Architecture", "arm64"),
                        ("Descriptor", None),
                    ):
                        item = copy.deepcopy(current)
                        item[field] = value
                        variants.append(item)
                    for field, value in (
                        ("digest", "sha256:" + "f" * 64),
                        ("size", 1),
                        ("mediaType", "application/vnd.oci.image.index.v1+json"),
                    ):
                        item = copy.deepcopy(current)
                        item["Descriptor"][field] = value
                        variants.append(item)
                    for item in variants:
                        with self.assertRaises(ValueError):
                            resources.runtime_image_id(root, pin, inspection=item)
                    contradictory = {**classic, "Descriptor": {**current["Descriptor"], "digest": "sha256:" + "f" * 64}}
                    with self.assertRaises(ValueError):
                        resources.runtime_image_id(root, pin, inspection=contradictory)
                    wrong = {**pin, "image_id": "sha256:" + "e" * 64}
                    with self.assertRaises(ValueError):
                        resources.runtime_image_id(root, wrong, inspection=current)
                    path = root / ".getzilla/config/ci-image-blobs" / (pin["image_id"][7:] + ".json")
                    original = path.read_bytes()
                    changed = original.replace(b'"created"', b'"creatfd"', 1)
                    self.assertNotEqual(changed, original)
                    self.assertEqual(len(changed), len(original))
                    path.write_bytes(changed)
                    with self.assertRaises(ValueError):
                        resources.runtime_image_id(root, pin, inspection=current)
                    path.write_bytes(original)
                    path.write_bytes(original + b" ")
                    with self.assertRaises(ValueError):
                        resources.runtime_image_id(root, pin, inspection=current)
                    path.write_bytes(original)
