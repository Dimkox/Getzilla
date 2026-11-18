"""Tiny complete graphs retain linked opaque provenance without trust credit."""

import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from tests import test_offline_oci_import as fixtures
INDEX, MANIFEST, CONFIG = fixtures.INDEX, fixtures.MANIFEST, fixtures.CONFIG

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".getzilla"))
from getzilla import security_oci as oci, security_image_registry as registry

OPAQUE = "application/vnd.in-toto+json"


class OpaqueAttestationGraphTests(unittest.TestCase):
    def world(self, mutation=None):
        fixture = fixtures.OfflineOCIImportTests("runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        inventory, catalog, image, config, _ = fixture.artifact()
        image = {**image, "platform": {"os": "linux", "architecture": "amd64"}}
        layer = fixture.blob(b"owned opaque bytes, deliberately not a tar or accepted attestation", OPAQUE)
        config_value = {
            "architecture": "unknown",
            "os": "unknown",
            "config": {},
            "rootfs": {"type": "layers", "diff_ids": [layer["digest"]]},
        }
        if mutation == "diff":
            config_value["rootfs"]["diff_ids"] = ["sha256:" + "e" * 64]
        if mutation == "platform":
            config_value["architecture"] = "amd64"
        if mutation == 'foreign-media':
            layer['mediaType'] = 'application/octet-stream'
        cfg = fixture.blob(config_value, CONFIG)
        manifest = fixture.blob({"schemaVersion": 2, "mediaType": MANIFEST, "config": cfg, "layers": [layer]}, MANIFEST)
        desc = {
            **manifest,
            "platform": {"os": "unknown", "architecture": "unknown"},
            "annotations": {
                "vnd.docker.reference.type": "attestation-manifest",
                "vnd.docker.reference.digest": image["digest"],
                "com.docker.official-images.bashbrew.arch": "amd64",
            },
        }
        if mutation == "missing-role":
            desc["annotations"].pop("vnd.docker.reference.type")
        if mutation == "dangling":
            desc["annotations"]["vnd.docker.reference.digest"] = "sha256:" + "e" * 64
        if mutation == "self":
            desc["annotations"]["vnd.docker.reference.digest"] = desc["digest"]
        children = [image, desc]
        if mutation == "role-conflict":
            children.append({**manifest, "platform": {"os": "linux", "architecture": "amd64"}})
        index = fixture.blob({"schemaVersion": 2, "mediaType": INDEX, "manifests": children}, INDEX)
        (fixture.layout / "index.json").write_text(
            json.dumps({"schemaVersion": 2, "manifests": [index]}), encoding="utf-8"
        )
        ref = "example.invalid/owned@" + index["digest"]
        fixture.profile["images"] = [ref]
        inventory["images"][0]["reference"] = ref
        catalog["records"][0]["reference"] = ref
        return fixture, inventory, catalog, index, desc, layer, config

    def test_complete_registry_roundtrip_retains_opaque_without_scanner_credit(self):
        f, inventory, catalog, index, desc, layer, config = self.world()
        collector = registry.Registry(transport=object())

        def get(_repository, _kind, digest, _maximum):
            raw = (f.layout / "blobs/sha256" / digest[7:]).read_bytes()
            return {}, raw, None

        with (
            patch.object(collector, "_get", side_effect=get),
            patch("socket.socket", side_effect=AssertionError("no network")),
        ):
            collector._graph("library/owned", index)
        self.assertIn(layer["digest"], collector.blobs)
        with oci.import_layouts(catalog, inventory, f.profile, f.stage) as images:
            image = images[0]
            self.assertEqual(image.config_digest, config["digest"])
            self.assertIn("blobs/sha256/" + layer["digest"][7:], image._files)
            self.assertGreaterEqual(image._budget.totals["unpacked"], layer["size"])
            oci.scanner_identity({"Metadata": {"ImageID": config["digest"]}}, image)
            with self.assertRaises(ValueError):
                oci.scanner_identity({"Metadata": {"ImageID": desc["digest"]}}, image)
            path = image.layout / "blobs/sha256" / layer["digest"][7:]
            path.write_bytes(b"x" * layer["size"])
            with self.assertRaises(ValueError):
                oci.scanner_identity({"Metadata": {"ImageID": config["digest"]}}, image)
        self.assertEqual(list(f.stage.iterdir()), [])

    def test_missing_or_conflicting_roles_and_config_proofs_refuse(self):
        for mutation in ("missing-role", "dangling", "self", "role-conflict", "platform", "diff", "foreign-media"):
            with self.subTest(mutation=mutation):
                f, inventory, catalog, *_ = self.world(mutation)
                with self.assertRaises(ValueError):
                    with oci.import_layouts(catalog, inventory, f.profile, f.stage):
                        pass
                self.assertEqual(list(f.stage.iterdir()), [])

    def test_generic_media_and_original_aggregate_limits_remain_closed(self):
        f, inventory, catalog, index, desc, layer, _ = self.world()
        with self.assertRaises(ValueError):
            oci._descriptor(layer)
        self.assertNotIn(OPAQUE, oci.LAYER_MEDIA)
        f.profile["max_unpacked_bytes"] = layer["size"] - 1
        with self.assertRaises(ValueError):
            with oci.import_layouts(catalog, inventory, f.profile, f.stage):
                pass
        self.assertEqual(list(f.stage.iterdir()), [])
