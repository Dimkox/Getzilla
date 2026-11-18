"""Tiny complete retained-shape graph; no downloads, scanners or execution."""

import gzip
import hashlib
import io
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".getzilla"))
from getzilla import security_oci as oci

# Platform tuples from retained postgres17-alpine index a77aa70e... (10301B),
# independently observed as8runnable+8linked attestations. Fixture bytes below
# are owned tiny data, not those public images or a published-image claim.
PLATFORMS = (
    ("amd64", None),
    ("arm", "v6"),
    ("arm", "v7"),
    ("arm64", "v8"),
    ("386", None),
    ("ppc64le", None),
    ("riscv64", None),
    ("s390x", None),
)


def owned_graph(root, *, defect=None, config_variants=True):
    blobs = root / "blobs/sha256"
    blobs.mkdir(parents=True)

    def blob(media, raw):
        digest = hashlib.sha256(raw).hexdigest()
        (blobs / digest).write_bytes(raw)
        return dict(mediaType=media, digest="sha256:" + digest, size=len(raw))

    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        item = tarfile.TarInfo("owned-marker")
        item.size = 6
        archive.addfile(item, io.BytesIO(b"owned\n"))
    raw = stream.getvalue()
    layer = blob(oci.GZIP, gzip.compress(raw, mtime=0))
    children = []
    selected_config = None
    for architecture, variant in PLATFORMS:
        claim = dict(os="linux", architecture=architecture)
        if variant:
            claim["variant"] = variant
        config = dict(
            os="linux",
            architecture=architecture,
            rootfs=dict(type="layers", diff_ids=["sha256:" + hashlib.sha256(raw).hexdigest()]),
        )
        config["config"] = {"Labels": {"owned.fixture.platform": architecture + "/" + str(variant)}}
        if config_variants and variant:
            config["variant"] = variant
        if architecture == "amd64" and defect in {"amd64-v7", "amd64-v8"}:
            claim["variant"] = defect[6:]
        if architecture == "arm" and variant == "v6":
            if defect == "foreign-variant":
                claim["variant"] = "v9"
            if defect == "unknown-combination":
                claim.update(architecture="owned-unknown", variant="v7")
                config.update(architecture="owned-unknown", variant="v7")
            if defect == "config-mismatch":
                config["variant"] = "v7"
            if defect == "config-architecture":
                config["architecture"] = "amd64"
        config_desc = blob(oci.CONFIG, oci.canonical(config))
        manifest = blob(
            oci.MANIFEST,
            oci.canonical(dict(schemaVersion=2, mediaType=oci.MANIFEST, config=config_desc, layers=[layer])),
        )
        manifest["platform"] = claim
        if architecture == "amd64":
            selected_config = config_desc["digest"]
        opaque = blob(oci.OPAQUE_ATTESTATION, oci.canonical({"owned_subject": manifest["digest"]}))
        compatibility = blob(
            oci.CONFIG,
            oci.canonical(
                dict(
                    os="unknown",
                    architecture="unknown",
                    config={},
                    rootfs=dict(type="layers", diff_ids=[opaque["digest"]]),
                )
            ),
        )
        attestation = blob(
            oci.MANIFEST,
            oci.canonical(dict(schemaVersion=2, mediaType=oci.MANIFEST, config=compatibility, layers=[opaque])),
        )
        attestation.update(
            platform=dict(os="unknown", architecture="unknown"),
            annotations={
                "vnd.docker.reference.type": "attestation-manifest",
                "vnd.docker.reference.digest": manifest["digest"],
            },
        )
        children.extend((manifest, attestation))
    index = blob(oci.INDEX, oci.canonical(dict(schemaVersion=2, mediaType=oci.INDEX, manifests=children)))
    (root / "oci-layout").write_bytes(oci.canonical({"imageLayoutVersion": "1.0.0"}))
    (root / "index.json").write_bytes(oci.canonical(dict(schemaVersion=2, mediaType=oci.INDEX, manifests=[index])))
    reference = "owned.local/variants@" + index["digest"]
    inventory = dict(complete=True, gaps=[], images=[dict(reference=reference, platform="linux/amd64")])
    inventory["digest"] = hashlib.sha256(oci.canonical(inventory)).hexdigest()
    catalog = dict(
        schema_version=1,
        inventory_sha256=inventory["digest"],
        records=[dict(reference=reference, platform="linux/amd64", layout=str(root))],
    )
    profile = dict(oci.LIMITS, images=[reference], platform="linux/amd64")
    return catalog, inventory, profile, selected_config, {p.name for p in blobs.iterdir()}


class VariantGraphControls(unittest.TestCase):
    def setUp(self):
        previous = os.umask(0o077)
        self.addCleanup(os.umask, previous)
        for name in ("socket.socket", "socket.getaddrinfo", "subprocess.Popen"):
            port = mock.patch(name, side_effect=AssertionError("outside fixture effect denied"))
            port.start()
            self.addCleanup(port.stop)

    def test_complete_eight_platform_sixteen_child_graph_keeps_arm6_arm7_and_attestations(self):
        for explicit_config in (False, True):
            with (
                self.subTest(explicit_config=explicit_config),
                tempfile.TemporaryDirectory(dir=ROOT / ".getzilla/runtime") as directory,
            ):
                workspace = Path(directory)
                catalog, inventory, profile, selected, blobs = owned_graph(
                    workspace / "layout", config_variants=explicit_config
                )
                try:
                    with oci.import_layouts(catalog, inventory, profile, workspace) as images:
                        self.assertEqual(len(images), 1)
                        self.assertEqual(images[0].config_digest, selected)
                        self.assertEqual({p.name for p in (images[0].layout / "blobs/sha256").iterdir()}, blobs)
                        entry = oci.document((images[0].layout / "index.json").read_bytes())
                        self.assertEqual(len(entry["manifests"]), 1)
                        self.assertEqual(entry["manifests"][0]["platform"], dict(os="linux", architecture="amd64"))
                except oci.OCIError as error:
                    self.fail("complete owned retained-shape graph refused: " + str(error))

    def test_wrong_architecture_variant_and_config_combinations_refuse(self):
        for defect in (
            "amd64-v7",
            "amd64-v8",
            "foreign-variant",
            "unknown-combination",
            "config-mismatch",
            "config-architecture",
        ):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory(dir=ROOT / ".getzilla/runtime") as directory:
                workspace = Path(directory)
                catalog, inventory, profile, _selected, _blobs = owned_graph(workspace / "layout", defect=defect)
                with self.assertRaises(oci.OCIError):
                    with oci.import_layouts(catalog, inventory, profile, workspace):
                        self.fail("invalid platform proof accepted")
