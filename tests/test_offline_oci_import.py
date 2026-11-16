"""NEW tiny owned OCI bytes only: no old producer, scanner, archive or daemon runs."""

import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

W = Path(__file__).resolve().parents[1]
E = W / ".getzilla/runtime/scratch/new-offline-oci-fixtures"
INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
CONFIG = "application/vnd.oci.image.config.v1+json"
LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"


class OfflineOCIImportTests(unittest.TestCase):
    def api(self):
        p = W / ".getzilla/getzilla/security_oci.py"
        self.assertTrue(p.is_file(), "missing bounded OCI consumer")
        spec = importlib.util.spec_from_file_location("owned_new_oci", p)
        result = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(result)
        return result

    def setUp(self):
        E.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.tmp = tempfile.TemporaryDirectory(dir=E)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.layout = self.root / "layout"
        self.layout.mkdir()
        (self.layout / "blobs/sha256").mkdir(parents=True)
        self.stage = self.root / "stage"
        self.stage.mkdir(mode=0o700)
        self.profile = dict(
            images=[],
            platform="linux/amd64",
            max_images=512,
            max_compressed_bytes=524288000,
            max_unpacked_bytes=524288000,
            max_storage_bytes=524288000,
            max_manifest_bytes=16777216,
            max_layers=10000,
            deadline_seconds=900,
        )

    def blob(self, value, media):
        raw = value if isinstance(value, bytes) else json.dumps(value, separators=(",", ":")).encode()
        sha = hashlib.sha256(raw).hexdigest()
        p = self.layout / "blobs/sha256" / sha
        p.write_bytes(raw)
        p.chmod(0o600)
        return dict(mediaType=media, digest="sha256:" + sha, size=len(raw))

    def artifact(self, arch="amd64", nested=False):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as t:
            item = tarfile.TarInfo("etc/owned.txt")
            item.size = 5
            t.addfile(item, io.BytesIO(b"owned"))
        layer = self.blob(gzip.compress(raw.getvalue()), LAYER)
        config = self.blob(
            dict(
                os="linux",
                architecture=arch,
                rootfs=dict(type="layers", diff_ids=["sha256:" + hashlib.sha256(raw.getvalue()).hexdigest()]),
            ),
            CONFIG,
        )
        manifest = self.blob(dict(schemaVersion=2, mediaType=MANIFEST, config=config, layers=[layer]), MANIFEST)
        selection = dict(manifest, platform=dict(os="linux", architecture=arch))
        entry = self.blob(dict(schemaVersion=2, mediaType=INDEX, manifests=[selection]), INDEX) if nested else selection
        (self.layout / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
        (self.layout / "index.json").write_text(json.dumps(dict(schemaVersion=2, manifests=[entry])))
        ref = "example.invalid/owned@" + entry["digest"]
        self.profile["images"] = [ref]
        inventory = dict(digest="d" * 64, complete=True, gaps=[], images=[dict(reference=ref, platform="linux/amd64")])
        catalog = dict(
            schema_version=1,
            inventory_sha256="d" * 64,
            records=[dict(reference=ref, platform="linux/amd64", layout=str(self.layout))],
        )
        return inventory, catalog, manifest, config, layer

    def test_valid_complete_graph_imports_flat_singleton_and_scanner_identity(self):
        a = self.api()
        inventory, catalog, m, c, _ = self.artifact(nested=True)
        with a.import_layouts(catalog, inventory, self.profile, self.stage) as images:
            image = images[0]
            index = json.loads((image.layout / "index.json").read_bytes())
            self.assertEqual(len(index["manifests"]), 1)
            self.assertEqual(index["manifests"][0]["digest"], m["digest"])
            self.assertEqual(image.config_digest, c["digest"])
            self.assertEqual(image.reference, self.profile["images"][0])
            a.scanner_identity(dict(Metadata=dict(ImageID=c["digest"], RepoDigests=[])), image)
            with self.assertRaises(ValueError):
                a.scanner_identity(dict(Metadata=dict(ImageID="sha256:" + "0" * 64)), image)
        self.assertEqual(list(self.stage.iterdir()), [])

    def test_digest_tamper_and_missing_selected_blob_refuse(self):
        a = self.api()
        inventory, catalog, m, _, _ = self.artifact()
        p = self.layout / "blobs/sha256" / m["digest"][7:]
        before = p.read_bytes()
        p.write_bytes(b"X" * len(before))
        with self.assertRaises(ValueError):
            with a.import_layouts(catalog, inventory, self.profile, self.stage):
                pass
        p.unlink()
        with self.assertRaises(ValueError):
            with a.import_layouts(catalog, inventory, self.profile, self.stage):
                pass
        self.assertEqual(list(self.stage.iterdir()), [])

    def test_descriptor_platform_and_actual_config_platform_both_required(self):
        a = self.api()
        inventory, catalog, _, _, _ = self.artifact("arm64")
        # The descriptor claims the selected platform; config still disagrees.
        index = json.loads((self.layout / "index.json").read_bytes())
        index["manifests"][0]["platform"]["architecture"] = "amd64"
        (self.layout / "index.json").write_text(json.dumps(index))
        with self.assertRaises(ValueError):
            with a.import_layouts(catalog, inventory, self.profile, self.stage):
                pass

    def test_ambiguous_index_and_unbound_inventory_refuse(self):
        a = self.api()
        inventory, catalog, _, _, _ = self.artifact()
        index = json.loads((self.layout / "index.json").read_bytes())
        index["manifests"] *= 2
        (self.layout / "index.json").write_text(json.dumps(index))
        with self.assertRaises(ValueError):
            with a.import_layouts(catalog, inventory, self.profile, self.stage):
                pass
        catalog["inventory_sha256"] = "e" * 64
        with self.assertRaises(ValueError):
            with a.import_layouts(catalog, inventory, self.profile, self.stage):
                pass

    def test_existing_byte_and_layer_ceiling_fail_closed(self):
        a = self.api()
        inventory, catalog, _, _, _ = self.artifact()
        for key in ("max_compressed_bytes", "max_unpacked_bytes", "max_storage_bytes", "max_manifest_bytes"):
            limits = dict(self.profile)
            limits[key] = 1
            with self.assertRaises(ValueError):
                with a.import_layouts(catalog, inventory, limits, self.stage):
                    pass
        limits = dict(self.profile, max_layers=10001)
        with self.assertRaises(ValueError):
            with a.import_layouts(catalog, inventory, limits, self.stage):
                pass

    def test_cross_image_budget_is_aggregate_not_reset(self):
        a = self.api()
        inventory, catalog, _, _, _ = self.artifact()
        reference = self.profile["images"][0]
        other = reference.replace("/owned@", "/second@")
        self.profile["images"].append(other)
        inventory["images"].append(dict(reference=other, platform="linux/amd64"))
        catalog["records"].append(dict(catalog["records"][0], reference=other))
        # Each image alone has one layer; both distinct imported images exceed one.
        self.profile["max_layers"] = 1
        with self.assertRaises(ValueError):
            with a.import_layouts(catalog, inventory, self.profile, self.stage):
                pass

    def test_symlink_and_unsupported_descriptor_algorithm_refuse(self):
        a = self.api()
        inventory, catalog, m, _, _ = self.artifact()
        p = self.layout / "blobs/sha256" / m["digest"][7:]
        data = p.read_bytes()
        p.unlink()
        target = self.root / "external"
        target.write_bytes(data)
        p.symlink_to(target)
        with self.assertRaises(ValueError):
            with a.import_layouts(catalog, inventory, self.profile, self.stage):
                pass
        p.unlink()
        p.write_bytes(data)
        index = json.loads((self.layout / "index.json").read_bytes())
        index["manifests"][0]["digest"] = "sha512:" + "a" * 128
        (self.layout / "index.json").write_text(json.dumps(index))
        with self.assertRaises(ValueError):
            with a.import_layouts(catalog, inventory, self.profile, self.stage):
                pass

    def test_proof_expires_and_changed_private_bytes_refuse(self):
        a = self.api()
        inventory, catalog, _, config, _ = self.artifact()
        report = dict(Metadata=dict(ImageID=config["digest"]))
        with a.import_layouts(catalog, inventory, self.profile, self.stage) as images:
            image = images[0]
            a.scanner_identity(report, image)
        with self.assertRaises(ValueError):
            a.scanner_identity(report, image)
        with a.import_layouts(catalog, inventory, self.profile, self.stage) as images:
            image = images[0]
            blob = image.layout / "blobs/sha256" / config["digest"][7:]
            blob.write_bytes(b"tampered")
            with self.assertRaises(ValueError):
                a.scanner_identity(report, image)

    def test_incomplete_inventory_and_wrong_config_pin_refuse(self):
        a = self.api()
        inventory, catalog, _, _, _ = self.artifact()
        inventory["complete"] = False
        with self.assertRaises(ValueError):
            with a.import_layouts(catalog, inventory, self.profile, self.stage):
                pass
        inventory["complete"] = True
        inventory["images"][0]["image_id"] = "sha256:" + "0" * 64
        with self.assertRaises(ValueError):
            with a.import_layouts(catalog, inventory, self.profile, self.stage):
                pass

    def test_real_offline_consumers_with_denied_scanner_and_owned_report(self):
        # Only the changed offline branches run. No real scanner/DB observation.
        import sys
        from types import SimpleNamespace
        from unittest.mock import patch

        sys.path.insert(0, str(W / ".getzilla"))
        with patch("subprocess.Popen", side_effect=AssertionError("native process denied")):
            from getzilla import security_tools as tools

            inventory, catalog, manifest, config, _ = self.artifact(nested=True)
            catalog_path = self.root / "catalog.json"
            catalog_path.write_text(json.dumps(catalog))
            catalog_path.chmod(0o600)
            with patch.object(
                tools, "pinned_tool", side_effect=AssertionError("tool lookup denied during local import")
            ):
                observation = tools.refresh_images(
                    inventory, self.stage, profile=self.profile, image_artifacts=catalog_path
                )
            self.assertEqual(observation[0]["kind"], "oci-local-import")
            self.assertEqual(observation[0]["images"][0]["manifest_sha256"], manifest["digest"])
            seen = []
            wrong = [False]

            def process(argv, cwd, scratch, **kwargs):
                self.assertIn("--input", argv)
                self.assertNotIn("--image-src", argv)
                selected = argv[argv.index("--input") + 1]
                directory, digest = selected.rsplit("@", 1)
                self.assertEqual(digest, manifest["digest"])
                index = json.loads((Path(directory) / "index.json").read_bytes())
                self.assertEqual([row["digest"] for row in index["manifests"]], [digest])
                report = dict(
                    SchemaVersion=2,
                    ArtifactType="container_image",
                    Metadata=dict(ImageID="sha256:" + "0" * 64 if wrong[0] else config["digest"], RepoDigests=[]),
                    Results=[
                        dict(Class="os-pkgs", Packages=[dict(Name="owned-fixture", Version="1")], Vulnerabilities=[])
                    ],
                )
                Path(argv[argv.index("--output") + 1]).write_text(json.dumps(report))
                seen.append(selected)
                return SimpleNamespace(returncode=0)

            env = {
                "GETZILLA_SECURITY_TOOLS": str(self.stage),
                "GETZILLA_SECURITY_IMAGE_ARTIFACTS": str(catalog_path),
                "GETZILLA_SECURITY_IMAGE_PROFILE": json.dumps(self.profile),
            }
            with (
                patch.object(tools, "pinned_tool", return_value=self.root / "UNEXECUTED-scanner"),
                patch.object(tools, "trivy_database_source", return_value={"source_id": "owned-mocked-db"}),
                patch.object(tools, "_process", side_effect=process),
            ):
                controlled = tools.scan_images(inventory, environ=env)
                self.assertEqual(controlled["outcome"], "pass", controlled["gaps"])
                wrong[0] = True
                refused = tools.scan_images(inventory, environ=env)
                self.assertEqual(refused["outcome"], "blocked")
                self.assertEqual(refused["gaps"][0]["code"], "image-scan-unavailable")
            from contextlib import nullcontext
            from getzilla import security_oci

            with (
                patch.object(security_oci, "import_layouts", return_value=nullcontext([])),
                patch.object(tools, "pinned_tool", return_value=self.root / "UNEXECUTED-scanner"),
                patch.object(tools, "trivy_database_source", return_value={"source_id": "owned-mocked-db"}),
                patch.object(tools, "_process", return_value=SimpleNamespace(returncode=1)) as denied,
            ):
                refused = tools.scan_images(inventory, environ=env)
                self.assertEqual(refused["outcome"], "blocked")
                self.assertEqual(denied.call_count, 0, "missing offline identity fell back to daemon")
            self.assertEqual(len(seen), 2)
            self.assertFalse(any(p.name.startswith("verified-oci-") for p in self.stage.rglob("*")))

    def test_shared_deadline_reaches_offline_scanner(self):
        from unittest.mock import patch

        a = self.api()
        inventory, catalog, _, _, _ = self.artifact()
        clock = [0.0]
        with patch.object(a.time, "monotonic", side_effect=lambda: clock[0]):
            with a.import_layouts(catalog, inventory, self.profile, self.stage) as images:
                image = images[0]
                self.assertTrue(hasattr(image, "remaining_seconds"), "shared scanner deadline missing")
                clock[0] = 899.5
                self.assertLessEqual(image.remaining_seconds(), 0.5)
                clock[0] = 901
                with self.assertRaises(ValueError):
                    image.remaining_seconds()
                clock[0] = 0.0

    def test_complete_existing_consumers_reference_offline_path(self):
        tools = (W / ".getzilla/getzilla/security_tools.py").read_text()
        cli = (W / ".getzilla/getzilla/security_cli.py").read_text()
        self.assertTrue("import_layouts(" in tools, "offline importer not connected")
        self.assertTrue("verified_oci=" in tools, "verified scanner identity not connected")
        self.assertTrue("--input" in tools, "offline scanner path missing")
        self.assertTrue("--image-artifacts" in cli, "explicit artifact input missing")
        self.assertTrue("image_artifacts=args.image_artifacts" in cli, "supervised input forwarding missing")


if __name__ == "__main__":
    unittest.main(verbosity=2)
