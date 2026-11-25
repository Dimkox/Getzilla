"""An image, package family and exact target must agree before scanner credit."""
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from getzilla.security_image_package_coverage import apk_inventory, package_index
from getzilla.security_image_file_origins import archive_origins, project_origins
import hashlib


class PackageEvidenceTests(unittest.TestCase):
    def test_apk_ownership_needs_a_unique_package_and_bound_file_record(self):
        payload = b"P:tiny\nV:1-r0\nA:x86_64\nL:MIT\nF:usr/bin\nR:tiny\nZ:Q1proof\n"
        record = apk_inventory(payload)[("tiny", "1-r0", "x86_64")]
        self.assertEqual(record, ("MIT", {"usr/bin/tiny": "Q1proof"}))
        for bad in (payload.replace(b"F:usr/bin\n", b""), payload.replace(b"R:tiny", b"R:../tiny"),
                    payload + b"Z:Q1second\n", payload + b"\n" + payload):
            with self.assertRaises(ValueError):
                apk_inventory(bad)

    def test_go_needs_a_versioned_root_at_the_exact_scanned_path(self):
        report = dict(SchemaVersion=2, ArtifactType="container_image", Metadata={"ImageID": "fixture"},
                      Results=[dict(Class="lang-pkgs", Type="gobinary", Target="usr/bin/tiny",
                                    Packages=[dict(Name="example/tiny", Version="v1.0", Relationship="root")])])
        image = SimpleNamespace(config_digest="fixture")
        self.assertIn(("gobinary", "usr/bin/tiny"), package_index(report, image))
        self.assertNotIn(("gobinary", "usr/bin/other"), package_index(report, image))
        with self.assertRaises(ValueError):
            package_index(report, SimpleNamespace(config_digest="other"))
        report["Results"][0]["Packages"][0].pop("Relationship")
        self.assertEqual(package_index(report, image), {})

    def test_upstream_support_script_requires_its_exact_path_hash_and_layer(self):
        from getzilla.security_image_file_origins import upstream_origin
        row = dict(path="usr/local/bin/dind",
                   sha256="673bb7adc8b463b56e9e929672ea74b40951f655a023d0b9801f46c9da4bc509",
                   layer="replace-layer")
        self.assertIsNone(upstream_origin(row))
        row["layer"] = "sha256:21f6d15792afa1fa17a8ae24fea133929514be58ade0f07e0589d55c54a97f33"
        self.assertIn("moby/moby", upstream_origin(row))
        self.assertIsNone(upstream_origin(dict(row, sha256="0" * 64)))
        self.assertIsNone(upstream_origin(dict(row, path="usr/local/bin/other")))

    def test_same_path_with_different_source_bytes_cannot_establish_ownership(self):
        body = b"owned"
        row = dict(path="opt/adaptive-trust-ci/src/x.py", sha256=hashlib.sha256(body).hexdigest(), bytes=len(body))
        with TemporaryDirectory() as temp:
            path = Path(temp) / "trust-ci/src/x.py"
            path.parent.mkdir(parents=True)
            path.write_bytes(body)
            self.assertEqual(project_origins([row], temp)[0]["source"], "trust-ci/src/x.py")
            path.write_bytes(b"other")
            self.assertEqual(project_origins([row], temp), [])
        self.assertEqual(archive_origins([dict(row, path="opt/node/bin/node")]), [])
