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

    def test_debian_release_and_epoch_are_part_of_the_exact_installed_version(self):
        package = dict(Name="postgresql-client-15", Version="15.20", Release="0+deb12u1", Arch="amd64")
        image = SimpleNamespace(config_digest="fixture")
        report = dict(SchemaVersion=2, ArtifactType="container_image", Metadata={"ImageID": "fixture"},
                      Results=[dict(Class="os-pkgs", Type="debian", Target="Debian", Packages=[package])])
        expected = ("postgresql-client-15", "15.20-0+deb12u1", "amd64")
        self.assertEqual(package_index(report, image)[("debian", "")], {expected})
        package.update(Epoch=1)
        self.assertNotIn(expected, package_index(report, image)[("debian", "")])
        self.assertIn(("postgresql-client-15", "1:15.20-0+deb12u1", "amd64"), package_index(report, image)[("debian", "")])

    def test_vendored_vulnerable_docker_cli_is_blocked_even_under_another_name(self):
        from getzilla.security_image_package_coverage import VulnerableImageBinary, check_known_binary
        image = SimpleNamespace(config_digest="config", manifest_digest="manifest")
        row = dict(path="other/name", layer="layer",
                   sha256="f71558dcbb6c2e028fc5c7cf67270ef6fafd9cc865570b73700d405b2c2ebc02")
        with self.assertRaises(VulnerableImageBinary) as failed:
            check_known_binary(row, image)
        self.assertEqual(failed.exception.report["cves"], ["CVE-2026-85747"])
        self.assertEqual(failed.exception.report["kind"], "image-component-vulnerability")
        self.assertIsNone(check_known_binary(dict(row, sha256="0"*64), image))

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

    def test_debian_go_coverage_requires_exact_upstream_executable_installed_owner_and_scanned_version(self):
        from getzilla.security_image_package_coverage import debian_go_coverage, _DEBIAN_GO
        sha, name, version, _ = _DEBIAN_GO["usr/bin/ctr"]
        row = dict(path="usr/bin/ctr", sha256=sha, layer="observed-layer")
        index = {("debian", ""): {(name, version, "amd64")}}
        owners = {f"deb:{name}:amd64@{version}"}
        self.assertEqual(debian_go_coverage(row, owners, index)["provider"], "trivy-debian")
        self.assertIsNone(debian_go_coverage(dict(row, sha256="0"*64), owners, index))
        self.assertIsNone(debian_go_coverage(row, owners | {"other"}, index))
        self.assertIsNone(debian_go_coverage(row, owners, {}))

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
