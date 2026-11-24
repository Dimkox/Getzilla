"""Tiny held image component data; no registry, daemon or executable images."""

import hashlib
import sys
from pathlib import Path
import unittest

from tests.test_ci_image_license_inputs import RequestedImageMembersTests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".getzilla"))

import json

MIT = json.loads((Path(__file__).parent / "fixtures/security-license-texts.json").read_text())["MIT"]["text"].encode()
COPY = (
    b"Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n\nFiles: *\nCopyright: Example\nLicense: MIT\n"
    + b"".join(b" " + (line or b".") + b"\n" for line in MIT.splitlines())
)


class ImageComponentTests(unittest.TestCase):
    setUp = RequestedImageMembersTests.setUp
    blob = RequestedImageMembersTests.blob
    image = RequestedImageMembersTests.image

    def api(self):
        from getzilla import security_oci

        return security_oci

    def observe(self, layers):
        from getzilla import security_image_licenses as license_api

        api = self.api()
        inv, cat = self.image(layers)
        with api.import_layouts(cat, inv, self.profile, self.stage) as images:
            result = license_api.observe_components(images[0])
            return result.document()

    def debian(self):
        return [
            (
                "var/lib/dpkg/status",
                b"Package: tiny\nStatus: install ok installed\nVersion: 1\nArchitecture: amd64\n\n",
            ),
            ("var/lib/dpkg/info/tiny.list", b"/usr/bin/tiny\n/usr/share/doc/tiny/copyright\n"),
            ("usr/bin/tiny", b"\x7fELFtiny"),
            ("usr/share/doc/tiny/copyright", COPY),
        ]

    def test_actual_dpkg_component_hash_and_complete_terms(self):
        value = self.observe([self.debian()])
        self.assertEqual(value["unresolved"], [])
        self.assertTrue(value["complete"])
        c = value["components"][0]
        self.assertEqual(c["id"], "deb:tiny:amd64@1")
        self.assertEqual(c["expression"], "MIT")
        self.assertEqual(c["files"][0]["sha256"], hashlib.sha256(b"\x7fELFtiny").hexdigest())
        self.assertTrue(c["license_paths"])

    def test_declared_mit_without_fulltext_is_unknown(self):
        rows = self.debian()
        rows[-1] = (rows[-1][0], COPY.split(b"Permission")[0])
        value = self.observe([rows])
        self.assertFalse(value["complete"])
        self.assertIn("license-term-unproved", {x["code"] for x in value["unresolved"]})

    def test_removed_software_is_not_historical_component(self):
        value = self.observe([self.debian(), [("usr/bin/.wh.tiny", b"")]])
        self.assertNotIn("usr/bin/tiny", [v["path"] for v in value["components"][0]["files"]])

    def test_unknown_installed_elf_and_apk_explicit(self):
        value = self.observe([[("usr/bin/alien", b"\x7fELFalien"), ("lib/apk/db/installed", b"P:alpine\nV:1\n")]])
        self.assertFalse(value["complete"])
        self.assertEqual(
            {"unsupported-apk-components", "unattributed-software"}, {x["code"] for x in value["unresolved"]}
        )

    def test_python_metadata_record_actual_license(self):
        body = b"print(1)\n"
        import base64

        h = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=")
        prefix = "usr/local/lib/python3.13/site-packages/"
        rows = [
            (prefix + "thing.py", body),
            (
                prefix + "thing-1.dist-info/METADATA",
                b"Name: thing\nVersion: 1\nLicense-Expression: MIT\nLicense-File: LICENSE\n",
            ),
            (prefix + "thing-1.dist-info/RECORD", b"thing.py,sha256=" + h + b",9\n"),
            (prefix + "thing-1.dist-info/licenses/LICENSE", MIT),
        ]
        value = self.observe([rows])
        self.assertTrue(value["complete"])
        self.assertEqual(value["components"][0]["id"], "pypi:thing@1")

    def test_record_hash_mismatch_does_not_attest_installation(self):
        prefix = "opt/site-packages/"
        value = self.observe(
            [
                [
                    (prefix + "thing.py", b"wrong"),
                    (
                        prefix + "thing-1.dist-info/METADATA",
                        b"Name: thing\nVersion: 1\nLicense-Expression: MIT\nLicense-File: LICENSE\n",
                    ),
                    (prefix + "thing-1.dist-info/RECORD", b"thing.py,sha256=AAAA,5\n"),
                    (prefix + "thing-1.dist-info/licenses/LICENSE", MIT),
                ]
            ]
        )
        self.assertIn("python-record-mismatch", {x["code"] for x in value["unresolved"]})

    def test_observation_expires_and_caller_json_cannot_supply_files(self):
        from getzilla import security_image_licenses as license_api

        a = self.api()
        inv, cat = self.image([self.debian()])
        with a.import_layouts(cat, inv, self.profile, self.stage) as images:
            result = license_api.observe_components(images[0])
            self.assertTrue(result.document()["complete"])
        with self.assertRaises(ValueError):
            result.document()
        with self.assertRaises(ValueError):
            license_api.observe_components({"complete": True})

    def test_unrecognized_additional_terms_cannot_hide_behind_mit(self):
        prefix = "opt/site-packages/"
        rows = [
            (
                prefix + "thing-1.dist-info/METADATA",
                b"Name: thing\nVersion: 1\nLicense-Expression: MIT\nLicense-File: LICENSE\nLicense-File: EXTRA\n",
            ),
            (prefix + "thing-1.dist-info/RECORD", b""),
            (prefix + "thing-1.dist-info/licenses/LICENSE", MIT),
            (prefix + "thing-1.dist-info/licenses/EXTRA", b"Extra restrictions apply."),
        ]
        value = self.observe([rows])
        self.assertFalse(value["complete"])

    def test_nonexecutable_unowned_source_is_a_finite_software_gap(self):
        value = self.observe([[("app/main.py", b"print(1)\n")]])
        self.assertIn("unattributed-software", {x["code"] for x in value["unresolved"]})

    def test_owned_go_binary_still_requires_bundled_component_data(self):
        rows = self.debian()
        rows[2] = (rows[2][0], b"\x7fELF\xff Go buildinf:some actual data")
        value = self.observe([rows])
        self.assertIn("unsupported-go-components", {x["code"] for x in value["unresolved"]})

    def test_live_observation_cannot_survive_blob_tamper(self):
        from getzilla import security_image_licenses as license_api

        a = self.api()
        inv, cat = self.image([self.debian()])
        with a.import_layouts(cat, inv, self.profile, self.stage) as images:
            result = license_api.observe_components(images[0])
            image = images[0]
            target = image.layout / "blobs/sha256" / image.config_digest[7:]
            body = target.read_bytes()
            target.write_bytes(b"x" * len(body))
            with self.assertRaises(ValueError):
                result.document()

    def test_component_dictionary_mutation_does_not_change_observation(self):
        from getzilla import security_image_licenses as license_api

        a = self.api()
        inv, cat = self.image([self.debian()])
        with a.import_layouts(cat, inv, self.profile, self.stage) as images:
            result = license_api.observe_components(images[0])
            first = result.document()
            first["components"].clear()
            self.assertEqual(len(result.document()["components"]), 1)

    def linked_image(self, layers):
        import gzip
        import io
        import json
        import tarfile
        from tests.test_offline_oci_import import LAYER, CONFIG, MANIFEST

        descriptors, diffs = [], []
        for rows in layers:
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w") as archive:
                for name, body, mode in rows:
                    item = tarfile.TarInfo(name)
                    item.mode = 0o644
                    if mode == "symlink":
                        item.type, item.linkname = tarfile.SYMTYPE, body
                    elif mode == "hardlink":
                        item.type, item.linkname = tarfile.LNKTYPE, body
                    else:
                        item.size = len(body)
                        item.mode = mode
                    archive.addfile(item, None if isinstance(mode, str) else io.BytesIO(body))
            raw = buffer.getvalue()
            descriptors.append(self.blob(gzip.compress(raw), LAYER))
            diffs.append("sha256:" + hashlib.sha256(raw).hexdigest())
        config = self.blob(dict(os="linux", architecture="amd64", rootfs=dict(type="layers", diff_ids=diffs)), CONFIG)
        manifest = self.blob(dict(schemaVersion=2, mediaType=MANIFEST, config=config, layers=descriptors), MANIFEST)
        (self.layout / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
        (self.layout / "index.json").write_text(json.dumps(dict(schemaVersion=2, manifests=[manifest])))
        ref = "example.invalid/owned@" + manifest["digest"]
        self.profile["images"] = [ref]
        return dict(
            digest="d" * 64, complete=True, gaps=[], images=[dict(reference=ref, platform="linux/amd64")]
        ), dict(
            schema_version=1,
            inventory_sha256="d" * 64,
            records=[dict(reference=ref, platform="linux/amd64", layout=str(self.layout))],
        )

    def test_common_term_symlink_is_data_and_shared_by_two_components(self):
        from getzilla import security_image_licenses as license_api

        rows = self.debian()
        rows[-1] = (
            rows[-1][0],
            b"Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n\nFiles: *\nCopyright: Example\nLicense: MIT\n See /usr/share/common-licenses/MIT\n",
        )
        rows[0] = (
            rows[0][0],
            rows[0][1] + b"Package: tiny2\nStatus: install ok installed\nVersion: 1\nArchitecture: amd64\n\n",
        )
        rows.extend([("var/lib/dpkg/info/tiny2.list", b"/usr/bin/tiny2\n"), ("usr/bin/tiny2", b"\x7fELFtwo")])
        layers = [
            [(p, b, 0o644) for p, b in rows]
            + [
                ("usr/share/doc/tiny2/copyright", "../tiny/copyright", "symlink"),
                ("usr/share/common-licenses/MIT", "MIT-full", "symlink"),
                ("usr/share/common-licenses/MIT-full", MIT, 0o644),
            ]
        ]
        a = self.api()
        inv, cat = self.linked_image(layers)
        with a.import_layouts(cat, inv, self.profile, self.stage) as images:
            document = license_api.observe_components(images[0]).document()
            self.assertTrue(document["complete"])
            self.assertEqual(len(document["components"]), 2)
            for c in document["components"]:
                self.assertIn("usr/share/common-licenses/MIT-full", [p["path"] for p in c["license_paths"]])

    def test_alias_cycle_does_not_follow_host_paths(self):
        from getzilla import security_image_licenses as license_api

        layers = [
            [
                (
                    "var/lib/dpkg/status",
                    b"Package: tiny\nStatus: install ok installed\nVersion: 1\nArchitecture: amd64\n\n",
                    0o644,
                ),
                ("var/lib/dpkg/info/tiny.list", "tiny.list", "symlink"),
            ]
        ]
        a = self.api()
        inv, cat = self.linked_image(layers)
        with a.import_layouts(cat, inv, self.profile, self.stage) as images:
            with self.assertRaisesRegex(ValueError, "Cyclic"):
                license_api.observe_components(images[0])

    def test_imported_component_facts_reuse_bytes_and_recheck_live_blobs(self):
        from getzilla.security_image_licenses import _retain

        api = self.api()
        inv, cat = self.linked_image([
            [("pkg/LICENSE", b"first", 0o644), ("pkg/other", "pkg/LICENSE", "hardlink")],
            [("pkg/.wh.LICENSE", b"", 0o644), ("pkg/LICENSE", b"second", 0o644)],
        ])
        with api.import_layouts(cat, inv, self.profile, self.stage) as images:
            expected = api.observe_final_files(images[0], _retain)
        with api.import_layouts(cat, inv, self.profile, self.stage, index_components=True) as images:
            image = images[0]
            before = dict(image._budget.totals)
            actual = api.observe_final_files(image, _retain)
            self.assertEqual(actual, expected)
            self.assertEqual(actual["pkg/other"]["body"], b"first")
            self.assertEqual(image._budget.totals["entries"], before["entries"])
            self.assertEqual(image._budget.totals["unpacked"], before["unpacked"])
            actual["pkg/LICENSE"]["body"] = b"modified"
            self.assertEqual(api.observe_final_files(image, _retain), expected)
            manifest = json.loads((image.layout / "blobs/sha256" / image.manifest_digest[7:]).read_bytes())
            layer = image.layout / "blobs/sha256" / manifest["layers"][0]["digest"][7:]
            layer.write_bytes(bytes(layer.stat().st_size))
            with self.assertRaisesRegex(api.OCIError, "blob changed"):
                api.observe_final_files(image, _retain)

    def test_component_cache_bound_falls_back_and_cache_hit_keeps_proof_limit(self):
        from unittest.mock import patch
        from getzilla.security_image_licenses import _retain

        api = self.api()
        inv, cat = self.image([[("LICENSE", b"abc")]])
        with patch.object(api, "_COMPONENT_CACHE_BYTES", 1):
            with api.import_layouts(cat, inv, self.profile, self.stage, index_components=True) as images:
                image = images[0]
                before = image._budget.totals["entries"]
                self.assertEqual(api.observe_final_files(image, _retain)["LICENSE"]["body"], b"abc")
                self.assertEqual(image._budget.totals["entries"], before + 1)
        with api.import_layouts(cat, inv, self.profile, self.stage, index_components=True) as images:
            image = images[0]
            image._budget._component_proof_bytes = api._COMPONENT_PROOFS_TOTAL
            with self.assertRaisesRegex(api.OCIError, "proof exceeds bound"):
                api.observe_final_files(image, _retain)

    def test_shared_proof_counter_enforces_limit_before_body_read(self):
        a = self.api()
        inv, cat = self.image([self.debian()])
        with a.import_layouts(cat, inv, self.profile, self.stage) as images:
            images[0]._budget._component_proof_bytes = 512 * 1024 * 1024
            with self.assertRaisesRegex(ValueError, "package proof"):
                a.observe_final_files(images[0], lambda p: True)

    def test_opaque_whiteout_keeps_same_layer_new_final_data(self):
        from getzilla import security_image_licenses as license_api

        rows = self.debian()
        a = self.api()
        inv, cat = self.image([rows, [("usr/share/doc/tiny/.wh..wh..opq", b""), rows[-1]]])
        with a.import_layouts(cat, inv, self.profile, self.stage) as images:
            self.assertTrue(license_api.observe_components(images[0]).document()["complete"])

    def test_source_only_copyright_globs_do_not_choose_binary_license(self):
        rows = self.debian()
        rows[-1] = (rows[-1][0], COPY + b"\nFiles: docs/*\nCopyright: Other\nLicense: custom\n Full custom terms.\n")
        value = self.observe([rows])
        self.assertIn("dpkg-binary-license-scope", {v["code"] for v in value["unresolved"]})

    def test_cpython_umbrella_does_not_close_bundled_extensions(self):
        value = self.observe(
            [
                [
                    ("usr/local/lib/python3.13/LICENSE.txt", b"PSF history terms"),
                    ("usr/local/lib/python3.13/lib-dynload/zlib.cpython-313-x86_64-linux-gnu.so", b"\x7fELFext"),
                ]
            ]
        )
        self.assertIn("cpython-bundled-terms-unproved", {v["code"] for v in value["unresolved"]})
        self.assertEqual(len(value["components"]), 1)

    def test_vendor_component_catalog_is_not_repeated_for_each_distribution(self):
        root = "usr/local/lib/python3.13/site-packages/"
        rows = []
        for name in ("pip", "app"):
            rows.extend(
                [
                    (
                        root + name + "-1.dist-info/METADATA",
                        ("Name: " + name + "\nVersion: 1\nLicense-Expression: MIT\nLicense-File: LICENSE\n").encode(),
                    ),
                    (root + name + "-1.dist-info/RECORD", b""),
                    (root + name + "-1.dist-info/licenses/LICENSE", MIT),
                ]
            )
        rows.extend(
            [
                (root + "pip/_vendor/vendor.txt", b"example==1\n"),
                (root + "pip/_vendor/example/__init__.py", b""),
                (root + "pip/_vendor/example/LICENSE", MIT),
            ]
        )
        value = self.observe([rows])
        self.assertEqual(len([c for c in value["components"] if c["kind"] == "python-vendored"]), 1)

    def test_postgres_group_does_not_receive_global_root_license(self):
        rows = self.debian()
        rows[0] = (rows[0][0], rows[0][1].replace(b"tiny", b"postgresql-17"))
        rows[1] = ("var/lib/dpkg/info/postgresql-17.list", b"/usr/bin/tiny\n")
        rows[-1] = ("usr/share/doc/postgresql-17/copyright", COPY)
        value = self.observe([rows])
        self.assertIn("unsupported-postgres-components", {x["code"] for x in value["unresolved"]})

    def test_hardlink_keeps_original_inode_when_target_path_is_overwritten(self):
        a = self.api()
        inv, cat = self.linked_image(
            [
                [
                    ("usr/share/common-licenses/MIT", MIT, 0o644),
                    ("usr/share/doc/tiny/copyright", "usr/share/common-licenses/MIT", "hardlink"),
                ],
                [("usr/share/common-licenses/MIT", b"new unrelated file", 0o644)],
            ]
        )
        with a.import_layouts(cat, inv, self.profile, self.stage) as images:
            final = a.observe_final_files(images[0], lambda p: True)
            self.assertEqual(final["usr/share/doc/tiny/copyright"].get("body"), MIT)
            self.assertEqual(final["usr/share/doc/tiny/copyright"]["sha256"], hashlib.sha256(MIT).hexdigest())

    def test_retained_proof_bytes_are_actual_and_expire_with_live_context(self):
        from getzilla import security_image_licenses as license_api

        a = self.api()
        inv, cat = self.image([self.debian()])
        with a.import_layouts(cat, inv, self.profile, self.stage) as images:
            result = license_api.observe_components(images[0])
            proof = result.proof_files()
            self.assertEqual(proof["usr/share/doc/tiny/copyright"], COPY)
            proof.clear()
            self.assertTrue(result.proof_files())
        with self.assertRaises(ValueError):
            result.proof_files()
