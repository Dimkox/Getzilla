"""Real owned TAR work only; no project graphs, network, processes or kernel jobs."""

from contextlib import ExitStack
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


@unittest.skipUnless(os.name == "posix", "existing OCI importer requires held POSIX descriptors")
class LayerReuseControls(unittest.TestCase):
    def setUp(self):
        effects = ExitStack()
        self.addCleanup(effects.close)
        for port in ("socket.socket", "socket.getaddrinfo", "subprocess.Popen", "subprocess.run"):
            effects.enter_context(mock.patch(port, side_effect=AssertionError("outside effects denied")))
        temporary = tempfile.TemporaryDirectory(dir=ROOT / ".getzilla/runtime")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.profile = dict(oci.LIMITS, images=[], platform="linux/amd64")
        self.ledger = oci._Budget(self.profile)

    def layer(self, name="owned", *, count=1, link=None):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as archive:
            for _ in range(count):
                member = tarfile.TarInfo(name)
                if link is not None:
                    member.type = tarfile.SYMTYPE
                    member.linkname = link
                payload = b"owned" if count == 1 and link is None else b""
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
        decoded = raw.getvalue()
        compressed = gzip.compress(decoded, mtime=0)
        path = self.root / ("layer-" + str(len(list(self.root.iterdir()))))
        path.write_bytes(compressed)
        expected = "sha256:" + hashlib.sha256(decoded).hexdigest()
        key = (hashlib.sha256(compressed).hexdigest(), len(compressed), oci.GZIP, expected)
        return path, expected, key, len(decoded)

    def test_hit_avoids_tar_and_gzip_but_preserves_byte_and_layer_weights(self):
        path, expected, _key, decoded = self.layer()
        other = self.root / "independent-copy"
        other.write_bytes(path.read_bytes())
        real_tar, real_gzip = tarfile.open, gzip.GzipFile
        with (
            mock.patch.object(oci.tarfile, "open", wraps=real_tar) as parser,
            mock.patch.object(oci.gzip, "GzipFile", wraps=real_gzip) as decompress,
        ):
            oci._layer(path, oci.GZIP, expected, self.ledger)
            first = dict(self.ledger.totals)
            oci._layer(other, oci.GZIP, expected, self.ledger)
            self.assertEqual(parser.call_count, 1, "hit must do no second TAR parse")
            self.assertEqual(decompress.call_count, 1, "hit must do no second gzip decode")
        self.assertEqual(self.ledger.totals["entries"], 1)
        self.assertEqual(self.ledger.totals["layers"], 2)
        self.assertEqual(self.ledger.totals["unpacked"], 2 * decoded)
        self.assertGreater(first["expanded"], 0)
        self.assertEqual(self.ledger.totals["expanded"], 2 * first["expanded"])

    def test_changed_current_bytes_and_wrong_diffid_cannot_hit(self):
        path, expected, _key, _decoded = self.layer()
        oci._layer(path, oci.GZIP, expected, self.ledger)
        original = path.read_bytes()
        path.write_bytes(original[:-8] + b"changed!")
        with self.assertRaises((oci.OCIError, EOFError, OSError)):
            oci._layer(path, oci.GZIP, expected, self.ledger)
        path.write_bytes(original)
        with self.assertRaisesRegex(oci.OCIError, "digest differs"):
            oci._layer(path, oci.GZIP, "sha256:" + "0" * 64, self.ledger)

    def test_exact_media_and_failed_or_poisoned_facts_are_not_reused(self):
        self.assertTrue(hasattr(self.ledger, "_layer_facts"))
        path, expected, key, _decoded = self.layer()
        unsafe, bad_expected, bad_key, _n = self.layer("escape", link="../../outside")
        real = tarfile.open
        with mock.patch.object(oci.tarfile, "open", wraps=real) as parser:
            oci._layer(path, oci.GZIP, expected, self.ledger)
            fact = self.ledger._layer_facts[key]
            self.ledger._layer_facts[bad_key] = fact
            with self.assertRaisesRegex(oci.OCIError, "escapes"):
                oci._layer(unsafe, oci.GZIP, bad_expected, self.ledger)
            self.assertNotIn(bad_key, self.ledger._layer_facts)
            oci._layer(path, oci.DOCKER_GZIP, expected, self.ledger)
            self.assertEqual(parser.call_count, 3, "different media must parse independently")
        with self.assertRaises(tarfile.TarError):
            oci._layer(path, oci.TAR, expected, self.ledger)
        self.assertNotIn((key[0], key[1], oci.TAR, expected), self.ledger._layer_facts)
        forged = self.layer("another")
        self.ledger._layer_facts[forged[2]] = (None, forged[2], 0, 0, 0)
        before = self.ledger.totals["entries"]
        oci._layer(forged[0], oci.GZIP, forged[1], self.ledger)
        self.assertEqual(self.ledger.totals["entries"], before + 1)

    def test_full_cache_falls_back_to_actual_parse_without_truncation(self):
        self.assertTrue(hasattr(oci, "_LAYER_CACHE_MAX"))
        first = self.layer("first")
        second = self.layer("second")
        real = tarfile.open
        with (
            mock.patch.object(oci, "_LAYER_CACHE_MAX", 1),
            mock.patch.object(oci.tarfile, "open", wraps=real) as parser,
        ):
            for value in (first, second, second):
                oci._layer(value[0], oci.GZIP, value[1], self.ledger)
        self.assertEqual(parser.call_count, 3)
        self.assertEqual(self.ledger.totals["entries"], 3)
        self.assertEqual(len(self.ledger._layer_facts), 1)

    def test_failed_and_unstable_validation_never_populates_cache(self):
        self.assertTrue(hasattr(self.ledger, "_layer_facts"))
        path, expected, key, _decoded = self.layer()
        with self.assertRaisesRegex(oci.OCIError, "digest differs"):
            oci._layer(path, oci.GZIP, "sha256:" + "0" * 64, self.ledger)
        self.assertFalse(self.ledger._layer_facts)
        original = path.read_bytes()
        path.write_bytes(original[:-3])
        with self.assertRaises((oci.OCIError, EOFError, OSError)):
            oci._layer(path, oci.GZIP, expected, self.ledger)
        self.assertFalse(self.ledger._layer_facts)
        path.write_bytes(original)
        real = oci._Root.file
        from contextlib import contextmanager

        @contextmanager
        def unstable(root, *args, **kwargs):
            with real(root, *args, **kwargs) as value:
                yield value
                path.write_bytes(path.read_bytes() + b"owned-change")

        with mock.patch.object(oci._Root, "file", unstable), self.assertRaises(oci.OCIError):
            oci._layer(path, oci.GZIP, expected, self.ledger)
        self.assertNotIn(key, self.ledger._layer_facts)

    def world(self, mutation=None):
        path, expected, _key, _size = self.layer()
        source = self.root / ("layout-" + str(len(list(self.root.iterdir()))))
        blobs = source / "blobs/sha256"
        blobs.mkdir(parents=True)

        def blob(raw, media):
            raw = raw if type(raw) is bytes else oci.canonical(raw)
            digest = hashlib.sha256(raw).hexdigest()
            (blobs / digest).write_bytes(raw)
            return dict(mediaType=media, digest="sha256:" + digest, size=len(raw))

        layer = blob(path.read_bytes(), oci.GZIP)
        manifests = []
        records = []
        uses = []
        images = []
        configs = []
        for index in range(2):
            config = blob(
                dict(
                    architecture="arm64" if mutation == "platform" and index == 1 else "amd64",
                    os="linux",
                    config=dict(Env=["OWNED=" + str(index)]),
                    rootfs=dict(
                        type="layers",
                        diff_ids=["sha256:" + "0" * 64 if mutation == "diffid" and index == 1 else expected],
                    ),
                ),
                oci.CONFIG,
            )
            configs.append(config)
            manifest = blob(dict(schemaVersion=2, mediaType=oci.MANIFEST, config=config, layers=[layer]), oci.MANIFEST)
            manifest["platform"] = dict(os="linux", architecture="amd64")
            manifests.append(manifest)
            reference = "owned/" + str(index) + "@" + manifest["digest"]
            records.append(dict(reference=reference, platform="linux/amd64", layout=str(source)))
            use = dict(
                manifest="compose.yaml",
                line=index + 1,
                source_sha256="a" * 64,
                source_reference="${OWNED}",
                reference=reference,
                platform="linux/amd64",
            )
            uses.append(use)
            images.append(
                dict(
                    use,
                    image_id="sha256:" + "0" * 64 if mutation == "pin" and index == 1 else config["digest"],
                    source_selection_sha256="0" * 64
                    if mutation == "use" and index == 1
                    else hashlib.sha256(oci.canonical(use)).hexdigest(),
                )
            )
        (source / "oci-layout").write_bytes(oci.canonical(dict(imageLayoutVersion="1.0.0")))
        (source / "index.json").write_bytes(
            oci.canonical(dict(schemaVersion=2, mediaType=oci.INDEX, manifests=manifests))
        )
        if mutation == "missing-current-config":
            (blobs / configs[1]["digest"][7:]).unlink()
        inventory = dict(complete=True, gaps=[], digest="a" * 64, images=images)
        catalog = dict(schema_version=1, inventory_sha256=inventory["digest"], records=records, source_bindings=uses)
        return catalog, inventory, dict(self.profile, images=[row["reference"] for row in records])

    def test_complete_records_keep_all_bytes_and_fresh_identity_validation(self):
        catalog, inventory, profile = self.world()
        real_budget, real_tar = oci._Budget, tarfile.open
        budgets = []

        def ledger(selected):
            value = real_budget(selected)
            budgets.append(value)
            return value

        totals = []
        for maximum in (1024, 0):
            with (
                mock.patch.object(oci, "_Budget", side_effect=ledger),
                mock.patch.object(oci, "_LAYER_CACHE_MAX", maximum),
                mock.patch.object(oci.tarfile, "open", wraps=real_tar) as parser,
            ):
                with oci.import_layouts(catalog, inventory, profile, self.root) as images:
                    self.assertEqual(len(images), 2)
                    self.assertNotEqual(images[0].config_digest, images[1].config_digest)
                    totals.append(dict(budgets[-1].totals))
                self.assertEqual(parser.call_count, 1 if maximum else 2)
                self.assertFalse(budgets[-1]._layer_facts, "all facts expire at context exit")
                self.assertTrue(all(image._proof is None for image in images))
        self.assertEqual(totals[0]["entries"], 1)
        self.assertEqual(totals[1]["entries"], 2)
        for key in ("storage", "compressed", "unpacked", "expanded", "layers"):
            self.assertEqual(totals[0][key], totals[1][key], key)
        for mutation in ("platform", "pin", "diffid", "use", "missing-current-config"):
            with self.subTest(mutation=mutation):
                values = self.world(mutation)
                with mock.patch.object(oci, "_Budget", side_effect=ledger), self.assertRaises(oci.OCIError):
                    with oci.import_layouts(*values, self.root):
                        self.fail("invalid current record gained credit")
                self.assertFalse(budgets[-1]._layer_facts, "failed import must clear all facts")

    def test_fixed_entry_ceiling_is_not_a_caller_profile_setting(self):
        self.assertEqual(oci._MAX_TAR_ENTRIES, 100000)
        with self.assertRaises(oci.OCIError):
            oci._Budget(dict(self.profile, max_tar_entries=200000))

    def test_real_new_header_boundary_still_refuses_100001(self):
        # One exact-bound synthetic stream (~49MiB decoded, small gzip), not a project graph.
        path, expected, _key, _decoded = self.layer(count=100000)
        real = tarfile.open
        with mock.patch.object(oci.tarfile, "open", wraps=real) as parser:
            oci._layer(path, oci.GZIP, expected, self.ledger)
            self.assertEqual(self.ledger.totals["entries"], 100000)
            oci._layer(path, oci.GZIP, expected, self.ledger)
            self.assertEqual(parser.call_count, 1)
            self.assertEqual(self.ledger.totals["entries"], 100000)
            distinct = self.layer("genuinely-new")
            with self.assertRaises(oci.OCIError) as caught:
                oci._layer(distinct[0], oci.GZIP, distinct[1], self.ledger)
        self.assertEqual(caught.exception.detail["dimension"], "entries")
        self.assertEqual(caught.exception.detail["attempted"], 100001)

    def test_hit_still_obeys_remaining_byte_budget_and_deadline(self):
        path, expected, _key, decoded = self.layer()
        self.profile["max_unpacked_bytes"] = decoded
        oci._layer(path, oci.GZIP, expected, self.ledger)
        with self.assertRaises(oci.OCIError) as caught:
            oci._layer(path, oci.GZIP, expected, self.ledger)
        self.assertEqual(caught.exception.detail["dimension"], "unpacked")
        self.assertEqual(self.ledger.totals["entries"], 1)
        self.ledger.deadline = 0
        with self.assertRaisesRegex(oci.OCIError, "deadline"):
            oci._layer(path, oci.GZIP, expected, self.ledger)
