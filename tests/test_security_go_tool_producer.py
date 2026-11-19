"""Owned data-only controls; no network or actual hosted qualification."""

from datetime import datetime, timezone
import base64
import errno
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".getzilla"))
from getzilla import security_go_tool_inputs as reader
from getzilla.security_artifacts import ArtifactError

NOW = datetime(2026, 11, 19, 0, 0, tzinfo=timezone.utc)


class GoToolProducerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=ROOT / ".getzilla/runtime")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def producer(self):
        self.assertIsNotNone(
            importlib.util.find_spec("getzilla.security_go_tool_producer"),
            "missing joined checker tool source producer",
        )
        from getzilla import security_go_tool_producer

        return security_go_tool_producer

    def test_missing_sources_keep_both_required_uses_without_live_or_scratch_authority(self):
        producer = self.producer()
        calls = []

        def unavailable(url, maximum):
            calls.append((url, maximum))
            raise OSError(errno.ENETUNREACH, "PRIVATE_MARKER")

        from getzilla import security_image_producer as images

        before = images._LIVE
        result = producer.prepare_tools(ROOT, self.root, inventory_digest="a" * 64, now=NOW, fetch=unavailable)
        self.assertEqual(result["status"], "incomplete-source-inputs")
        self.assertEqual(result["inventory"], reader.checker_inventory(ROOT))
        self.assertEqual(result["parent_inventory_sha256"], "a" * 64)
        self.assertEqual(result["records"], [])
        self.assertEqual({gap["role"] for gap in result["gaps"]}, {"trivy", "buildkit"})
        self.assertTrue(all(gap["stage"] in {"archive", "release"} for gap in result["gaps"]))
        self.assertEqual(len(calls), 4)
        self.assertTrue(all(url.startswith("https://") for url, _ in calls))
        self.assertIs(images._LIVE, before)
        self.assertNotIn("PRIVATE_MARKER", str(result))

    def test_default_transport_rejects_foreign_origins_before_opening_a_socket(self):
        producer = self.producer()
        for url in (
            "http://127.0.0.1/source",
            "https://api.github.com.evil.test/source",
            "https://user:password@api.github.com/source",
            "https://proxy.golang.org/a/../b.zip",
        ):
            with self.subTest(url=url), mock.patch("http.client.HTTPSConnection") as connection:
                with self.assertRaises(ArtifactError):
                    producer.fetch_public(url, 1024)
                connection.assert_not_called()

    def test_actual_github_asset_namespace_is_allowed_without_cross_source_redirects(self):
        producer = self.producer()
        original = reader.PIN_SPECS["trivy"]["url"]
        self.assertTrue(
            producer._allowed(
                "https://release-assets.githubusercontent.com/github-production-release-asset/180687624/object",
                redirect_from=original,
            )
        )
        self.assertFalse(
            producer._allowed("https://proxy.golang.org/example.org/lib/@v/v1.0.0.zip", redirect_from=original)
        )

    def test_cache_revalidates_immutable_bytes_and_preserves_original_fetch_clock(self):
        producer = self.producer()
        url = "https://raw.githubusercontent.com/golang/go/go1.25.5/LICENSE"
        original = NOW.timestamp() - 3600

        def fetch(source, maximum):
            return b"owned inert bytes", dict(requested_url=source, fetched_at=original, status=200)

        with producer.Store(self.root, now=NOW, fetch=fetch) as store:
            body, fact = store.get(url, 1024, stage="runtime", roles=["trivy"])
        self.assertEqual(body, b"owned inert bytes")
        self.assertEqual(fact["fetched_at"], original)
        with producer.Store(self.root, now=NOW, fetch=lambda *_: self.fail("fresh cache fetched again")) as store:
            cached, fact = store.get(url, 1024, stage="runtime", roles=["trivy"])
        self.assertEqual(cached, body)
        self.assertEqual(fact["fetched_at"], original)
        path = self.root / fact["body"]["path"]
        path.write_bytes(b"altered")
        with producer.Store(self.root, now=NOW, fetch=lambda *_: self.fail("corrupt cache was hidden")) as store:
            with self.assertRaises(ArtifactError):
                store.get(url, 1024, stage="runtime", roles=["trivy"])

    def test_default_clock_accepts_a_real_local_receipt_after_store_creation(self):
        producer = self.producer()
        url = "https://raw.githubusercontent.com/golang/go/go1.25.5/LICENSE"
        failure = None

        def fetch(source, maximum):
            return b"owned source", dict(requested_url=source, fetched_at=time.time(), status=200)

        try:
            with producer.Store(self.root, fetch=fetch) as store:
                body, fact = store.get(url, 1024, stage="runtime", roles=["trivy"])
        except ArtifactError as error:
            failure = error.code
        self.assertIsNone(failure, "a later real local fetch is not a future source clock")
        self.assertEqual(body, b"owned source")
        self.assertLessEqual(fact["fetched_at"], time.time())

    def test_stale_cache_and_future_receipts_cannot_refresh_source_custody(self):
        from datetime import timedelta

        producer = self.producer()
        url = "https://raw.githubusercontent.com/golang/go/go1.25.5/LICENSE"

        def fetch(source, maximum):
            return b"owned", dict(requested_url=source, fetched_at=NOW.timestamp(), status=200)

        with producer.Store(self.root, now=NOW, fetch=fetch) as store:
            _, original = store.get(url, 1024, stage="runtime", roles=["trivy"])
        with producer.Store(self.root, now=NOW + timedelta(hours=73), cache_only=True) as store:
            with self.assertRaises(ArtifactError) as refused:
                store.get(url, 1024, stage="runtime", roles=["trivy"])
            self.assertEqual(refused.exception.code, "go-source-stale")
        self.assertEqual(original["fetched_at"], NOW.timestamp())

        def future(source, maximum):
            return b"owned", dict(requested_url=source, fetched_at=NOW.timestamp() + 1, status=200)

        with producer.Store(self.root / "future", now=NOW, fetch=future) as store:
            with self.assertRaises(ArtifactError) as refused:
                store.get(url, 1024, stage="runtime", roles=["trivy"])
            self.assertEqual(refused.exception.code, "go-source-clock")

    def owned_sources(self, *, cgo="0"):
        from tests.test_security_go_tool_inputs import qualified_fixture

        checker, artifacts, record, specs = qualified_fixture(self.root / "owned", cgo=cgo)
        proof = json.loads((artifacts / record["components"]["path"]).read_bytes())
        module = json.loads((artifacts / proof["modules"]["example.org/lib@v1.0.0"]["path"]).read_bytes())
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            for name, term in module["terms"].items():
                archive.writestr("example.org/lib@v1.0.0/" + name, base64.b64decode(term["body"]))
        sources = {
            record["origin"]["artifact_url"]: (artifacts / record["path"]).read_bytes(),
            record["origin"]["index_url"]: (artifacts / proof["release"]["path"]).read_bytes(),
            module["origin"]["requested_url"]: payload.getvalue(),
        }
        for item in proof["runtime"]["go1.25.5"].values():
            sources[item["url"]] = (artifacts / item["path"]).read_bytes()

        def fetch(url, maximum):
            if url not in sources:
                raise OSError(errno.ENETUNREACH, "PRIVATE_MARKER")
            return sources[url], dict(requested_url=url, fetched_at=NOW.timestamp(), status=200)

        return checker, specs, fetch

    def test_actual_reader_can_qualify_one_owned_family_but_missing_second_tool_still_fails(self):
        producer = self.producer()
        checker, specs, fetch = self.owned_sources()
        with mock.patch.object(reader, "PIN_SPECS", specs):
            result = producer.prepare_tools(
                checker, self.root / "output", inventory_digest="a" * 64, now=NOW, fetch=fetch
            )
            self.assertEqual(len(result["records"]), 1, result["gaps"])
            self.assertEqual(result["status"], "incomplete-source-inputs")
            evidence = reader.verify_family(
                self.root / "output" / producer.ROOT_NAME, result["records"][0], checker=checker, now=NOW
            )
            self.assertTrue(evidence["components"])
            self.assertEqual({gap["role"] for gap in result["gaps"]}, {"buildkit"})

    def test_cgo_stays_a_named_gap_after_other_owned_source_facts_are_collected(self):
        producer = self.producer()
        checker, specs, fetch = self.owned_sources(cgo="1")
        with mock.patch.object(reader, "PIN_SPECS", specs):
            result = producer.prepare_tools(
                checker, self.root / "output", inventory_digest="a" * 64, now=NOW, fetch=fetch
            )
        self.assertEqual(result["records"], [])
        self.assertTrue(
            any(gap["role"] == "trivy" and gap["code"] == "go-cgo-native-unresolved" for gap in result["gaps"]),
            result["gaps"],
        )

    def test_expired_operation_deadline_also_bounds_cache_only_reads(self):
        producer = self.producer()
        url = "https://raw.githubusercontent.com/golang/go/go1.25.5/LICENSE"

        def fetch(source, maximum):
            return b"owned", dict(requested_url=source, fetched_at=NOW.timestamp(), status=200)

        with producer.Store(self.root, now=NOW, fetch=fetch) as store:
            store.get(url, 1024, stage="runtime", roles=["trivy"])
        with producer.Store(self.root, now=NOW, cache_only=True) as store:
            store.deadline = time.monotonic() - 1
            with self.assertRaises(ArtifactError) as refused:
                store.get(url, 1024, stage="runtime", roles=["trivy"])
            self.assertEqual(refused.exception.code, "go-source-timeout")

    def test_common_provider_rederives_cost_and_missing_tool_without_network_or_raw_inventory_rows(self):
        producer = self.producer()
        self.assertTrue(
            callable(getattr(producer, "validate_preparation", None)), "missing independent Go source counter"
        )
        checker, specs, fetch = self.owned_sources()
        from getzilla import security_family_inputs as common, security_tools
        from getzilla.manifest import _open_root
        import os

        output = self.root / "output"
        with mock.patch.object(reader, "PIN_SPECS", specs), mock.patch.object(security_tools, "TRUSTED_ROOT", checker):
            report = producer.prepare_tools(checker, output, inventory_digest="a" * 64, now=NOW, fetch=fetch)
            with mock.patch.object(producer, "fetch_public", side_effect=AssertionError("counter fetched")):
                checked = producer.validate_preparation(output, report, inventory_digest="a" * 64, now=NOW)
                self.assertEqual(checked["records"], [])
                self.assertTrue(checked["gaps"])
                self.assertGreater(checked["bound_bytes"], 0)
                with self.assertRaises(ArtifactError):
                    producer.validate_preparation(output, report, inventory_digest="b" * 64, now=NOW)
                omitted = json.loads(json.dumps(report))
                omitted["gaps"] = []
                with self.assertRaises(ArtifactError):
                    producer.validate_preparation(output, omitted, inventory_digest="a" * 64, now=NOW)
                altered = json.loads(json.dumps(report))
                altered["source_facts"][0]["bytes"] = 0
                with self.assertRaises(ArtifactError):
                    producer.validate_preparation(output, altered, inventory_digest="a" * 64, now=NOW)
                with self.assertRaises(ArtifactError) as refused:
                    producer.validate_preparation(
                        output, report, inventory_digest="a" * 64, now=NOW, byte_budget=checked["bound_bytes"] - 1
                    )
                self.assertEqual(refused.exception.code, "artifact-size")
                root, fd = _open_root(output)
                try:
                    published = None
                    failure = None
                    try:
                        published = common.publish(
                            root,
                            fd,
                            dict(schema_version=1, providers=[dict(kind="go-checker-tools-v1", report=report)]),
                            inventory_digest="a" * 64,
                            now=NOW,
                        )
                    except ArtifactError as error:
                        failure = error.code
                    self.assertIsNone(failure, "missing finite common Go provider")
                    self.assertEqual(published["records"], [])
                    self.assertGreater(published["bound_bytes"], checked["bound_bytes"])
                finally:
                    os.close(fd)


if __name__ == "__main__":
    unittest.main()
