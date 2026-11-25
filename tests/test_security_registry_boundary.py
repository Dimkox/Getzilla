"""Owned resolver and transport-fault controls. No real network or namespaces."""

from contextlib import ExitStack
import io
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".getzilla"))
from getzilla import security_image_authority as image_authority
from getzilla import security_image_backend as backend, security_image_registry as registry
from getzilla import security_image_producer as producer


class RegistryBoundaryControls(unittest.TestCase):
    def setUp(self):
        self.effects = ExitStack()
        self.addCleanup(self.effects.close)
        self.effects.enter_context(mock.patch("socket.socket", side_effect=AssertionError("network denied")))
        self.effects.enter_context(mock.patch("socket.getaddrinfo", side_effect=AssertionError("network denied")))
        for effect in ("subprocess.Popen", "subprocess.run"):
            self.effects.enter_context(mock.patch(effect, side_effect=AssertionError("process denied")))

    def test_resolver_copy_permissions_ignore_umask_without_private_state_widening(self):
        self.assertTrue(callable(getattr(backend, "_install_resolver", None)), "need closed resolver setup")
        with tempfile.TemporaryDirectory(dir=ROOT / ".getzilla/runtime") as directory:
            root = Path(directory)
            (root / "run").mkdir(mode=0o700)
            (root / "run/daemon-private").mkdir(mode=0o700)
            previous = os.umask(0o077)
            try:
                backend._install_resolver(root, b"nameserver 192.0.2.1\n")
            finally:
                os.umask(previous)
            for name in ("run", "run/systemd", "run/systemd/resolve"):
                self.assertEqual((root / name).stat().st_mode & 0o777, 0o711)
            for name in ("resolv.conf", "stub-resolv.conf"):
                p = root / "run/systemd/resolve" / name
                self.assertEqual(p.stat().st_mode & 0o777, 0o644)
                self.assertEqual(p.read_bytes(), b"nameserver 192.0.2.1\n")
            self.assertEqual((root / "run/daemon-private").stat().st_mode & 0o777, 0o700)

    def worker_failure(self, error):
        request = dict(
            url="https://auth.docker.io/token?PRIVATE_QUERY_MARKER",
            headers={"Authorization": "Bearer PRIVATE_TOKEN_MARKER"},
            maximum=4096,
            seconds=1,
        )
        stderr = io.StringIO()
        with (
            mock.patch.object(registry.urllib.request, "build_opener") as opener,
            mock.patch.object(sys, "stdin", mock.Mock(buffer=io.BytesIO(registry.canonical(request)))),
            mock.patch.object(sys, "stdout", mock.Mock(buffer=io.BytesIO())),
            mock.patch.object(sys, "stderr", stderr),
        ):
            opener.return_value.open.side_effect = error
            self.assertEqual(registry._worker(), 1)
        raw = stderr.getvalue()
        self.assertTrue(raw.startswith("{"), "worker must retain a closed typed fault, not discard cause")
        self.assertNotIn("PRIVATE", raw)
        self.assertNotIn("https://", raw)
        return json.loads(raw)

    def test_dns_tls_http_and_os_errors_keep_safe_typed_cause(self):
        cases = [
            (urllib.error.URLError(socket.gaierror(-3, "PRIVATE_REASON_MARKER")), "dns", -3, None),
            (urllib.error.URLError(ssl.SSLCertVerificationError(1, "PRIVATE_CERT_MARKER")), "tls", 1, None),
            (
                urllib.error.HTTPError(
                    "https://auth.docker.io/token?PRIVATE_QUERY_MARKER", 429, "PRIVATE_BODY_MARKER", {}, None
                ),
                "http",
                None,
                429,
            ),
            (PermissionError(13, "PRIVATE_PATH_MARKER"), "os", 13, None),
        ]
        for error, category, errno, status in cases:
            with self.subTest(category=category):
                fault = self.worker_failure(error)
                self.assertEqual(fault["category"], category)
                self.assertEqual(fault["errno"], errno)
                self.assertEqual(fault["http_status"], status)
                self.assertEqual(fault["origin"], "auth.docker.io")
                self.assertEqual(fault["request_kind"], "auth")

    def test_blocked_blob_redirect_reports_status_without_location(self):
        url = "https://registry-1.docker.io/v2/library/docker/blobs/sha256:" + "a" * 64
        with self.assertRaises(registry.RegistryError) as caught:
            registry._Redirect(url).redirect_request(None, None, 307, "", {},
                "https://untrusted.invalid/download?PRIVATE_SIGNATURE")
        detail = registry._exception_fault({"url": url}, caught.exception, "registry-connect")
        self.assertEqual(detail["category"], "redirect-refused")
        self.assertEqual(detail["http_status"], 307)
        self.assertEqual(detail["origin"], "registry-1.docker.io")
        self.assertNotIn("untrusted", json.dumps(detail))
        self.assertNotIn("PRIVATE", json.dumps(detail))

    def test_parent_preserves_valid_fault_but_refuses_secret_or_malformed_fields(self):
        fault = dict(
            version=1,
            category="http",
            phase="registry-headers",
            request_kind="auth",
            origin="auth.docker.io",
            errno=None,
            http_status=429,
            command_id="registry-http",
        )
        for change in (
            None,
            {"secret": "PRIVATE_TOKEN_MARKER"},
            {"origin": "https://evil.invalid/?PRIVATE_TOKEN_MARKER"},
            {"errno": "PRIVATE_TOKEN_MARKER"},
        ):
            with self.subTest(change=change):
                value = dict(fault)
                if change:
                    value.update(change)
                port = mock.Mock(return_value=(1, b"", registry.canonical(value) + b"\n"))
                with (
                    mock.patch("getzilla.architecture_diff._run_capped", port),
                    self.assertRaises(registry.RegistryError) as caught,
                ):
                    registry.BoundedHTTP(deadline=registry.time.monotonic() + 1).get(
                        "https://auth.docker.io/token?PRIVATE_QUERY_MARKER", {}, 4096
                    )
                detail = getattr(caught.exception, "detail", {})
                self.assertTrue(detail, "parent must preserve bounded typed failure")
                self.assertNotIn("PRIVATE", json.dumps(detail))
                self.assertEqual(detail["exit_code"], 1)
                if change is None:
                    self.assertEqual(detail["http_status"], 429)
                else:
                    self.assertEqual(detail["category"], "worker")

                with mock.patch.object(os, "write") as sink:
                    producer._fault(caught.exception)
                artifact = json.loads(sink.call_args.args[1])["fault"]
                self.assertEqual(artifact["category"], detail["category"])
                self.assertEqual(artifact["http_status"], detail["http_status"])
                self.assertNotIn("PRIVATE", json.dumps(artifact))

    def test_fixed_prerequisite_roles_complete_before_pipeline_network(self):
        with tempfile.TemporaryDirectory(dir=ROOT / ".getzilla/runtime") as directory:
            volume = Path(directory)
            endpoint = volume / "owned-socket-model"
            endpoint.write_bytes(b"owned socket identity model")
            request = {
                key: str(volume / key) for key in ("tools", "database", "artifacts", "profile", "preparation", "report")
            }
            builder = SimpleNamespace(client=sys.executable, socket=endpoint, deadline=time.monotonic() + 2)
            with (
                mock.patch.object(image_authority, "_GUARD", (volume, object(), [])),
                mock.patch.object(tempfile, "tempdir", str(volume)),
                mock.patch.object(producer.stat, "S_ISSOCK", return_value=True),
                mock.patch.object(registry.BoundedHTTP, "bootstrap") as bootstrap,
            ):
                try:
                    producer._postdrop_preflight(request, volume, builder)
                except backend.BackendUnavailable as error:
                    self.fail(error.detail)
            bootstrap.assert_called_once_with()

    def test_postdrop_prerequisite_fault_has_only_fixed_role_and_errno(self):
        with tempfile.TemporaryDirectory(dir=ROOT / ".getzilla/runtime") as directory:
            volume = Path(directory)
            request = dict(tools=str(volume / "tools"))
            with (
                mock.patch.object(image_authority, "_GUARD", (volume, object(), [])),
                mock.patch("builtins.open", side_effect=PermissionError(13, "PRIVATE_PATH_MARKER")),
                self.assertRaises(backend.BackendUnavailable) as error,
            ):
                producer._postdrop_preflight(request, volume, object())
            self.assertEqual(error.exception.detail["command_id"], "postdrop-resolver")
            self.assertEqual(error.exception.detail["errno"], 13)
            self.assertNotIn("PRIVATE", json.dumps(error.exception.detail) + str(error.exception))

    def test_worker_bootstrap_uses_rejected_request_without_network(self):
        request = dict(url="invalid://bootstrap", headers={}, maximum=1, seconds=1)
        stderr = io.StringIO()
        with (
            mock.patch.object(sys, "stdin", mock.Mock(buffer=io.BytesIO(registry.canonical(request)))),
            mock.patch.object(sys, "stdout", mock.Mock(buffer=io.BytesIO())),
            mock.patch.object(sys, "stderr", stderr),
            mock.patch.object(
                registry.urllib.request, "build_opener", side_effect=AssertionError("no bootstrap egress")
            ),
        ):
            self.assertEqual(registry._worker(), 1)
        fault = json.loads(stderr.getvalue())
        self.assertEqual(
            (fault["category"], fault["phase"], fault["origin"]), ("request", "registry-request", "unknown")
        )
        with mock.patch("getzilla.architecture_diff._run_capped", return_value=(1, b"", stderr.getvalue().encode())):
            registry.BoundedHTTP(deadline=registry.time.monotonic() + 1).bootstrap()
