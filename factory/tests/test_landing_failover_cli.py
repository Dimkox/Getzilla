"""Real Unix-socket caller path, process absence, and CLI redaction."""

from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler
import io
import json
from pathlib import Path
import socketserver
import tempfile
import unittest
from unittest.mock import patch

from getzilla_factory.landing_failover import FailoverCoordinator
from getzilla_factory.landing_failover_cli import main
from getzilla_factory.landing_failover_config import FailoverConfig
from getzilla_factory.landing_failover_journal import CallerJournal
from getzilla_factory import landing_failover_transport as transport_module
from getzilla_factory import landing_failover_cli as cli_module
from getzilla_factory import landing_failover_config as config_module
from getzilla_factory.settings import SettingsError
from factory.tests.test_landing_failover import configuration, ScriptedBackends


class UnixCallerTests(unittest.TestCase):
    def test_capability_timeout_advances_without_post_but_auth_and_malformed_capabilities_stop(self):
        for outcome in ("read_timeout", "connect_timeout", "slow_body", "auth", "malformed"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                config = FailoverConfig.from_dict(configuration(root, count=2))
                primary = config.backends[0]
                primary.token_file.write_text("t" * 32)
                primary.token_file.chmod(0o600)
                script = ScriptedBackends({"grok-vision": "success"})
                requests, deadlines = [], []
                monotonic = [100.0]
                def handler(request):
                    requests.append((request.method, request.content, request.extensions["timeout"]["read"]))
                    if outcome == "read_timeout":
                        raise transport_module.httpx.ReadTimeout("synthetic read timeout")
                    if outcome == "connect_timeout":
                        raise transport_module.httpx.ConnectTimeout("synthetic connect timeout")
                    if outcome == "slow_body":
                        monotonic[0] += 3
                    return transport_module.httpx.Response(401 if outcome == "auth" else 200,
                        headers={"content-type": "application/json"},
                        stream=transport_module.httpx.ByteStream(b"{}"))
                def factory(backend, **kwargs):
                    if backend.profile_id != "qwen-intl":
                        return script.factory(backend, **kwargs)
                    client = transport_module.UnixLandingBackend(backend, **kwargs)
                    deadlines.append(client)
                    return client
                with socketserver.UnixStreamServer(str(primary.socket_path), BaseHTTPRequestHandler):
                    with patch.object(transport_module.time, "monotonic", side_effect=lambda: monotonic[0]):
                        with patch.object(transport_module.httpx, "AsyncHTTPTransport",
                                          return_value=transport_module.httpx.MockTransport(handler)):
                            with CallerJournal(config) as journal:
                                result = FailoverCoordinator(config, journal, backend_factory=factory).submit(
                                    "capability", b"brief", "text/plain")
                self.assertEqual([("GET", b"", 2.0)], requests)
                self.assertEqual(430.0, deadlines[0].deadline, "capability must preserve the POST/observe deadline")
                if outcome in {"read_timeout", "connect_timeout", "slow_body"}:
                    self.assertEqual("artifact_ready", result["state"])
                    self.assertEqual("not_submitted", result["attempts"][0]["state"])
                    self.assertEqual("grok", result["winner"]["provider_id"])
                    self.assertEqual(["grok-vision"], script.calls)
                else:
                    self.assertEqual("stopped", result["state"])
                    self.assertEqual([], script.calls)

    @unittest.skipUnless(__import__('os').environ.get('FACTORY_TEST_DATABASE_URL'),
                         'shared-control positive requires bound disposable PostgreSQL; legacy POST stays blocked')
    def test_absent_primary_real_unix_secondary_lost_post_recovers_existing_winner(self):
        # The old independent-host protocol cannot submit paid work. Qualify the
        # new opt-in control with real CLI/server processes and one paid store.
        from factory.tests.shared_control_process_case import qualified_lost_response
        qualified_lost_response(self)

    def test_cli_all_absent_has_five_slots_and_never_prints_input_or_tokens(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = configuration(root)
            for item in config["backends"]:
                leaf = Path(item["token_file"])
                leaf.write_text("secret" * 8)
                leaf.chmod(0o600)
            config_path = root / "config.json"
            config_path.write_text(json.dumps(config))
            config_path.chmod(0o600)
            payload = root / "brief.txt"
            payload.write_text("private source must not be logged")
            payload.chmod(0o600)
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["--config", str(config_path), "submit", "--job-id", "cli-test", "--input", str(payload)])
            result = json.loads(output.getvalue())
            self.assertEqual(2, code)
            self.assertEqual("exhausted", result["state"])
            self.assertEqual(5, len(result["attempts"]))
            self.assertNotIn(payload.read_text(), output.getvalue())
            self.assertNotIn("secret" * 8, output.getvalue())


class CallerBoundaryTests(unittest.TestCase):
    def fixture(self, root):
        document = configuration(root)
        for item in document["backends"]:
            token = Path(item["token_file"])
            token.write_text("t" * 32)
            token.chmod(0o600)
        config_path = root / "config.json"
        config_path.write_text(json.dumps(document))
        config_path.chmod(0o600)
        return document, config_path

    def assert_rejected(self, arguments):
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(arguments)
        self.assertEqual(2, code)
        self.assertEqual({"schema_version": 1, "state": "stopped", "reason": "caller_request_rejected"},
                         json.loads(output.getvalue()))

    def test_double_slash_inputs_cannot_alias_tokens_config_or_protected_roots(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            document, config_path = self.fixture(root)
            protected = [config_path, *(Path(item["token_file"]) for item in document["backends"])]
            for name in ("control_repository", "source_path", "journal_path"):
                path = Path(document[name]) / "private.txt"
                path.write_text("protected synthetic content")
                path.chmod(0o600)
                protected.append(path)
            for path in protected:
                for spelling in (str(path), "/" + str(path)):
                    with self.subTest(path=path, alias=spelling.startswith("//")):
                        with patch.object(cli_module, "read_private_file", wraps=cli_module.read_private_file) as reader:
                            with patch.object(FailoverCoordinator, "submit", return_value={"state": "artifact_ready"}) as submit:
                                self.assert_rejected(["--config", str(config_path), "submit", "--job-id", "alias",
                                                      "--input", spelling])
                            reader.assert_not_called()
                            submit.assert_not_called()

    def test_config_alias_is_rejected_before_read_and_cannot_escape_forbidden_roots(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            document, config_path = self.fixture(root)
            paths = [config_path]
            for name in ("control_repository", "source_path", "journal_path"):
                path = Path(document[name]) / "config.json"
                path.write_text(json.dumps(document))
                path.chmod(0o600)
                paths.append(path)
                with self.assertRaises(SettingsError):
                    config_module.load_failover_config(path)
            for path in paths:
                alias = "/" + str(path)
                with self.subTest(path=path), patch.object(config_module, "read_private_file",
                                                         wraps=config_module.read_private_file) as reader:
                    with self.assertRaises(SettingsError):
                        config_module.load_failover_config(Path(alias))
                    self.assert_rejected(["--config", alias, "status", "--job-id", "alias"])
                    reader.assert_not_called()

    def test_busy_journal_returns_fixed_json_for_every_cli_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            document, config_path = self.fixture(root)
            brief = root / "brief.txt"
            brief.write_text("brief")
            brief.chmod(0o600)
            with CallerJournal(FailoverConfig.from_dict(document)):
                for command in ("submit", "status", "resume"):
                    arguments = ["--config", str(config_path), command, "--job-id", "busy"]
                    if command == "submit":
                        arguments += ["--input", str(brief)]
                    with self.subTest(command=command), patch.object(cli_module, "FailoverCoordinator") as coordinator:
                        self.assert_rejected(arguments)
                        coordinator.assert_not_called()

    def test_invalid_sqlite_file_returns_fixed_json_without_dispatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            document, config_path = self.fixture(root)
            database = Path(document["journal_path"]) / "failover.sqlite3"
            database.write_bytes(b"invalid synthetic SQLite file")
            database.chmod(0o600)
            with patch.object(cli_module, "FailoverCoordinator") as coordinator:
                self.assert_rejected(["--config", str(config_path), "status", "--job-id", "invalid"])
                coordinator.assert_not_called()


if __name__ == "__main__":
    unittest.main()
