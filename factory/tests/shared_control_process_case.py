"""Real CLI/server process test over one owned authority database."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid
from unittest.mock import patch

from factory.tests.test_landing_failover import configuration
from factory.tests.test_landing_renderer import sealed_target
from getzilla_factory.landing_sqlite_store import SQLiteLandingJobStore


def qualified_lost_response(case):
    import psycopg
    from psycopg import sql
    from getzilla_factory.admin import provision_runtime_login
    from getzilla_factory.migrations import PostgresMigrator
    from factory.tests.postgres_restart_probe import _assert_disposable_target

    url = os.environ["FACTORY_TEST_DATABASE_URL"]
    identity = (
        url,
        os.environ["FACTORY_TEST_POSTGRES_CONTAINER"],
        os.environ["FACTORY_TEST_POSTGRES_CONTAINER_ID"],
        os.environ["FACTORY_TEST_POSTGRES_NONCE"],
    )
    _assert_disposable_target(*identity)
    PostgresMigrator(url).apply()
    login = "shared_" + uuid.uuid4().hex[:12]
    with psycopg.connect(url) as db:
        case.assertIsNone(db.execute("SELECT oid FROM pg_roles WHERE rolname=%s", (login,)).fetchone())
    provision_runtime_login(url, login, "synthetic-fixture-only")
    with psycopg.connect(url) as db:
        role_oid = db.execute("SELECT oid FROM pg_roles WHERE rolname=%s", (login,)).fetchone()[0]
    try:
        _qualified_lost_response(case, login)
    finally:
        # Uvicorn re-raises SIGTERM after shutdown. The confirmed parent owns
        # cluster-role cleanup even when Python child finally blocks cannot run.
        _assert_disposable_target(*identity)
        with psycopg.connect(url) as db:
            case.assertEqual(db.execute("SELECT oid FROM pg_roles WHERE rolname=%s", (login,)).fetchone(), (role_oid,))
            db.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(login)))
        case.assertEqual(PostgresMigrator(url).apply(), ())


def _qualified_lost_response(case, login):
    common = Path(subprocess.check_output(["git", "rev-parse", "--git-common-dir"], text=True).strip()).resolve()
    runtime = common.parent / ".getzilla/runtime/tests"
    runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (
        tempfile.TemporaryDirectory(prefix="su-", dir=runtime) as temporary,
        patch("tempfile.tempdir", str(runtime)),
        sealed_target() as (source, head, tree),
    ):
        root = Path(temporary)
        document = configuration(root, count=2)
        document.update(
            schema_version=2,
            shared_task_id="finite-source-task",
            source_path=str(source),
            exact_base_sha=head,
            exact_base_tree=tree,
        )
        document["backends"][0]["socket_path"] = str(root / "run/stopped-primary/control.sock")
        token = Path(document["backends"][1]["token_file"])
        token.write_text("t" * 32)
        token.chmod(0o600)
        document["backends"][0]["token_file"] = str(token)
        config_path = root / "caller.json"
        config_path.write_text(json.dumps(document))
        config_path.chmod(0o600)
        input_path = root / "brief.txt"
        input_path.write_bytes(b"private synthetic source")
        input_path.chmod(0o600)
        command = [sys.executable, "-B", "-m", "factory.tests.shared_control_process_fixture"]
        server_log = (root / "server.log").open("w")
        process = subprocess.Popen(
            [*command, "server", str(config_path), str(input_path), "real-unix", login],
            stdout=server_log,
            stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 30
            while not (root / "ready").exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            case.assertTrue((root / "ready").exists(), (root / "server.log").read_text()[-8000:])

            def client(*arguments):
                completed = subprocess.run(
                    [*command, "client", str(source), "--config", str(config_path), *arguments],
                    capture_output=True,
                    text=True,
                    timeout=45,
                )
                case.assertEqual(
                    0,
                    completed.returncode,
                    completed.stdout + "\n" + completed.stderr + "\n" + (root / "server.log").read_text()[-8000:],
                )
                return json.loads(completed.stdout)

            result = client("submit", "--job-id", "real-unix", "--input", str(input_path))
            case.assertEqual("artifact_ready", result["state"])
            case.assertEqual("not_submitted", result["attempts"][0]["state"])
            case.assertEqual("grok", result["winner"]["provider_id"])
            case.assertEqual(["executed"], (root / "executions.txt").read_text().splitlines())
            case.assertEqual(
                [document["actor_id"], document["backends"][1]["profile_digest"]],
                json.loads((root / "headers.json").read_text()),
            )
            case.assertEqual(result, client("resume", "--job-id", "real-unix"))
            case.assertEqual(["executed"], (root / "executions.txt").read_text().splitlines())
        finally:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            server_log.close()
        with_store = SQLiteLandingJobStore(root / "authority", repository_root=Path(document["control_repository"]))
        try:
            audit = with_store.paid_audit("account")
            case.assertEqual(1, len(audit))
            case.assertEqual("observed", audit[0]["state"])
            case.assertEqual(1, with_store._connection.execute("SELECT count(*) FROM landing_commands").fetchone()[0])
            case.assertEqual(
                1, with_store._connection.execute("SELECT count(*) FROM shared_control_bindings").fetchone()[0]
            )
        finally:
            with_store.close()
