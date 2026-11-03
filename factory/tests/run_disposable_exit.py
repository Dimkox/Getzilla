#!/usr/bin/env python3
"""Run mandatory API/PostgreSQL/actual-restart evidence in one disposable container."""

from __future__ import annotations

import os
import signal
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import uuid


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / ".getzilla"))
from getzilla.disposable_resources import OwnedDocker, image_pins, ensure_images

POSTGRES = image_pins(ROOT)["postgres"]

_CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
_DEFAULT_COMMAND_TIMEOUT_SECONDS = 300
_FULL_SUITE_TIMEOUT_SECONDS = 720


class _CleanupError(RuntimeError):
    def __init__(self, failures: list[tuple[str, BaseException]]) -> None:
        super().__init__("disposable verification cleanup failed")
        self.failures = tuple(failures)


def _error_detail(error: BaseException | None) -> str:
    """Describe control flow without exposing exception text, argv or output."""
    if error is None:
        return "error=none"
    kind = type(error).__name__
    if re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]{0,79}", kind) is None:
        kind = "BaseException"
    detail = f"error={kind}"
    if isinstance(error, subprocess.CalledProcessError) and type(error.returncode) is int:
        code = error.returncode
        detail += f" signal={-code}" if code < 0 else f" exit={code}"
    elif isinstance(error, subprocess.TimeoutExpired):
        if type(error.timeout) in (int, float) and 0 <= error.timeout < float("inf"):
            detail += f" timeout_seconds={error.timeout}"
    elif isinstance(error, KeyboardInterrupt):
        detail += " signal=2"
    elif isinstance(error, SystemExit) and type(error.code) is int:
        detail += f" exit={error.code}"
    return detail


def _binding_matches(
    container_id: str,
    name: str,
    nonce: str,
    *,
    require_running: bool,
) -> bool:
    if not _CONTAINER_ID.fullmatch(container_id):
        return False
    inspected = subprocess.run(
        [
            "docker",
            "inspect",
            "--format",
            '{{.Id}}\t{{.Name}}\t{{.Config.Image}}\t{{.State.Running}}\t'
            '{{index .Config.Labels "getzilla.ci.nonce"}}\t{{.Image}}',
            container_id,
        ],
        text=True,
        capture_output=True,
        timeout=10,
    )
    if inspected.returncode != 0:
        return False
    fields = inspected.stdout.strip().split("\t")
    if len(fields) != 6:
        return False
    identity_matches = fields[:3] == [
        container_id,
        f"/{name}",
        POSTGRES["reference"],
    ] and fields[3] in {"true", "false"} and fields[4] == nonce and fields[5] == POSTGRES["image_id"]
    return identity_matches and (not require_running or fields[3] == "true")


def _remove_bound_container(container_id: str, name: str, nonce: str) -> None:
    if not _binding_matches(
        container_id, name, nonce, require_running=False
    ):
        raise RuntimeError(
            f"refusing to delete unbound container; leaked id={container_id}"
        )
    subprocess.run(
        ["docker", "rm", "-f", container_id],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
    )
    remaining = subprocess.run(["docker", "container", "ls", "--all", "--no-trunc", "--format", "{{.ID}}"],
                               check=True, capture_output=True, text=True, timeout=10).stdout.splitlines()
    if container_id in remaining:
        raise RuntimeError("disposable container removal is unconfirmed")


def _run(
    command: list[str],
    *,
    environment: dict[str, str] | None = None,
    timeout: int = _DEFAULT_COMMAND_TIMEOUT_SECONDS,
) -> None:
    subprocess.run(command, check=True, env=environment, timeout=timeout)


def _published_loopback_port(value: str) -> int:
    lines = value.strip().splitlines()
    if len(lines) != 1:
        raise RuntimeError("disposable PostgreSQL port mapping is ambiguous")
    match = re.fullmatch(r"127\.0\.0\.1:([0-9]{1,5})", lines[0])
    if match is None:
        raise RuntimeError("disposable PostgreSQL port is not loopback-only")
    port = int(match.group(1))
    if not 1 <= port <= 65_535:
        raise RuntimeError("disposable PostgreSQL port is invalid")
    return port


def _final_postgres_ready(container_id: str) -> bool:
    final_postmaster = subprocess.run(
        [
            "docker", "exec", container_id, "sh", "-c",
            'test "$(sed -n "1p" "$PGDATA/postmaster.pid")" = 1',
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
    )
    if final_postmaster.returncode != 0:
        return False
    ready = subprocess.run(
        ["docker", "exec", container_id, "pg_isready", "-U", "factory_exit", "-d", "factory_exit"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
    )
    return ready.returncode == 0


def _new_owner() -> OwnedDocker:
    ensure_images(ROOT, ("postgres",))
    namespace = os.environ.get("GETZILLA_LIVE_NAMESPACE", "gz-factory-" + uuid.uuid4().hex[:12])
    artifacts = Path(os.environ.get("GETZILLA_LIVE_ARTIFACTS", str(ROOT / ".getzilla/runtime/live" / namespace)))
    return OwnedDocker(artifacts / "factory-resources.json", namespace)


def _postgres(owner, suffix, password, network):
    volume = owner.volume(suffix + "-data")
    item = owner.container(suffix, POSTGRES["reference"], volume=volume, network=network,
                           publish_postgres=True, environment={"POSTGRES_DB": "factory_exit",
                           "POSTGRES_USER": "factory_exit", "POSTGRES_PASSWORD": password})
    if item["image_id"] != POSTGRES["image_id"]:
        raise RuntimeError("Pinned PostgreSQL image configuration mismatch")
    identifier = item["id"]
    deadline = time.monotonic() + 45
    while not _final_postgres_ready(identifier):
        if time.monotonic() >= deadline:
            raise RuntimeError("disposable PostgreSQL final postmaster did not become ready")
        time.sleep(0.25)
    port = _published_loopback_port(subprocess.run(
        ["docker", "port", identifier, "5432/tcp"], check=True, text=True,
        capture_output=True, timeout=10).stdout)
    return item, f"postgresql://factory_exit:{password}@127.0.0.1:{port}/factory_exit"


def main() -> int:
    phase = "setup"
    primary_error: BaseException | None = None
    cleanup_errors: list[tuple[str, BaseException]] = []
    venv = None
    venv_status = "not_created"
    container_status = "not_created"
    container_id = "unknown"
    owner = None
    try:
        owner = _new_owner()
        nonce = owner.nonce
        password = f"local-{uuid.uuid4().hex}"
        environment = os.environ.copy()
        environment["GETZILLA_LIVE_ARTIFACTS"] = str(owner.manifest.parent)
        for variable in ("FACTORY_TEST_DATABASE_URL", "FACTORY_FRESH_CLUSTER_DATABASE_URL",
                         "FACTORY_TEST_POSTGRES_CONTAINER", "FACTORY_TEST_POSTGRES_CONTAINER_ID", "FACTORY_TEST_POSTGRES_NONCE"):
            environment.pop(variable, None)
        environment["PYTHONPATH"] = os.pathsep.join((str(ROOT / "factory/src"), str(ROOT), str(ROOT / ".getzilla")))
        phase = "container-create"
        container_status = "unbound"
        network = owner.network("db-network")
        item, database_url = _postgres(owner, "db", password, network)
        container_id, name = item["id"], item["name"]
        phase = "container-bind"
        if not _binding_matches(container_id, name, nonce, require_running=True):
            raise RuntimeError(f"disposable container binding failed; leaked id={container_id}")
        environment.update(FACTORY_TEST_DATABASE_URL=database_url,
                           FACTORY_TEST_POSTGRES_CONTAINER=name,
                           FACTORY_TEST_POSTGRES_CONTAINER_ID=container_id,
                           FACTORY_TEST_POSTGRES_NONCE=nonce)
        phase = "venv-create"
        venv = tempfile.TemporaryDirectory(prefix="adaptive-factory-exit-venv-")
        environment["UV_PROJECT_ENVIRONMENT"] = venv.name
        uv = ["uv", "run", "--locked", "--project", "factory"]
        phase = "preflight"
        _run(
            [
                *uv,
                "python",
                "factory/tests/postgres_restart_probe.py",
                "--preflight-only",
            ],
            environment=environment,
        )
        phase = "fresh-cluster"
        fresh, fresh_url = _postgres(owner, "fresh", f"local-{uuid.uuid4().hex}", network)
        fresh_environment = dict(environment, FACTORY_TEST_DATABASE_URL=fresh_url,
                                 FACTORY_TEST_POSTGRES_CONTAINER=fresh["name"],
                                 FACTORY_TEST_POSTGRES_CONTAINER_ID=fresh["id"])
        _run([*uv, "python", "factory/tests/postgres_restart_probe.py", "--preflight-only"],
             environment=fresh_environment)
        environment["FACTORY_FRESH_CLUSTER_DATABASE_URL"] = fresh_url
        phase = "suite"
        _run(
            [
                *uv,
                "python",
                "factory/tests/run_live_suite.py",
            ],
            environment=environment,
            timeout=_FULL_SUITE_TIMEOUT_SECONDS,
        )
        phase = "container-revalidate"
        if not _binding_matches(
            container_id, name, nonce, require_running=True
        ):
            raise RuntimeError(
                f"disposable container binding changed after tests; leaked id={container_id}"
            )
        phase = "restart-port"
        published = subprocess.run(
            ["docker", "port", container_id, "5432/tcp"],
            check=True,
            text=True,
            capture_output=True,
            timeout=10,
        ).stdout.strip()
        port = _published_loopback_port(published)
        environment["FACTORY_TEST_DATABASE_URL"] = (
            f"postgresql://factory_exit:{password}@127.0.0.1:{port}/factory_exit"
        )
        phase = "restart"
        _run([*uv, "python", "factory/tests/postgres_restart_probe.py"], environment=environment)
    except BaseException as error:
        primary_error = error
    finally:
        if venv is not None:
            try:
                venv.cleanup()
                venv_status = "removed"
            except BaseException as error:
                venv_status = "failed"
                cleanup_errors.append(("venv", error))
        if owner is not None:
            try:
                owner.cleanup()
                container_status = "removed"
            except BaseException as error:
                container_status = "unconfirmed"
                cleanup_errors.append(("container", error))
        if primary_error is not None or cleanup_errors:
            # A cleanup timeout must not become a primary timeout at the CLI.
            failure = primary_error
            if failure is None:
                failure = next(
                    (error for _, error in cleanup_errors if not isinstance(error, Exception)),
                    _CleanupError(cleanup_errors),
                )
            primary_status = "passed" if primary_error is None else "failed"
            if isinstance(primary_error, subprocess.TimeoutExpired):
                primary_status = "timed_out"
            elif isinstance(primary_error, KeyboardInterrupt):
                primary_status = "cancelled"
            safe_id = container_id if _CONTAINER_ID.fullmatch(container_id) else "unknown"
            errors = dict(cleanup_errors)
            summaries = (
                f"RESULT: primary={primary_status} phase={phase} {_error_detail(primary_error)}",
                f"CLEANUP: venv={venv_status} phase=venv-cleanup {_error_detail(errors.get('venv'))}",
                f"CLEANUP: container={container_status} phase=container-cleanup "
                f"container_id={safe_id} {_error_detail(errors.get('container'))}",
            )
            for summary in summaries:
                BaseException.add_note(failure, summary)
            try:
                for summary in summaries:
                    print(summary, file=sys.stderr)
            finally:
                # Even a closed diagnostic stream must not replace the primary.
                raise failure
    print("PASS: disposable PostgreSQL + API + effective roles + actual restart/reconciliation")
    return 0


def _cli() -> int:
    previous = signal.getsignal(signal.SIGTERM)
    def cancelled(_number, _frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, cancelled)
    try:
        return main()
    except BaseException as error:
        if isinstance(error, KeyboardInterrupt):
            return 130
        if isinstance(error, subprocess.TimeoutExpired):
            return 124
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    raise SystemExit(_cli())
