"""Observed disposable component tests. These observations are not attestations."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import time
import uuid

from .factory_tests import decode_document, source_census, source_matches
from .disposable_resources import CleanupUnconfirmed, OwnedDocker, image_pins, ensure_images, verified_image_id, process_error_detail

CELLS = {"factory": ("factory-postgres-exit",), "trust-ci": ("trust-ci-postgres", "trust-ci-postgres-restart")}
OUTPUT_LIMIT = 16 * 1024 * 1024
_EVIDENCE_NAMES = frozenset(("observer.json", "command.log", "factory-resources.json", "factory-suite.json",
    "factory-restart.json", "trust-ci-resources.json", "trust-ci-suite.json", "trust-ci-restart.json",
    "protected-resources.json", "protected-evidence.txt"))


def evidence_name(name):
    return name in _EVIDENCE_NAMES or re.fullmatch(r"gz-[a-z0-9-]+-(resources|sample|ack)\.json", name) is not None


_FACTORY_SUITE_KEYS = frozenset(("schema_version", "check_id", "status", "census", "collected_ids",
    "started", "executed", "skipped", "tests_run", "failures", "errors", "loader_errors", "source_stable"))
_FACTORY_CONDITIONAL_SKIP = {
    "id": "factory.tests.test_landing_pdf_worker.PdfWorkerWithoutParser.test_worker_executes_and_reports_parser_unavailable",
    "reason": "pypdf present; unavailable branch cannot run",
}


def _live_ids(value):
    return (type(value) is list and len(value) <= 10000
            and all(type(item) is str and 0 < len(item) <= 2048 for item in value)
            and len(set(value)) == len(value))


def factory_suite_status(document, expected_census):
    """Reconcile live-only observations against independently checked source."""
    try:
        if (type(document) is not dict or set(document) != _FACTORY_SUITE_KEYS
                or type(expected_census) is not dict
                or set(expected_census) != {"source_inventory", "source_bindings", "declared_ids"}
                or type(document["schema_version"]) is not int or document["schema_version"] != 2
                or document["check_id"] != "factory-postgres-exit"
                or document["status"] not in ("pass", "fail")
                or document["source_stable"] is not True
                # JSON comparison preserves scalar types (bool is not an int)
                # throughout the closed checked-source projection.
                or json.dumps(document["census"], sort_keys=True) != json.dumps(expected_census, sort_keys=True)):
            return "fail"
        expected = expected_census["declared_ids"]
        if not _live_ids(expected) or not expected:
            return "fail"
        for key in ("collected_ids", "started", "executed"):
            if not _live_ids(document[key]):
                return "fail"
        for key in ("tests_run", "failures", "errors", "loader_errors"):
            if type(document[key]) is not int or not 0 <= document[key] <= 10000:
                return "fail"
        skipped_rows = document["skipped"]
        if (type(skipped_rows) is not list or len(skipped_rows) > 1
                or any(type(row) is not dict or row != _FACTORY_CONDITIONAL_SKIP for row in skipped_rows)):
            return "fail"
        skipped = {row["id"] for row in skipped_rows}
        executed = set(document["executed"])
        complete = set(expected)
        if (set(document["collected_ids"]) != complete or set(document["started"]) != complete
                or executed & skipped or executed | skipped != complete
                or document["tests_run"] != len(complete)
                or any(document[key] for key in ("failures", "errors", "loader_errors"))
                or not any("FreshClusterArtifactAttestorMigrationTests." in name for name in executed)
                or not any("test_postgres_integration." in name for name in executed)):
            return "fail"
        return "pass"
    except (ValueError, TypeError, KeyError, RecursionError):
        return "fail"


def validate_components(output, cell, *, source_root=None):
    def read(name):
        path = output / name
        if path.is_symlink() or path.stat().st_size > OUTPUT_LIMIT:
            raise ValueError("Unsafe live component report")
        document = decode_document(path.read_text(encoding="utf-8"))
        if type(document) is not dict:
            raise ValueError("Invalid live component report shape")
        return document
    try:
        if cell == "factory":
            if source_root is None:
                return False
            expected = source_census(source_root)
            suite, restart = read("factory-suite.json"), read("factory-restart.json")
            return (suite.get("status") == factory_suite_status(suite, expected) == "pass"
                    and source_matches(source_root, expected)
                    and restart.get("status") == "pass" and len(restart.get("restarts", [])) == 2
                    and all(row["before"] < row["after"] for row in restart["restarts"]))
        if cell == "trust-ci":
            suite, restart = read("trust-ci-suite.json"), read("trust-ci-restart.json")
            return bool(suite.get("status") == "pass" and suite.get("tests_run") == 10
                        and suite.get("tests_run") == len(suite.get("executed", [])) == len(set(suite.get("executed", []))) and not suite.get("skipped")
                        and suite.get("failures") == 0 and suite.get("errors") == 0
                        and restart.get("status") == "pass" and restart["postmaster_before"] != restart["postmaster_after"])
    except (OSError, ValueError, KeyError, TypeError, SyntaxError, RecursionError):
        return False
    return False


def _write(path, value):
    with Path(path).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)


def _git(root, *args):
    return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True,
                          text=True, encoding="utf-8", timeout=15).stdout.strip()


def _stop(process, grace):
    escalated = False
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + grace
    while process.poll() is None and time.monotonic() < deadline:
        time.sleep(.05)
    # Descendants may survive a finished leader. Finish the entire owned group.
    try:
        os.killpg(process.pid, signal.SIGKILL)
        escalated = process.poll() is None
    except ProcessLookupError:
        pass
    process.wait(timeout=5)
    return escalated


def observe(command, *, root, environment, output, timeout, grace=75,
            namespace=None, require_resources=False):
    """Keep the observer outside its child's session and reserve bounded cleanup."""
    if os.name != "posix" or not 0 < timeout <= 1800 or not 0 < grace <= 180:
        raise ValueError("Live observer requires POSIX and bounded deadlines")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    cancelled = []
    handlers = {}
    for number in (signal.SIGTERM, signal.SIGINT):
        handlers[number] = signal.signal(number, lambda n, _f: cancelled.append(n))
    result = {"primary_outcome": "unknown", "cleanup_outcome": "not_applicable",
              "child_exit_confirmed": False, "child_returncode": None, "escalated": False}
    started = time.monotonic()
    try:
        with (output / "command.log").open("xb") as log:
            process = subprocess.Popen(command, cwd=root, env=environment, stdout=log,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            try:
                while process.poll() is None:
                    if cancelled:
                        result["primary_outcome"] = "cancelled"
                        break
                    if time.monotonic() - started >= timeout:
                        result["primary_outcome"] = "timed_out"
                        break
                    if os.fstat(log.fileno()).st_size > OUTPUT_LIMIT:
                        result["primary_outcome"] = "output_limit"
                        break
                    time.sleep(.05)
            finally:
                result["escalated"] = _stop(process, grace)
                result["child_returncode"] = process.returncode
                result["child_exit_confirmed"] = process.returncode is not None
            if result["primary_outcome"] == "unknown":
                result["primary_outcome"] = "passed" if process.returncode == 0 else "failed"
            if os.fstat(log.fileno()).st_size > OUTPUT_LIMIT:
                result["primary_outcome"] = "output_limit"
                log.truncate(OUTPUT_LIMIT)
        raw_log = (output / "command.log").read_bytes()
        result["raw_log_sha256"] = hashlib.sha256(raw_log).hexdigest()
        readable = raw_log.decode("utf-8", errors="backslashreplace")
        readable = re.sub(r"(postgres(?:ql)?://[^\s'\"/@:]+:)[^\s'\"/@]+@", r"\1[redacted]@", readable)
        readable = re.sub(r"(?i)(password\s*=\s*)[^\s'\"]+", r"\1[redacted]", readable)
        (output / "command.log").write_text(readable, encoding="utf-8", newline="\n")
        journals = sorted(output.glob("*-resources.json"))
        if require_resources and not journals:
            result["cleanup_outcome"] = "unknown"
        elif journals:
            statuses = []
            cleanup_deadline = time.monotonic() + 60
            for path in journals:
                try:
                    owner = OwnedDocker.recover(path)
                    if namespace is None or not (owner.namespace == namespace or owner.namespace.startswith(namespace + "-")):
                        raise ValueError("Observer refuses a foreign resource journal")
                    native = owner.cleanup_status == "removed"
                    # The child has been reaped; recovery cannot race that child's allocator.
                    owner.cleanup(deadline=cleanup_deadline)
                    statuses.append("confirmed" if native else "rescued")
                except (OSError, ValueError, KeyError, subprocess.SubprocessError, CleanupUnconfirmed):
                    statuses.append("unknown")
            result["cleanup_outcome"] = "unknown" if "unknown" in statuses else "rescued" if "rescued" in statuses else "confirmed"
        result["status"] = "pass" if (result["primary_outcome"] == "passed"
                            and result["cleanup_outcome"] in ("confirmed", "not_applicable")) else "fail"
    except (OSError, subprocess.SubprocessError) as exc:
        result.update(status="fail", cleanup_outcome="unknown", observer_error=type(exc).__name__)
    finally:
        for number, handler in handlers.items():
            signal.signal(number, handler)
        result["seconds"] = round(time.monotonic() - started, 3)
        _write(output / "observer.json", result)
    return result


def _run(command, *, timeout=60, environment=None):
    process = subprocess.run(command, check=False, text=True, encoding="utf-8", capture_output=True,
                             timeout=timeout, env=environment)
    if process.returncode:
        raise subprocess.CalledProcessError(process.returncode, command)
    return process.stdout.strip()


def _wait_container(identifier, timeout=600):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = json.loads(_run(["docker", "container", "inspect", "--format", "{{json .State}}", identifier]))
        if not state["Running"]:
            if state["ExitCode"] != 0:
                raise RuntimeError("Disposable provisioning or test container failed")
            return
        time.sleep(.25)
    raise TimeoutError("Disposable container deadline exceeded")


def _trust_ci(root, output, namespace):
    pins = image_pins(root)
    owner = OwnedDocker(output / "trust-ci-resources.json", namespace)
    primary = None
    phase = "provision"
    try:
        # Prepare hash-locked wheels before creating the private DB network. No build cache.
        deps = owner.volume("deps")
        provision = owner.container("provision", pins["python"]["reference"], configuration_digest=pins["python"]["image_id"], volume=deps,
            volume_target="/deps", bind={root / "trust-ci": "/src"},
            command=("python3", "-m", "pip", "install", "--disable-pip-version-check", "--no-cache-dir",
                     "--require-hashes", "--target", "/deps", "-r", "/src/requirements-test.txt"))
        _wait_container(provision["id"])
        phase = "network-create"
        network = owner.network("db-network")
        data = owner.volume("data")
        passwords = {role: secrets.token_urlsafe(24) for role in ("admin", "api", "worker", "migrator", "backup")}
        phase = "container-create"
        postgres = owner.container("db", pins["postgres"]["reference"], configuration_digest=pins["postgres"]["image_id"], volume=data, network=network,
            alias="postgres-test", bind={root / "trust-ci/postgres/init": "/docker-entrypoint-initdb.d"}, environment={
                "POSTGRES_DB": "trust_ci_test", "POSTGRES_USER": "trust_ci_admin_test",
                "POSTGRES_PASSWORD": passwords["admin"], "TRUST_CI_API_DB_PASSWORD": passwords["api"],
                "TRUST_CI_WORKER_DB_PASSWORD": passwords["worker"], "TRUST_CI_MIGRATOR_DB_PASSWORD": passwords["migrator"],
                "TRUST_CI_BACKUP_DB_PASSWORD": passwords["backup"]})
        phase = "database-ready"
        deadline = time.monotonic() + 60
        def ready():
            return subprocess.run(["docker", "exec", postgres["id"], "sh", "-c",
                'test "$(head -n1 "$PGDATA/postmaster.pid")" = 1 && pg_isready -U trust_ci_admin_test -d trust_ci_test'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10).returncode == 0
        while not ready():
            if time.monotonic() >= deadline:
                raise TimeoutError("Trust CI PostgreSQL final postmaster did not become ready")
            time.sleep(.25)
        environment = {"PYTHONPATH": "/deps:/src/src:/src/tests:/src", "PYTHONDONTWRITEBYTECODE": "1"}
        for label, role in (("", "migrator"), ("API_", "api"), ("WORKER_", "worker"), ("BACKUP_", "backup")):
            environment["TRUST_CI_TEST_" + label + "DATABASE_URL"] = (
                f"postgresql://trust_ci_{role}:{passwords[role]}@postgres-test:5432/trust_ci_test")
        phase = "tester-create"
        tester = owner.container("tests", pins["python"]["reference"], configuration_digest=pins["python"]["image_id"], volume=deps, volume_target="/deps",
            network=network, bind={root / "trust-ci": "/src",
                root / "scripts/getzilla_trust_ci_postgres_suite.py": "/runner/run_postgres_suite.py"},
            working_directory="/src", environment=environment,
            command=("sleep", "1200"))
        for item, key in ((provision, "python"), (postgres, "postgres"), (tester, "python")):
            if item["image_id"] != verified_image_id(pins[key]["reference"], pins[key]["image_id"]):
                raise ValueError("Trust CI image configuration digest mismatch")
        phase = "database-suite"
        output_json = _run(["docker", "exec", tester["id"], "python3", "/runner/run_postgres_suite.py", "--tests", "/src/tests"], timeout=300)
        report = json.loads(output_json)
        if report.get("status") != "pass" or not report.get("tests_run") or report.get("skipped"):
            raise RuntimeError("Trust CI required PostgreSQL tests did not execute")
        _write(output / "trust-ci-suite.json", report)
        phase = "restart-seed"
        before = _run(["docker", "exec", postgres["id"], "psql", "-U", "trust_ci_admin_test", "-d", "trust_ci_test", "-Atc",
                       "SELECT pg_postmaster_start_time(),system_identifier FROM pg_control_system()"])
        seed = _run(["docker", "exec", tester["id"], "python3", "-m", "tests.postgres_restart_probe", "seed"])
        phase = "database-restart"
        _run(["docker", "restart", postgres["id"]], timeout=45)
        deadline = time.monotonic() + 45
        while not ready():
            if time.monotonic() >= deadline:
                raise TimeoutError("Trust CI PostgreSQL restart deadline exceeded")
            time.sleep(.25)
        phase = "restart-verify"
        after = _run(["docker", "exec", postgres["id"], "psql", "-U", "trust_ci_admin_test", "-d", "trust_ci_test", "-Atc",
                      "SELECT pg_postmaster_start_time(),system_identifier FROM pg_control_system()"])
        verified = _run(["docker", "exec", tester["id"], "python3", "-m", "tests.postgres_restart_probe", "verify"])
        if before == after or before.split("|")[-1] != after.split("|")[-1] or seed != verified:
            raise RuntimeError("Trust CI restart did not retain the bound cluster and durable job")
        _write(output / "trust-ci-restart.json", {"status": "pass", "check_id": "trust-ci-postgres-restart",
            "postmaster_before": before, "postmaster_after": after, "synthetic_job_id": verified,
            "scope": "component persistence; no service deployment or external attestation"})
    except BaseException as exc:
        primary = exc
        print("RESULT: cell=trust-ci phase=" + phase + " " + process_error_detail(exc), file=sys.stderr)
        raise
    finally:
        try:
            owner.cleanup()
        except BaseException as cleanup:
            if primary is None:
                raise
            primary.add_note("Trust CI cleanup unconfirmed: " + type(cleanup).__name__)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cell", required=True, choices=CELLS)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=1500)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    root, output = args.root.resolve(strict=True), args.output.resolve()
    if args.worker:
        def cancelled(_number, _frame):
            raise KeyboardInterrupt()
        signal.signal(signal.SIGTERM, cancelled)
        namespace = os.environ["GETZILLA_LIVE_NAMESPACE"]
        try:
            if args.cell == "trust-ci":
                _trust_ci(root, output, namespace)
            return 0
        except BaseException as error:
            print("RESULT: cell=trust-ci worker " + process_error_detail(error), file=sys.stderr)
            return 130 if isinstance(error, KeyboardInterrupt) else 124 if isinstance(error, subprocess.TimeoutExpired) else 1
    output.mkdir(parents=True, exist_ok=False)
    head, tree = _git(root, "rev-parse", "HEAD"), _git(root, "rev-parse", "HEAD^{tree}")
    expected = os.environ.get("GETZILLA_EXPECTED_HEAD", head)
    if head != expected or not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ValueError("Live acceptance source does not match expected head")
    budget = args.timeout_seconds
    if os.environ.get("GETZILLA_LIVE_DEADLINE"):
        budget = min(budget, int(os.environ["GETZILLA_LIVE_DEADLINE"]) - int(time.time()))
    if budget <= 0:
        raise ValueError("Insufficient main-phase time remains before reserved cleanup/evidence budget")
    if budget > 1800:
        raise ValueError("Live acceptance main budget exceeds its bound")
    factory_baseline = source_census(root) if args.cell == "factory" else None
    ensure_images(root, ("postgres",) if args.cell == "factory" else ("postgres", "python"))
    if os.environ.get("GETZILLA_LIVE_DEADLINE"):
        budget = min(budget, int(os.environ["GETZILLA_LIVE_DEADLINE"]) - int(time.time()))
        if budget <= 0:
            raise ValueError("Image preparation exhausted the reserved main budget")
    namespace = "gz-" + "-".join((os.environ.get("GITHUB_RUN_ID", "local"), os.environ.get("GITHUB_RUN_ATTEMPT", "1"), args.cell, uuid.uuid4().hex[:10]))
    environment = dict(os.environ, GETZILLA_LIVE_NAMESPACE=namespace, GETZILLA_LIVE_ARTIFACTS=str(output))
    command = ([sys.executable, str(root / "factory/tests/run_disposable_exit.py")] if args.cell == "factory" else
               [sys.executable, str(root / "scripts/getzilla_live.py"), "--root", str(root), "--cell", args.cell,
                "--output", str(output), "--worker"])
    result = observe(command, root=root, environment=environment, output=output, namespace=namespace,
                     timeout=budget, require_resources=True)
    factory_stable = factory_baseline is None or source_matches(root, factory_baseline)
    if not factory_stable or not validate_components(output, args.cell, source_root=root):
        result["status"] = "fail"
        result["component_evidence"] = "missing_or_failed"
    if _git(root, "rev-parse", "HEAD") != head or _git(root, "status", "--porcelain"):
        result["status"] = "fail"
        result["source_mutation"] = True
    report = {"schema": "getzilla-live-acceptance-v1", "source": {"head": head, "tree": tree},
        "run_id": os.environ.get("GITHUB_RUN_ID", "local"), "attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "1"),
        "cell": args.cell, "namespace": namespace, **result,
        "event_sha": os.environ.get("GITHUB_SHA"), "base_sha": os.environ.get("GETZILLA_BASE_SHA"),
        "workflow_sha": os.environ.get("GITHUB_WORKFLOW_SHA"), "workflow_ref": os.environ.get("GITHUB_WORKFLOW_REF"),
        "checks": [{"id": name, "status": result["status"], "reason": result["primary_outcome"]} for name in CELLS[args.cell]],
        "authority": "Candidate test observations; not independent workflow or scanner attestation",
        "runner_loss": "Cleanup unknown if the observer or hosted VM is lost"}
    report["files"] = [{"path": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                       for path in sorted(output.iterdir()) if evidence_name(path.name) and path.is_file()
                       and not path.is_symlink() and path.stat().st_size <= OUTPUT_LIMIT]
    _write(output / "manifest.json", report)
    print(json.dumps({"cell": args.cell, "status": result["status"], "primary": result["primary_outcome"], "cleanup": result["cleanup_outcome"]}))
    return 0 if result["status"] == "pass" else 1
