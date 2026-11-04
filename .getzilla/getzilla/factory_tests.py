"""Source-bound Factory unit discovery with explicit skip applicability."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import unittest
import uuid

MAX_REPORT_BYTES = 4 * 1024 * 1024
_DATABASE_BINDINGS = (
    "FACTORY_TEST_DATABASE_URL", "FACTORY_FRESH_CLUSTER_DATABASE_URL",
    "FACTORY_TEST_POSTGRES_CONTAINER", "FACTORY_TEST_POSTGRES_CONTAINER_ID",
    "FACTORY_TEST_POSTGRES_NONCE", "FACTORY_TEST_POSTGRES_NETWORK_ID",
    "FACTORY_TEST_POSTGRES_NAMESPACE",
)
_DATABASE_CLASSES = {
    "test_decision_persistence_postgres.DecisionPersistencePostgresTests": "FACTORY_TEST_DATABASE_URL must name a disposable database",
    "test_execution_persistence_postgres.ExecutionPersistencePostgresTests": "FACTORY_TEST_DATABASE_URL must name a disposable database",
    "test_postgres_integration.PostgresFactoryTests": "FACTORY_TEST_DATABASE_URL must name a disposable database",
    "test_runtime_capability_postgres.RuntimeCapabilityPostgresTests": "FACTORY_TEST_DATABASE_URL must name a disposable database",
    "test_execution_persistence_postgres.FreshClusterArtifactAttestorMigrationTests": "FACTORY_FRESH_CLUSTER_DATABASE_URL must name an empty disposable PG17 cluster",
    "test_postgres_fixture_reset.FixtureResetPostgresTests": "requires exact disposable PostgreSQL",
}
_LINUX_CASES = frozenset({
    "test_real_child_has_fixed_identity_health_logs_and_bounded_shutdown",
    "test_pid_record_tamper_and_reuse_fail_closed_without_signalling",
    "test_startup_failure_kills_resistant_descendant_process_group",
    "test_stop_kills_resistant_descendant_and_never_signals_own_group",
    "test_stop_kills_child_forked_by_term_handler_before_deleting_state",
    "test_leaderless_group_blocks_status_restart_and_signal_until_manual_recovery",
    "test_stale_boot_record_never_signals_live_group",
    "test_setup_manager_real_process_install_failed_update_reconcile_remove_and_purge",
    "test_concurrent_managers_leave_one_child_and_coherent_journal",
})
_CLI_CASES = frozenset({
    "test_bb_contracts.BBContractTests.test_structural_schemas_accept_canonical_records_but_parser_is_semantic_gate",
    "test_execution_contracts.ExecutionContractTests.test_workspace_result_schema_validates_records_with_jsonschema_cli",
    "test_semantic_bridge.SemanticBridgeTests.test_bridge_records_validate_with_jsonschema_cli",
})
# The fixture-taking pytest function runs through this existing stdlib-tempdir adapter.
_FUNCTION_ADAPTERS = {
    "factory.tests.test_model_rotator_registry.test_clean_import_cannot_open_socket_spawn_or_write_settings_or_environment":
        "factory.tests.test_model_rotator_registry._test_clean_import_with_stdlib_tempdir",
}
_REPORT_KEYS = frozenset({
    "schema_version", "check_id", "status", "binding", "collected", "collected_ids",
    "expected_ids", "required_ids", "tests_run", "started", "executed", "failures",
    "errors", "loader_errors", "skipped", "unqualified_skips", "missing_required",
    "source_stable", "database_obligations",
})


def source_inventory(root: Path) -> dict[str, str]:
    """Bind the test modules and their published Factory inputs, without caches."""
    paths = {root / name for name in (
        "factory/pyproject.toml", "factory/uv.lock", "scripts/getzilla_m8.py",
        "scripts/getzilla_landing_publish.py", "engineering/contracts/openapi/factory-result-admission.v2.json",
        "delivery/src/getzilla_delivery/landing_filesystem.py",
        "delivery/src/getzilla_delivery/landing_publication.py",
        "delivery/src/getzilla_delivery/landing_publication_contracts.py",
    )}
    for directory in ("factory/tests", "factory/src", "factory/runtime", "factory/contracts"):
        for path in (root / directory).rglob("*"):
            if "__pycache__" in path.parts:
                continue
            if path.is_symlink():
                raise ValueError("Factory source inventory contains a linked input")
            if path.suffix in {".py", ".json", ".sql", ".toml"}:
                paths.add(path)
    inventory = {}
    for path in sorted(paths):
        if not path.exists():
            continue
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_REPORT_BYTES:
            raise ValueError("Factory input is not a bounded regular file")
        inventory[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        if len(inventory) > 10000:
            raise ValueError("Factory source inventory exceeds bound")
    return inventory


def declared_ids(root: Path) -> list[str]:
    """Read the mandatory source cases without importing candidate test code."""
    identifiers = []
    for path in sorted((root / "factory/tests").rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        module = ".".join(path.relative_to(root).with_suffix("").parts)
        tree = ast.parse(path.read_bytes(), filename=str(path))
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                identifiers.extend(module + "." + node.name + "." + method.name for method in node.body
                                   if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
                                   and method.name.startswith("test_"))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
                    node.name.startswith("test_") or (module == "factory.tests.test_model_rotator_registry"
                                                      and node.name == "_test_clean_import_with_stdlib_tempdir")):
                identifier = module + "." + node.name
                identifiers.append(_FUNCTION_ADAPTERS.get(identifier, identifier))
    return sorted(set(identifiers))


def observed_context(path: str | None = None) -> dict:
    try:
        child = subprocess.run(
            [sys.executable, "-B", "-I", "-c",
             "import importlib.metadata as m,importlib.util as u; "
             "print(m.version('pypdf')) if u.find_spec('pypdf') else None"],
            cwd="/", env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
            capture_output=True, text=True, timeout=30, check=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("Isolated parser context unavailable") from exc
    supported = False
    try:
        distro = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
        python = subprocess.run(["/usr/bin/python3.12", "--version"], capture_output=True,
                                text=True, timeout=5, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        supported = (platform.system() == "Linux" and platform.machine() == "x86_64"
                     and distro.get("ID", "").strip('"') == "ubuntu"
                     and distro.get("VERSION_ID", "").strip('"') == "24.04"
                     and python.returncode == 0 and python.stdout.strip().startswith("Python 3.12.")
                     and callable(getattr(os, "pidfd_open", None))
                     and callable(getattr(signal, "pidfd_send_signal", None)))
    except (OSError, subprocess.SubprocessError, UnicodeError):
        pass
    return {"unit_database_bindings": "scrubbed", "host_supported": supported,
            "pypdf_version": child.stdout.strip() or None,
            "jsonschema_cli": shutil.which("jsonschema", path=path)}


def invocation(root: Path, *, path: str | None = None) -> dict:
    return {"root": str(root.resolve()), "python": str(Path(sys.executable).absolute()),
            "invocation_id": uuid.uuid4().hex,
            "engine_sha256": hashlib.sha256(__loader__.get_data(__file__)).hexdigest(),
            "source_inventory": source_inventory(root), "declared_ids": declared_ids(root),
            "context": observed_context(path)}


def skip_allowance(identifier: str, context: dict) -> tuple[str, str] | None:
    """Closed case/class selectors plus independently measured conditions, never reason-only."""
    prefix = "factory.tests."
    if not identifier.startswith(prefix):
        return None
    case = identifier[len(prefix):]
    group, _, method = case.rpartition(".")
    if group in _DATABASE_CLASSES and context["unit_database_bindings"] == "scrubbed":
        return "separate-disposable-postgres", _DATABASE_CLASSES[group]
    if (group == "test_linux_process_adapter.LinuxProcessAdapterTests"
            and method in _LINUX_CASES and not context["host_supported"]):
        return "unsupported-process-host", "requires the supported host profile: Ubuntu 24.04 x86_64 with /usr/bin/python3.12"
    if (case == "test_landing_pdf_worker.PdfWorkerWithoutParser.test_worker_executes_and_reports_parser_unavailable"
            and context["pypdf_version"] is not None):
        return "parser-present", "pypdf present; unavailable branch cannot run"
    if group == "test_landing_pdf_worker.PdfWorkerWithPinnedParser" and context["pypdf_version"] is None:
        return "parser-absent", "requires pypdf installed for the child interpreter"
    if case in _CLI_CASES and context["jsonschema_cli"] is None:
        return "optional-validator-absent", "jsonschema CLI not installed; it is an optional external validator (no jsonschema dependency is declared)"
    return None


def test_id(test) -> str:
    if isinstance(test, unittest.FunctionTestCase):
        function = test._testFunc
        return function.__module__ + "." + function.__name__
    return test.id()


def cases(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from cases(test)
        else:
            yield test



class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.started = []
        self.executed = []

    def startTest(self, test):
        self.started.append(test_id(test))
        self.executed.append(test_id(test))
        super().startTest(test)

    def addSkip(self, test, reason):
        identifier = test_id(test)
        if identifier in self.executed:
            self.executed.remove(identifier)
        super().addSkip(test, reason)


def _ids(value) -> bool:
    return (isinstance(value, list) and len(value) <= 10000 and len(value) == len(set(value))
            and all(isinstance(item, str) and 0 < len(item) <= 2048 for item in value))


def decode_document(content: str) -> dict:
    def pairs(items):
        document = {}
        for key, value in items:
            if key in document:
                raise ValueError("Duplicate Factory evidence field")
            document[key] = value
        return document
    return json.loads(content, object_pairs_hook=pairs)


def validate_report(document: dict, expected_binding: dict) -> None:
    if (not isinstance(document, dict) or set(document) != _REPORT_KEYS
            or type(document["schema_version"]) is not int or document["schema_version"] != 2
            or document["check_id"] != "factory-unit" or document["status"] not in {"pass", "fail"}
            or document["binding"] != expected_binding
            or document["database_obligations"] != "not_run_in_unit_mode"
            or type(document["source_stable"]) is not bool):
        raise ValueError("Factory report schema or invocation binding mismatch")
    for key in ("collected_ids", "expected_ids", "required_ids", "started", "executed", "unqualified_skips", "missing_required"):
        if not _ids(document[key]):
            raise ValueError("Factory report has invalid or duplicate identities")
    for key in ("collected", "tests_run", "failures", "errors", "loader_errors"):
        if type(document[key]) is not int or not 0 <= document[key] <= 10000:
            raise ValueError("Factory report has invalid counts")
    if (document["collected"] != len(document["collected_ids"])
            or document["tests_run"] != len(document["started"])
            or not set(document["started"]) <= set(document["collected_ids"])
            or not isinstance(document["skipped"], list)):
        raise ValueError("Factory report inventory counts do not match")
    skipped, unqualified = [], []
    for item in document["skipped"]:
        if (not isinstance(item, dict) or set(item) != {"id", "reason", "applicability"}
                or not isinstance(item["id"], str) or not isinstance(item["reason"], str) or not item["reason"]
                or len(item["reason"]) > 4096):
            raise ValueError("Factory report skip record is invalid")
        allowed = skip_allowance(item["id"], expected_binding["context"])
        rule = allowed[0] if allowed and allowed[1] == item["reason"] else None
        if item["applicability"] != rule:
            raise ValueError("Factory report skip applicability mismatch")
        skipped.append(item["id"])
        if rule is None:
            unqualified.append(item["id"])
    if document["expected_ids"] != expected_binding["declared_ids"]:
        raise ValueError("Factory report does not match source-declared cases")
    required = sorted(identifier for identifier in document["expected_ids"]
                      if skip_allowance(identifier, expected_binding["context"]) is None)
    missing = sorted(set(required) - set(document["executed"]))
    if (not _ids(skipped) or not set(skipped) <= set(document["started"])
            or set(document["executed"]) != set(document["started"]) - set(skipped)
            or document["required_ids"] != required or document["missing_required"] != missing
            or document["unqualified_skips"] != sorted(unqualified)):
        raise ValueError("Factory report execution or required-case accounting mismatch")
    passed = (bool(document["executed"]) and document["source_stable"]
              and set(document["collected_ids"]) == set(document["expected_ids"])
              and set(document["started"]) == set(document["collected_ids"])
              and not any(document[key] for key in ("failures", "errors", "loader_errors", "missing_required", "unqualified_skips")))
    if document["status"] != ("pass" if passed else "fail"):
        raise ValueError("Factory report status does not match complete execution")


def run(root: Path, *, report: Path | None = None, request: dict | None = None) -> int:
    for name in _DATABASE_BINDINGS:
        os.environ.pop(name, None)
    binding = invocation(root) if request is None else request
    observed = invocation(root)
    observed["invocation_id"] = binding["invocation_id"]
    if observed != binding:
        raise ValueError("Factory invocation does not match current source and context")
    candidate_paths = [str(root), str(root / "factory/src")]
    sys.path[:0] = candidate_paths
    os.environ["PYTHONPATH"] = os.pathsep.join(candidate_paths + [os.environ.get("PYTHONPATH", "")])
    loader = unittest.TestLoader()
    suite = loader.discover(str(root / "factory/tests"), pattern="test_*.py", top_level_dir=str(root))
    collected = [test_id(test) for test in cases(suite)]
    expected = binding["declared_ids"]
    result = unittest.TextTestRunner(verbosity=2, resultclass=RecordedResult).run(suite)
    skipped = []
    for test, reason in result.skipped:
        identifier = test_id(test)
        allowance = skip_allowance(identifier, binding["context"])
        rule = allowance[0] if allowance and allowance[1] == reason else None
        skipped.append({"id": identifier, "reason": reason, "applicability": rule})
    required = sorted(identifier for identifier in expected if skip_allowance(identifier, binding["context"]) is None)
    document = {
        "schema_version": 2, "check_id": "factory-unit", "status": "fail", "binding": binding,
        "collected": len(collected), "collected_ids": collected, "expected_ids": expected, "required_ids": required,
        "tests_run": result.testsRun, "started": result.started, "executed": result.executed,
        "failures": len(result.failures) + len(result.expectedFailures) + len(result.unexpectedSuccesses),
        "errors": len(result.errors), "loader_errors": len(loader.errors), "skipped": skipped,
        "unqualified_skips": sorted(item["id"] for item in skipped if item["applicability"] is None),
        "missing_required": sorted(set(required) - set(result.executed)),
        "source_stable": source_inventory(root) == binding["source_inventory"],
        "database_obligations": "not_run_in_unit_mode",
    }
    passed = (bool(result.executed) and result.wasSuccessful() and not result.expectedFailures
              and not loader.errors and set(collected) == set(expected)
              and set(result.started) == set(collected) and document["source_stable"]
              and not document["missing_required"] and not document["unqualified_skips"])
    document["status"] = "pass" if passed else "fail"
    validate_report(document, binding)
    if not passed:
        print("Factory unit discovery refused: incomplete, failed, or unqualified skipped inventory", file=sys.stderr)
    if report is not None:
        content = json.dumps(document, sort_keys=True, indent=2).encode()
        if len(content) > MAX_REPORT_BYTES:
            raise ValueError("Factory result exceeds evidence bound")
        with report.open("xb") as stream:
            stream.write(content)
    return 0 if passed else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--report", type=Path)
    parser.add_argument("--request", type=Path)
    args = parser.parse_args(argv)
    request = None
    if args.request is not None:
        if args.request.stat().st_size > MAX_REPORT_BYTES:
            raise ValueError("Factory request exceeds bound")
        request = decode_document(args.request.read_text(encoding="utf-8"))
    return run(args.root.resolve(strict=True), report=args.report, request=request)


if __name__ == "__main__":
    raise SystemExit(main())
