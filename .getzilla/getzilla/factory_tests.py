"""Source-bound Factory unit discovery with explicit skip applicability."""
from __future__ import annotations

import argparse
import ast
import hashlib
from contextlib import contextmanager
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import unittest
import uuid

if not __package__:  # Preserve the source-file entrypoint as well as the archived module.
    sys.path.insert(0, str(Path(__file__).absolute().parents[1]))
from getzilla import fsx
from getzilla.component_state import BoundRoot, _file_identity

MAX_REPORT_BYTES = 4 * 1024 * 1024
MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_TOTAL_INPUT_BYTES = 32 * 1024 * 1024
MAX_INPUT_ENTRIES = 10000
MAX_INPUT_DEPTH = 64
_INPUT_DIRECTORIES = ("factory/tests", "factory/src", "factory/runtime", "factory/contracts")
_INPUT_FILES = (
    "factory/pyproject.toml", "factory/uv.lock", "scripts/getzilla_m8.py",
    "scripts/getzilla_landing_publish.py", "engineering/contracts/openapi/factory-result-admission.v2.json",
    "delivery/src/getzilla_delivery/landing_filesystem.py",
    "delivery/src/getzilla_delivery/landing_publication.py",
    "delivery/src/getzilla_delivery/landing_publication_contracts.py",
)
_GENERATED_DIRECTORIES = frozenset({"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"})
_GENERATED_SUFFIXES = frozenset({".pyc", ".pyo"})
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
_PROCFS_STORE_CASES = frozenset({
    "test_crc_and_encrypted_members_fail_closed",
    "test_descriptor_lifecycle_close_constructor_rollback_and_hostile_replay_are_bounded",
    "test_exact_archive_bounds_are_admitted",
    "test_external_hardlinks_in_object_generation_manifest_and_active_fail_closed",
    "test_hostile_zip_matrix_preserves_old_active",
    "test_manifest_tamper_and_generation_symlink_are_rejected",
    "test_registry_callback_cannot_redirect_object_writes_or_reads",
    "test_replay_rechecks_digest_origin_and_lifecycle_authority",
    "test_restart_and_tenant_repository_symlink_isolation",
    "test_thread_and_process_competitors_converge_and_reconcile",
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
    "source_stable", "database_obligations", "problems",
})


def _directory_identity(info) -> list[int]:
    identity = (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))
    return list(fsx.directory_identity(info, identity))


def _ancestry(root: Path) -> dict[str, list[int]]:
    """Check lexical components before any canonicalization can hide a link."""
    if ".." in root.parts:
        raise ValueError("Factory source root must not contain parent traversal")
    result = {}
    current = Path(root.anchor)
    for component in (None, *root.parts[1:]):
        if component is not None:
            current /= component
        info = os.lstat(current)
        if fsx.is_link(info) or not stat.S_ISDIR(info.st_mode):
            raise ValueError("Factory source ancestry contains a linked or non-directory input")
        result[str(current)] = _directory_identity(info)
    return result


@contextmanager
def _source_root(root: Path):
    root = Path(root).absolute()
    ancestry = _ancestry(root)
    with BoundRoot(root) as bound:
        # BoundRoot accepts trusted system aliases for other callers. This
        # inventory has a stricter lexical contract and never admits an alias.
        if bound.path != root or _ancestry(root) != ancestry:
            raise ValueError("Factory source root changed during binding")
        yield bound, ancestry
        bound.check()
        if _ancestry(root) != ancestry:
            raise ValueError("Factory source ancestry changed during reading")


def _input_layout(bound: BoundRoot):
    files, directories = {}, {}
    entries = 0

    def directory(relative):
        try:
            with bound.parent(relative + "/.inventory") as (parent, _name, check):
                check()
                identity = _directory_identity(fsx.fstat_dir(parent))
                check()
                return identity
        except FileNotFoundError:
            return None

    def walk(relative):
        nonlocal entries
        if len(relative.split("/")) > MAX_INPUT_DEPTH:
            raise ValueError("Factory source directory depth exceeds bound")
        opened = False
        try:
            with bound.parent(relative + "/.inventory") as (parent, _name, check):
                opened = True
                before = _directory_identity(fsx.fstat_dir(parent))
                directories[relative] = before
                names = []
                with fsx.scandir(parent) as listing:
                    for entry in listing:
                        entries += 1
                        if entries > MAX_INPUT_ENTRIES:
                            raise ValueError("Factory source inventory exceeds entry bound")
                        names.append(entry.name)
                check()
                for name in sorted(names):
                    metadata = fsx.lstat_at(parent, name)
                    path = relative + "/" + name
                    if fsx.is_link(metadata):
                        raise ValueError("Factory source inventory contains a linked input")
                    if stat.S_ISDIR(metadata.st_mode):
                        if name not in _GENERATED_DIRECTORIES:
                            walk(path)
                    elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                        if Path(name).suffix not in _GENERATED_SUFFIXES:
                            files[path] = list(_file_identity(metadata))
                    else:
                        raise ValueError("Factory input is not a regular single-link file")
                    check()
                if before != _directory_identity(fsx.fstat_dir(parent)):
                    raise ValueError("Factory source directory changed during inventory")
                check()
        except FileNotFoundError:
            if opened:
                raise ValueError("Factory source disappeared during inventory") from None

    for relative in (*_INPUT_DIRECTORIES, *_INPUT_FILES):
        parts = relative.split("/")
        for index in range(1, len(parts)):
            name = "/".join(parts[:index])
            if name not in directories:
                identity = directory(name)
                if identity is not None:
                    directories[name] = identity
    for relative in _INPUT_DIRECTORIES:
        walk(relative)
    for relative in _INPUT_FILES:
        try:
            with bound.parent(relative) as (parent, name, check):
                metadata = fsx.lstat_at(parent, name)
                if fsx.is_link(metadata) or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise ValueError("Factory input is not a regular single-link file")
                files[relative] = list(_file_identity(metadata))
                check()
        except FileNotFoundError:
            continue
    return dict(sorted(files.items())), dict(sorted(directories.items()))


def _source_snapshot(root: Path):
    """Read a bounded closed inventory through checked directory identities."""
    with _source_root(root) as (bound, ancestry):
        files, directories = _input_layout(bound)
        contents = {}
        total = 0
        for name, identity in files.items():
            snapshot = bound.read(name, limit=min(MAX_INPUT_BYTES, MAX_TOTAL_INPUT_BYTES - total))
            if snapshot is None or list(snapshot.identity) != identity:
                raise ValueError("Factory input changed after inventory")
            contents[name] = snapshot.content
            total += len(snapshot.content)
        if _input_layout(bound) != (files, directories):
            raise ValueError("Factory source bindings changed during reading")
        bound.check()
    return contents, {"ancestry": ancestry, "directories": directories, "files": files}


def source_inventory(root: Path) -> dict[str, str]:
    contents, _bindings = _source_snapshot(root)
    return {name: hashlib.sha256(content).hexdigest() for name, content in contents.items()}


def source_matches(root: Path, binding: dict) -> bool:
    contents, identities = _source_snapshot(root)
    return (identities == binding["source_bindings"]
            and {name: hashlib.sha256(content).hexdigest() for name, content in contents.items()}
            == binding["source_inventory"])


def declared_ids(root: Path, *, contents: dict[str, bytes] | None = None) -> list[str]:
    """Parse the same checked bytes whose hashes bind the mandatory cases."""
    if contents is None:
        contents, _bindings = _source_snapshot(root)
    identifiers = []
    for name, content in contents.items():
        path = Path(name)
        if not name.startswith("factory/tests/") or path.suffix != ".py":
            continue
        module = ".".join(path.with_suffix("").parts)
        tree = ast.parse(content, filename=name)
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


def _procfs_descriptor_reopen() -> bool:
    # Measure independently of the optional Factory implementation. A caller's
    # skip reason, host label or a changed report cannot supply this fact.
    if not sys.platform.startswith("linux"):
        return False
    opened = []
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        opened.append(os.open("/", flags | os.O_NOFOLLOW))
        opened.append(os.open(f"/proc/self/fd/{opened[0]}", flags))
        identities = [_directory_identity(os.fstat(descriptor)) for descriptor in opened]
        return identities[0] == identities[1]
    except (OSError, AttributeError):
        return False
    finally:
        for descriptor in reversed(opened):
            os.close(descriptor)


def observed_context(path: str | None = None) -> dict:
    try:
        child = subprocess.run(
            [sys.executable, "-B", "-I", "-c",
             "import importlib.metadata as m,importlib.util as u; "
             "print(m.version('pypdf')) if u.find_spec('pypdf') else None"],
            cwd="/", env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
            capture_output=True, text=True, encoding="utf-8", timeout=30, check=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("Isolated parser context unavailable") from exc
    supported = False
    try:
        distro = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines() if "=" in line)
        python = subprocess.run(["/usr/bin/python3.12", "--version"], capture_output=True,
                                text=True, encoding="utf-8", timeout=5, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        supported = (platform.system() == "Linux" and platform.machine() == "x86_64"
                     and distro.get("ID", "").strip('"') == "ubuntu"
                     and distro.get("VERSION_ID", "").strip('"') == "24.04"
                     and python.returncode == 0 and python.stdout.strip().startswith("Python 3.12.")
                     and callable(getattr(os, "pidfd_open", None))
                     and callable(getattr(signal, "pidfd_send_signal", None)))
    except (OSError, subprocess.SubprocessError, UnicodeError):
        pass
    return {"unit_database_bindings": "scrubbed", "host_supported": supported,
            "procfs_descriptor_reopen": _procfs_descriptor_reopen(),
            "pypdf_version": child.stdout.strip() or None,
            "jsonschema_cli": shutil.which("jsonschema", path=path)}


def invocation(root: Path, *, path: str | None = None) -> dict:
    contents, identities = _source_snapshot(root)
    return {"root": str(root.absolute()), "python": str(Path(sys.executable).absolute()),
            "invocation_id": uuid.uuid4().hex,
            "engine_sha256": hashlib.sha256(__loader__.get_data(__file__)).hexdigest(),
            "source_inventory": {name: hashlib.sha256(content).hexdigest() for name, content in contents.items()},
            "source_bindings": identities, "declared_ids": declared_ids(root, contents=contents),
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
    if (group == "test_vibevm_store.VibeVMStoreTests" and method in _PROCFS_STORE_CASES
            and context.get("procfs_descriptor_reopen") is False):
        return "unsupported-procfs-store", "requires Linux procfs descriptor reopening"
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
    def __init__(self, *args, source_root=None, source_paths=(), **kwargs):
        super().__init__(*args, **kwargs)
        self.started = []
        self.executed = []
        self.problems = []
        self.source_root = source_root
        self.source_paths = frozenset(source_paths)

    def _problem(self, test, error, kind):
        # Never retain exception messages, locals, subtest values or absolute
        # paths. Only a collected parent case and source-bound frame locations.
        parent = getattr(test, "test_case", test)
        identifier, phase = test_id(parent), "case"
        if identifier not in self.started:
            fixture = re.fullmatch(r"(setUpClass|tearDownClass|setUpModule|tearDownModule) \(([^()]+)\)", identifier)
            if fixture:
                phase, identifier = fixture.groups()
            else:
                identifier, phase = "unqualified_fixture", "unqualified_fixture"
        frames = []
        traceback = error[2] if error else None
        while traceback is not None:
            filename = Path(traceback.tb_frame.f_code.co_filename)
            if self.source_root is not None and filename.is_relative_to(self.source_root):
                relative = filename.relative_to(self.source_root).as_posix()
                if relative in self.source_paths:
                    frames.append({"path": relative, "line": traceback.tb_lineno})
            traceback = traceback.tb_next
        exception = error[0].__name__ if error else "UnexpectedSuccess"
        self.problems.append({"id": identifier, "phase": phase, "kind": kind,
                              "exception": exception, "frames": frames[-32:]})

    def addFailure(self, test, error):
        self._problem(test, error, "failure")
        super().addFailure(test, error)

    def addError(self, test, error):
        self._problem(test, error, "error")
        super().addError(test, error)

    def addSubTest(self, test, subtest, error):
        if error is not None:
            self._problem(test, error, "failure" if issubclass(error[0], test.failureException) else "error")
        super().addSubTest(test, subtest, error)

    def addExpectedFailure(self, test, error):
        self._problem(test, error, "expected_failure")
        super().addExpectedFailure(test, error)

    def addUnexpectedSuccess(self, test):
        self._problem(test, None, "unexpected_success")
        super().addUnexpectedSuccess(test)

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
            or type(document["schema_version"]) is not int or document["schema_version"] != 3
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
    problems = document["problems"]
    if not isinstance(problems, list) or len(problems) > 10000:
        raise ValueError("Factory problem inventory exceeds bound")
    for row in problems:
        if (not isinstance(row, dict) or set(row) != {"id", "phase", "kind", "exception", "frames"}
                or not isinstance(row["id"], str) or not 1 <= len(row["id"]) <= 2048
                or not isinstance(row["phase"], str)
                or row["phase"] not in {"case", "setUpClass", "tearDownClass", "setUpModule", "tearDownModule", "unqualified_fixture"}
                or not isinstance(row["kind"], str) or row["kind"] not in {"error", "failure", "expected_failure", "unexpected_success"}
                or not isinstance(row["exception"], str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", row["exception"])
                or not isinstance(row["frames"], list) or len(row["frames"]) > 32):
            raise ValueError("Factory problem record is invalid")
        if row["phase"] == "case":
            related = row["id"] in document["executed"]
        elif row["phase"] == "unqualified_fixture":
            related = row["id"] == "unqualified_fixture" and row["kind"] == "error"
        else:
            related = (row["kind"] == "error"
                       and any(identifier.startswith(row["id"] + ".") for identifier in document["collected_ids"]))
        if not related:
            raise ValueError("Factory problem is not bound to its case or fixture")
        for frame in row["frames"]:
            if (not isinstance(frame, dict) or set(frame) != {"path", "line"}
                    or not isinstance(frame["path"], str) or frame["path"] not in expected_binding["source_inventory"]
                    or type(frame["line"]) is not int or not 1 <= frame["line"] <= 1000000):
                raise ValueError("Factory problem frame is invalid")
    errors = sum(row["kind"] == "error" for row in problems)
    if errors != document["errors"] or len(problems) - errors != document["failures"]:
        raise ValueError("Factory problem inventory does not match counts")
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
    def recorded(*args, **kwargs):
        return RecordedResult(*args, source_root=root, source_paths=binding["source_inventory"], **kwargs)
    result = unittest.TextTestRunner(verbosity=2, resultclass=recorded).run(suite)
    skipped = []
    for test, reason in result.skipped:
        identifier = test_id(test)
        allowance = skip_allowance(identifier, binding["context"])
        rule = allowance[0] if allowance and allowance[1] == reason else None
        skipped.append({"id": identifier, "reason": reason, "applicability": rule})
    required = sorted(identifier for identifier in expected if skip_allowance(identifier, binding["context"]) is None)
    document = {
        "schema_version": 3, "check_id": "factory-unit", "status": "fail", "binding": binding,
        "collected": len(collected), "collected_ids": collected, "expected_ids": expected, "required_ids": required,
        "tests_run": result.testsRun, "started": result.started, "executed": result.executed,
        "failures": len(result.failures) + len(result.expectedFailures) + len(result.unexpectedSuccesses),
        "errors": len(result.errors), "loader_errors": len(loader.errors), "skipped": skipped,
        "unqualified_skips": sorted(item["id"] for item in skipped if item["applicability"] is None),
        "missing_required": sorted(set(required) - set(result.executed)),
        "source_stable": source_matches(root, binding),
        "database_obligations": "not_run_in_unit_mode",
        "problems": result.problems,
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
    return run(args.root.absolute(), report=args.report, request=request)


if __name__ == "__main__":
    raise SystemExit(main())
