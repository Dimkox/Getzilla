"""Preserve the required linux check as a fail-closed evidence aggregator.

An ordinary candidate-controlled PR workflow is not independent attestation.
This module checks completeness and bindings; it cannot create workflow trust.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

SECURITY_CHECKS = frozenset(("security-inventory", "known-vulnerabilities", "security-kev", "security-epss",
    "security-malicious-packages", "security-licenses", "security-container-images", "opengrep",
    "secret-scan", "bandit", "trivy-config"))
OPTIONAL_SECURITY_CHECKS = frozenset(("ruff",))
CELL_CHECKS = {"factory": {"factory-postgres-exit"}, "trust-ci": {"trust-ci-postgres", "trust-ci-postgres-restart"},
               "lifecycle": {"factory-lifecycle"}}
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SAFE = re.compile(r"[A-Za-z0-9_.-]{1,160}\Z")
MAX_FILE = 16 * 1024 * 1024
BOUNDARY = "Candidate-controlled workflow; independent trusted workflow admission is not established by this JSON"


def _timestamp(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Timestamp lacks a timezone")
    return result


def _security(record, head, tree, now):
    problems = []
    report, checker = record.get("report") or {}, record.get("checker") or {}
    if (report.get("schema_version") != 1 or report.get("kind") != "security-expanded"
            or report.get("status") != "pass"):
        problems.append("security report missing or failed")
    if report.get("assurance") != "local-input-integrity-only":
        problems.append("security assurance boundary missing or unsupported")
    checker_sha, checker_tree = checker.get("head", ""), checker.get("tree", "")
    if (not HEX40.fullmatch(checker_sha) or not HEX40.fullmatch(checker_tree)
            or checker.get("selected_ref") != checker_sha or checker.get("boundary") != "separate-checkout"
            or checker.get("selection") not in ("operator-variable", "base-commit")):
        problems.append("checker source is unbound or bootstrap is blocked")
    expected = {"head_sha": head, "tree_sha": tree, "checker_sha": checker_sha, "checker_tree_sha": checker_tree}
    if any((report.get("source") or {}).get(key) != value for key, value in expected.items()):
        problems.append("security candidate/checker identity mismatch")
    if any((report.get("source") or {}).get(key) is not True
           for key in ("candidate_clean", "checker_clean", "same_project")):
        problems.append("security candidate/checker cleanliness or project binding missing")
    try:
        created, expires = _timestamp(report["created_at_utc"]), _timestamp(report["valid_until_utc"])
        if not (timedelta(0) <= now - created <= timedelta(hours=72) and now <= expires <= created + timedelta(hours=72)):
            problems.append("security evidence expired or has an invalid time bound")
    except (KeyError, TypeError, ValueError, AttributeError):
        problems.append("security freshness evidence missing")
    inventory = report.get("inventory_sha256", "")
    if not HEX64.fullmatch(inventory) or not HEX64.fullmatch(report.get("policy_sha256", "")):
        problems.append("security inventory/policy digest missing")
    checks = report.get("checks")
    if not isinstance(checks, list) or not all(isinstance(check, dict) for check in checks):
        return problems + ["security check inventory is malformed"]
    names = [check.get("name") for check in checks]
    if len(names) != len(set(names)) or not SECURITY_CHECKS.issubset(names):
        problems.append("security check inventory is incomplete or duplicated")
    for check in checks:
        if check.get("name") not in SECURITY_CHECKS:
            if check.get("name") not in OPTIONAL_SECURITY_CHECKS:
                problems.append("unknown security check is not admitted")
            elif check.get("status") != "pass":
                problems.append("additional security check did not pass")
            continue
        details = check.get("details") or []
        markers = [item for item in details if isinstance(item, dict) and item.get("kind") == "security-result"]
        if len(markers) != 1 or markers[0].get("schema_version") != 1:
            problems.append(f"{check['name']}: structural result missing")
            continue
        marker = markers[0]
        if check.get("status") == "pass" and marker.get("outcome") == "pass":
            continue
        evidence = marker.get("applicability_evidence") or {}
        if not (check.get("status") == "skip" and marker.get("outcome") == "not_applicable"
                and evidence.get("complete") is True and evidence.get("inventory_sha256") == inventory
                and evidence.get("reason") == "complete-inventory-no-objects"):
            problems.append(f"{check['name']}: required check unavailable or failed")
    return problems


def evaluate(needs, records, *, head, tree, run_id, attempt, now=None):
    now = now or datetime.now(timezone.utc)
    problems = []
    for name in ("linux-core", "live-acceptance", "security-expanded"):
        if needs.get(name) != "success":
            problems.append(f"required job {name} did not succeed")
    for name in ("linux-core", *CELL_CHECKS, "security-expanded"):
        record = records.get(name)
        if not isinstance(record, dict):
            problems.append(f"{name}: required artifact missing")
            continue
        if (record.get("source") != {"head": head, "tree": tree} or record.get("run_id") != run_id
                or record.get("attempt") != attempt or record.get("status") != "pass"):
            problems.append(f"{name}: source/run identity or outcome mismatch")
        if name in CELL_CHECKS:
            checks = record.get("checks") or []
            if ({check.get("id") for check in checks} != CELL_CHECKS[name]
                    or len(checks) != len(CELL_CHECKS[name]) or any(check.get("status") != "pass" for check in checks)
                    or record.get("primary_outcome") != "passed" or record.get("cleanup_outcome") != "confirmed"):
                problems.append(f"{name}: required component or native cleanup evidence incomplete")
        elif name == "linux-core":
            unit = record.get("unit") or {}
            executed = unit.get("executed") or []
            prefixes = ("factory.tests.test_disposable_exit.DisposableExitTests.",
                        "factory.tests.test_postgres_fixture_reset.FixtureResetTests.")
            skipped = {item['id'] for item in unit.get('skipped', [])}
            if (unit.get("status") != "pass" or not unit.get("tests_run") or unit.get("collected") != unit.get("tests_run")
                    or len(executed) != unit.get("tests_run") or len(set(executed)) != len(executed)
                    or unit.get("failures") != 0 or unit.get("errors") != 0
                    or unit.get("database_obligations") != "not_run_in_unit_mode"
                    or any(not any(item.startswith(prefix) and item not in skipped for item in executed) for prefix in prefixes)
                    or any(item.startswith(prefixes) for item in skipped)):
                problems.append("Factory unit discovery evidence is missing or incomplete")
        else:
            problems.extend(_security(record, head, tree, now))
    return problems


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate evidence key")
        result[key] = value
    return result


def _bytes(path):
    attributes = path.lstat()
    if not stat.S_ISREG(attributes.st_mode) or attributes.st_size > MAX_FILE:
        raise ValueError("Unsafe or oversized evidence file")
    return path.read_bytes()


def _read(path):
    return json.loads(_bytes(path), object_pairs_hook=_pairs)


def _verify_files(directory, manifest):
    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries or len(entries) > 600:
        raise ValueError("Evidence file inventory missing or excessive")
    names, total = set(), 0
    for entry in entries:
        name = entry["path"]
        if not SAFE.fullmatch(name) or name in (".", "..") or name in names or not HEX64.fullmatch(entry["sha256"]):
            raise ValueError("Unsafe evidence inventory entry")
        content = _bytes(directory / name)
        total += len(content)
        if total > 32 * 1024 * 1024 or hashlib.sha256(content).hexdigest() != entry["sha256"]:
            raise ValueError("Evidence digest or size mismatch")
        names.add(name)


def load_records(artifacts, run_id, attempt):
    records = {}
    for name in ("linux-core", *CELL_CHECKS, "security-expanded"):
        label = "live-" + name if name in CELL_CHECKS else name
        directory = artifacts / f"getzilla-{label}-evidence-{run_id}-{attempt}"
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError(f"{name}: required artifact directory missing")
        if name == "linux-core":
            provenance, state = _read(directory / "provenance.json"), _read(directory / "state.json")
            _verify_files(directory, provenance)
            records[name] = {"source": {"head": provenance["head"], "tree": provenance["tree"]},
                "run_id": provenance["run_id"], "attempt": provenance["attempt"],
                "status": "pass" if state["job_status"] == "success" else "fail",
                "unit": _read(directory / "factory-unit.json")}
        else:
            record = _read(directory / "manifest.json")
            _verify_files(directory, record)
            if name in CELL_CHECKS and record.get("cell") != name:
                raise ValueError("Live cell artifact name mismatch")
            if name in CELL_CHECKS:
                from .live_acceptance import validate_components
                if not validate_components(directory, name):
                    raise ValueError("Live component observations are incomplete")
            records[name] = record
    return records


def _git(root, *args):
    return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True,
                          text=True, encoding="utf-8", timeout=15).stdout.strip()


def security_envelope(root, checker, selected_ref, selection, report_path, output):
    output.mkdir(parents=True, exist_ok=False)
    report = _read(report_path) if report_path.is_file() else {"status": "fail", "reason": "trusted checker missing or bootstrap blocked"}
    source = {"head": _git(root, "rev-parse", "HEAD"), "tree": _git(root, "rev-parse", "HEAD^{tree}")}
    identity = {"selected_ref": selected_ref, "selection": selection, "boundary": "separate-checkout"}
    if checker.is_dir():
        identity.update(head=_git(checker, "rev-parse", "HEAD"), tree=_git(checker, "rev-parse", "HEAD^{tree}"))
    record = {"schema": "getzilla-security-ci-v1", "source": source, "checker": identity, "report": report,
        "status": "fail", "run_id": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "event_sha": os.environ.get("GITHUB_SHA"), "base_sha": os.environ.get("GETZILLA_BASE_SHA"),
        "workflow_sha": os.environ.get("GITHUB_WORKFLOW_SHA"), "workflow_ref": os.environ.get("GITHUB_WORKFLOW_REF"),
        "authority": BOUNDARY}
    problems = _security(record, source["head"], source["tree"], datetime.now(timezone.utc))
    if source["head"] != os.environ.get("GETZILLA_EXPECTED_HEAD") or _git(root, "status", "--porcelain"):
        problems.append("candidate changed or expected head mismatch")
    if checker.is_dir() and _git(checker, "status", "--porcelain"):
        problems.append("trusted checker checkout changed during scanning")
    record["problems"] = problems
    record["status"] = "fail" if problems else "pass"
    encoded = json.dumps(report, sort_keys=True, indent=2).encode()
    (output / "security-expanded.json").write_bytes(encoded)
    record["files"] = [{"path": "security-expanded.json", "sha256": hashlib.sha256(encoded).hexdigest()}]
    (output / "manifest.json").write_text(json.dumps(record, sort_keys=True, indent=2), encoding="utf-8", newline="\n")
    return not problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--security-envelope", action="store_true")
    parser.add_argument("--checker", type=Path)
    parser.add_argument("--checker-ref")
    parser.add_argument("--checker-selection")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.security_envelope:
        return 0 if security_envelope(args.root, args.checker, args.checker_ref, args.checker_selection, args.report, args.output) else 1
    try:
        raw_needs = json.loads(os.environ["GETZILLA_NEEDS"])
        needs = {name: value.get("result") for name, value in raw_needs.items()}
        head, tree = _git(args.root, "rev-parse", "HEAD"), _git(args.root, "rev-parse", "HEAD^{tree}")
        if head != os.environ["GETZILLA_EXPECTED_HEAD"]:
            raise ValueError("Aggregator checked out the wrong source head")
        records = load_records(args.artifacts, os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_RUN_ATTEMPT"])
        problems = evaluate(needs, records, head=head, tree=tree, run_id=os.environ["GITHUB_RUN_ID"], attempt=os.environ["GITHUB_RUN_ATTEMPT"])
    except (OSError, ValueError, TypeError, KeyError, AttributeError, subprocess.SubprocessError) as exc:
        problems = ["Required CI evidence unavailable: " + type(exc).__name__]
    print(json.dumps({"status": "fail" if problems else "pass", "problems": problems, "authority": BOUNDARY}, indent=2))
    return 1 if problems else 0
