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
_SCOPE_SEAL=object()


class _ScopeExpectation(dict):
    def __init__(self,value,seal):
        if seal is not _SCOPE_SEAL:
            raise ValueError('Source-reobserved selected-run expectation required')
        super().__init__(value)
        self._seal=seal
        self._digest=hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

    def __deepcopy__(self,memo):
        from copy import deepcopy
        result=_ScopeExpectation(deepcopy(dict(self),memo),_SCOPE_SEAL)
        result._digest=self._digest
        return result


def _timestamp(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Timestamp lacks a timezone")
    return result


def _security(record, head, tree, now):
    problems = []
    report, checker = record.get("report") or {}, record.get("checker") or {}
    if (report.get("schema_version") != 1 or report.get("kind") != "security-expanded"
            or report.get("status") not in {"pass","pass-for-selected-run"}):
        problems.append("security report missing or failed")
    scoped=('acceptance_scope' in report or 'overall_coverage_complete' in report
        or report.get('status') in {'pass-for-selected-run','fail-for-selected-run'})
    if scoped and (report.get('status')!='pass-for-selected-run' or not _selected_scope(record,now)):
        problems.append('selected-run applicability is missing, changed or incomplete')
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


def _selected_scope(record,now):
    """Consume the source-reobserved expectation; JSON is still not attestation."""
    from .security_python_target import digest
    try:
        report=record['report']
        expected=record['scope_expectation']
        if (type(expected) is not _ScopeExpectation or expected._seal is not _SCOPE_SEAL
                or digest(expected)!=expected._digest):
            return False
        selected=report['acceptance_scope']
        claim=expected['claim']
        conditions=expected['conditions']
        if (not conditions or claim['required_ids']!=sorted(conditions)
                or report.get('overall_coverage_complete') is not False
                or claim.get('overall_coverage_complete') is not False
                or any(selected.get(key)!=value for key,value in claim.items())
                or claim['source']!=report['source'] or claim['inventory_sha256']!=report['inventory_sha256']
                or claim['run']['run_id']!=record['run_id'] or claim['run']['run_attempt']!=record['attempt']
                or claim['run']['head_sha']!=report['source']['head_sha']
                or selected.get('status')!='pass-for-selected-run' or selected.get('gaps')):
            return False
        body={key:value for key,value in claim.items() if key!='context_sha256'}
        if digest(body)!=claim['context_sha256'] or not HEX64.fullmatch(claim['profile_sha256']):
            return False
        actual=selected['conditions']
        if (len(actual)!=len(conditions) or {row['id'] for row in actual}!=set(conditions)
                or any(row!={**conditions[row['id']],'id':row['id'],'status':'pass',
                    'evidence_sha256':row.get('evidence_sha256')} or not HEX64.fullmatch(row.get('evidence_sha256','')) for row in actual)):
            return False
        markers=[detail for check in report['checks'] if check['name']=='security-licenses'
            for detail in check['details'] if detail.get('kind')=='security-result']
        if len(markers)!=1:
            return False
        marker=markers[0]
        return (marker.get('selected_run')==selected and marker.get('findings')==selected['details']
            and marker['raw_coverage'].get('complete') is False
            and digest(marker['raw_coverage'])==selected['raw_coverage_sha256']
            and type(marker['raw_license_diagnostics']) is list
            and digest(marker['raw_license_diagnostics'])==selected['raw_diagnostics_sha256']
            and timedelta(0)<=now-_timestamp(selected['checked_at_utc'])<=timedelta(hours=72))
    except (KeyError,TypeError,ValueError,AttributeError):
        return False


def _factory_unit_source(root):
    """Read accepted Factory source custody without collecting or executing tests."""
    from . import fsx
    from .factory_tests import MAX_INPUT_BYTES, _source_snapshot, declared_ids
    contents, _bindings = _source_snapshot(root)
    with fsx.ReadOnlyBoundRoot(root) as bound:
        engine = bound.read(".getzilla/getzilla/factory_tests.py", limit=MAX_INPUT_BYTES)
        if engine is None:
            raise ValueError("Factory runner source is missing")
    return {"source_inventory": {name: hashlib.sha256(raw).hexdigest() for name, raw in contents.items()},
            "declared_ids": declared_ids(root, contents=contents),
            "engine_sha256": hashlib.sha256(engine.content).hexdigest()}


def _factory_unit_valid(unit, expected_source):
    """Validate schema3; inode bindings describe the producer's distinct CI checkout."""
    from .factory_tests import validate_report
    try:
        if (type(expected_source) is not dict
                or set(expected_source) != {"source_inventory", "declared_ids", "engine_sha256"}
                or type(unit) is not dict or type(unit.get("binding")) is not dict):
            return False
        binding = unit["binding"]
        if (set(binding) != {"root", "python", "invocation_id", "engine_sha256", "source_inventory",
                             "source_bindings", "declared_ids", "context"}
                or not isinstance(binding["root"], str) or not binding["root"]
                or not isinstance(binding["python"], str) or not binding["python"]
                or not isinstance(binding["invocation_id"], str)
                or not re.fullmatch(r"[0-9a-f]{32}", binding["invocation_id"])
                or type(binding["source_bindings"]) is not dict
                or set(binding["source_bindings"]) != {"ancestry", "directories", "files"}):
            return False
        context = binding["context"]
        linux_capabilities = {"linux_kernel", "posix_source_custody", "unix_peer_credentials"}
        if (type(context) is not dict or set(context) != {"unit_database_bindings", "host_supported",
                "procfs_descriptor_reopen", "pypdf_version", "jsonschema_cli"} | linux_capabilities
                or any(context[key] is not True for key in linux_capabilities)
                or context["unit_database_bindings"] != "scrubbed"
                or type(context["host_supported"]) is not bool
                or type(context["procfs_descriptor_reopen"]) is not bool
                or any(context[key] is not None and (not isinstance(context[key], str) or not context[key])
                       for key in ("pypdf_version", "jsonschema_cli"))):
            return False
        # Source hashes/declared cases/engine come from this exact candidate,
        # while producer context and inode observations retain their original provenance.
        validate_report(unit, {**binding, **expected_source})
        prefixes = ("factory.tests.test_disposable_exit.DisposableExitTests.",
                    "factory.tests.test_postgres_fixture_reset.FixtureResetTests.")
        skipped = {item["id"] for item in unit["skipped"]}
        return (unit["status"] == "pass"
                and all(any(item.startswith(prefix) for item in unit["executed"]) for prefix in prefixes)
                and not any(item.startswith(prefixes) for item in skipped))
    except (ValueError, TypeError, KeyError, AttributeError):
        return False


def admission_result(needs, records, *, head, tree, run_id, attempt):
    problems = evaluate(needs, records, head=head, tree=tree, run_id=run_id, attempt=attempt)
    return {"status": "fail" if problems else "pass", "security-expanded": "informational",
            "problems": problems, "authority": BOUNDARY}


def evaluate(needs, records, *, head, tree, run_id, attempt):
    problems = []
    for name in ("linux-core", "linux-core-tests", "live-acceptance"):
        if needs.get(name) != "success":
            problems.append(f"required job {name} did not succeed")
    for name in ("linux-core", *CELL_CHECKS):
        record = records.get(name)
        if not isinstance(record, dict):
            problems.append(f"{name}: required artifact missing")
            continue
        if (record.get("source") != {"head": head, "tree": tree} or record.get("run_id") != run_id
                or record.get("attempt") != attempt
                or record.get("status") != "pass"):
            problems.append(f"{name}: source/run identity or outcome mismatch")
        if name in CELL_CHECKS:
            checks = record.get("checks") or []
            if ({check.get("id") for check in checks} != CELL_CHECKS[name]
                    or len(checks) != len(CELL_CHECKS[name]) or any(check.get("status") != "pass" for check in checks)
                    or record.get("primary_outcome") != "passed" or record.get("cleanup_outcome") != "confirmed"):
                problems.append(f"{name}: required component or native cleanup evidence incomplete")
        elif name == "linux-core":
            if not _factory_unit_valid(record.get("unit") or {}, record.get("unit_source")):
                problems.append("Factory unit discovery evidence is missing or incomplete")
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


def _verify_files(directory, manifest, *, maximum=600):
    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries or len(entries) > maximum:
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


def load_records(artifacts, run_id, attempt, *, root=None, include_security=True):
    root = Path.cwd() if root is None else Path(root)
    records = {}
    names = ("linux-core", *CELL_CHECKS)
    if include_security:
        names += ("security-expanded",)
    for name in names:
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
                "unit": _read(directory / "factory-unit.json"), "unit_source": _factory_unit_source(root)}
        else:
            record = _read(directory / "manifest.json")
            _verify_files(directory, record, maximum=128 if name in CELL_CHECKS else 600)
            if name in CELL_CHECKS:
                from .live_acceptance import _producer_digest
                from .live_contracts import ci_binding, read_live_record
                expected = ci_binding(head=_git(root, 'rev-parse', 'HEAD'), tree=_git(root, 'rev-parse', 'HEAD^{tree}'),
                    run_id=run_id, attempt=attempt, cell=name, producer_sha256=_producer_digest(root, name))
                applicability = None
                if name == 'factory':
                    from .live_acceptance import retained_parser_contract
                    applicability = retained_parser_contract(root)
                    source = records['linux-core']['unit_source']
                    inventory, expected_ids = source['source_inventory'], source['declared_ids']
                elif name == 'trust-ci':
                    from .live_contracts import trust_source_contract
                    inventory, expected_ids = trust_source_contract(root)
                else:
                    inventory, expected_ids = None, None
                record = read_live_record(directory, expected, expected_source_inventory=inventory, expected_ids=expected_ids,
                                          expected_factory_applicability=applicability)
            elif ("security-expanded.json" not in {entry["path"] for entry in record["files"]}
                  or _read(directory / "security-expanded.json") != record.get("report")):
                raise ValueError("Bound security report missing or inconsistent")
            elif record.get('report',{}).get('status')=='pass-for-selected-run':
                record['scope_expectation']=_reobserve_scope(root,directory,record,run_id,attempt)
            records[name] = record
    return records


def _git(root, *args):
    return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True,
                          text=True, encoding="utf-8", timeout=15).stdout.strip()


def _reobserve_scope(root,directory,record,run_id,attempt):
    from .security_license_scope import declaration_expectation
    from .ci_security_context import selected_run_environment
    from .public_security_context import ci_run_context
    override=os.environ.get('GETZILLA_OPERATOR_CHECKER','')
    checker=override or os.environ.get('GETZILLA_BASE_SHA','')
    identity=record['checker']
    if (not HEX40.fullmatch(checker) or checker=='0'*40 or identity.get('head')!=checker
            or identity.get('selected_ref')!=checker
            or identity.get('selection')!=('operator-variable' if override else 'base-commit')
            or _git(root,'rev-parse',checker+'^{commit}')!=checker
            or _git(root,'rev-parse',checker+'^{tree}')!=identity.get('tree')):
        raise ValueError('Selected checker differs from independent workflow selection or Git objects')
    policy='.getzilla/config/license-policy.json'
    size=int(_git(root,'cat-file','-s',checker+':'+policy))
    if not 0<size<=65536:
        raise ValueError('Selected checker policy is unbounded')
    raw=subprocess.run(['git','show',checker+':'+policy],cwd=root,check=True,capture_output=True,timeout=15).stdout
    if len(raw)!=size or raw!=_bytes(root/policy):
        raise ValueError('Candidate policy differs from exact selected checker policy')
    head,tree=_git(root,'rev-parse','HEAD'),_git(root,'rev-parse','HEAD^{tree}')
    if _git(root,'status','--porcelain'):
        raise ValueError('Aggregator source is not clean')
    source=dict(head_sha=head,tree_sha=tree,checker_sha=checker,checker_tree_sha=identity['tree'],
        candidate_clean=True,checker_clean=True,same_project=True)
    env,_=selected_run_environment(os.environ,head)
    run=ci_run_context(env)
    if run['run_id']!=run_id or run['run_attempt']!=attempt:
        raise ValueError('Aggregator run differs from current workflow invocation')
    filename='security-run-inputs.json'
    if filename not in {row['path'] for row in record['files']}:
        raise ValueError('Selected-run source declaration is not bound by the artifact manifest')
    raw=_bytes(directory/filename)
    if len(raw)>2*1024*1024:
        raise ValueError('Selected-run source declaration exceeds its finite budget')
    inputs=json.loads(raw,object_pairs_hook=_pairs)
    observed=declaration_expectation(root,root,inputs,source,run,now=datetime.now(timezone.utc),scratch=directory,
        checker_revision=checker)
    if record.get('scope_expectation')!=observed:
        raise ValueError('Stored selected-run condition set differs from source reobservation')
    return _ScopeExpectation(observed,_SCOPE_SEAL)


def security_envelope(root, checker, selected_ref, selection, report_path, output):
    output.mkdir(parents=True, exist_ok=False)
    from .ci_security_context import closed_phase_report, primary_report, selected_run_environment
    phase_inputs = {}
    # Keep the closed primary refusal and original byte digest; never replace
    # it with a fabricated bootstrap explanation or export arbitrary values.
    for phase, filename in (('declaration', 'security-profile-declaration.json'),
                            ('preparation', 'security-input-preparation.json'),
                            ('event', 'security-event.json')):
        path = report_path.parent / filename
        if path.is_file():
            raw = _bytes(path)
            if len(raw) > 2 * 1024 * 1024:
                raise ValueError('Primary security phase exceeds existing bounded evidence budget')
            observed = _read(path)
            if phase == 'event':
                _, expected_event = selected_run_environment(os.environ, _git(root, 'rev-parse', 'HEAD'))
                if observed != expected_event:
                    raise ValueError('Original event provenance differs from current invocation')
                phase_inputs[phase] = observed
            elif isinstance(observed, dict) and observed.get('status') in ('fail', 'unavailable'):
                phase_inputs[phase] = closed_phase_report(observed, raw)
            else:
                continue
            (output / filename).write_text(json.dumps(phase_inputs[phase], sort_keys=True), encoding='utf-8', newline='\n')
    phase, report = primary_report(_read(report_path) if report_path.is_file() else None,
                                   phase_inputs.get('declaration'), phase_inputs.get('preparation'))
    source = {"head": _git(root, "rev-parse", "HEAD"), "tree": _git(root, "rev-parse", "HEAD^{tree}")}
    identity = {"selected_ref": selected_ref, "selection": selection, "boundary": "separate-checkout"}
    if checker.is_dir():
        identity.update(head=_git(checker, "rev-parse", "HEAD"), tree=_git(checker, "rev-parse", "HEAD^{tree}"))
    record = {"schema": "getzilla-security-ci-v1", "source": source, "checker": identity, "report": report,
        "status": "fail", "run_id": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "event_sha": os.environ.get("GITHUB_SHA"), "base_sha": os.environ.get("GETZILLA_BASE_SHA"),
        "workflow_sha": os.environ.get("GITHUB_WORKFLOW_SHA"), "workflow_ref": os.environ.get("GITHUB_WORKFLOW_REF"),
        "authority": BOUNDARY, "primary_phase": phase, "event_provenance": phase_inputs.get("event")}
    if report.get('status')=='pass-for-selected-run':
        try:
            from .security_license_scope import declaration_expectation
            from .public_security_context import ci_run_context
            env,_=selected_run_environment(os.environ,source['head'])
            raw_inputs=_bytes(report_path.parent/'security-run-inputs.json')
            if len(raw_inputs)>2*1024*1024:
                raise ValueError('Selected-run declaration exceeds its finite evidence budget')
            inputs=json.loads(raw_inputs)
            actual_source={**{key:report['source'][key] for key in ('candidate_clean','checker_clean','same_project')},
                'head_sha':source['head'],'tree_sha':source['tree'],'checker_sha':identity['head'],'checker_tree_sha':identity['tree']}
            observed=declaration_expectation(root,checker,inputs,actual_source,ci_run_context(env),
                now=datetime.now(timezone.utc),scratch=output)
            record['scope_expectation']=_ScopeExpectation(observed,_SCOPE_SEAL)
            (output/'security-run-inputs.json').write_bytes(raw_inputs)
        except (KeyError,ValueError,TypeError,OSError,RuntimeError):
            record['scope_expectation']=None
    problems = _security(record, source["head"], source["tree"], datetime.now(timezone.utc))
    if source["head"] != os.environ.get("GETZILLA_EXPECTED_HEAD") or _git(root, "status", "--porcelain"):
        problems.append("candidate changed or expected head mismatch")
    if checker.is_dir() and _git(checker, "status", "--porcelain"):
        problems.append("trusted checker checkout changed during scanning")
    record["problems"] = problems
    record["status"] = "fail" if problems else "pass"
    encoded = json.dumps(report, sort_keys=True, indent=2).encode()
    (output / "security-expanded.json").write_bytes(encoded)
    record["files"] = [{"path": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                       for path in sorted(output.iterdir()) if path.is_file()]
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
        if head != os.environ["GETZILLA_EXPECTED_HEAD"] or _git(args.root, "status", "--porcelain"):
            raise ValueError("Aggregator source head is wrong or the worktree is not clean")
        records = load_records(args.artifacts, os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_RUN_ATTEMPT"],
                               root=args.root, include_security=False)
        result = admission_result(needs, records, head=head, tree=tree, run_id=os.environ["GITHUB_RUN_ID"],
                                  attempt=os.environ["GITHUB_RUN_ATTEMPT"])
    except (OSError, ValueError, TypeError, KeyError, AttributeError, subprocess.SubprocessError) as exc:
        result = {"status": "fail", "security-expanded": "informational", "problems": ["Required CI evidence unavailable: " + type(exc).__name__],
                  "authority": BOUNDARY}
    print(json.dumps(result, indent=2))
    return int(result["status"] == "fail")


def trust_source_inventory(root):
    from .live_contracts import source_inventory
    return source_inventory(Path(root), 'trust-ci')
