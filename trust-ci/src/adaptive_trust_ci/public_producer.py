"""Protected public producer: source is data; failed evidence is never signed.

All effectful entry points are host-only. This module is also its fixed owned
worker; it never imports a module, hook or configuration from a candidate.
"""

from __future__ import annotations

import base64
from dataclasses import replace
from datetime import timedelta
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time
from urllib.parse import quote

if __name__ == "__main__" and not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    __package__ = "adaptive_trust_ci"

from . import security_bundle as bundle
from .github import GitHubClient
from .github_observer import BoundedGetTransport, _run_owned, observe
from .models import utc_now, parse_datetime
from .public_admission import (
    Selector,
    Evidence,
    evaluate,
    content_manifest,
    read_file,
    validate_local_inputs,
    _snapshot_preflight,
)
from .public_http import _read_app_key, issue_scoped_token
from .public_merge import ObservationSessions
from .public_process import ProducerEnvelope, ProducerCleanupUnknown

CHECKER_ROOT = Path("/opt/getzilla-checker")
_WORKER = str(Path(__file__).resolve())
# One complete selected source plus its bounded Git store and control records.
# This storage profile is distinct from the unchanged32MiB snapshot limit.
SOURCE_STORAGE_BYTES = 2 * bundle.SOURCE_BYTES + bundle.CONTROL_TOTAL
binding_valid = bundle._binding


def select_current(client, authority, pr, *, running=None):
    """Select identities from bounded provider reads, never webhook record fields."""
    if type(pr) is not int or not 0 < pr <= 2147483647:
        raise ValueError("producer-pr")
    value = client._request("GET", f"/repos/{authority.repository}/pulls/{pr}")
    if (
        type(value) is not dict
        or value.get("number") != pr
        or value.get("state") != "open"
        or value["base"]["ref"] != "main"
        or value["head"]["ref"] == "main"
        or not value["head"]["ref"]
        or value["base"]["repo"]["id"] != authority.repository_id
        or value["head"]["repo"]["id"] != authority.repository_id
    ):
        raise ValueError("producer-pr-currentness")
    commit = client._request("GET", f"/repos/{authority.repository}/git/commits/{value['head']['sha']}")
    runs = client._request(
        "GET",
        f"/repos/{authority.runner_repository}/actions/workflows/{authority.workflow_id}"
        f"/runs?branch={quote(authority.branch, safe='')}&per_page=1",
    )
    if type(runs.get("total_count")) is not int or runs["total_count"] < 1 or len(runs["workflow_runs"]) != 1:
        raise ValueError("producer-run-unavailable")
    run = runs["workflow_runs"][0]
    if (
        run.get("workflow_id") != authority.workflow_id
        or run.get("head_sha") != authority.runner_sha
        or run.get("head_branch") != authority.branch
        or run.get("event") != authority.event
        or run.get("status") != ("in_progress" if running is not None else "completed")
        or run.get("conclusion") != (None if running is not None else "success")
        or running is not None
        and (run.get("id"), run.get("run_attempt"), run.get("head_sha")) != running
        or commit.get("sha") != value["head"]["sha"]
    ):
        raise ValueError("producer-run-currentness")
    selected = Selector(
        authority.repository,
        authority.repository_id,
        pr,
        value["base"]["sha"],
        value["head"]["sha"],
        commit["tree"]["sha"],
        run["id"],
        run["run_attempt"],
    )
    selected.source()
    return selected


def checker_identity(root):
    """Read genuine distribution Git identities before importing its Python."""
    raw = _run_owned(
        [
            "git",
            "--no-optional-locks",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "safe.directory=" + str(root),
            "-C",
            str(root),
            "rev-parse",
            "HEAD",
            "HEAD^{tree}",
        ],
        b"",
        time.monotonic() + 5,
    )
    rows = raw.decode("ascii").splitlines()
    if len(rows) != 2 or any(re.fullmatch("[0-9a-f]{40}", row) is None for row in rows):
        raise ValueError("checker-distribution-identity")
    dirty = _run_owned(
        [
            "git",
            "--no-optional-locks",
            "-c",
            "safe.directory=" + str(root),
            "-C",
            str(root),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ],
        b"",
        time.monotonic() + 5,
    )
    if dirty.strip():
        raise ValueError("checker-distribution-dirty")
    return tuple(rows)


def import_core(root):
    from .public_admission import _core

    return _core(policy_root=root)


def load_checker(authority):
    if checker_identity(CHECKER_ROOT) != (authority.checker_sha, authority.checker_tree_sha):
        raise ValueError("checker-distribution-pin-mismatch")
    return import_core(CHECKER_ROOT)


def _normalize(selector, authority, report):
    if (
        type(report) is not dict
        or report.get("kind") != "security-expanded"
        or type(report.get("schema_version")) is not int
        or report.get("schema_version") != 1
        or report.get("status") != "pass"
        or report.get("qualification_gaps") != []
        or report.get("policy_sha256") != authority.policy_digest
    ):
        raise ValueError("producer-checker-refused")
    expected = {
        "head_sha": selector.head_sha,
        "tree_sha": selector.tree_sha,
        "checker_sha": authority.checker_sha,
        "checker_tree_sha": authority.checker_tree_sha,
        "candidate_clean": True,
        "checker_clean": True,
        "same_project": True,
    }
    if report.get("source") != expected or any(
        report["source"].get(key) is not True for key in ("candidate_clean", "checker_clean", "same_project")
    ):
        raise ValueError("producer-checker-source")
    checks, sources = [], set()
    supplied = report.get("checks")
    if type(supplied) is not list or not 1 <= len(supplied) <= bundle.MAX_CHECKS:
        raise ValueError("producer-checker-shape")
    for check in supplied:
        markers = [
            row for row in check.get("details", []) if type(row) is dict and row.get("kind") == "security-result"
        ]
        if len(markers) != 1:
            raise ValueError("producer-checker-shape")
        marker = markers[0]
        if (
            check.get("status") not in ("pass", "skip")
            or marker.get("outcome") not in ("pass", "not_applicable")
            or marker.get("gaps") != []
            or type(marker.get("findings")) is not list
            or bundle.result_finding_count(check["name"], marker) != 0
        ):
            raise ValueError("producer-checker-refused")
        identifiers = [row["source_id"] for row in marker["data_sources"]]
        sources.update(identifiers)
        checks.append(
            {
                "name": check["name"],
                "status": check["status"],
                "outcome": marker["outcome"],
                "finding_count": bundle.result_finding_count(check["name"], marker),
                "gap_count": 0,
                "source_ids": identifiers,
                "coverage_sha256": report["inventory_sha256"],
            }
        )
    descriptors = {"checks": supplied, "source_descriptors": sorted(sources)}
    normalized = {
        "inventory_sha256": report["inventory_sha256"],
        "created_at": report["created_at_utc"],
        "valid_until": report["valid_until_utc"],
        "checks": checks,
        "evidence_sha256": bundle.digest(descriptors),
    }
    return normalized, descriptors


def _checked_preparation(selector, authority, report, integration, *, candidate_root, snapshot_root, core, now):
    """Canonical input/coverage precondition only; no provider eligibility."""
    normalized, descriptors = _normalize(selector, authority, report)
    policy, source = authority.as_policy(), selector.source()
    doc = {
        "version": 1,
        "source": source.as_dict(),
        "policy_sha256": policy.policy_digest,
        "report": normalized,
        "binding": None,
        "integration": integration,
    }
    parsed = bundle.parse_bundle(bundle.canonical_json(doc))
    facts = validate_local_inputs(
        policy,
        parsed,
        source_root=candidate_root,
        snapshot_root=snapshot_root,
        descriptors=descriptors,
        now=now,
        core=core,
    )
    if (
        facts.source_validated is not True
        or facts.blockers
        or facts.integration_validated is not True
        or facts.checker_source != (authority.checker_sha, authority.checker_tree_sha)
        or facts.valid_until is None
        or parse_datetime(facts.valid_until) < now
    ):
        raise ValueError("producer-canonical-input-refusal")
    if bundle.coverage_refusal(facts, normalized["checks"], now=now) is not None:
        raise ValueError("producer-canonical-coverage-refusal")
    return normalized, descriptors, facts, policy, source, doc


def _signing_plan(selector, authority, report, integration, *, candidate_root, snapshot_root, core, client, now):
    """Only canonical facts + fresh provider observations can reach MACHINE signing."""
    normalized, descriptors, facts, policy, source, doc = _checked_preparation(
        selector,
        authority,
        report,
        integration,
        candidate_root=candidate_root,
        snapshot_root=snapshot_root,
        core=core,
        now=now,
    )
    # Repeat complete provider currentness immediately before signing. observe
    # checks repository/app/workflow/jobs/latest run/attempt and re-reads PR/run.
    observed = observe(client, authority, source)
    if (
        observed.validated is not True
        or observed.blockers
        or observed.source_digest != bundle.digest(source.as_dict())
        or observed.authority_digest != policy.authority_digest
        or tuple(sorted(observed.jobs)) != tuple(sorted(authority.required_jobs))
    ):
        raise ValueError("producer-observation-refused")
    expires = min(
        parse_datetime(normalized["valid_until"]),
        parse_datetime(facts.valid_until),
        now + timedelta(seconds=bundle.AGE_SECONDS),
    )
    if expires <= now:
        raise ValueError("producer-evidence-expired")
    payload = {
        "version": 1,
        "kind": "getzilla-security-bundle-binding",
        "source_sha256": bundle.digest(source.as_dict()),
        "report_sha256": bundle.digest(normalized),
        "policy_sha256": policy.policy_digest,
        "authority_sha256": policy.authority_digest,
        "issued_at": now.isoformat(),
        "expires_at": expires.isoformat(),
        "integration_sha256": bundle.digest(integration),
    }
    return {
        "selector": selector.__dict__,
        "evidence": {
            "binding": {"payload": payload, "signature": None},
            "report": normalized,
            "integration": integration,
            "descriptors": descriptors,
        },
    }


def _finish_signature(record, authority, *, sign, now):
    record = bundle.bounded_json(bundle.canonical_json(record), maximum=bundle.CONTROL_TOTAL)
    selector = Selector(**record["selector"])
    value = record["evidence"]
    doc = {
        "version": 1,
        "source": selector.source().as_dict(),
        "policy_sha256": authority.policy_digest,
        "report": value["report"],
        "binding": value["binding"],
        "integration": value["integration"],
    }
    value["binding"]["signature"] = sign(value["binding"]["payload"])
    if not binding_valid(authority.as_policy(), selector.source(), doc, now):
        raise ValueError("producer-machine-signature-refused")
    bundle.parse_bundle(bundle.canonical_json(doc))
    return record


def reuse_record(record, selector, authority, *, root, snapshot, client, now):
    # Reuse an original signed execution only inside its unchanged lifetime.
    # The canonical evaluator revalidates it; no retained JSON becomes a new run.
    if type(record) is not dict or set(record) != {"selector", "evidence"} or record["selector"] != selector.__dict__:
        raise ValueError("producer-cached-source-mismatch")
    evidence = Evidence(**record["evidence"])
    decision = evaluate(
        client, authority, selector, evidence, now=now, candidate_root=root / "candidate", snapshot_root=snapshot
    )
    if decision.eligible is not True:
        raise ValueError("producer-cached-evidence-refused")
    return record


def _tree_bound(root, maximum):
    total = count = 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs:
            if not stat.S_ISDIR((Path(directory) / name).lstat().st_mode):
                raise ValueError("producer-storage-type")
        for name in files:
            info = (Path(directory) / name).lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("producer-storage-type")
            total += info.st_size
            count += 1
            if total > maximum or count > 10000:
                raise ValueError("producer-storage-limit")
    return total


def materialize(selector, root, deadline):
    """Public HTTPS Git only; no candidate hook, filter config, shell or submodule."""
    import subprocess
    import signal

    root.mkdir(mode=0o700)
    environment = {
        "PATH": os.defpath,
        "LANG": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }
    prefix = [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "credential.helper=",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.attributesFile=/dev/null",
        "-C",
        str(root),
    ]

    def run(args):
        # No stdout artifacts or raw diagnostic output. The fixed worker's
        # outer deadline owns this leader and all Git descendants as one group.
        if time.monotonic() >= deadline:
            raise ValueError("producer-source-deadline")
        proc = subprocess.Popen(
            prefix + args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environment,
        )
        try:
            while proc.poll() is None:
                if time.monotonic() >= deadline:
                    raise ValueError("producer-source-deadline")
                _tree_bound(root.parent, SOURCE_STORAGE_BYTES)
                time.sleep(0.01)
            if proc.returncode != 0:
                raise ValueError("producer-source-command-refused")
        finally:
            if proc.poll() is None:
                proc.send_signal(signal.SIGKILL)
                proc.wait(timeout=max(0.01, deadline - time.monotonic()))
        _tree_bound(root.parent, SOURCE_STORAGE_BYTES)

    run(["init", "--quiet"])
    run(["remote", "add", "origin", f"https://github.com/{selector.repository}.git"])
    run(
        [
            "fetch",
            "--quiet",
            "--no-tags",
            "origin",
            selector.base_sha,
            selector.head_sha,
            f"refs/pull/{selector.pr_number}/merge:refs/remotes/origin/public-merge",
        ]
    )
    merge = (
        _run_owned(prefix + ["rev-parse", "refs/remotes/origin/public-merge"], b"", deadline).decode("ascii").strip()
    )
    bundle.exact_sha(merge)
    # Reject symlinks/submodules before checkout. .gitattributes has no host
    # filter definitions in this fresh repository and no hooks are permitted.
    listing = _run_owned(prefix + ["ls-tree", "-r", "-l", "-z", selector.head_sha], b"", deadline)
    total = count = 0
    for row in listing.split(b"\0"):
        if not row:
            continue
        metadata = row.split(b"\t", 1)[0].split()
        if len(metadata) != 4 or metadata[0] not in (b"100644", b"100755") or metadata[1] != b"blob":
            raise ValueError("producer-source-entry-unsupported")
        total += int(metadata[3])
        count += 1
        if not bundle.source_size_ok(total, count):
            raise ValueError("producer-source-capacity")
    _tree_bound(root / ".git", bundle.SOURCE_BYTES)
    run(["-c", "advice.detachedHead=false", "checkout", "--quiet", "--detach", selector.head_sha])
    identity = _run_owned(prefix + ["rev-parse", "HEAD", "HEAD^{tree}"], b"", deadline).decode().splitlines()
    if identity != [selector.head_sha, selector.tree_sha]:
        raise ValueError("producer-source-identity")
    content_manifest(root)
    tree = _run_owned(prefix + ["rev-parse", merge + "^{tree}"], b"", deadline).decode().strip()
    return {
        "merge_sha": merge,
        "tree_sha": tree,
        "parents": [selector.base_sha, selector.head_sha],
        "strategy": "merge",
    }


def run_checker(core, selector, authority, candidate, snapshot, *, image_artifacts, now):
    """Accepted offline API; never forge a candidate head as the runner head."""
    inventory = core.inventory.collect_inventory(candidate)
    if inventory.get('images') or image_artifacts is not None:
        raise ValueError('accepted-independent-image-evaluator-unavailable')
    database, artifacts, tools = (snapshot / name for name in ('database', 'artifacts', 'tools'))
    return core.report.evaluate(candidate, database, artifacts, tools, refresh=False, provision=False, now=now)


def machine_sign(path, public_key, payload):
    fields = {
        "version",
        "kind",
        "source_sha256",
        "report_sha256",
        "policy_sha256",
        "authority_sha256",
        "issued_at",
        "expires_at",
        "integration_sha256",
    }
    now = utc_now()
    if (
        type(payload) is not dict
        or set(payload) != fields
        or type(payload["version"]) is not int
        or payload["version"] != 1
        or payload["kind"] != "getzilla-security-bundle-binding"
        or not parse_datetime(payload["issued_at"]) <= now < parse_datetime(payload["expires_at"])
    ):
        raise ValueError("machine-producer-payload-refused")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = serialization.load_pem_private_key(_read_app_key(path), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("machine-producer-key-type")
    actual = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    if actual != public_key:
        raise ValueError("machine-producer-key-pin")
    return base64.b64encode(key.sign(bundle.canonical_json(payload))).decode("ascii")


def check_cleanup_latch(config):
    try:
        (config.input_root / 'producer-cleanup-unknown').lstat()
    except FileNotFoundError:
        return
    raise ProducerCleanupUnknown('producer-prior-cleanup-unresolved')


def retain_cleanup_latch(config):
    if os.name != 'posix' or not hasattr(os, 'O_NOFOLLOW'):
        raise ProducerCleanupUnknown('producer-profile-unavailable')
    try:
        descriptor = os.open(config.input_root / 'producer-cleanup-unknown',
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        return
    try:
        os.write(descriptor, b'producer-cleanup-unconfirmed\n')
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def refresh_for_pr(config, pr, *, clock=time.monotonic, before_sign=None):
    """One bounded owned producer; returns its sealed record path, never a callback."""
    if not config.producer:
        raise ValueError("public-producer-unconfigured")
    deadline = clock() + 20
    request = bundle.canonical_json(
        {"config_path": str(config.config_path), "pr": pr, "remaining_ns": int((deadline - clock()) * 1000000000)}
    )
    check_cleanup_latch(config)
    try:
        with ProducerEnvelope(config.producer["cgroup_root"], deadline, clock=clock) as envelope:
            raw = _run_owned([sys.executable, "-I", "-B", _WORKER, "--produce"], request, deadline, containment=envelope)
    except ProducerCleanupUnknown:
        try:
            retain_cleanup_latch(config)
        except (OSError, ValueError):
            pass
        raise
    if envelope.empty_confirmed is not True:
        raise ProducerCleanupUnknown("producer-cgroup-cleanup-unconfirmed")
    result = bundle.bounded_json(raw, maximum=65536)
    if (
        type(result) is not dict
        or set(result) != {"root", "ready"}
        or type(result["ready"]) is not bool
        or not isinstance(result["root"], str)
    ):
        raise ValueError("producer-worker-result")
    root = Path(result["root"])
    if root.parent != config.input_root or re.fullmatch("public-[a-z0-9_]{8,64}", root.name) is None:
        raise ValueError("producer-worker-root")
    if result["ready"]:
        if not callable(before_sign):
            raise ValueError("producer-signing-stop-guard-required")
        before_sign()
        plan = bundle.bounded_json(
            read_file(root / "signing-plan.json", bundle.CONTROL_TOTAL), maximum=bundle.CONTROL_TOTAL
        )
        snapshot = Path(config.producer["snapshot_root"])
        if (
            type(plan) is not dict
            or set(plan) != {"record", "content_sha256", "snapshot_sha256", "scope"}
            or plan["scope"] != config.scope
            or bundle.digest(content_manifest(root / "candidate")) != plan["content_sha256"]
            or bundle.digest(_snapshot_preflight(snapshot)) != plan["snapshot_sha256"]
        ):
            raise ValueError("producer-plan-inputs-changed")
        authority = replace(config.authority, public_key_pem=read_file(config.producer_key_path, 65536))
        before_sign()
        record = _finish_signature(
            plan["record"],
            authority,
            now=utc_now(),
            sign=lambda payload: _sign_owned(config, payload, authority.public_key_pem, deadline),
        )
        if (
            clock() >= deadline
            or bundle.digest(content_manifest(root / "candidate")) != plan["content_sha256"]
            or bundle.digest(_snapshot_preflight(snapshot)) != plan["snapshot_sha256"]
        ):
            raise ValueError("producer-plan-inputs-changed")
        _seal_file(root / "record.json", bundle.canonical_json(record))
    return root


def retain_step(root, step, state):
    """Closed per-step metadata only; two2048-byte owned logs, no raw errors."""
    if sys.platform != "linux" or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("producer-profile-unavailable")
    if step not in (
        "configuration",
        "selection",
        "materialize",
        "checker",
        "binding",
        "cache",
        "seal",
    ) or state not in ("start", "complete", "refused"):
        raise ValueError("producer-log-schema")
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("producer-log-root")
    path, previous = root / "producer.log", root / "producer.previous.log"
    row = bundle.canonical_json({"step": step, "state": state}) + b"\n"

    def check(path):
        item = path.lstat()
        if (
            not stat.S_ISREG(item.st_mode)
            or item.st_uid != os.getuid()
            or item.st_nlink != 1
            or item.st_mode & 0o077
            or item.st_size > 2048
        ):
            raise ValueError("producer-log-file")
        return item

    try:
        item = check(path)
    except FileNotFoundError:
        item = None
    if item is not None and item.st_size + len(row) > 2048:
        try:
            check(previous)
            previous.unlink()
        except FileNotFoundError:
            pass
        os.replace(path, previous)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    try:
        item = os.fstat(descriptor)
        if (
            not stat.S_ISREG(item.st_mode)
            or item.st_uid != os.getuid()
            or item.st_nlink != 1
            or item.st_mode & 0o077
            or item.st_size + len(row) > 2048
        ):
            raise ValueError("producer-log-file")
        if os.write(descriptor, row) != len(row):
            raise ValueError("producer-log-write")
    finally:
        os.close(descriptor)


def _configuration(request):
    from .public_runtime import load_config

    config = load_config(request["config_path"], enabled=True)
    config.input_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = config.input_root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("producer-input-root-shape")
    _tree_bound(config.input_root, SOURCE_STORAGE_BYTES)
    core = load_checker(config.authority)
    authority = replace(config.authority, public_key_pem=read_file(config.producer_key_path, 65536), security_core=core)
    return config, core, authority


def _record_root(config, selector, authority):
    identity = bundle.digest({"selector": selector.__dict__, "authority": authority.as_policy().authority_digest})
    return config.input_root / ("public-" + identity)


def _request(fields):
    value = bundle.bounded_json(sys.stdin.buffer.read(65537), maximum=65536)
    if type(value) is not dict or set(value) != fields:
        raise ValueError("producer-worker-input")
    remaining = value["remaining_ns"]
    if type(remaining) is not int or not 0 < remaining <= 20000000000:
        raise ValueError("producer-worker-deadline")
    return value, time.monotonic() + remaining / 1000000000


def _worker_main():
    config, step = None, "configuration"
    try:
        request, deadline = _request({"config_path", "pr", "remaining_ns"})
        config, core, authority = _configuration(request)
        retain_step(config.input_root, step, "complete")
        snapshot = Path(config.producer["snapshot_root"])
        before = _snapshot_preflight(snapshot)
        holder = []
        original = GitHubClient(token_provider=lambda: holder[0], transport=BoundedGetTransport())
        budget = ObservationSessions(
            original,
            lambda end, maximum: GitHubClient(token=holder[0], transport=BoundedGetTransport(clock=budget.clock)),
            purpose="publisher",
        )
        holder.append(
            issue_scoped_token(
                config.publisher,
                config.app_key_path,
                budget,
                now=utc_now(),
                purpose="observer",
                observer_repository_id=authority.runner_repository_id,
            )
        )
        context = bundle.digest({"pr": request["pr"], "scope": config.scope})
        step = "selection"
        with budget.session(context) as client:
            selector = select_current(client, authority, request["pr"])
        retain_step(config.input_root, step, "complete")
        root = _record_root(config, selector, authority)
        # The shipped protected workflow produces this immutable unsigned
        # preparation. A completed GitHub run alone never manufactures it.
        if not root.is_dir():
            raise ValueError("producer-workflow-preparation-unavailable")
        with budget.session(context) as client:
            step = "cache" if (root / "record.json").exists() else "binding"
            if step == "cache":
                record = bundle.bounded_json(
                    read_file(root / "record.json", bundle.CONTROL_TOTAL), maximum=bundle.CONTROL_TOTAL
                )
                reuse_record(record, selector, authority, root=root, snapshot=snapshot, client=client, now=utc_now())
            else:
                preparation = bundle.bounded_json(
                    read_file(root / "preparation.json", bundle.CONTROL_TOTAL), maximum=bundle.CONTROL_TOTAL
                )
                if (
                    type(preparation) is not dict
                    or set(preparation) != {"selector", "report", "integration", "snapshot_sha256"}
                    or preparation["selector"] != selector.__dict__
                    or preparation["snapshot_sha256"] != bundle.digest(before)
                ):
                    raise ValueError("producer-workflow-preparation-mismatch")
                if (root / "signing-plan.json").exists():
                    raise ValueError("producer-prior-signing-unresolved")
                record = _signing_plan(
                    selector,
                    authority,
                    preparation["report"],
                    preparation["integration"],
                    candidate_root=root / "candidate",
                    snapshot_root=snapshot,
                    core=core,
                    client=client,
                    now=utc_now(),
                )
                if _snapshot_preflight(snapshot) != before or time.monotonic() >= deadline:
                    raise ValueError("producer-input-or-lifetime-changed")
                _seal_file(
                    root / "signing-plan.json",
                    bundle.canonical_json(
                        {
                            "record": record,
                            "content_sha256": bundle.digest(content_manifest(root / "candidate")),
                            "snapshot_sha256": bundle.digest(before),
                            "scope": config.scope,
                        }
                    ),
                )
        retain_step(config.input_root, step, "complete")
        sys.stdout.buffer.write(bundle.canonical_json({"root": str(root), "ready": step == "binding"}))
        return 0
    except Exception:
        _refused(config, step)
        return 1


def _seal_file(path, data):
    if len(data) > bundle.CONTROL_TOTAL:
        raise ValueError("producer-record-bound")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def _refused(config, step):
    if config is not None:
        try:
            retain_step(config.input_root, step, "refused")
        except (OSError, ValueError):
            pass


def prepare_workflow(config_path, pr, *, environ=None, clock=time.monotonic):
    """Shipped protected workflow entry; only its read-only job token crosses IPC."""
    environment = os.environ if environ is None else environ
    token = environment.get("GITHUB_TOKEN")
    sha = environment.get("GITHUB_SHA")
    if (
        type(token) is not str
        or not 0 < len(token) <= 4096
        or any(c.isspace() for c in token)
        or type(sha) is not str
        or re.fullmatch("[0-9a-f]{40}", sha) is None
        or environment.get("GITHUB_EVENT_NAME") not in ("workflow_dispatch", "repository_dispatch")
    ):
        raise ValueError("producer-workflow-context-required")
    ids = [environment.get(name, "") for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")]
    if any(type(value) is not str or re.fullmatch("[1-9][0-9]{0,19}", value) is None for value in ids):
        raise ValueError("producer-workflow-run-required")
    deadline = clock() + 20
    request = bundle.canonical_json(
        {
            "config_path": str(config_path),
            "pr": pr,
            "token": token,
            "run": [int(ids[0]), int(ids[1]), sha],
            "remaining_ns": int((deadline - clock()) * 1000000000),
        }
    )
    config = workflow_config(config_path)
    check_cleanup_latch(config)
    try:
        with ProducerEnvelope(config.producer["cgroup_root"], deadline, clock=clock) as envelope:
            raw = _run_owned([sys.executable, "-I", "-B", _WORKER, "--prepare"], request, deadline, containment=envelope)
    except ProducerCleanupUnknown:
        try:
            retain_cleanup_latch(config)
        except (OSError, ValueError):
            pass
        raise
    if envelope.empty_confirmed is not True:
        raise ProducerCleanupUnknown("producer-cgroup-cleanup-unconfirmed")
    if raw != b"prepared":
        raise ValueError("producer-preparation-unconfirmed")


def workflow_config(path):
    from .public_runtime import load_config

    return load_config(path, enabled=True)


def _sign_owned(config, payload, public_key, deadline):
    request = bundle.canonical_json(
        {
            "key_path": config.producer["machine_key_path"],
            "public_key": base64.b64encode(public_key).decode("ascii"),
            "payload": payload,
        }
    )
    raw = _run_owned([sys.executable, "-I", "-B", _WORKER, "--sign"], request, min(deadline, time.monotonic() + 5))
    if not 1 <= len(raw) <= 256:
        raise ValueError("producer-machine-signature-unavailable")
    return raw.decode("ascii")


def _sign_main():
    try:

        def no_effects(event, args):
            if event.startswith(("socket.", "subprocess.")) or event in (
                "os.system",
                "os.fork",
                "os.forkpty",
                "os.posix_spawn",
                "os.posix_spawnp",
            ):
                raise ValueError("machine-signer-effect-refused")

        sys.addaudithook(no_effects)
        request = bundle.bounded_json(sys.stdin.buffer.read(65537), maximum=65536)
        if type(request) is not dict or set(request) != {"key_path", "public_key", "payload"}:
            raise ValueError("machine-signer-request")
        value = machine_sign(
            Path(request["key_path"]), base64.b64decode(request["public_key"], validate=True), request["payload"]
        )
        sys.stdout.buffer.write(value.encode("ascii"))
        return 0
    except Exception:
        return 1


def _prepare_main():
    # This process never calls the App broker or machine signer. Their private
    # files are not mounted into the shipped producer-control workflow image.
    config, step = None, "configuration"
    try:
        request, deadline = _request({"config_path", "pr", "remaining_ns", "run", "token"})
        if (
            type(request["token"]) is not str
            or not 0 < len(request["token"]) <= 4096
            or any(c.isspace() for c in request["token"])
            or type(request["run"]) is not list
            or len(request["run"]) != 3
            or any(type(value) is not int or value <= 0 for value in request["run"][:2])
            or type(request["run"][2]) is not str
            or re.fullmatch("[0-9a-f]{40}", request["run"][2]) is None
        ):
            raise ValueError("producer-workflow-context")
        config, core, authority = _configuration(request)
        if request["run"][2] != authority.runner_sha:
            raise ValueError("producer-workflow-source-pin")
        transport = BoundedGetTransport()
        client = GitHubClient(token=request["token"], transport=transport)
        step = "selection"
        selector = select_current(client, authority, request["pr"], running=tuple(request["run"]))
        root = _record_root(config, selector, authority)
        if root.exists():
            raise ValueError("producer-workflow-generation-already-exists")
        # Do not guess cleanup of a killed generation. It is never proof and
        # cannot be overwritten by a new result for the same source/run.
        if any(entry.name.startswith("public-tmp-") for entry in config.input_root.iterdir()):
            raise ValueError("producer-prior-generation-unresolved")
        snapshot = Path(config.producer["snapshot_root"])
        before = _snapshot_preflight(snapshot)
        with tempfile.TemporaryDirectory(prefix="public-tmp-", dir=config.input_root) as owned:
            temporary = Path(owned)
            step = "materialize"
            retain_step(config.input_root, step, "start")
            integration = materialize(selector, temporary / "candidate", deadline)
            retain_step(config.input_root, step, "complete")
            step = "checker"
            retain_step(config.input_root, step, "start")
            image_artifacts = Path(config.producer["image_artifacts"]) if config.producer["image_artifacts"] else None
            report = run_checker(
                core,
                selector,
                authority,
                temporary / "candidate",
                snapshot,
                image_artifacts=image_artifacts,
                now=utc_now(),
            )
            _normalize(selector, authority, report)
            if (
                select_current(client, authority, request["pr"], running=tuple(request["run"])) != selector
                or _snapshot_preflight(snapshot) != before
                or time.monotonic() >= deadline
            ):
                raise ValueError("producer-workflow-inputs-changed")
            retain_step(config.input_root, step, "complete")
            step = "seal"
            prepared = {
                "selector": selector.__dict__,
                "report": report,
                "integration": integration,
                "snapshot_sha256": bundle.digest(before),
            }
            _seal_file(temporary / "preparation.json", bundle.canonical_json(prepared))
            _tree_bound(config.input_root, SOURCE_STORAGE_BYTES)
            os.rename(temporary, root)
        retain_step(config.input_root, step, "complete")
        sys.stdout.buffer.write(b"prepared")
        return 0
    except Exception:
        _refused(config, step)
        return 1


if __name__ == "__main__":
    action = sys.argv[1:]
    raise SystemExit(
        _worker_main()
        if action == ["--produce"]
        else _prepare_main()
        if action == ["--prepare"]
        else _sign_main()
        if action == ["--sign"]
        else 1
    )
