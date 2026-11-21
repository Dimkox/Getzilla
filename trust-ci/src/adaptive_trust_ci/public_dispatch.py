"""Default-off automatic dispatch of the pinned protected producer workflow.

Only the protected host holds this separately configured Actions-write role.
Read-only observation and check publication credentials keep their old scopes.
"""

from __future__ import annotations
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote

from .github import GitHubClient
from .github_observer import BoundedGetTransport
from .models import utc_now
from .public_admission import _snapshot_preflight
from .public_http import WorkflowDispatchConfig, WorkflowDispatchPort, issue_scoped_token
from .public_merge import ObservationSessions
from .public_process import ProducerEnvelope
from .public_producer import load_checker
from .public_publisher import Publication
from .security_bundle import digest, exact_sha


def _context(config, pr, guard):
    authority = config.authority
    if type(pr) is not int or not 0 < pr <= 2147483647:
        raise ValueError("producer-pr")
    # No credentials or Actions-write request until the installed immutable
    # checker and actual delegated-kernel profile are available.
    load_checker(authority)
    holder = []
    original = GitHubClient(token_provider=lambda: holder[0], transport=BoundedGetTransport())
    budget = ObservationSessions(
        original,
        lambda end, maximum: GitHubClient(token=holder[0], transport=BoundedGetTransport(clock=budget.clock)),
        purpose="publisher",
    )
    with ProducerEnvelope(config.producer["cgroup_root"], budget.deadline, clock=budget.clock):
        pass
    holder.append(
        issue_scoped_token(
            config.publisher,
            config.app_key_path,
            budget,
            now=guard(),
            purpose="observer",
            observer_repository_id=authority.runner_repository_id,
        )
    )
    with budget.session(digest({"scope": config.scope, "pr": pr})) as client:
        repo = client._request("GET", f"/repos/{authority.repository}")
        target = client._request("GET", f"/repos/{authority.repository}/pulls/{pr}")
        if (
            repo.get("id") != authority.repository_id
            or repo.get("full_name") != authority.repository
            or target.get("number") != pr
            or target.get("state") != "open"
            or target["base"]["ref"] != "main"
            or target["head"]["ref"] == "main"
            or target["head"]["repo"]["id"] != authority.repository_id
            or target["base"]["repo"]["id"] != authority.repository_id
        ):
            raise ValueError("producer-dispatch-target-refused")
        head, base = target["head"]["sha"], target["base"]["sha"]
        exact_sha(head)
        exact_sha(base)
        runner = "/repos/" + authority.runner_repository
        branch = client._request("GET", f"{runner}/git/ref/heads/{quote(authority.branch, safe='')}")
        workflow = client._request("GET", f"{runner}/actions/workflows/{authority.workflow_id}")
        blob = client._request("GET", f"{runner}/contents/{authority.workflow_path}?ref={authority.runner_sha}")
        if (
            branch.get("ref") != "refs/heads/" + authority.branch
            or branch["object"].get("type") != "commit"
            or branch["object"].get("sha") != authority.runner_sha
            or workflow.get("id") != authority.workflow_id
            or workflow.get("path") != authority.workflow_path
            or workflow.get("state") != "active"
            or blob.get("type") != "file"
            or blob.get("path") != authority.workflow_path
            or blob.get("sha") != authority.workflow_blob_sha
        ):
            raise ValueError("producer-dispatch-workflow-pin-refused")
        latest = client._request(
            "GET",
            f"{runner}/actions/workflows/{authority.workflow_id}"
            f"/runs?branch={quote(authority.branch, safe='')}&per_page=1",
        )
        if (
            type(latest.get("total_count")) is not int
            or latest["total_count"] < 0
            or type(latest.get("workflow_runs")) is not list
            or len(latest["workflow_runs"]) != min(latest["total_count"], 1)
        ):
            raise ValueError("producer-dispatch-run-observation")
        active = False
        if latest["workflow_runs"]:
            run = latest["workflow_runs"][0]
            if run.get("workflow_id") != authority.workflow_id or run.get("head_sha") != authority.runner_sha:
                raise ValueError("producer-dispatch-run-pin")
            active = run.get("status") != "completed"
    # Actual selected bytes identify a generation; they confer no qualification.
    # A failed/missing family cannot be fixed by repeatedly dispatching this key.
    snapshots = digest(_snapshot_preflight(Path(config.producer["snapshot_root"]), authority.as_policy()))
    key = digest({"scope": config.scope, "pr": pr, "base": base, "head": head, "snapshots": snapshots})
    role = config.producer["dispatch"]
    selected = WorkflowDispatchConfig(
        authority.runner_repository,
        authority.runner_repository_id,
        role["app_id"],
        role["installation_id"],
        authority.workflow_id,
        authority.branch,
        Path(role["key_path"]),
    )
    return SimpleNamespace(key=key, active=active, role=selected, budget=budget)


def request_producer(config, pr, journal, *, guard=utc_now):
    role = config.producer["dispatch"]
    if role.get("enabled") is not True:
        return Publication("blocked", "producer-dispatch-disabled")
    guard()
    current = _context(config, pr, guard)
    if current.active:
        return Publication("blocked", "producer-run-pending")
    if not journal.reserve_dispatch(current.key, pr):
        return Publication("blocked", "producer-generation-already-requested")
    # Durable intent precedes both token issuance and the mutation. Unknown
    # outcomes stay fenced; neither absence of a run nor a new webhook retries.
    try:
        token = issue_scoped_token(
            current.role, current.role.key_path, current.budget, now=guard(), purpose="dispatcher"
        )
        client = GitHubClient(token=token)
        guard()
        response = WorkflowDispatchPort(current.role).open(
            client,
            "POST",
            f"/repos/{current.role.repository}/actions/workflows/{current.role.workflow_id}/dispatches",
            {"ref": current.role.branch, "inputs": {"pull_request": str(pr)}},
            deadline=current.budget.deadline,
            maximum=65536,
        )
        try:
            if response.status != 204 or response.read(65536) != b"":
                raise ValueError("producer-dispatch-response-unconfirmed")
        finally:
            response.close()
        journal.finish_dispatch(current.key, "requested")
        return Publication("blocked", "producer-run-requested")
    except Exception:
        try:
            journal.finish_dispatch(current.key, "unknown")
        except (OSError, ValueError, RuntimeError):
            pass
        return Publication("unknown", "producer-dispatch-unconfirmed")
