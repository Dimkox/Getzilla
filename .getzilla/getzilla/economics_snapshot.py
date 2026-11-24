"""Freeze existing owned canonical sources; no ledger, import or acceptance API."""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
import os
import hashlib
import re
import time

from . import fsx, policy, state
from .metrics_journal import MAX_BYTES, MAX_RECORDS, digest
from .observation_privacy import _load_local, owned_journal
from .spec import _parse_canonical_json
from .trace_contracts import native_context

MAX_ROUTES = 120


def _time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


class SnapshotError(ValueError):
    pass


@contextmanager
def _existing_read_guard(anchor, name):
    if name not in {"task-transition", "executions"}:
        raise SnapshotError("protected_read_unavailable")
    path = ".getzilla/runtime/." + name + ".guard.lock"
    with anchor.file(path, limit=128) as (descriptor, _):
        fsx.lock_file(descriptor, exclusive=False, blocking=False)
        try:
            yield
        finally:
            fsx.unlock_file(descriptor)


def freeze(root, anchor, query, deadline):
    """Task → execution → nonblocking journal lock. All reads are bounded.

    Locks bracket the immutable read cut; no provider, model or subprocess runs.
    Repeating this capture is the final source/permission recheck.
    """

    def check():
        anchor.check_cwd()
        if time.monotonic() >= deadline:
            raise SnapshotError("input_limit")

    documents = {}

    def read(path, limit=1048576, *, source=False):
        check()
        if not policy.evaluate_pre_tool(
            root, {"tool_name": "Read", "tool_input": {"file_path": str(root / path)}}, execution_cwd=root
        )[0]:
            raise SnapshotError("protected_read_unavailable")
        raw = anchor.read(path, limit, source=source)
        documents[path] = raw
        if sum(map(len, documents.values())) > MAX_BYTES:
            raise SnapshotError("input_limit")
        return raw

    owner = state.require_route_owner(root, anchor=anchor)
    if owner.get("workspace") != str(root) or not state.current_session():
        raise SnapshotError("protected_read_unavailable")
    policy_bytes = read(".getzilla/config/policy.json", 65536, source=True)
    declared = _parse_canonical_json(policy_bytes, root / "policy")
    if (
        not isinstance(declared, dict)
        or declared.get("schema_version") != 2
        or type(declared.get("secret_read_paths")) is not list
        or any(type(item) is not str for item in declared["secret_read_paths"])
    ):
        raise SnapshotError("input_unavailable")
    source = anchor.git_source()
    with ExitStack() as locks:
        locks.enter_context(_existing_read_guard(anchor, "task-transition"))
        registry_path = ".getzilla/runtime/executions/registry.json"
        if anchor.exists(".getzilla/runtime/.executions.guard.lock"):
            locks.enter_context(_existing_read_guard(anchor, "executions"))
        elif anchor.exists(registry_path):
            raise SnapshotError("protected_read_unavailable")
        descriptor, _, binding = locks.enter_context(owned_journal(root, anchor=anchor))
        fsx.lock_file(descriptor, exclusive=False, blocking=False)
        locks.callback(fsx.unlock_file, descriptor)
        raw = read(".getzilla/runtime/metrics.jsonl", MAX_BYTES)
        if len(raw.splitlines()) > MAX_RECORDS or raw and not raw.endswith(b"\n"):
            raise SnapshotError("input_limit")
        local = _load_local(root, anchor)
        if local.get("access") != "local_owner" or local.get("input_digest") is None:
            raise SnapshotError("protected_read_unavailable")
        bad = set(local["gaps"]) & {
            "record_limit",
            "malformed_row",
            "native_inventory_limit",
            "native_inventory_unqualified",
        }
        if bad:
            raise SnapshotError("input_unavailable")
        with anchor.parent(".getzilla/runtime/routes/.economics-index") as (directory, _):
            names = []
            with os.scandir(directory) as inventory:
                for entry in inventory:
                    check()
                    if len(names) >= MAX_ROUTES or not re.fullmatch("[0-9a-f]{12}\\.json", entry.name):
                        raise SnapshotError("input_limit")
                    names.append(entry.name)
            routes = []
            for name in sorted(names):
                read(".getzilla/runtime/routes/" + name)
                route = state.canonical_route(root, name[:-5], anchor=anchor)
                if route.get("workspace") != str(root):
                    raise SnapshotError("protected_read_unavailable")
                routes.append(route)
        registry_path = ".getzilla/runtime/executions/registry.json"
        registry = None
        if anchor.exists(registry_path):
            from .execution_store import MAX_REGISTRY_BYTES, _validate

            registry = _parse_canonical_json(read(registry_path, MAX_REGISTRY_BYTES), root / "registry")
            _validate(registry)
        if state.require_route_owner(root, anchor=anchor) != owner or anchor.git_source() != source:
            raise SnapshotError("snapshot_unavailable")
        check()
        cut, coverage = _derive(local, routes, registry, binding, query)
        identity = digest(
            {
                "source": source,
                "owner": {
                    k: owner[k]
                    for k in ("route_id", "logical_task_id", "session_id", "authority_epoch", "state_revision")
                },
                "documents": {path: hashlib.sha256(raw).hexdigest() for path, raw in documents.items()},
                "registry_missing": registry is None,
            }
        )
        cut["source_cut_digest"] = identity
        return {
            "cut": cut,
            "documents": documents,
            "binding": binding,
            "owner": owner,
            "source": source,
            "identity": identity,
            "coverage": coverage,
            "policy_digest": hashlib.sha256(policy_bytes).hexdigest(),
        }


def _derive(local, routes, registry, binding, query):
    until = _time(query["as_of"])
    proof = local["delivery_proofs"]
    rows = [
        row
        for row in local["events"]
        if row.get("schema_version") in {3, 4}
        and row["event_id"] in proof
        and _time(row["at"]) < until
        and _time(row["captured_at"]) < until
        and _time(proof[row["event_id"]]["delivered_by"]) <= until
    ]
    by_route = {route["route_id"]: route for route in routes}
    census = []
    for route in routes:
        if _time(route["created_at"]) <= until:
            census.append(
                {
                    "domain": "core_native",
                    "project_digest": binding["repository_digest"],
                    "task_id": route["logical_task_id"],
                }
            )
    census = list({digest(task): task for task in census}.values())
    gaps = set()
    if any(row.get("schema_version") not in {3, 4} for row in local["events"]):
        gaps.add("source_unqualified")
    if local["gaps"]:
        gaps.add("capture_gap")
    if "conflicting_replay" in local["gaps"]:
        gaps.add("conflicted")
    if "native_observer_unqualified" in local["gaps"] or "project_binding_mismatch" in local["gaps"]:
        gaps.add("source_unqualified")
    if any(
        not route.get("observation_publication")
        or route.get("observation_capture_failed")
        or route["observation_publication"].get("dropped")
        for route in routes
    ):
        gaps.add("capture_gap")
    if registry is not None and registry.get("records"):
        gaps.add("history_gap")
    claims = [row for row in rows if row.get("schema_version") == 3 and row.get("kind") == "budget_claimed"]
    bindings = []
    canonical = {}
    for claim in claims:
        route = by_route[claim["route_id"]]
        operation = (route.get("task_budget") or {}).get("operations", {}).get(claim["operation_id"])
        if operation is None or operation["owner_epoch"] != claim["authority_epoch"]:
            gaps.add("history_gap")
            continue
        context = native_context(claim)
        producer = digest({"context": context, "claim_key": operation["key"], "claim_event": claim["event_id"]})
        bound = {
            "claim_event_digest": claim["event_id"],
            "operation_id": claim["operation_id"],
            "attempt_id": claim["attempt_id"],
            "producer_binding_digest": producer,
            "physical_operation_digest": claim["event_id"],
            "task": {
                "domain": "core_native",
                "project_digest": binding["repository_digest"],
                "task_id": claim["logical_task_id"],
            },
            "head": claim["head"],
            "outcome": "unknown",
        }
        finishes = [
            row
            for row in rows
            if row.get("schema_version") == 3
            and row.get("kind") == "operation_finished"
            and row.get("operation_id") == claim["operation_id"]
            and native_context(row) == context
        ]
        starts = [
            row
            for row in rows
            if row.get("schema_version") == 3
            and row.get("kind") == "operation_started"
            and row.get("operation_id") == claim["operation_id"]
            and native_context(row) == context
        ]
        if len(finishes) == len(starts) == 1:
            bound["outcome"] = (
                finishes[0]["outcome"] if finishes[0]["outcome"] in {"succeeded", "failed", "cancelled"} else "unknown"
            )
            canonical[claim["event_id"]] = (bound, finishes[0], claim, operation["key"])
        else:
            gaps.add("history_gap")
        if bound["attempt_id"] is None:
            gaps.add("history_gap")
        bindings.append(bound)
    if len(bindings) > 4096:
        raise SnapshotError("input_limit")
    observations = []
    for row in rows:
        if row.get("kind") != "economics_observation":
            continue
        payload = row["payload"]
        operation = payload.get("operation")
        matched = canonical.get((operation or {}).get("claim_event_digest"))
        if payload["candidate_kind"] != "local_usage" or matched is None:
            gaps.add("source_unqualified")
            continue
        bound, finished, claim, key = matched
        from .trace_observation import _elapsed_observation

        if row != _elapsed_observation(claim, key, finished):
            gaps.add("source_unqualified")
            continue
        observations.append({"row": row, "delivery": proof[row["event_id"]]})
    if not observations:
        gaps.add("not_observed")
    selected = [
        {
            "task": {
                "domain": "core_native",
                "project_digest": binding["repository_digest"],
                "task_id": row["logical_task_id"],
            },
            "selected_at": row["at"],
            "selection_event_digest": row["event_id"],
        }
        for row in rows
        if row.get("kind") == "selected"
    ]
    return {
        "observations": observations,
        "bindings": bindings,
        "selections": selected,
        "census": census,
        "gaps": sorted(gaps),
        "source_cut_digest": "0" * 64,
    }, {
        "canonical_routes": len(routes),
        "native_observations": len(observations),
        "actual_attempt_identities": sum(b["attempt_id"] is not None for b in bindings),
        "gaps": sorted(gaps),
        "native_source_gaps": list(local["gaps"]),
    }
