"""Join the two finite source-data providers into the shared artifact budget."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .security_artifacts import ArtifactError, MAX_INDEX_BYTES, _saved_proof

RELEASE = "opengrep-release-v1"
ACTION = "github-action-source-v1"


def _fail(message):
    raise ArtifactError("artifact-family-preparation", message)


def publish(root, descriptor, value, *, inventory_digest, now=None, byte_budget=None, records=None):
    """Persist typed provider data; then independently read its source proofs."""
    from .security_license_acquisition import _write

    if not isinstance(value, dict):
        _fail("family preparation must be an object")
    if set(value) == {"records", "gaps", "bound_bytes", "frontiers"}:
        if value["records"] != []:
            _fail("raw release preparation cannot assert qualified components")
        providers = [{"kind": RELEASE, "frontiers": value["frontiers"]}]
    elif (
        set(value) == {"schema_version", "providers"}
        and type(value["schema_version"]) is int
        and value["schema_version"] == 1
    ):
        providers = value["providers"]
    else:
        _fail("family preparation has an unsupported schema")
    if not isinstance(providers, list) or len(providers) > 2:
        _fail("finite family provider list is malformed")
    frontiers = []
    seen = set()
    for provider in providers:
        if not isinstance(provider, dict) or provider.get("kind") in seen:
            _fail("family provider is malformed or repeated")
        kind = provider.get("kind")
        seen.add(kind)
        if kind == RELEASE and set(provider) == {"kind", "frontiers"}:
            if not isinstance(provider["frontiers"], list):
                _fail("raw release frontier list is malformed")
            frontiers.extend({"kind": RELEASE, "descriptor": item} for item in provider["frontiers"])
        elif kind == ACTION and set(provider) == {"kind", "report"}:
            body = json.dumps(provider["report"], sort_keys=True, separators=(",", ":")).encode()
            if len(body) > MAX_INDEX_BYTES:
                raise ArtifactError("artifact-size", "Action source report exceeds the metadata bound")
            digest = hashlib.sha256(body).hexdigest()
            path = "proofs/" + digest
            _write(descriptor, path, body, immutable=True)
            frontiers.append({"kind": ACTION, "descriptor": {"path": path, "sha256": digest}})
        else:
            _fail("family provider is not one of the qualified finite source-data readers")
    return validate_frontiers(
        root, frontiers, inventory_digest=inventory_digest, now=now, byte_budget=byte_budget, records=records
    )


def validate_frontiers(root, frontiers, *, inventory_digest=None, now=None, byte_budget=None, records=None):
    """Rederive costs, freshness and specific gaps for persisted source facts."""
    from .security_license_acquisition import MAX_BATCH_BYTES, MAX_PACKAGES
    from .security_release_tool_inputs import validate_preparation

    budget = MAX_BATCH_BYTES if byte_budget is None else byte_budget
    if type(budget) is not int or not 1 <= budget <= MAX_BATCH_BYTES:
        raise ArtifactError("artifact-size", "shared family source budget is invalid")
    if not isinstance(frontiers, list) or len(frontiers) > MAX_PACKAGES:
        _fail("persisted family frontiers are malformed or unbounded")
    release = []
    actions = []
    normalized = []
    for frontier in frontiers:
        # The first raw producer's shape remains readable without widening the
        # provider namespace. Every such object still enters the fixed reader.
        if isinstance(frontier, dict) and set(frontier) == {"path", "sha256", "subject", "acquired_at"}:
            release.append(frontier)
            normalized.append({"kind": RELEASE, "descriptor": frontier})
            continue
        if not isinstance(frontier, dict) or set(frontier) != {"kind", "descriptor"}:
            _fail("persisted family provider descriptor is malformed")
        kind = frontier["kind"]
        if kind == RELEASE:
            release.append(frontier["descriptor"])
        elif kind == ACTION:
            actions.append(frontier["descriptor"])
        else:
            _fail("unknown family source provider")
        normalized.append(frontier)
    if len(actions) > 1:
        _fail("one exact Action source report is required per inventory")
    result = validate_preparation(Path(root), release, now=now, byte_budget=budget)
    output = {
        "records": [],
        "gaps": result["gaps"],
        "bound_bytes": result["bound_bytes"],
        "frontiers": [{"kind": RELEASE, "descriptor": item} for item in result["frontiers"]],
    }
    for descriptor in actions:
        if not isinstance(descriptor, dict) or set(descriptor) != {"path", "sha256"}:
            _fail("Action source report descriptor is malformed")
        body, report = _saved_proof(Path(root), descriptor["path"], descriptor["sha256"])
        try:
            from .security_action_inputs import validate_source_facts
        except ImportError as exc:
            raise ArtifactError(
                "artifact-family-preparation", "qualified Action source-fact reader is unavailable"
            ) from exc
        checked = validate_source_facts(Path(root), report, now=now, inventory_digest=inventory_digest, records=records)
        if (
            not isinstance(checked, dict)
            or set(checked) != {"gaps", "bound_bytes", "records"}
            or type(checked["bound_bytes"]) is not int
            or checked["bound_bytes"] < 0
            or not isinstance(checked["records"], list)
            or not isinstance(checked["gaps"], list)
        ):
            _fail("Action source-fact reader returned an unsupported result")
        output["bound_bytes"] += len(body) + checked["bound_bytes"]
        if output["bound_bytes"] > budget:
            raise ArtifactError("artifact-size", "finite family source data exceeds the shared catalog byte budget")
        output["records"].extend(checked["records"])
        output["gaps"].extend(checked["gaps"])
        output["frontiers"].append({"kind": ACTION, "descriptor": descriptor})
    return output
