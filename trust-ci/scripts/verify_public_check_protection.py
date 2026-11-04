#!/usr/bin/env python3
"""Compare two administrator GET protection snapshots without network or writes."""
import argparse
import copy
import json
import math
from pathlib import Path
import sys

MAX_BYTES = 1024 * 1024
GITHUB_ACTIONS_APP_ID = 15368
PROTECTION_URL = "https://api.github.com/repos/Dimkox/Getzilla/branches/main/protection"


def _bounded(value, depth=0):
    if depth > 32:
        raise ValueError("snapshot nesting exceeds limit")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite JSON number")
    if isinstance(value, (str, list, dict)) and len(value) > 65536:
        raise ValueError("snapshot value exceeds limit")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("non-string JSON key")
            _bounded(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _bounded(item, depth + 1)


def _policy(snapshot):
    _bounded(snapshot)
    if not isinstance(snapshot, dict):
        raise ValueError("expected branch protection object")
    policy = copy.deepcopy(snapshot)
    if policy.get("url") != PROTECTION_URL:
        raise ValueError("expected the Dimkox/Getzilla main branch protection GET endpoint")
    status = policy.get("required_status_checks")
    admins = policy.get("enforce_admins")
    if not isinstance(status, dict) or type(status.get("strict")) is not bool:
        raise ValueError("missing required status-check policy")
    if not isinstance(admins, dict) or type(admins.get("enabled")) is not bool:
        raise ValueError("missing enforce-admins policy")
    checks = status.get("checks")
    if not isinstance(checks, list) or not checks:
        raise ValueError("publisher-aware checks are required")
    bindings = {}
    for check in checks:
        if not isinstance(check, dict) or set(check) != {"context", "app_id"}:
            raise ValueError("unsupported check record")
        name, publisher = check["context"], check["app_id"]
        if not isinstance(name, str) or not name.strip() or name != name.strip():
            raise ValueError("invalid check context")
        if publisher is not None and (type(publisher) is not int or publisher < -1 or publisher == 0):
            raise ValueError("invalid check publisher")
        if name in bindings:
            raise ValueError("duplicate check context")
        bindings[name] = publisher
    contexts = status.get("contexts")
    if not isinstance(contexts, list) or any(not isinstance(x, str) for x in contexts):
        raise ValueError("invalid legacy contexts")
    if len(set(contexts)) != len(contexts) or set(contexts) != set(bindings):
        raise ValueError("contexts and publisher-aware checks disagree")
    # The root endpoint binds repository and branch. Nested endpoint links are metadata.
    admins.pop("url", None)
    status.pop("url", None)
    status.pop("contexts_url", None)
    status.pop("checks")
    status.pop("contexts")
    return policy, bindings


def verify_protection(before, after, context, app_id):
    if not isinstance(context, str) or not context.strip() or context != context.strip():
        raise ValueError("exact new context is required")
    if any(character in context for character in "*?[]"):
        raise ValueError("wildcard check context is unsupported")
    if type(app_id) is not int or app_id <= 0:
        raise ValueError("positive expected App ID is required")
    if app_id == GITHUB_ACTIONS_APP_ID:
        raise ValueError("the security check publisher must be independent of GitHub Actions")
    old_policy, old_checks = _policy(before)
    new_policy, new_checks = _policy(after)
    if not {"linux", "windows"}.issubset(old_checks):
        raise ValueError("baseline must require linux and windows")
    if context in old_checks:
        raise ValueError("new context already exists in baseline")
    expected = dict(old_checks, **{context: app_id})
    if new_checks != expected:
        raise ValueError("required contexts or exact publisher bindings differ")
    # JSON comparison retains type distinctions such as true versus 1.
    if json.dumps(old_policy, sort_keys=True) != json.dumps(new_policy, sort_keys=True):
        raise ValueError("other branch protection settings changed")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def read_snapshot(path):
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("snapshot exceeds 1 MiB")
    value = json.loads(data, object_pairs_hook=_unique_object)
    _bounded(value)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", help="administrator GET snapshot before addition")
    parser.add_argument("after", help="administrator GET snapshot after addition")
    parser.add_argument("--context", required=True)
    parser.add_argument("--app-id", required=True, type=int)
    args = parser.parse_args()
    try:
        verify_protection(read_snapshot(args.before), read_snapshot(args.after),
                          args.context, args.app_id)
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        print(json.dumps({"ready": False, "reason": str(exc)}))
        return 1
    print(json.dumps({"ready": True, "context": args.context, "app_id": args.app_id,
                      "scope": "snapshot policy preservation only"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
