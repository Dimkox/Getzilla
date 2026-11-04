#!/usr/bin/env python3
"""Check an operator-supplied GitHub single-ruleset GET snapshot offline."""
import argparse
import json
import sys

from verify_public_check_protection import GITHUB_ACTIONS_APP_ID, read_snapshot


REPOSITORY = "Dimkox/Getzilla"
SCOPE = "operator snapshot of main update ruleset only"


def verify_ruleset(snapshot, ruleset_id, merge_app_id, publisher_app_id):
    if any(type(number) is not int or number < 1
           for number in (ruleset_id, merge_app_id, publisher_app_id)):
        raise ValueError("positive numeric ruleset and GitHub App IDs required")
    if len({merge_app_id, publisher_app_id, GITHUB_ACTIONS_APP_ID}) != 3:
        raise ValueError("the merge App, publisher and GitHub Actions must have distinct App IDs")
    if not isinstance(snapshot, dict):
        raise ValueError("expected one repository ruleset GET object")

    endpoint = f"https://api.github.com/repos/{REPOSITORY}/rulesets/{ruleset_id}"
    links = snapshot.get("_links")
    self_link = links.get("self") if isinstance(links, dict) else None
    if not isinstance(self_link, dict) or self_link.get("href") != endpoint:
        raise ValueError("unexpected ruleset GET endpoint")

    expected = {
        "id": ruleset_id,
        "source_type": "Repository",
        "source": REPOSITORY,
        "target": "branch",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
        "bypass_actors": [{"actor_type": "Integration", "actor_id": merge_app_id,
                           "bypass_mode": "pull_request"}],
        "rules": [{"type": "update", "parameters": {"update_allows_fetch_and_merge": False}}],
    }
    # Exact nested JSON types matter because Python equates booleans and numbers.
    for name, value in expected.items():
        if json.dumps(snapshot.get(name), sort_keys=True) != json.dumps(value, sort_keys=True):
            raise ValueError(f"unexpected or missing ruleset field {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", help="operator snapshot from the authenticated single-ruleset GET")
    parser.add_argument("--ruleset-id", type=int, required=True)
    parser.add_argument("--merge-app-id", type=int, required=True)
    parser.add_argument("--publisher-app-id", type=int, required=True)
    args = parser.parse_args()
    try:
        verify_ruleset(read_snapshot(args.snapshot), args.ruleset_id,
                       args.merge_app_id, args.publisher_app_id)
    except (OSError, ValueError, RecursionError) as exc:
        print(json.dumps({"matches": False, "scope": SCOPE, "reason": str(exc)}))
        return 1
    print(json.dumps({"matches": True, "scope": SCOPE, "ruleset_id": args.ruleset_id,
                      "merge_app_id": args.merge_app_id}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
