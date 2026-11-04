# Verify the Getzilla main update ruleset

Use this proposed ruleset only after the owner approves the dedicated merge App, confirms its numeric App ID and its installation on Dimkox/Getzilla, and qualifies it on an isolated repository. Keep the merge App and status publisher on separate credentials and runtimes. The merge App needs Contents write for the merge endpoint. Keep repository administration and check/status write outside its permissions. The status App needs no Contents write or ruleset bypass.

## Desired single-ruleset GET fields

| Field | Required value |
|---|---|
| `source_type`, `source` | `Repository`, `Dimkox/Getzilla` |
| `id`, `_links.self.href` | Approved numeric ruleset ID and the matching GitHub API repository ruleset URL |
| `target`, `enforcement` | `branch`, `active` |
| `conditions.ref_name.include`, `conditions.ref_name.exclude` | `["refs/heads/main"]`, `[]` |
| `rules` | `[{"type":"update","parameters":{"update_allows_fetch_and_merge":false}}]` |
| `bypass_actors` | One entry with `actor_type` equal to `Integration`, `actor_id` equal to the dedicated numeric merge App ID, and `bypass_mode` equal to `pull_request` |

## Readback

Obtain the three positive numeric IDs independently from the owner's trusted configuration. The actor ID here is the **App ID**. GitHub only includes the bypass list for a reader with write access to the ruleset. Run the GET using an operator identity with that visibility. Leave ruleset administration outside both runtime Apps.

```sh
gh api --hostname github.com --method GET \
  "repos/Dimkox/Getzilla/rulesets/${RULESET_ID}?includes_parents=false" > ruleset.json &&
python trust-ci/scripts/verify_main_update_ruleset.py ruleset.json \
  --ruleset-id "${RULESET_ID}" --merge-app-id "${MERGE_APP_ID}" \
  --publisher-app-id "${PUBLISHER_APP_ID}"
```

Exit 0 means the supplied operator snapshot matches. Its provenance, capture time and the identity of the running service require independent verification. Capture fresh readbacks after each authorized policy change. [GitHub single-ruleset GET](https://docs.github.com/en/rest/repos/rules#get-a-repository-ruleset)

## Additive rollout

1. Capture complete administrator GETs of existing classic branch protection and all active rulesets affecting main. Record the existing `linux` and `windows` publisher bindings (observed GitHub Actions App ID `15368`), all other required checks, and review, push and administrator rules. Keep those settings intact.
2. Use a **separate active policy with no bypass** for required PRs and required checks. Include `linux`, `windows`, and the exact approved security context pinned to its publisher. Confirm that it applies to the merge App. In a separate ruleset these rules are named `pull_request` and `required_status_checks`. Within `required_status_checks.parameters.required_status_checks`, the binding fields are `context` and `integration_id`. Classic protection uses `context` and `app_id`. Preserve the independent owner authorization requirement, including a path for the owner's own PRs. Where a new check is added to classic protection, run `verify_public_check_protection.py` on the administrator's before/after GETs.
3. After owner authorization, add the dedicated update ruleset and read it back. On the isolated target, prove that a human owner, ordinary writer, Actions workflow and status publisher cannot update the branch while policy is active. The merge App must fail direct pushes and PR merges with failed required checks. Exercise its permitted merge only on a fully qualified PR. Retain the evidence and all pre-existing controls during rollout.
4. An authenticated merge service still has to enforce approval and freshness. GitHub's merge endpoint accepts an expected head SHA and provides no atomic base, run-attempt or deadline condition. Treat the ruleset readback as a configuration check. Production qualification also requires a documented resolution for that interval. A personal repository owner retains administrative control of the policy. [GitHub merge endpoint](https://docs.github.com/en/rest/pulls/pulls#merge-a-pull-request)
