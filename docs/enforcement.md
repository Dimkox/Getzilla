# What Getzilla enforces

```text
getzilla doctor --enforcement [--json]
```

reports the level actually in effect in this repository; the lowest confirmed level wins:

| Level | Meaning |
|---|---|
| `none` | hooks are missing or their self-test fails: Getzilla neither guards nor advises |
| `advisory` | agent hooks run: they block protected writes, pushes and merges, but they fail open on their own errors and the stop gate mostly warns |
| `ci-enforced` | the default branch requires the Getzilla checks (`getzilla-verify`, or `linux` + `windows` in Getzilla itself) |
| `external` | a Trust CI check, outside the agent's reach, is required as well |

The report also lists:
- the hooks configured per agent;
- the hook self-test: a harmless command must pass, and a write into `.git` must be denied;
- the stop gate mode and the CI workflow.

It also lists the branch protection that GitHub reports. Branch protection is read with `gh api` (read-only). Without GitHub access it is `unknown` and never counted as enforced. When `enforce_admins` is off, the report says that admins can merge without the checks.

## Making the checks binding

```text
getzilla ci --protect-plan            # prints the protection JSON and the gh command; sends nothing
getzilla ci --protect-apply --yes     # applies it (changes repository settings)
```

The plan:
- requires the Getzilla checks with `strict` (the head must be up to date);
- disallows force pushes and deletion of the default branch;
- leaves reviews and admin enforcement to the owner.

`--protect-apply` without `--yes` refuses.
