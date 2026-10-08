# Requirements — Reject wildcard resources in delegated grants

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Acceptance criteria

- [x] AC-001: add_approval refuses protected-path and external-write resources containing * ? [ or ], with or without a route gate.
- [x] AC-002: Protected-path resources must be repository-relative file paths without .. or absolute prefixes.
- [x] AC-003: has_valid_approval matches resources by exact equality, so a stored pattern grant authorizes no control-plane write.
- [x] AC-004: getzilla_approve.py exits 2 with a usage message (no traceback, no grant written) for a wildcard resource.
- [x] AC-006: External-write grants for gh api and PR reviews name the exact request (github-api:<METHOD> <host>/<endpoint>, github-pr-review:<owner>/<repo>#<n>); category resource names are refused and a grant authorizes no other method, endpoint, repository or PR.
- [x] AC-007: Production grants are checked against the exact target of the command (branch or tag for git push, owner/repo#N for a merge including gh api PUT .../pulls/N/merge, owner/repo@tag for a release, image for docker push, name@version for npm publish); an unbound grant or an undeterminable target authorizes nothing, and push to main/master, --all or --mirror is refused even with a grant.
- [x] AC-008: Exact URLs with a query string are grantable; protected-path grants refuse drive letters, ':' streams, '~', braces, empty segments and trailing dots; the control-plane runbook lists exact files.
- [x] AC-005: Full PR verification, independent reviews and the exact-head external check precede merge.

## Failure and edge cases

- Review follow-up (security review of #53, P53-1..P53-5): category resources and unbound production grants acted as wildcards; they are now bound to the exact target.
- `git push` without a refspec or with `HEAD` resolves the current branch; a detached HEAD has no target and is refused.
- A non-`origin` remote prefixes the target (`<remote> <branch>`), so a grant for `fix/x` does not cover pushing `fix/x` to another remote.
- Production human gates still decide per action; only the delegated grant binds the target.

- Legacy or hand-edited approvals.json entries with patterns: matched literally, so inert.
- Windows backslashes are normalized to `/` before validation.

## Governance context

- Applicable rule IDs: AGENTS.md "Local delegated grants", "Prohibited routine actions".
- Canonical-example deviations and evidence: none.
- Intentional debt created, repaid, or accepted: none.

## Non-functional requirements

- Security: fail closed on any non-exact resource.
- Reliability: no new dependency.
- Performance: none.
- Observability: ValueError / CLI usage message names the refused resource.
