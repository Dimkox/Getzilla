# Requirements — Reject wildcard resources in delegated grants

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Acceptance criteria

- [x] AC-001: add_approval refuses protected-path and external-write resources containing * ? [ or ], with or without a route gate.
- [x] AC-002: Protected-path resources must be repository-relative file paths without .. or absolute prefixes.
- [x] AC-003: has_valid_approval matches resources by exact equality, so a stored pattern grant authorizes no control-plane write.
- [x] AC-004: getzilla_approve.py exits 2 with a usage message (no traceback, no grant written) for a wildcard resource.
- [x] AC-005: Full PR verification, independent reviews and the exact-head external check precede merge.

## Failure and edge cases

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
