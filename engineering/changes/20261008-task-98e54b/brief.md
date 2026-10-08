# Reject wildcard resources in delegated grants

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

Change ID: `20261008-task-98e54b`
Created: 2026-10-08T15:32:22+00:00
Risk: high
Complexity: high-risk
Domains: security, api
Issues: #38 (high)
Source finding: independent review of `a8f9338` (S7)

## Problem

`state.add_approval` accepted fnmatch patterns as grant resources. For `protected-path` nothing rejected them, and for `external-write` only the `migration_or_external_write_approval` route gate did; `has_valid_approval` matched with `fnmatch`. One `protected-path --resource '*'` grant therefore authorized writes to the whole control plane, including the hook that enforces the policy, contradicting AGENTS.md "The wildcard scope is forbidden".

## Outcome

Grants name exact resources only; a stored pattern never widens a grant; the CLI refuses patterns with a usage error.

## Scope

### In scope

- `add_approval`: refuse `* ? [ ]` in protected-path and external-write resources; protected-path resources must be repository-relative without `..`; strip leading `./`.
- `has_valid_approval`: exact-equality resource match.
- `scripts/getzilla_approve.py`: help text and usage-error on refusal.
- Tests: `tests/test_approval_resources.py`; `tests/test_policy.py` uses an exact URL grant.

### Out of scope

- Hook bypasses (#36/#37) and updater (#39): separate PRs.
- Trust CI approvals (server-side, already exact).

## Constraints

- Backward compatibility: exact grants behave as before; pattern grants (never allowed by the rules) stop matching.
- Data/privacy: none.
- Performance: none.
- Operational: grants are per-tree runtime state, so no migration is needed.

Re-routed at `07b461c` after `main` advanced (the owner merged the 2026-10-08 fix batch). This supersedes route `22f19c781423` (base `a8f9338`), so architecture comparison uses the current base. Implementation and tests are unchanged.
