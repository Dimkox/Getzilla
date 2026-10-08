# Architecture — Reject wildcard resources in delegated grants

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Current behavior

`add_approval` normalized resources with `replace` and `strip` only; `has_valid_approval` used `fnmatch.fnmatchcase(resource, pattern)`.

## Proposed behavior

`_normalize_grant_resource(scope, raw)` validates each resource; `has_valid_approval` checks `resource in grant.resources`.

## Components and boundaries

Only `.getzilla/getzilla/state.py` and `scripts/getzilla_approve.py`; callers (`policy`, `protected_write`, `deploy`) are unchanged.

## Data flow

CLI -> `add_approval` -> `.getzilla/runtime/approvals.json` -> `has_valid_approval` in the hook.

## API and event contracts

None changed.

## Governance context

- Applicable rule IDs: none in `governance/`.
- Applicable canonical example IDs/versions: none.
- Open or overdue debt IDs: none.
- Expected governance handoff or receipt impact: none.

## Bitrix-specific impact

- Modules/events/agents/components affected: none.
- Cache and managed cache impact: none.
- Installation/update/uninstall impact: installed stacks get exact-only grants on next install.
- Core modification: none.

## Decisions

Exact equality at both write and read time, so the read side stays safe even if the runtime file is edited by hand.

## Risks and mitigations

- Users relying on a URL prefix pattern for external writes must list exact URLs: matches the documented rule.
