# Architecture — Refreeze the migration digest after the package rename

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Current behavior

The test compares current bytes with pre-rename digests and fails, so factory-postgres-exit is red on main.

## Proposed behavior

The digests are recomputed from the current tree. Comments name the commits responsible for each difference.

## Components and boundaries

Only `factory/tests/test_landing_api.py`.

## Data flow

Unchanged.

## API and event contracts

Unchanged.

## Governance context

Canonical governance JSON under `governance/` remains separately reviewed authority. Any rule, example, debt, or digest named here is non-authoritative context until the verifier rederives current governance evidence.

- Applicable rule IDs: none.
- Applicable canonical example IDs/versions: none.
- Open or overdue debt IDs: none.
- Expected governance handoff or receipt impact: none.

## Bitrix-specific impact

- Modules/events/agents/components affected: none.
- Cache and managed cache impact: none.
- Installation/update/uninstall impact: none.
- Core modification: forbidden unless explicitly approved.

## Decisions

Re-anchor rather than restore: none of these files is checksum-bound at runtime (no code reads their digests; applied SQL migrations are unchanged). Restoring the old titles would partially revert the owner-approved rename. Recorded in decisions.md.

## Risks and mitigations

Re-anchoring could hide an accidental change. Mitigation: every byte difference since the predecessor import ceea797 was reviewed (titles only, a footer string and a retry bound).
