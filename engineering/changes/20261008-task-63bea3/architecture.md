# Architecture — Refuse unchecked pinned dependencies in pr/release gates

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Current behavior

An unchecked skip is admitted.

## Proposed behavior

An unchecked skip is refused in pr/release.

## Components and boundaries

quality_gates.py, tests/test_known_vulns.py and docs/REFERENCE.md.

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

Refuse at admission rather than going online by default. The scanner's no-network-without-opt-in contract stays, and the operator chooses the source explicitly.

## Risks and mitigations

pr/release verifies without an OSV source now fail. The generated GitHub Actions workflow sets GETZILLA_OSV_ONLINE=1. A Trust CI deployment without `vulnerability_db_host_path` will now fail pr verifies until a mirror is configured, which is the intended fail-closed behaviour.
