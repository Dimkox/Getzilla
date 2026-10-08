# Architecture — Make the jsonschema CLI checks optional

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Current behavior

Semantic and CLI assertions share one test, so a missing CLI errors the whole test.

## Proposed behavior

CLI checks move to separate tests that skip with a reason when the CLI is missing; the semantic parser checks stay unconditional.

## Components and boundaries

Three factory test modules.

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

Optional CLI instead of a declared dependency. The docs (M1/M2a plans) deliberately avoid a jsonschema dependency, and `build_offline_release.derive_inventory` ships every uv.lock package, so a dev group would bloat and change the runtime release. This supersedes the issue's suggested remedy and is noted on #26.

## Risks and mitigations

In environments without the CLI the structural cross-check is skipped. The skip is visible and the parsers remain the authoritative semantic gate.
