# Architecture — Move the informational Windows full suite to a nightly workflow

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Current behavior

The informational suite runs on every PR.

## Proposed behavior

The informational suite runs nightly and on owner dispatch.

## Components and boundaries

Two workflow files and three test files.

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

`workflow_dispatch` is admitted only in windows-full-suite.yml, without inputs, so the owner can run it manually. Agents still never dispatch workflows.

## Risks and mitigations

Windows-only regressions in non-ported modules surface up to a day later; they were never gating anyway.
