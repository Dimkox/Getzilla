# Architecture — Pin summary soundness of sequence widening

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Current behavior

M4 survives the suite.

## Proposed behavior

The new test kills M4.

## Components and boundaries

tests/test_architecture_fitness.py only.

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

Assert the concrete enqueue semantic-call signal rather than `uncertain`, because `uncertain` is set for unrelated reasons in these fixtures.

## Risks and mitigations

Signal formatting is part of the assertion (`attr='enqueue'`), which matches how the existing tests inspect signals.
