# Architecture — Skip real-process adapter tests on unsupported hosts

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Current behavior

Real-process tests run unconditionally.

## Proposed behavior

A module-level `real_process` decorator skips them unless `_host_supported()` is true.

## Components and boundaries

Only `factory/tests/test_linux_process_adapter.py`.

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

The product contract is a single host profile, so the tests follow it rather than the product being widened.

## Risks and mitigations

Nobody runs these tests unless a supported host does; the skip reason is printed and counted by the gate.
