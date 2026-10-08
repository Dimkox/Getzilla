# Architecture — Run landing publication tests on a device-consistent filesystem

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Current behavior

The fixture creates the target in the default temp dir regardless of filesystem semantics.

## Proposed behavior

`_device_consistent_base()` probes the default temp base, then /dev/shm, and the fixture uses the first one where a directory and a file share st_dev; otherwise setUp skips.

## Components and boundaries

Only `factory/tests/test_landing_publication_cli.py`.

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

Fix the fixture, not the product: on overlayfs a publication target really cannot prove same-device placement, so needs_human is the correct product outcome.

## Risks and mitigations

A host without /dev/shm and with overlay /tmp skips these tests. The reason is explicit and the gate still reports skips.
