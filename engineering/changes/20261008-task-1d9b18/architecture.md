# Architecture — fix main ci failures 19-23

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Current behavior

Main is red: the OpenGrep stage is missing, customers.py is unregistered, the landing digest is stale, factory pins carry OSV advisories, and bandit flags B105.

## Proposed behavior

Restore and repair each item without changing any boundary.

## Components and boundaries

## Data flow

## API and event contracts

## Governance context

Canonical governance JSON under `governance/` remains separately reviewed authority. Any rule, example, debt, or digest named here is non-authoritative context until the verifier rederives current governance evidence.

- Applicable rule IDs:
- Applicable canonical example IDs/versions:
- Open or overdue debt IDs:
- Expected governance handoff or receipt impact:

## Bitrix-specific impact

- Modules/events/agents/components affected:
- Cache and managed cache impact:
- Installation/update/uninstall impact:
- Core modification: forbidden unless explicitly approved.

## Decisions

The trust-ci pins ship in a separate PR (FIT-TRUST-CI-SEPARATION).

## Risks and mitigations

The starlette 1.x major upgrade in factory is covered by factory-unit and the Core suite.
