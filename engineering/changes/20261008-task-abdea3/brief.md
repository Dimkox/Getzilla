# trust-ci vulnerable pins

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

Change ID: `20261008-task-abdea3`
Created: 2026-10-08T14:21:01+00:00
Risk: medium
Complexity: standard
Domains: api

## Problem

Fix the trust-ci known vulnerabilities from issue #22 by pinning cryptography 50.0.2 and fastapi 0.142.4

## Outcome

OSV reports no known vulnerabilities in trust-ci pins; the Trust CI suite passes on them.

## Scope

### In scope

- `trust-ci/pyproject.toml`: cryptography 46.0.4 → 50.0.2, fastapi 0.128.2 → 0.142.4.
- `trust-ci/README.md`: operator runbook minimal install pin.

### Out of scope

- Implementation fixes for #19–#21, #23 and the factory pins (companion PR; FIT-TRUST-CI-SEPARATION).

## Constraints

- Backward compatibility: Trust CI suite (266 tests) passes on the new pins.
- Data/privacy: none.
- Performance: none.
- Operational: deployed Trust CI images pick up the pins on their next rebuild.
