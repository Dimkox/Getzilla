# Skip real-process adapter tests on unsupported hosts

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

Change ID: `20261008-task-ff5fda`
Created: 2026-10-08T14:56:17+00:00
Risk: medium
Complexity: standard
Domains: api

## Problem

On Debian 13 / Python 3.13 the nine tests that start real child processes error with UNSUPPORTED_HOST/RUNTIME_UNAVAILABLE or fail on preflight, so factory-postgres-exit is red for host reasons.

## Outcome

The gate reports these as skips with the host requirement instead of failures.

## Scope

### In scope

- skipUnless(HOST_SUPPORTED) on the nine real-process tests.

### Out of scope

- Supporting more host profiles.

## Constraints

- Backward compatibility: unchanged.
- Data/privacy: none.
- Performance: none.
- Operational: none.
