# Do not admit an unchecked OSV gate in PR verification

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

Change ID: `20261008-task-63bea3`
Created: 2026-10-08T14:56:20+00:00
Risk: medium
Complexity: standard
Domains: api

## Problem

With neither GETZILLA_OSV_DB nor GETZILLA_OSV_ONLINE set, known-vulnerabilities skips, and QG-01 admitted that skip. pr/release therefore passed without any vulnerability check.

## Outcome

pr/release admission requires an actual OSV check whenever pinned dependencies exist.

## Scope

### In scope

- `_allowed_skip` for known-vulnerabilities.
- The QualityGateTests expectation.
- A REFERENCE.md sentence.

### Out of scope

- Network defaults.
- Trust CI sandbox policy (`vulnerability_db_host_path`).

## Constraints

- Backward compatibility: unchanged.
- Data/privacy: none.
- Performance: none.
- Operational: none.
