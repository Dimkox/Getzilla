# Show package and advisory in known-vulnerabilities details

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

Change ID: `20261008-task-7dfe03`
Created: 2026-10-08T14:56:19+00:00
Risk: medium
Complexity: standard
Domains: api

## Problem

`getzilla_verify.py` prints `{severity} {path}: {message}` per detail, but `_known_vulnerabilities()` passed `Finding.to_dict()` without `path`/`message`, so failures printed as `HIGH None: None`.

## Outcome

Operators see which package and advisory to fix directly in the verify output.

## Scope

### In scope

- `_vulnerability_detail()` adds path and message.

### Out of scope

- The text printer and other checks.

## Constraints

- Backward compatibility: unchanged.
- Data/privacy: none.
- Performance: none.
- Operational: none.
