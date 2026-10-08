# Require bandit in PR verification like ruff

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

Change ID: `20261008-task-26c995`
Created: 2026-10-08T14:56:21+00:00
Risk: medium
Complexity: standard
Domains: api

## Problem

QG-01 admitted `bandit not available` and `opengrep not available`, and opengrep was not mandatory, so a host without the scanners passed pr/release with SAST skipped. ruff already refused this.

## Outcome

pr/release admission requires the scanners to have actually run wherever there is something to scan.

## Scope

### In scope

- `_allowed_skip` for bandit and opengrep.
- `MANDATORY_PR_CHECKS` gains opengrep.
- Tests that encoded the old allowance.

### Out of scope

- ruff (already strict).
- The known-vulnerabilities offline skip (#32, a separate PR).
- trust-ci lockfile (#42).

## Constraints

- Backward compatibility: unchanged.
- Data/privacy: none.
- Performance: none.
- Operational: none.
