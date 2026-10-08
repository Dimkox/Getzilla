# Move informational Windows full suite to a nightly workflow

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

Change ID: `20261008-task-4b79a6`
Created: 2026-10-08T15:10:30+00:00
Risk: medium
Complexity: standard
Domains: api

## Problem

The `windows` job spent ~36 min on a continue-on-error, module-by-module core suite that gates nothing. Branch protection requires `windows`, so every PR waited ~37 min.

## Outcome

PR checks finish in ~6 min, and the Windows full-suite signal is still produced nightly.

## Scope

### In scope

- Move the step into a new workflow.
- Header comment.
- Workflow invariant tests in tests/ and trust-ci/tests.
- decisions.md and CHANGELOG.

### Out of scope

- Branch protection.
- Consumer workflow template (getzilla_ci.py renders getzilla-verify.yml, which has no such step).

## Constraints

- Backward compatibility: unchanged.
- Data/privacy: none.
- Performance: none.
- Operational: none.
