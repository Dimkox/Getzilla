# Pin summary soundness of sequence widening

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

Change ID: `20261008-task-6e7b5f`
Created: 2026-10-08T15:04:37+00:00
Risk: medium
Complexity: standard
Domains: event, api

## Problem

The loop-widening tests from #29 assert `uncertain or enqueue-signal`. The unresolved names in those fixtures already set `uncertain`, so a widening that drops the summary (M4) survives.

## Outcome

A regression that loses queue provenance on widening fails the suite.

## Scope

### In scope

- One new test that asserts the enqueue signal itself.

### Out of scope

- Analyser changes and changes to the existing tests.

## Constraints

- Backward compatibility: unchanged.
- Data/privacy: none.
- Performance: none.
- Operational: none.
