# Run landing publication tests on a device-consistent filesystem

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

Change ID: `20261008-task-3d63e1`
Created: 2026-10-08T14:56:19+00:00
Risk: medium
Complexity: standard
Domains: api

## Problem

Seven landing publication tests end in `needs_human`/`publication_file_owner` on overlayfs (box: /tmp dir st_dev 39, file st_dev 40). The publisher rejects `release.json` because its st_dev differs from the target root's.

## Outcome

The tests exercise the publisher on a filesystem that satisfies its device invariant.

## Scope

### In scope

- Fixture temp-base probe and skip.
- A red test that pins the invariant.

### Out of scope

- Changing the publisher (its fail-closed behavior on overlayfs is intended).

## Constraints

- Backward compatibility: unchanged.
- Data/privacy: none.
- Performance: none.
- Operational: none.
