# Refreeze the migration digest after the package rename

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

Change ID: `20261008-task-28b4eb`
Created: 2026-10-08T14:56:18+00:00
Risk: medium
Complexity: standard
Domains: api

## Problem

`test_predecessor_contract_migration_showcase_and_published_release_record_are_frozen` fails on main. Its three digests were taken before the rename. Migrations 001-018: byte-identical, but the digest includes the path (`adaptive_factory` to `getzilla_factory`). Predecessor contracts: rename 73d97c5 changed only the `title` of 14 contracts. Showcase: the footer text (rename) and the cold-Chrome retry count (e07cfbe).

## Outcome

The freeze holds against the current bytes, so any further change to these files fails the test again.

## Scope

### In scope

- Re-anchor the three digests with provenance comments.

### Out of scope

- Reverting the deliberate rename or the CI retry change (the identity test forbids the old product name in live files).

## Constraints

- Backward compatibility: unchanged.
- Data/privacy: none.
- Performance: none.
- Operational: none.
