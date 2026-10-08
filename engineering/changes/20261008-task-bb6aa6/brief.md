# Cursor rules as a harness target

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

Change ID: `20261008-task-bb6aa6`
Created: 2026-10-08T16:27:07+00:00
Risk: medium
Complexity: standard
Domains: api

## Problem

PR #55 added Cursor rules through a second generator (`cursor_rules.py`, own JSON source, path-based writes with a symlink race, files mode 0600), quoted `globs` that Cursor may not match, left `.cursor/**` unprotected, and broke two `tests/test_structure.py` guards while `verification-evidence` and the evidence template kept the old "verify, review, rerun" order.

## Outcome

Cursor rules are one more output of `scripts/getzilla_harness.py`; the delivery documents agree on one order.

## Scope

### In scope

- Cursor target in `harnesses.py`, sources `.grok/cursor-rules/*.toml`, descriptor-safe writes via `fsx` for every generated harness file.
- `.cursor/**` control-plane protection; delivery-order wording and its tests.

### Out of scope

- Shipping `.cursor/rules/getzilla/` to consumers through `install_into.py`.
- Live Cursor acceptance (needs the owner's Cursor install).

## Constraints

- Backward compatibility: other harness outputs are byte-identical; only their write path changed.
- Data/privacy: none.
- Performance: none.
- Operational: `python3 scripts/getzilla_harness.py --write` regenerates; the drift test fails on any difference.
