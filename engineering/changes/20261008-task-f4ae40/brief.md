# Declare the jsonschema CLI as a factory test dependency

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

Change ID: `20261008-task-f4ae40`
Created: 2026-10-08T14:56:16+00:00
Risk: medium
Complexity: standard
Domains: api

## Problem

`test_bb_contracts`, `test_execution_contracts` and `test_semantic_bridge` call `subprocess.run(["jsonschema", ...])`. The factory project never declares it, so the gate's clean uv environment raises FileNotFoundError (5 errors).

## Outcome

The semantic assertions run everywhere and the optional external structural cross-check runs where the CLI exists.

## Scope

### In scope

- Split each CLI cross-check into its own skipUnless(shutil.which("jsonschema")) test.

### Out of scope

- Adding a jsonschema dependency or an in-repo JSON Schema validator.

## Constraints

- Backward compatibility: unchanged.
- Data/privacy: none.
- Performance: none.
- Operational: none.
