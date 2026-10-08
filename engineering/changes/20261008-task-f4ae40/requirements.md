# Requirements — Declare the jsonschema CLI as a factory test dependency

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Acceptance criteria

- [x] Without a jsonschema CLI, the bb/execution/semantic-bridge tests pass with the three CLI cross-checks reported as skipped.
- [x] With the CLI installed, all 31 tests in the three modules pass.
- [x] The BB parser's invalid_deadlines rejection always runs.

## Failure and edge cases

- CLI present: structural tests run and pass (verified with `uv run --with jsonschema==4.25.1`).

## Governance context

Canonical governance JSON under `governance/` remains separately reviewed authority. Any rule, example, debt, or digest named here is non-authoritative context until the verifier rederives current governance evidence.

- Applicable rule IDs: none.
- Canonical-example deviations and evidence: none.
- Intentional debt created, repaid, or accepted: none.

## Non-functional requirements

- Security: unchanged.
- Reliability: unchanged.
- Performance: unchanged.
- Observability: unchanged.
