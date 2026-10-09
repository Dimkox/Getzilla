# Requirements — Cursor rules as a harness target

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Acceptance criteria

See AC-001..AC-006 in `change-spec.yaml`.

## Failure and edge cases

- Invalid rule source (unknown key, bad glob, budget, zero or two core rules): `ValueError`, nothing written.
- A symlinked directory below the repository root: `OSError`, nothing written outside.

## Governance context

Canonical governance JSON under `governance/` remains separately reviewed authority. Any rule, example, debt, or digest named here is non-authoritative context until the verifier rederives current governance evidence.

- Applicable rule IDs: none.
- Canonical-example deviations and evidence: none.
- Intentional debt created, repaid, or accepted: none.

## Non-functional requirements

- Security: prompt-only rules; protection comes from policy paths and the drift test.
- Reliability: per-file atomic replace; not a transaction across files.
- Performance: unchanged.
- Observability: drift lines name each file.
