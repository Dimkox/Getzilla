# Requirements — trust-ci vulnerable pins

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Acceptance criteria

- [x] Given trust-ci pins, when OSV is queried, then no findings remain (AC-002).
- [x] Given the new pins, when the Trust CI suite runs, then it passes (AC-001).

## Failure and edge cases

- cryptography 50 API changes: covered by the Trust CI signature tests.

## Governance context

Canonical governance JSON under `governance/` remains separately reviewed authority. Any rule, example, debt, or digest named here is non-authoritative context until the verifier rederives current governance evidence.

- Applicable rule IDs: FIT-TRUST-CI-SEPARATION.
- Canonical-example deviations and evidence: none.
- Intentional debt created, repaid, or accepted: none.

## Non-functional requirements

- Security: closes the cryptography and starlette advisories.
- Reliability: unchanged.
- Performance: unchanged.
- Observability: unchanged.
