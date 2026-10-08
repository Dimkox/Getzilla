# Requirements — Show package and advisory in known-vulnerabilities details

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Acceptance criteria

- [x] Each known-vulnerabilities detail has path=manifest and message='package==version ID (aliases): summary; fixed in X'.
- [x] All existing finding keys remain in the details for JSON output.

## Failure and edge cases

- Finding without aliases, summary or fixed versions: those parts are omitted.

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
