# Requirements — Refuse unchecked pinned dependencies in pr/release gates

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Acceptance criteria

- [x] A known-vulnerabilities skip `N pinned dependencies not checked: …` is refused in pr/release.
- [x] `no pinned dependencies in lockfiles or requirements` stays admitted.
- [x] fast mode is unchanged.

## Failure and edge cases

- No pins: still admitted
- fast mode: still admitted

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
