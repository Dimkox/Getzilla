# Requirements — Refuse missing bandit and OpenGrep binaries in pr/release gates

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Acceptance criteria

- [x] A `bandit not available` skip is refused in pr/release, and `no non-test python paths` stays admitted.
- [x] opengrep is in MANDATORY_PR_CHECKS; `opengrep not available` is refused in pr/release, and `no OpenGrep rules installed` stays admitted.
- [x] fast mode admits both skips as before.

## Failure and edge cases

- fast mode is unchanged
- rules absent stays admitted
- --keep-going still reports the other checks

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
