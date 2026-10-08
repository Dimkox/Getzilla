# Requirements — Pin summary soundness of sequence widening

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Acceptance criteria

- [x] A queue stored before a growing loop (append or concatenation) and used after it (index, iteration, pop) produces exactly one enqueue signal.
- [x] The test fails under review mutant M4 and passes on the shipped analyser.

## Failure and edge cases

- while and for loops
- append and concatenation growth
- index, iteration and pop reads

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
