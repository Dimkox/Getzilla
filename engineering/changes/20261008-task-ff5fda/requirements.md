# Requirements — Skip real-process adapter tests on unsupported hosts

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Acceptance criteria

- [x] On a host outside Ubuntu 24.04/python3.12, the nine real-process tests skip with an explicit reason and the other four run and pass.
- [x] On a supported host, all 13 tests run.

## Failure and edge cases

- /usr/bin/python3.12 missing on Ubuntu 24.04: skips (same as preflight).

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
