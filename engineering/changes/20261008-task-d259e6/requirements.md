# Requirements — Queue provenance analysis converges on list-append loops

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Acceptance criteria

- [x] Given a module importing `queue` with a list-append loop, when it is analysed, then no QueueAnalysisLimit is raised and the list stays ordinary.
- [x] Given 60 unchanged locals and 30 branches, when analysed with value_limit=256, then the budget is not exhausted.
- [x] Given main's architecture_diff.py, when analysed with default limits, then analysis succeeds.

## Failure and edge cases

- Queue appended inside a while/for loop and then indexed: flagged.
- Ordinary appends in a loop followed by a queue append and an index: flagged (unknown length).

## Governance context

Canonical governance JSON under `governance/` remains separately reviewed authority. Any rule, example, debt, or digest named here is non-authoritative context until the verifier rederives current governance evidence.

- Applicable rule IDs: FIT-BOUNDED-WORKER-JOBS.
- Canonical-example deviations and evidence: none.
- Intentional debt created, repaid, or accepted: none.

## Non-functional requirements

- Security: the analysis stays conservative and bounded.
- Reliability: no limit changed.
- Performance: architecture_diff.py needs 774 of 4,096 values.
- Observability: unchanged.
