# Requirements — Move the informational Windows full suite to a nightly workflow

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Acceptance criteria

- [x] getzilla.yml has no module-by-module step and no continue-on-error, and keeps the linux/windows jobs with Doctor, Windows-ported tests, Hooks and CLI smoke and Annotate smoke failure.
- [x] windows-full-suite.yml runs that step on schedule only (minute not 0), no workflow_dispatch, with no pull_request/push, contents: read, persist-credentials: false and the same pinned actions.

## Failure and edge cases

- The scheduled run on the default branch only
- No inputs on dispatch

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
