# Requirements — fix main ci failures 19-23

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Acceptance criteria

- [x] Given the PR verifier with OpenGrep installed, when it runs, then the opengrep stage executes after known-vulnerabilities (AC-001).
- [x] Given the architecture model, when drift is checked, then customers.py is registered (AC-002).
- [x] Given the landing page, when the copy digest test runs, then it matches (AC-003).
- [x] Given factory pins, when OSV is queried, then no factory findings remain (AC-004).
- [x] Given the verifier quality paths, when bandit runs, then there are zero issues (AC-005).

## Failure and edge cases

- OpenGrep absent: the stage reports an allowed skip (QG-01 allowance restored).

## Governance context

Canonical governance JSON under `governance/` remains separately reviewed authority. Any rule, example, debt, or digest named here is non-authoritative context until the verifier rederives current governance evidence.

- Applicable rule IDs: FIT-TRUST-CI-SEPARATION (why the trust-ci pins are split out).
- Canonical-example deviations and evidence: none.
- Intentional debt created, repaid, or accepted: none.

## Non-functional requirements

- Security: closes the factory advisories; restores SAST taint analysis.
- Reliability: no runtime change.
- Performance: unchanged.
- Observability: unchanged.
