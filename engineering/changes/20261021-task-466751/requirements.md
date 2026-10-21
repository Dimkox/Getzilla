# Requirements — Trust CI signed command evidence for EU AI Act audit

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Acceptance criteria

- AC-001: Preserve default policy digests, check names and payloads.
- AC-002 and AC-003: Bind actual selected command argv only on opt-in. Ignore executor argv. Synthetic checks omit argv.
- AC-004: Preserve exact replay and reject signed argv tampering.
- AC-005: Protect the signed job identity from environment overrides on opted-in profiles.
- AC-006: Ship a separate mandatory audit command fragment without global activation.
- AC-007: Execute real Core audits after the Core/schema merge.

## Failure and edge cases

- Reject null, numeric and string flags. Cover failed commands, mutated source, malformed spec metadata and retried check publication.
- Old envelopes stay valid but do not qualify EU audit evidence without command argv.

## Governance context

Canonical governance JSON under `governance/` remains separately reviewed authority. Any rule, example, debt, or digest named here is non-authoritative context until the verifier rederives current governance evidence.

- Applicable rule IDs: FIT-TRUST-CI-SEPARATION and FIT-LOCAL-CANNOT-DEFINE-TRUST-CI.
- Canonical-example deviations and evidence: add a separate opt-in fragment instead of enabling the audit globally.
- Intentional debt created, repaid, or accepted: none. Core integration is a required dependency.

## Non-functional requirements

- Security: policy-owned argv and reserved identity environment; no secret arguments.
- Reliability: unchanged signing and exact stored-envelope replay.
- Performance: no additional work for default profiles; audit timeout is 300 seconds.
- Observability: existing signed status, exit code and output digest plus opted-in argv.
