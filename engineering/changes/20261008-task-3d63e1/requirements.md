# Requirements — Run landing publication tests on a device-consistent filesystem

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Acceptance criteria

- [x] On a host whose /tmp is overlayfs, the landing publication tests run on a device-consistent filesystem (/dev/shm) and pass.
- [x] Without any device-consistent temp filesystem, the tests skip with an explicit reason.

## Failure and edge cases

- /dev/shm missing: falls back to skip.
- Probe raises OSError: next candidate.

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
