# Requirements — Pin and checksum third-party tool downloads in the updater

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Acceptance criteria

- [x] AC-001: update_opengrep downloads only the pinned release asset URL and never queries releases/latest.
- [x] AC-002: A downloaded asset whose SHA-256 differs from the pinned digest is not written, and a previous binary stays untouched.
- [x] AC-003: The pinned version and linux/x86_64 digest equal trust-ci/runner.Dockerfile; every digest is 64 hex characters.
- [x] AC-004: OSV archives with bad CRCs or truncated content are refused and the previous mirror is kept.
- [x] AC-005: Full PR verification, independent reviews and the exact-head external check precede merge.

## Failure and edge cases

- Platform without a pinned asset: `skip`.
- Network failure: `fail`, nothing written.
- Installed binary already matching: `ok` without download.

## Governance context

- Applicable rule IDs: AGENTS.md "Local delegated grants", "Prohibited routine actions".
- Canonical-example deviations and evidence: none.
- Intentional debt created, repaid, or accepted: none.

## Non-functional requirements

- Security: integrity check before the executable bit is set.
- Reliability: no new dependency (stdlib `hashlib`, `hmac`, `zipfile`).
- Performance: no redundant 46 MB download.
- Observability: result detail names version, expected and actual digest on mismatch.
