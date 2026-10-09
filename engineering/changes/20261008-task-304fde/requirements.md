# Requirements — Verify the OpenGrep binary digest at run time and quarantine unverified binaries (#39)

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Acceptance criteria

- [x] AC-001: The verifier hashes the resolved PATH opengrep and does not execute it unless the SHA-256 equals the pinned digest for the platform; a mismatch is a failing, PR-refused stage.
- [x] AC-002: The verifier runs the exact resolved path it hashed.
- [x] AC-003: update_opengrep moves a non-matching previous binary to <name>.unverified without execute bits before downloading, whether the download fails or mismatches.
- [x] AC-004: Full PR verification, independent reviews and the exact-head external check precede merge.

## Failure and edge cases

- No pinned digest for the platform: stage fails with an explicit reason (not run).
- Previous target is a symlink: the symlink is removed, its target is not chmod-ed.
- Binary matches the pin: unchanged behaviour (not re-downloaded, exec bits restored).

## Governance context

- Applicable rule IDs: AGENTS.md "Local delegated grants", "Prohibited routine actions".
- Canonical-example deviations and evidence: none.
- Intentional debt created, repaid, or accepted: none.

## Non-functional requirements

Hashing the ~100 MB binary adds well under a second per verify run.
