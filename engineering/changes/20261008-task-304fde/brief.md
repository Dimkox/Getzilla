# Verify the OpenGrep binary digest at run time and quarantine unverified binaries (#39)

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

Change ID: `20261008-task-304fde`
Created: 2026-10-08T15:49:06+00:00
Risk: high
Complexity: high-risk
Domains: security, api
Issues: Refs #39 (stays open: npm @latest and curl|bash remain)
Source finding: independent security review of PR #52 (P52-1, medium)

## Problem

PR #52 pins OpenGrep and checks the download digest before install, but the verifier still runs whatever `opengrep` is first on PATH. A binary installed earlier from `latest` (unverified) stays runnable, and the updater test even required that an unverified previous binary be kept when the pinned download fails.

## Outcome

`getzilla_verify` runs OpenGrep only by its resolved path and only when that file's SHA-256 equals the pinned release digest for the platform; otherwise the stage fails (refused in pr/release). The updater moves any non-matching binary to `<name>.unverified` without execute bits before downloading, so a failed or mismatched download never leaves an unverified binary runnable.

## Scope

### In scope

- `.getzilla/getzilla/verification.py` `_opengrep`: resolve PATH once, hash, refuse on mismatch.
- `.getzilla/getzilla/updater.py` `update_opengrep`: quarantine before fetch.
- Tests in `tests/test_opengrep.py`, `tests/test_updater.py`.

### Out of scope

- Issue #39 item 2 (npm `@latest` agent CLIs, `curl | bash` installers).
- Trust CI runner image (already pins and checks the digest at build time).

## Constraints

No new dependency; reuse the pins in `updater.OPENGREP_ASSETS`; the CI workflow and Trust CI install the same pinned digest so their stage keeps passing.
