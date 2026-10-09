# Pin and checksum third-party tool downloads in the updater

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

Change ID: `20261008-task-de4956`
Created: 2026-10-08T15:34:47+00:00
Risk: high
Complexity: high-risk
Domains: security, infra
Issues: #39 (high; low/medium for npm and curl|bash)
Source finding: independent review of `a8f9338` (S10, S11)

## Problem

`updater.update_opengrep` fetched the `latest` OpenGrep release from the GitHub API and wrote the asset to `~/.getzilla/bin/opengrep` with mode 0755 without any checksum or signature check; the verifier later executes it as the SAST stage. The CI workflow pins the same binary by version and `sha256sum -c`. OSV archives were accepted on the `PK` magic bytes alone.

## Outcome

The updater installs only the pinned OpenGrep release whose SHA-256 matches the pinned digest, refuses and keeps the previous binary on mismatch, and refuses corrupt OSV archives.

## Scope

### In scope

- `OPENGREP_VERSION = 1.30.1` and per-platform SHA-256 digests (linux/x86_64 equals `trust-ci/runner.Dockerfile`; others are the release's published asset digests, aarch64 cross-checked by download).
- `update_opengrep`: pinned download URL, `hmac.compare_digest` check before `_replace_bytes`, skip when the installed binary already matches.
- `update_osv`: `zipfile.testzip()` CRC check.
- README/QUICKSTART wording; tests in `tests/test_updater.py`.

### Out of scope

- npm agent CLIs stay `@latest` and vendor installers (`x.ai`, `claude.ai`) stay download-and-run: the updater exists to bring these to their latest versions and the vendors publish no installer checksums; npm already verifies registry `integrity` hashes. Recorded as accepted residual trust in the PR.
- `trust-ci/` pins (owned by another writer); the linux digest is read-compared in a test, not edited.

## Constraints

- Backward compatibility: OpenGrep no longer floats to new releases; bumping is an explicit edit of version and all digests (test enforces lockstep with the CI runner pin).
- Data/privacy: none.
- Performance: an already matching binary is not downloaded again.
- Operational: on mismatch the result is `fail` and nothing is written.

Re-routed at `07b461c` after `main` advanced (the owner merged the 2026-10-08 fix batch). This supersedes route `3e50dcf6f57f` (base `a8f9338`), so architecture comparison uses the current base. Two automated review findings on #52 were then fixed with tests first: a cached binary that matches the pin now gets its execute bits back, and the OSV CRC test corrupts member data past the first read chunk.
