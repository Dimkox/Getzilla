# Architecture — Pin and checksum third-party tool downloads in the updater

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Current behavior

`fetch(OPENGREP_RELEASE)` -> pick `browser_download_url` -> `_replace_bytes(target, data, mode=0o755)`.

## Proposed behavior

`fetch(OPENGREP_DOWNLOAD.format(version, asset))` -> `sha256` compare with pinned digest -> `_replace_bytes` only on match.

## Components and boundaries

Only `.getzilla/getzilla/updater.py` (plus docs); `scripts/getzilla_update.py` and installers unchanged.

## Data flow

GitHub release asset -> memory -> SHA-256 check -> `~/.getzilla/bin/opengrep`.

## API and event contracts

None changed.

## Governance context

- Applicable rule IDs: none in `governance/`.
- Applicable canonical example IDs/versions: none.
- Open or overdue debt IDs: none.
- Expected governance handoff or receipt impact: none.

## Bitrix-specific impact

- Modules/events/agents/components affected: none.
- Cache and managed cache impact: none.
- Installation/update/uninstall impact: none for projects; `~/.getzilla/bin/opengrep` is replaced only by the pinned verified build.
- Core modification: none.

## Decisions

Pin in Python constants rather than reading `trust-ci/runner.Dockerfile` at runtime, because consumer installs do not ship `trust-ci/`; a test keeps the two pins equal.

## Risks and mitigations

- New OpenGrep releases are not picked up automatically: intended; bump version and digests together.
