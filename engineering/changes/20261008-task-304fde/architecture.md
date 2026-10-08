# Architecture — Verify the OpenGrep binary digest at run time and quarantine unverified binaries (#39)

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Current behavior

`_opengrep` checks `command_exists('opengrep')` and runs `opengrep` by name; `update_opengrep` leaves a non-matching previous binary in place on failure.

## Proposed behavior

`_opengrep` resolves `shutil.which('opengrep')`, refuses unless `_sha256_file` equals `OPENGREP_ASSETS[_platform_key()]`, then runs that path. `update_opengrep` quarantines a non-matching target first.

## Components and boundaries

`verification._unpinned_opengrep` (new, imports the pins from `updater`), `updater._quarantine` (new).

## Data flow

PATH -> resolved file -> sha256 -> compare with pin -> run or fail.

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
- Installation/update/uninstall impact: A machine with an unpinned opengrep must re-run `python3 scripts/getzilla_update.py --only opengrep`.
- Core modification: none.

## Decisions

Trust the content digest, not the name on PATH; quarantine rather than delete so a person can inspect what was installed.

## Risks and mitigations

A developer with a different local opengrep build now fails pr/release verify; the message names the reinstall command. TOCTOU between hash and exec remains (same user owns both).
