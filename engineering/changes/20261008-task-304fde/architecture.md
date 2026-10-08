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

A developer with a different local opengrep build now fails pr/release verify; the message names the reinstall command.

Residual LOW — TOCTOU hash-then-exec (review LOW-1): `_unpinned_opengrep` hashes the PATH binary resolved by `shutil.which('opengrep')` and then `run` executes that same path. An attacker who can write to the directory that supplied the binary could swap the file between the digest check and the exec. The window requires an attacker who already has write access to a directory on the verifier's PATH, in which case they could also replace the binary before the check; the exposure this adds over that baseline is small, so it is accepted here rather than fixed. If we tighten this later, the cheap mitigation is to copy the digest-verified binary into a freshly created 0700 temp directory and execute the copy, so the verified bytes cannot be swapped after the check; a regression would assert the executed path is the private copy, not the PATH entry.
