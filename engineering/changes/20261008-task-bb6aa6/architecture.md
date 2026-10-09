# Architecture — Cursor rules as a harness target

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Current behavior

`harnesses.py` renders Qwen/Claude/Codex/Gemini/Copilot files with path-based writes; PR #55 added a parallel Cursor generator.

## Proposed behavior

`harnesses.render` also renders `.grok/cursor-rules/*.toml` to `.cursor/rules/getzilla/*.mdc`; `.cursor/rules/getzilla` is a generated root, so drift and stale-file removal are shared. `write` walks directories with `fsx.open_dir_at`/`mkdir_at`, writes a temporary file with `O_EXCL|O_NOFOLLOW`, sets 0644 and `replace_at`s it.

## Components and boundaries

`.getzilla/getzilla/harnesses.py`, `scripts/getzilla_harness.py`, policy path lists, delivery documents.

## Data flow

TOML sources -> `render` -> bytes -> `drift`/`write`.

## API and event contracts

Unchanged.

## Governance context

Canonical governance JSON under `governance/` remains separately reviewed authority. Any rule, example, debt, or digest named here is non-authoritative context until the verifier rederives current governance evidence.

- Applicable rule IDs: none.
- Applicable canonical example IDs/versions: none.
- Open or overdue debt IDs: none.
- Expected governance handoff or receipt impact: none.

## Bitrix-specific impact

- Modules/events/agents/components affected: none.
- Cache and managed cache impact: none.
- Installation/update/uninstall impact: none.
- Core modification: forbidden unless explicitly approved.

## Decisions

See `decisions.md` (2026-10-08, Cursor rules are a harness target).

## Risks and mitigations

Cursor glob parsing is not specified beyond "comma-separated"; patterns are written unquoted without spaces and commas are rejected. Live Cursor attachment is unverified.
