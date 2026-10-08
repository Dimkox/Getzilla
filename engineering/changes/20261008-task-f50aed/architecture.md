# Architecture — Close hook policy bypasses (secret reads, merge/push/publish spellings, rm -rf /)

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Current behavior

`evaluate_pre_tool` checks `secret_read_paths` only for Read tools; `_production_action` compares `argv[:2]`/`argv[:3]`; `_http_write_resource_text` regex needs a space after `-X/--method`; `DESTRUCTIVE_COMMANDS` regex for `rm` needs `\b` after `/`.

## Proposed behavior

- `_glob_match`: leading `**/` also tried without it; leading `./` and `/` stripped exactly (no `lstrip('./')`).
- `shell_secret_reference(root, command, patterns)`: split raw/unquoted/unescaped command text into word fragments (URLs removed), resolve each against the repository (symlinks followed) and match the secret patterns case-insensitively; glob words are expanded (max 512).
- `_positionals` + per-executable value-option sets normalize gh/git/docker/npm before classification.
- `_gh_external_write`: tokenized `gh api` method/field parsing and `gh pr review`.
- `_recursive_remove_of_root`: tokenized `rm` flags/operands across `sh -c` nesting; returned by `_destructive_pattern` independent of configured regexes.
- `policy.sensitive_action` reports `secret-read` so an ambiguous hook root also fails closed.

## Components and boundaries

Only `.getzilla/getzilla/_policy_legacy.py` and `policy.py`; hooks import them, so `.grok/.qwen/.claude/.codex/.gemini/.github/hooks` need no regeneration (`getzilla_harness.py` reports no drift).

## Data flow

Hook payload -> `sensitive_action` / `evaluate_pre_tool` -> allow/deny. No file content is read.

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
- Installation/update/uninstall impact: installed consumer stacks receive the stricter policy on next install.
- Core modification: none.

## Decisions

Word-fragment matching instead of per-command allowlists: any command that names a secret path is denied, which covers `cat`, `cp`, `tar`, `git show rev:path`, `curl -d @file` and interpreter one-liners without enumerating readers. Trade-off: commit messages or greps that literally mention `.env` are also denied.

## Risks and mitigations

- False positives on literal mentions of secret names: documented in the deny reason and hooks README; use a structured tool or rephrase.
- Variable indirection is not resolved: unchanged limitation of a non-evaluating policy; merge authority remains external.
