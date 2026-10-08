# Architecture — Harden pre-tool hook policy against remaining authority, remove, secret-read and external-write bypasses

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Current behavior

Substring and shallow-split matching missed helper binaries, alias/nested definitions, abbreviated rm options, quoted/expanded secret names and gh/curl writes, and over-matched interpreter text; glob expansion was unbounded.

## Proposed behavior

A shlex-based tokenizer normalizes argv0 (basename, git-<sub> → git <sub>), unwraps command wrappers and nested command strings, and feeds three classifiers: authority (deny-by-default write verbs + ambiguity), recursive-remove, and a bounded secret-read path-word scan. External writes (gh/curl/wget) are bound to their exact resource.

## Components and boundaries

- `_simple_commands`/`_words`/`_nested_commands`: tokenizer and nested-command extraction.
- `analyze_command_authority`/`_candidate_authority`: authority + ambiguity.
- `_recursive_remove_of_root`/`_remove_operands`: deletes.
- `shell_secret_reference` and helpers (`_Budget`, `_bounded_glob`, `_walk_for_secret`, `_secret_path_words`): secret reads.
- `_http_write_resource_text`/`_gh_write_resource`/`_http_tool_write`: external writes.

## Data flow

PreToolUse payload → tokenize command → per-command classifiers → first deny reason returned to the hook; no side effects, no execution.

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
- Installation/update/uninstall impact: none (policy logic and config only).
- Core modification: none.

## Decisions

See `decisions.md`: a grant names the exact operation; ambiguous or dynamic commands fail closed; filesystem scans are bounded and deny-by-default when exhausted.

## Risks and mitigations

- Risk: over-blocking legitimate commands. Mitigation: AC-004 allow-probes for commit messages, greps, jq/awk programs.
- Risk: scan cost. Mitigation: entry/time budget with fail-closed marker (AC-006).
- Risk: merge conflict with the #38 grant-binding change touching the same module. Mitigation: noted for review; functions are additive.
