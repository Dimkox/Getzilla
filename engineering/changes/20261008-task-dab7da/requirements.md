# Requirements — Harden pre-tool hook policy against remaining authority, remove, secret-read and external-write bypasses

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

## Acceptance criteria

- [x] AC-001: git-core helper binaries (git-push, git-send-pack, git-http-push, git-remote-*) and alias/nested command definitions are classified as production authority and blocked without an exact grant.
- [x] AC-002: Recursive removes are detected across GNU long-option abbreviations, --no-preserve-root, Windows del/rd /s and Remove-Item -Recurse, and brace/variable/command-substitution targets.
- [x] AC-003: Secret reads are blocked under quoting, ANSI-C and brace expansion, through recursive readers of directories holding secrets, and for credential stores (~/.git-credentials, ~/.netrc, ~/.config/gh/hosts.yml, id_ecdsa, .npmrc, .kube/config, …); Grep and NotebookRead count as reads.
- [x] AC-004: Legitimate commands whose text merely mentions secret-like words (commit messages, grep/jq/awk/sed programs, git log --grep) stay allowed.
- [x] AC-005: Direct external writes via gh write subcommands and curl/wget mutations (non-GET method, body, form, upload) require an exact delegated grant; dynamic selectors are treated as ambiguous.
- [x] AC-006: Secret-read analysis is bounded by entry count and wall-clock time and fails closed (deny) when the budget is exhausted, so a hostile glob cannot hang or fail-open the hook.

## Failure and edge cases

- Unparseable command text falls back to a conservative raw-piece secret scan and regex authority/remove guards.
- Expansion-dependent delete targets ($HOME, "$PWD", `pwd`, {~,}) fail closed.
- A glob that cannot be expanded within budget returns a bounded fail-closed marker.
- Recursive readers pointed outside the repository root are not walked (documented residual).

## Governance context

- Applicable rule IDs: AGENTS.md "Local delegated grants", "Prohibited routine actions".
- Canonical-example deviations and evidence: none.
- Intentional debt created, repaid, or accepted: none.

## Non-functional requirements

- No command is executed by the policy; analysis is static tokenization.
- Per-command scan bounded to 3.0s / 20000 entries.
- ruff and bandit clean.
