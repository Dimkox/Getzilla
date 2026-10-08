# Close hook policy bypasses (secret reads, merge/push/publish spellings, rm -rf /)

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

Change ID: `20261008-task-f50aed`
Created: 2026-10-08T14:55:51+00:00
Risk: high
Complexity: high-risk
Domains: security, api, infra
Issues: #36 (secret reads, critical/high), #37 (blocked-action spellings, high/low)
Source finding: independent review of `a8f9338` (S1-S6, S8, S9)

## Problem

The `PreToolUse` policy (`.getzilla/getzilla/_policy_legacy.py`, imported by every generated harness) let several guarded operations through:

- secret paths were checked only for Read tools, never for Bash; `**/`-prefixed secret globs did not match root-level files;
- production actions were matched on the first literal argv tokens, so gh global options, git global flags, `git send-pack`, `docker image push` and npm global options hid merge/push/publish;
- `gh api --method=VERB` (the `=` form) was not an external write; `gh pr review` was not controlled;
- the `rm -rf /` regex needed a word boundary after `/`, so `/` itself and other flag spellings passed.

## Outcome

Every probe from the review is denied without a grant, ordinary commands stay allowed, and an exact grant still authorizes the normalized action.

## Scope

### In scope

- Shell secret-read detection (`shell_secret_reference`) and outside-root Read secret matching.
- Root-level matching for `**/` globs; `.env` no longer collapses to `env` in the matcher.
- Global-option normalization for git/gh/docker/npm production actions; `git send-pack`; docker image/manifest/compose push and buildx `--push`; gh release upload/edit.
- Tokenized `gh api` mutation detection; `gh pr review` as external write `github-pull-request-review`.
- Structured `rm` recursive-target check.
- `.grok/hooks/README.md` wording; regression tests `tests/test_policy_bypasses.py`.

### Out of scope

- Wildcard grants (#38, separate PR) and updater supply chain (#39, separate PR).
- Local destructive git (`git branch -D`, `git update-ref -d`) and variable/alias indirection (already reported as ambiguous by the hook root resolver).
- `verification.py` / `quality_gates.py` findings (bandit skip asymmetry, OSV no-op): owned by the concurrent CI-repair writer.

## Constraints

- Backward compatibility: policy only gets stricter; existing grants keep authorizing the same actions; harness copies are unchanged (policy is imported, not copied).
- Data/privacy: secret file contents are never read; only paths in the command text are matched.
- Performance: one tokenization pass and at most 512 glob matches per secret-looking word.
- Operational: local guardrail only; merge authority stays the exact-head external check.
