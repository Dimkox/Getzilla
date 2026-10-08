# Harden pre-tool hook policy against remaining authority, remove, secret-read and external-write bypasses

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

Change ID: `20261008-task-dab7da`
Created: 2026-10-08T16:23:11+00:00
Risk: high
Complexity: high-risk
Domains: security, hooks
Issues: #36, #37
Source finding: PR #54 review — residual production-authority, recursive-remove, secret-read false negatives/positives and uncontrolled external writes.

## Problem

After PR #54 the pre-tool guard still matched commands by substring. git-core helper binaries (git-push, git-send-pack), alias definitions, nested command strings, GNU long-option abbreviations for rm, brace/variable targets, quoted/ANSI-C secret names, recursive readers of secret directories, and gh/curl write verbs all slipped through, while legitimate commands (commit messages or greps mentioning 'credentials', jq/awk programs) were wrongly blocked. The analysis was also unbounded, so a hostile glob could push the hook past its 10s timeout and fail open.

## Outcome

Commands are tokenized (never executed) and classified by normalized argv: authority is decided deny-by-default for git/gh/docker/npm/pnpm/yarn/podman/buildah write verbs including git-core helpers, alias definitions and nested command strings; recursive removes are caught across spellings and expansion-dependent targets; secret reads use a path-word scan that walks recursive readers of secret directories and resolves brace/ANSI-C expansions while skipping interpreter text; direct gh/curl/wget writes require an exact grant. All filesystem scans are bounded and fail closed.

## Scope

### In scope

- `.getzilla/getzilla/_policy_legacy.py`: tokenizer, authority analysis, recursive-remove, secret-read, external-write classifiers.
- `.getzilla/config/policy.json`: credential-store secret paths.
- `tests/test_policy_hardening.py`: regression probes.

### Out of scope

- No changes to grant storage, human gates, or MCP policy.
- No execution of any blocked command; probes feed synthetic hook payloads only.

## Constraints

- Public repository: no copy-paste exploit recipes in issues/PRs; repros live in tests.
- Hook must stay within its 10s PreToolUse budget and fail closed on timeout.
- GETZILLA_TEST_WORKERS=2 (shared box).
