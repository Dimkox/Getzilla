# Adopting a project folder without Git (Zero-Git)

`getzilla adopt` turns an existing folder that has no Git history into a **new** local Getzilla
workspace. The original folder is only read: no `.git`, no lock, no ignore file or report is
written there, and no file is renamed or re-encoded.

```text
getzilla adopt plan   --source ./legacy-app --target ./legacy-app-getzilla --output plan.json
getzilla adopt apply  --plan plan.json --plan-digest <plan_id from plan.json> --writers-stopped
getzilla adopt status --operation-id op-...
getzilla adopt resume --operation-id op-... --writers-stopped
getzilla adopt abort  --operation-id op-...
```

## What you get

- Commit 1 (root): exactly the **admitted** source files, with the trailers
  `Getzilla-Import: zero-git`, `Getzilla-Source-SHA256: <digest>` and
  `Getzilla-Baseline-Schema: source-baseline-v1`. This is the clean point before Getzilla.
- Commit 2: the Getzilla managed layer (the same payload `install-into` uses) and
  `.getzilla/source-baseline.json`, which links the source digest, the plan, the scanner and
  commit 1. It never names its own commit; the final commit is in the external receipt.
- No remote and no push. Publishing to GitHub is a separate, explicit step.

`integrity_status=verified` means the bytes, both commits and the provenance match the approved
plan. `project_health_status=not_run`: adoption never runs your tests, build, package managers or
any project script, so it says nothing about whether the application works.

## The plan and its blockers

`plan` reads every file (without following links), hashes it, checks portable paths and scans the
contents, and writes nothing except the plan file you name (outside the source). `plan_id` is
the digest of everything in the plan: admitted files, exclusions, policy, scanner rules and the
target. `apply` refuses any other digest.

The plan is blocked (exit code in brackets) when:

| Reason | What to do |
|---|---|
| `SENSITIVE_ENV_FILE`, `SENSITIVE_KEY_MATERIAL`, `SENSITIVE_CREDENTIAL_STORE`, `SENSITIVE_DATABASE_DUMP` (3) | Exclude the file in the policy, or move the secret out of a separate copy of the source. Examples such as `.env.example` are admitted only if their content scan passes. |
| `SECRET_PATTERN` (3) | A content rule matched (path, rule and line are reported, never the value). Remove the value, exclude the file, or add a narrow exception bound to one rule, one path and the file's SHA-256. |
| `ARCHIVE_REQUIRES_EXCLUSION`, `OPAQUE_CONTAINER_REQUIRES_EXCLUSION` (3) | Compressed archives cannot be inspected; exclude them explicitly. |
| `LINK_OR_REPARSE_POINT`, `HARDLINK_SHARED_IDENTITY`, `SPECIAL_FILE` (4) | Links, junctions, hard links and devices are not imported in this version. |
| `PATH_*` (4) | A path is not portable (case collision, Windows reserved name or alias, not NFC, control character). Nothing is renamed for you. |
| `GIT_PRESENT`, `NESTED_GIT` (4) | The folder is (or contains) a Git repository: this flow is only for folders without Git. |
| `FILE_TOO_LARGE`, `LIMIT_*`, `DEPTH_LIMIT`, `UNREADABLE*` (4) | Raise the policy limit or exclude the path; nothing is truncated or skipped silently. |
| `TARGET_EXISTS`, `TARGET_INSIDE_SOURCE`, ... (4/6) | The target must be a new folder outside the source. |

A policy is JSON with these fields (all optional): `exclude` (explicit patterns, never `*`),
`exceptions` (`[{"path", "rule_id", "sha256"}]`), `max_file_bytes`, `max_files`,
`max_total_bytes`, `max_depth`, `max_buffered_file_bytes`, `max_total_buffer_bytes`,
`executable_mode` (`posix-mode` or `policy-manifest`), `executable_paths`. On Windows the
executable bit comes only from `executable_paths`, so a digest made on Windows equals a Linux
one only under the same executable policy.

## Quiescence and consistency

`apply` needs `--writers-stopped`: stop every program that writes to the source first. Each file
is read whole into memory (bounded by `max_buffered_file_bytes`), its digest compared with the
plan and the same bytes rescanned **before** anything is written; a file changed after the plan
is never stored, not even temporarily. After the copy the source is inventoried again
(`quiesced_two_pass`); any drift stops the operation with `STALE_PLAN` (5). This detects ordinary
concurrent writes; it is not an atomic filesystem snapshot. Bytes that live only in memory can
still reach swap or a crash dump unless the host disables them.

## Where state lives

The private state root (`GETZILLA_ADOPTION_STATE`, default `~/.local/state/getzilla/adoption`,
`%LOCALAPPDATA%\Getzilla\adoption` on Windows) holds the content-addressed snapshot store and one
journal per operation. Work happens in an operation-owned staging folder next to the target,
published to the absent target by one atomic no-replace rename after verification. A crash leaves
either no target or a verified one; `resume` re-verifies the source and repeats the remaining
stages, `abort` removes only the operation's own staging folder (never the shared store, never
a folder it cannot prove it created). Exit codes: 0 ok, 2 arguments, 3 security, 4 unsafe or
unsupported filesystem, 5 stale plan, 6 operation or target conflict, 7 verification, 8 tool error.

## Limits of this version

- The secret scanner is Getzilla's built-in, versioned rule set (`rules_digest` in the plan). A
  pass means none of these rules matched any admitted byte, not that no secret exists.
- Symlinks, junctions, hard links, empty directories and Git submodules are not imported.
- Source-owned files that collide with the Getzilla layer (`AGENTS.md`, `ruff.toml`,
  `.coveragerc`, `bandit.yaml`, hook shims) block the operation; rename or move them first.
  An existing `.gitignore` is kept unchanged and Getzilla's local ignores go to
  `.git/info/exclude`.
- Existing Git repositories keep their history and use the regular install flow, not this one.

## Which flow applies (routing)

`getzilla.project_ingestion.route_ingestion({'path': ..., 'kind': ...})` picks the flow:

| Input | Route |
|---|---|
| Folder without `.git`, not inside another repository | `zero_git_plan` (this document) |
| Folder with a `.git` directory or `.git` file (linked worktree, submodule) | `existing_git_baseline` |
| Fetched snapshot (`kind: remote_snapshot` with an `origin` the caller recorded) | `existing_git_baseline` with the snapshot's own history |
| Subdirectory of a repository, declared kind contradicting what is on disk, unborn repository, unknown kind | `blocked` with a reason |

The existing-Git baseline (`inspect_git_input`) records the object format, HEAD commit and tree,
whether the working tree is dirty (with a digest of the changed files), and whether history is
shallow or a partial clone. It runs Git with `--no-optional-locks`, isolated configuration and
network protocols disabled: it never fetches, commits, initialises or rewrites anything. An
unborn repository is not treated as a folder without Git; its first commit is a separate action.
Nothing is claimed about history before the earliest available commit (`prehistory: not_recorded`).
Fetching a remote is the caller's separate, authorised step; workflow records already in the
project (`.getzilla/AGBP_SYNC.json`, `.getzilla/source-baseline.json`) are reported by digest and reused.
