# Progress early stop for repeated paid actions (Superpowers × BMAD)

Issue: #153 (runaway-loop stop). Route `8797bb74ac67`. Base `23b0110f42fe588753351cec84e128aae10c9a5f`.
Method sources at their installed baseline pins: Superpowers `22f0b463e7a5e579904dd6211a520321035526f7`
(`brainstorming`, `writing-plans`, `systematic-debugging`, `test-driven-development`), BMAD Method
`bab9082c3e884e0d72c759bcd1a6d90bcc01be84` (`bmad-create-story` template).

## Problem

A loop is an agent that pays for the same action again although nothing changed since the last attempt and it
has no new hypothesis. Duration says little: CI can build images for half an hour, and an agent can repeat a
useless request three times in one minute.

`session_progress` observes only completed local checks (pytest, ruff, build). Characterization on the base
commit (`.getzilla/runtime/scratch/characterize_progress.py`) shows three defects:

| Case | Current result | Defect |
| --- | --- | --- |
| The same failing test; only `1 failed in 0.53s` changes | never detected | missed loop |
| A check that waits for an external event prints the same text 3 times | the next attempt is refused | false stop: only external state matters, and the refusal happens before the new state can be seen |
| A replayed old CI log (old run, attempt and head) | counted as a fresh failure | false stop from stale evidence |

`gh` commands are not observed at all, so repeated `gh run rerun` and status polls are not detected.

## BMAD requirements

| ID | Requirement |
| --- | --- |
| FR-01 | A local check failure signature ignores volatile text: durations, timestamps, memory addresses, temporary directory names and pytest progress percentages. |
| FR-02 | `gh` CI interactions are classified as poll, wait, mutation (rerun/cancel) or log replay. An unclassified command keeps the existing behaviour and is never refused by the new guard. |
| FR-03 | A CI state token comes only from structured JSON output (`--json`, or `gh api` without `--jq`/`--template`), bounded to 64 KiB. Text output gives no token. |
| FR-04 | An observation is historical when its head differs from `git rev-parse HEAD`, its attempt is lower than the highest attempt seen for that run, or it is an older replay of the same attempt. Historical observations never count, never block and never satisfy a resume condition. A log of a historical or unknown run gets a "historical evidence" hint. |
| FR-05 | After a failed rerun or cancel of a run that is not completed, the next identical mutation is refused at once. It resumes only when a later non-historical observation shows the run completed (`gh-run:<repo>:<run>:completed`). |
| FR-06 | A rerun is refused when the two newest completed attempts of the run on the current head failed with the same failure signature (failed jobs and steps). |
| FR-07 | A network failure (HTTP 429/5xx, connection reset, ECONNRESET, TLS handshake timeout, RPC failed, name resolution) of a `gh` command gets 2 extra retries: after 30 s and 120 s, or 60 s and 300 s for rate limits. A retry inside the pause is refused with the time it becomes allowed. Deterministic patterns win over transient ones. |
| FR-08 | The 4th status poll with an unchanged non-terminal token is refused. The refusal names a wait without model calls: `gh run watch <id> --exit-status`. A wait command is never refused, and the first poll after a wait is allowed. |
| FR-09 | Every refusal names the machine-checkable resume condition and the recovery command. `progress-recover` with a new diagnosis allows one retry, as for local loops. |
| FR-10 | External state lives in a separate runtime file. The existing `session-progress.json` version 1 is unchanged, so rollback and mixed engine versions keep working. Any error keeps the existing advisory "observations unavailable" behaviour and never blocks. |
| FR-11 | The guard is advisory and runs after ordinary policy authorization. It never grants authority, never makes network calls and never stores raw commands, output or session IDs. |

## Story 1.1: Stop repeated paid actions without progress

Status: ready-for-dev

### Story

As the owner of a Getzilla project,
I want the agent stopped before it repeats a paid action that cannot give a different result,
so that credits are spent only on attempts with a named change or a new hypothesis.

### Acceptance criteria

1. The same failing test with different durations is a loop after 3 identical failures (FR-01).
2. A rerun refused by GitHub while the run is in progress is not sent again until a later observation shows the run completed (FR-05, FR-09).
3. A log of an older attempt or another head is labelled historical and changes no count (FR-04).
4. A rerun of the same head with the same failed step in its two newest attempts is refused (FR-06).
5. A connection reset gets exactly two paced retries; a deterministic error gets none (FR-07).
6. Polls with an unchanged token stop at the 4th and point to `gh run watch` (FR-08).
7. A v1 state file written by the base engine still loads, and the new file never makes the old engine fail (FR-10).
8. Every new refusal happens only after policy authorization and is advisory on any internal error (FR-11).

### Tasks / Subtasks

- [ ] Task 1: Normalized local failure signature (AC: 1)
- [ ] Task 2: `ci_progress` classification, token, historical rule (AC: 3)
- [ ] Task 3: Mutation, deterministic, transient and poll rules with resume conditions (AC: 2, 4, 5, 6)
- [ ] Task 4: Hook wiring, inspect/recover, docs (AC: 7, 8)

### Dev notes

- Reuse `_policy_legacy._gh_command`, `_gh_arguments` and the lexical gates of `session_progress._eligible`.
- Reuse the `session_progress._store` lock and atomic publication for the new file.
- `gh run watch` is a read in policy; `gh run rerun` and `gh run cancel` stay external writes that need an exact grant.
- References: `.getzilla/getzilla/session_progress.py`, `engineering/runbooks/session-progress.md`,
  `.getzilla/runtime/changes/20261123-task-8797bb/evidence/analysis-*.md`.

## Design

`session_progress.py` keeps its role for local checks. Its failure digest normalizes the output first (FR-01).

A new module `.getzilla/getzilla/ci_progress.py` owns the `gh` model:

- `classify(command) -> Interaction | None` — kind, repository, run ID, attempt, structured flag.
- `parse_runs(output) -> list[RunState]` — bounded JSON parse; duplicate keys and deep nesting refused.
- `observe(root, scope, inputs, response, head, *, now)` — records runs, attempts, failure signatures and blocks;
  returns a hint (historical evidence, warning).
- `refusal(root, scope, inputs, head, *, now)` — returns a refusal text or `None`.
- `inspect(root, scope, *, now)` and `recover(root, scope, loop_id, revision, reason, evidence, *, now)`.

State: `.getzilla/runtime/session-external.json`, `{'version': 1, 'runs': {...}, 'blocks': {...}}`, at most 64
runs and 64 blocks, TTL 3600 s, same lock and publication as `session-progress.json`.

The hooks call `ci_progress` next to `session_progress`: `post_tool_use._progress_hint` adds its hint,
`pre_tool_use._progress_loop` checks it after the local refusal. Both remain after policy authorization.

## Non-goals

- No network calls, no polling daemon, no new service or dependency.
- No change to policy authority: reruns still need their grant; workflow dispatch stays forbidden.
- No review-approval resume condition in this slice (`gh-review:...`); it needs a review-state token.
- No interception of non-Bash tools or MCP GitHub tools.

## Rollout and rollback

- Rollout: engine files only; installed projects receive them through `getzilla update`.
- Rollback: revert the commit. `session-progress.json` keeps version 1; the new file is ignored by the old engine.
- Signals: refusal and hint texts start with `Getzilla:`; `getzilla agent progress-inspect` lists external blocks
  with their resume conditions.

## Review focus

1. A `gh` command the classifier does not fully understand (aliases, `--repo` forms, pipes) must never be refused.
2. A historical observation must never clear a block.
3. Transient patterns must not hide a deterministic error such as a 404 or a validation failure.
4. Volatile-text normalization must not merge two different failures (different test names or assertions).
5. The new state file must not break the old engine reading `session-progress.json`.
