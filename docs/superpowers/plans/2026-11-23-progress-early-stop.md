# Progress early stop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop an agent before it repeats a paid local check or GitHub CI action that cannot give a different result.

**Architecture:** `session_progress` keeps local checks and gains a normalized failure signature. A new
`ci_progress` module classifies `gh` commands, records structured CI state in its own runtime file and returns
advisory refusals with machine-checkable resume conditions. The existing hooks call both, after policy authorization.

**Tech Stack:** Python 3.11+ standard library, existing `fsx` and `session_progress._store` primitives.

**Spec:** `docs/superpowers/specs/2026-11-23-progress-early-stop-design.md`

## Global Constraints

- No network calls, services or dependencies.
- `session-progress.json` stays `{"version": 1, ...}` with the same record fields.
- New state: `.getzilla/runtime/session-external.json`, at most 64 runs and 64 blocks, TTL 3600 s.
- Transient retries: 2, after 30 s and 120 s; rate limits 60 s and 300 s.
- Poll stop: the 4th poll with an unchanged non-terminal token.
- Any internal error: advisory `Getzilla: progress observations unavailable; ordinary authorization still applies.`
- Rebind `SURFACE_SHA256` in a separate last commit.

## Review Focus

1. Unparsed or unusual `gh` command forms (aliases, `--repo=`, pipes, `--jq`) are never refused — classification test table with `None` rows.
2. A historical observation never clears a block — test: old-attempt token after a failed rerun keeps the refusal.
3. A deterministic error is not taken for a transient one — test: `HTTP 404` and `connection reset` together gives no retry budget.
4. Normalization keeps different failures apart — test: two test names with the same durations give different signatures.
5. The base engine still reads `session-progress.json` — test: the new code writes only `session-external.json` for `gh` commands.

---

### Task 1: Normalized local failure signature

**Files:**
- Modify: `.getzilla/getzilla/session_progress.py` (`_outcome`)
- Test: `tests/test_session_progress.py`

**Interfaces:**
- Produces: `session_progress.normalize_output(text: str) -> str`

- [ ] Write failing tests: same failure with different durations, timestamps, `0x` addresses, temp dirs and `[ 42%]` counts is one streak; different test names stay different.
- [ ] Run `python3 -m pytest tests/test_session_progress.py -k normalized` — expect FAIL.
- [ ] Implement `normalize_output` and apply it in `_outcome` before slicing.
- [ ] Run the module — expect PASS. Commit.

### Task 2: `ci_progress` classification, token and historical rule

**Files:**
- Create: `.getzilla/getzilla/ci_progress.py`
- Test: `tests/test_ci_progress.py`

**Interfaces:**
- Produces: `classify(command: str) -> Interaction | None`; `parse_runs(output: str) -> list[RunState]`;
  `observe(root, scope, inputs, response, head, *, now=None) -> str`; `refusal(root, scope, inputs, *, now=None) -> str | None`;
  `inspect(root, scope, *, now=None) -> list[dict]`; `recover(root, scope, block_id, revision, reason, evidence, *, now=None) -> dict | None`.

- [ ] Failing tests: classification table (poll, wait, mutation, log, `None`); token parse (object, array, `workflow_runs`, JSON lines, oversize, duplicate keys, `--jq`); historical rules (other head, lower attempt, older replay, unknown-run log).
- [ ] Implement; run; commit.

### Task 3: Rules and resume conditions

**Files:**
- Modify: `.getzilla/getzilla/ci_progress.py`
- Test: `tests/test_ci_progress.py`

- [ ] Failing tests: failed rerun blocks the identical rerun until a later non-historical `completed` token; a successful rerun blocks a second rerun until the new attempt completes; same failure signature in the two newest attempts refuses a rerun; transient budget 30 s/120 s with deterministic precedence; 4th unchanged poll refused, `gh run watch` never refused and resets polls; one-shot recovery with a new diagnosis.
- [ ] Implement; run; commit.

### Task 4: Hooks, CLI and docs

**Files:**
- Modify: `.getzilla/hooks/post_tool_use.py`, `.getzilla/hooks/pre_tool_use.py`, `.getzilla/getzilla/session_progress.py` (inspect/recover delegate), `engineering/runbooks/session-progress.md`, `docs/REFERENCE.md`
- Test: `tests/test_ci_progress.py` (real hook round trip)

- [ ] Failing test: real hooks — a failed `gh run rerun` then the same command is denied with the resume condition; ordinary policy still applies first.
- [ ] Wire both hooks; extend inspect/recover; update the runbook and reference.
- [ ] Run related modules; commit; rebind `SURFACE_SHA256` in its own commit.
