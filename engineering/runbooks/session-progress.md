# Repeated completed failures

The session progress guard catches a narrow, observable debugging loop: the same
test, build or lint command returns the same failure three times against the same
source. The third completion adds a warning. The next exact unchanged attempt is
refused after ordinary authorization. A different command remains available for
investigation. This is local workflow guidance; it grants no permissions, claims no
test success and does not interrupt processes or change agent ownership.

## Inspect and continue

Use the session ID from the current harness. For an identified child, also provide
the same `--agent-id` and, when supplied by the harness, `--generation` on both
commands. Calls without child identity are scoped to the session's main bucket.

```bash
getzilla agent progress-inspect --session-id SESSION
getzilla agent progress-recover --session-id SESSION --loop-id LOOP_ID --revision REVISION --reason new-evidence --evidence "The failing fixture uses the old schema; inspect its migration next."
```

The refusal identifies the opaque loop ID. Inspection returns its current revision,
failure count and status: `observing`, `warning`, `blocked`, `retry-available`, or
`expired`. A missing/mismatched session route returns `scope-unavailable`.
`scripts/getzilla_agent.py` accepts the same arguments if the `getzilla` shim is not
installed. `--root PATH` precedes the action when selecting a project explicitly.

Recovery requires the exact current revision and a nonempty diagnosis of at most
4,096 characters. Reasons are `new-evidence` and `changed-hypothesis`. It records
only a diagnosis hash and allows one matching retry. It does not reset the failure
count or assert that the diagnosis is correct. A stale revision, reused diagnosis,
already available retry or a seventeenth recovery in one streak is rejected. Read
the fresh inspection after a refusal; do not repeatedly submit an old revision.

A successful matching command clears its failure streak. Changed source or a
different failure signature starts a new streak on completion. Changing another
command, sending a heartbeat, polling a process or marking a lifecycle checkpoint
does not clear the blocked operation. Source changes are repository-wide evidence
of change, not proof that the particular defect was fixed.

## Observed commands and results

Only simple recognized check commands are observed: Python unittest/pytest, Ruff
check, mypy/pyright, TypeScript/ESLint/Bandit, common npm/pnpm/yarn check scripts,
Cargo checks, Go test/build/vet, dotnet test/build, named Make checks, and Getzilla
verification. Python `-m` and explicit working directories are supported. Shell
pipelines, compound commands, substitutions and unknown wrappers are left alone.
Nonzero search results such as `rg` finding no matches are not failures for this
guard. These conservative limits reduce false interruptions.

Existing `PostToolUse` results must include an integer `exit_code`, `exitCode`, or
`returncode`. Conflicting aliases, boolean/string codes, running/yielded sessions,
interrupted/timed-out results and unsupported response shapes are ignored. An
error-looking log or `is_error` alone is insufficient. The bounded output signature
uses each text output field's length and first/last 8 KiB; volatile timestamps can
prevent an exact match, and changes only in the middle of a large log can be missed.

Canonical hooks accept result envelopes `tool_response`, `toolResponse`, or
`tool_result`. They do not register a separate native `PostToolUseFailure` event.
Harnesses that omit structured exit codes or report failures only through another
event have incomplete coverage. Tests verify the explicit supported payload
contract; they do not establish every harness's current native behavior.

Without an available Git HEAD, the existing source identity cannot safely prove an
unchanged repository: the guard emits warnings only. It needs no commit history
scan and makes no LLM calls. Several concurrent starts can be admitted before the
third failure completes; this version does not reserve or cancel in-flight work.

## Isolation, storage and limits

Records are isolated by repository, explicit owner session, stable logical task
and authority epoch, agent/generation, exact command/input and working directory.
Package attachment, scope acknowledgment and review-plan reconciliation keep the
same task bucket. A deliberate new task or cross-session handoff creates a distinct
scope. Missing/manual sessions and unrelated global route fallbacks are never pooled. Harnesses that omit
child identity cannot distinguish that child from the session's main bucket.

The ignored runtime files are `session-progress.json` and the stable
`.session-progress.guard` lock. State contains hashes, bounded counters, timestamps
and the one-retry flag, with no raw command, output, identity or diagnosis. The
total limit is 128 operation records / 256 KiB; records expire after one hour.
At capacity, harmless old observations are removed first. Active blocked records
are retained; when all slots are blocked, a new result is disclosed as unrecorded.
Expired observations are not described as successful progress.

The last 16 completion IDs per operation suppress duplicate delivery when a
`tool_use_id`, `tool_call_id`, or `toolCallId` is available. Older replays and
deliveries without IDs cannot be reliably deduplicated. Updates hold a bounded
kernel lock and replace the JSON atomically. Linked, executable, multiply linked,
nonregular, oversized and corrupt observation files are refused. Instrumentation
failure emits a fixed unavailable diagnostic and lets otherwise authorized work
continue. Policy evaluation and receipt invalidation retain their own controls.

Rollback is a normal revert of this feature. Do not remove unrelated runtime
state, alter lifecycle ownership, or treat this ledger as review/verification evidence.
