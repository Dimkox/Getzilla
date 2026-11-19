# Local sprint and trace observations

The existing report command has two read-only modes:

```sh
getzilla report --sprint-start 2026-10-22T01:05:00Z --as-of 2026-11-05T01:05:00Z --json
getzilla report --trace-operation OPERATION_ID --as-of 2026-11-05T01:05:00Z --json
```

Both read this canonical root only. They do not scan task worktrees, connect to a
provider, activate export, or write observations. A route, green verification,
session end, grant or imported merge claim is not a selected or accepted task.
Unknown selection, acceptance, money, currency and human effort stay `null`.
Counts named `observed_*` describe qualified available observations, not a complete
commitment census. Coverage gaps remain part of the result.

Select the current owned task explicitly through the existing route command:

```sh
python3 scripts/getzilla_route.py --sprint-select UTC_START --expected-epoch EPOCH --expected-revision REVISION --session SESSION --json
python3 scripts/getzilla_route.py --trace-enroll --expected-epoch EPOCH --expected-revision REVISION --session SESSION --json
```

This uses the native canonical task, current owner and exact state revision. It
does not create another task ID. The first request initializes private storage
only for an actually owned, safe local journal. It never upgrades old observations
into native evidence. Do not change shared or foreign storage to bypass refusal.
Explicit enrollment may also make the current owner's selected runtime package
private: its directory becomes `0700`, and state/spec/requirements files become
`0600` after descriptor and native binding checks. It does not normalize tracked
legacy packages, shared storage, or permissions during report reads or late ACKs.

For an enrolled task, the existing managed local budget executor records an actual
`budget_claimed` cut separately from successful process spawn and owned child reap.
It keeps the original task, epoch, operation key and execution source binding.
Process phases freeze in memory and publish after reap, outside control and
settlement locks. A collector failure leaves a partial trace and does not repeat
the command. Interrupt and cancellation propagate after owned child cleanup.
Tokens, CPU, money, currency, model stages and TTFT remain unknown when unmeasured.

Native observations keep the original task, scope, context and source binding.
Their `captured_at` timestamp describes the native cut. Separate acknowledgements
in the same canonical route prove journal availability **by** `delivered_by` after
append and fsync. That timestamp is an upper bound, not first visibility. Replay
keeps event bytes unchanged. Lost acknowledgements, late delivery, missing rows,
capture failure and exhausted bounds leave the affected history censored. Metrics
failure does not repeat the original work or block the task's own state transition.
Proof version 2 uses strict UTC microseconds and the native local clock domain;
event timestamps remain UTC seconds. Old seconds-only proofs are unqualified.
Only a real current-owner exact-row reconciliation and fsync can give them a fresh
upper bound. The first valid proof remains stable. Conflicting duplicate IDs are
censored even when one row matches a proof.

Journal delivery uses one nonblocking lock attempt and one bounded batch after
the original work and its guards end. Filesystem fsync latency is not a real-time
guarantee. Direct library transitions can leave pending rows; public mutating CLI
consumers flush afterward and reread the explicit original route revision. Reads
and nonrecording verification do not flush. A pending metadata commit alone does
not mean the journal has been delivered.

Restricted reads require the real local OS owner and the actual project root as
the process CWD. The kernel `.` descriptor must match the intended workflow root;
the root must be owned and not group/other writable. Descendants are opened and
revalidated relative to that pinned descriptor. A shared writable parent outside
the root cannot redirect an already pinned operation. Group-writable roots,
subdirectory CWD, foreign owners and unprovable profiles remain unavailable.
The runtime is private and the journal is a single-link `0600` regular file.
Unqualified legacy storage exposes only admitted
aggregate event kinds and times, with no task IDs or payloads. Unknown ownership
does not expose even those counts. This local contract is not an enterprise ACL.
The anchor is storage custody and does not confer tool, customer or credential
authority. Original task/budget/paid-policy checks remain required.

The empirical forecast targets guarded completion of original selected scope.
Its pure method uses matching, non-overlapping covered windows, nearest-rank count
intervals and rolling-origin error/interval coverage. It keeps zero-completion
covered windows and excludes censored or future data. Eight training windows plus
eight backtest origins is a display floor, not proof of an 80% probability. Current
real history has no qualified cohorts, so the report exposes no numerical forecast.
Synthetic tests do not supply real calibration evidence.
The current original finish guard still reaches unanchored receipt/worker/source
readers. Its factual status change is censored for qualified completion; a path
bracket cannot manufacture an anchored completion witness.

This initial vertical does not complete issues #152 or #159. Additional native
retrieval collectors, full source ACL/revocation and sanitizer contracts, retention,
optional export lifecycle and backend deletion conformance remain tracked in the
full typed runtime package. Missing local implementation is work, not an account
blocker. No external destination is configured or enabled by these report modes.
