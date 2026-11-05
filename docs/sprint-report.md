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

Restricted reads require the real local OS owner, safe descriptor ancestry, a
private runtime directory and a single-link `0600` journal. Project binding comes
from the actual root descriptor. Unqualified legacy storage exposes only admitted
aggregate event kinds and times, with no task IDs or payloads. Unknown ownership
does not expose even those counts. This local contract is not an enterprise ACL.

The empirical forecast targets guarded completion of original selected scope.
Its pure method uses matching, non-overlapping covered windows, nearest-rank count
intervals and rolling-origin error/interval coverage. It keeps zero-completion
covered windows and excludes censored or future data. Eight training windows plus
eight backtest origins is a display floor, not proof of an 80% probability. Current
real history has no qualified cohorts, so the report exposes no numerical forecast.
Synthetic tests do not supply real calibration evidence.

This initial vertical does not complete issues #152 or #159. Additional native
retrieval collectors, full source ACL/revocation and sanitizer contracts, retention,
optional export lifecycle and backend deletion conformance remain tracked in the
full typed runtime package. Missing local implementation is work, not an account
blocker. No external destination is configured or enabled by these report modes.
