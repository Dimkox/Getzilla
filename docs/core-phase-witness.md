# Core phase observations

The existing optional pytest progress publisher records bounded phase facts in its private
invocation directory. Existing v1 test slots and failure prefixes keep their original protocol.
The controller records only `configured`. Each selected worker can record `configured`,
`collection_finished`, then `first_test_start`, once each. Empty collection can finish without
starting a test.

Offsets use that actor's monotonic clock from its actual configure callback (`configured=0`).
Do not subtract offsets across actors. Missing pre-configure publication cannot distinguish
process startup, imports, configuration delay or failed observation. A missing later event is
UNKNOWN, not evidence that collection or a test started or finished.

Each actor has one exclusive held-inode sidecar, at most1024 bytes and three ordered events.
There are at most64 workers plus the controller. Reads reject stale nonce, unexpected schema,
duplicate fields, torn/oversized/linked/replaced/nonprivate files and invalid clock order.
The primary runner, worker count,900-second deadline, output limits, verdicts and coverage
qualification do not change. Publication failure disables only this optional observation.

The runner's existing `CoreTestRun.progress` transports this data without modification.
Verification revalidates the closed optional phase envelope before export. It exports no nonce,
path, environment, raw nodeid, parameter, captured output or error value. If the phase envelope
would exceed the existing16000-byte progress budget, it is omitted and remains UNKNOWN;
existing slots and failure facts are preserved.

Reported phases are diagnostic data, never execution, coverage, approval or acceptance authority.
This source adds observability. It does not establish or fix the cause of historical issue365
timeouts. Fresh source-bound review, full qualification and required CI remain separate.
