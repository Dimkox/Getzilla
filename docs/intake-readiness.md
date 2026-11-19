# Native requirement intake (local slice of #158/#160)

The supported ingress is `scripts/getzilla_artifacts.py intake apply`. It requires
the real selected task owner, attached native package, current policy hash, exact
previous cut and raw projection digest. The request has `snapshot`, `requirements`
and a closed `event` (`record`, `question_round`, or `withdraw`). Use `none` and the
zero SHA256 only for an initial publication. `inspect`, `assess` and `trace` read
data; `recover --publication-id <T>` reuses the saved exact intent.

This slice supports source locators in the selected native package's
`requirements.md` and the native repository development operation. Other source
ACL and permission contracts refuse as unsupported. Source fields, imported done
statuses, owner labels and scope ACK never establish human approval. A draft that
requires a substantive decision stays `needs_decision/unsupported_decision_ingress`.

The immutable substantive digest D excludes decisions, status, questions,
timestamps and spec/context/state backreferences. The native spec references D.
Actual scope ACK establishes C. Mutable events produce M; the existing canonical
task publishes the final generation/D/S/R/ACK/C/M cut. Bookkeeping changes M and
the cut while preserving native spec bytes, scope revision and C.

Publication stages an immutable input and intent, latches pending, waits for
writers before substantive document changes, uses the existing descriptor CAS,
replays the real ACK, freezes state bytes and commits one canonical cut. M-only
withdrawal can publish while a writer is registered. Recovery preserves every
third-value human edit and remains pending. It never rolls back a foreign value,
clears pending to reuse old ready, or retries an unknown external create.

Enabled context-v2 tasks check the current cut before implementing/later
transitions, writer registration/reuse and managed product mutations. Required
helper/hook-loader faults deny affected writes. Existing policy and exact grants
still apply. Read-only inspection, private scratch and closed native repair stay
available. Undeclared v1 tasks retain compatibility with semantic intake NOT_RUN.

Readiness checks structured objective, bounded scope, measurable native criteria,
dependency/permission/source facts and typed conflicts. Unassessed prose and
unsupported units remain unknown. Questions are stable, at most five per round
and three persisted rounds; exhausted unknown facts remain visible. Retained
inputs/intents/state have ceilings of 64 versions, 4096 events and 1,000,000 bytes;
the first reached bound stops publication before recovery space is consumed.

`trace` links current source locators to native criteria/spec and, when present,
the existing recomputed task graph. Imported PR head/state observations remain
unqualified; a changed head is stale. Receipt/provider acceptance is NOT_RUN.

Actual trusted principal/delegation/ACL ingress, provider #207 reconciliation and
live source-to-PR qualification remain required Task5 work. Full delivery and
exact-head external checks remain required. These local controls are workflow
fences, not OS isolation or cancellation of an unmanaged in-flight write. No
upstream implementation was copied. No model/provider call is needed here.
