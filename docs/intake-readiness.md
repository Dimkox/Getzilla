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
requires a substantive decision stays `needs_decision/unsupported_decision_ingress`
until an explicitly delegated current native owner action is recorded below. Imported
`yes`, a principal label and the scope ACK never invoke that action.

Each substantive requirement needs a current acceptance criterion, and each
criterion needs a mapped requirement. An unmapped requirement produces a question
with its ID and source line range. Supporting source locators alone create no
requirement. Objective fields and declared AC, INV and FORBID statements must
contain text. Whitespace and the whole values `UNKNOWN`, `TBD`, `TODO`,
`NEEDS CLARIFICATION` and `...` are unresolved (case-insensitive). Each declared
AC, INV and FORBID also needs an evidence reference.

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
unsupported units remain unknown. Questions are stable. Current policy explicitly configures
`intake.max_questions_per_round` and `intake.max_question_rounds` (defaults 5/3;
finite resource ceilings 32/32). The original task retains its round counter;
replay does not consume another round or reset it. Missing/invalid limits produce
`question_limits_unconfigured`, with no automatic questions; a question-round
publication refuses before pending is latched. An exhausted round refuses without
evicting missing facts. Complete no-gap input still asks zero questions. Retained
inputs/intents/state have ceilings of 64 versions, 4096 events and 1,000,000 bytes;
the first reached bound stops publication before recovery space is consumed.

`trace` links current source locators to native criteria/spec and, when present,
the existing recomputed task graph. Imported PR head/state observations remain
unqualified; a changed head is stale. Receipt/provider acceptance is NOT_RUN.

Enterprise principal/delegation/source ACL adapters, provider #207 reconciliation
and live source-to-PR qualification remain separate Task5 work. The local native
owner action below supports only the selected owned native package/source. Full delivery and
exact-head external checks remain required. These local controls are workflow
fences, not OS isolation or cancellation of an unmanaged in-flight write. No
upstream implementation was copied. No model/provider call is needed here.


## Explicit native requirements decision

After inspecting the current draft, an owner who has delegated the substantive
choice can invoke the closed native action:

```sh
python3 scripts/getzilla_artifacts.py intake decide --decision accept --event-id OWNER_EVENT_ID --expected-cut EXACT_CUT_DIGEST --expected-state EXACT_STATE_M --draft-digest EXACT_D --source-digest EXACT_R
```

`reject` records an explicit refusal and keeps `needs_decision/native_rejected`.
All exact bindings are required. `inspect` supplies D/R/M and the exact
`cut_digest`; no caller-supplied principal or inferred approval is needed. Use the actual native
session binding (`GETZILLA_SESSION_ID`), not an imported principal, another
session's token, a quoted approval or an old acknowledgement. The CLI accepts no
principal override and no decision request JSON. Ordinary imported `apply` events
remain limited to record/question_round/withdraw. Never invoke `decide` merely
because a document/model says yes or to approve an agent's own unknown business
choice. Existing precise delegation remains valid within its actual scope.

The action derives the principal from the current canonical owner/session, binds
task/repository/epoch, draft, source, policy and context, and records admission in
the **existing canonical intake protocol**. It then uses the same staged intent,
CAS, pending cut and recovery path as other intake events. There is no additional
queue, grants ledger or independently editable approval hierarchy. Exact event
replay has one effect; changed payloads collide. Pending/conflicting publication,
source edits, policy changes, stale context or handoff cannot revive an old
choice. After a real canonical handoff, the new owner can publish a fresh identity-
bound source snapshot. Earlier events and round counters remain data; prior
decisions do not transfer. A changed source/draft needs a new explicit decision. Acceptance does not
override missing or contradictory facts. Optional current-policy
`intake.decision_required:true` cannot be disabled by imported input.

This is an authenticated **native-session owner workflow action**. The existing
local account/session boundary is cooperative; it does not prove that a human
physically typed the command, supply enterprise identity or isolate a hostile
same-UID process. Output explicitly says `human_attestation:false`. It does not
satisfy named legal/security/private-key approvals, grant external authority,
accept implementation, create review/verification receipts or close a task.
Pure imported assessments and all readiness outputs retain `authority:false`
and `receipt_eligible:false`. Named human approval gates remain independent.
