# Execution registry contract

The optional `getzilla.execution` Python API records one attempt per scoped intent.
It uses `.getzilla/runtime/executions/registry.json`, version 1. It adds no service,
database, queue, dependency, native executor or runtime approval. Existing
`getzilla par` remains synchronous and keeps its policy checks and exit codes.

`trusted_caller(root)` derives the native-bound session and canonical task context.
An adapter may select a registered agent with `agent_id`; its canonical generation
must match. Principal strings are not authorization inputs. `submit` captures the
workspace, existing route/logical task/change, session, authority epoch and agent
generation once. Run identity stays null when the adapter has no real run ID.
Each attempt gets an opaque execution ID and generation. Operation, MCP request
and remote-task IDs remain separate. No operation creates another task identity.
A new MCP transport request ID replays the same intent. The first stored MCP ID
stays immutable; retries add no history and do not reset a deadline. Remote task
association stays bound until a qualified backend owns that association.

Use `get(root, caller, execution_id)`, `wait(root, caller, execution_id, seconds)`
and `execution_output.read_output(root, caller, execution_id)` to observe work.
Wait accepts a finite positive value up to 30 seconds. It uses monotonic time;
`wait_expired` does not fail, restart or stop the attempt. Repeated observations
and heartbeats never extend the fixed hard deadline. A deadline consumed during
admission prevents dispatch. Timeout or orphan status does not prove process
termination or cleanup. Cleanup and operation outcome have separate fields.

The owning native session can observe its old attempt after selecting another
route, including through a freshly derived caller context. The saved canonical
owner route controls this ACL. Handoff revokes the old epoch. Worker generation
changes fence the old worker and its callbacks. This is cooperative local scope
checking, not isolation from the same OS user editing runtime or Python objects.

After restart or removal of active task pointers, use
`trusted_caller(root, execution_id=execution_id)`. This observation-only context
comes from that saved attempt and its canonical owner route. It checks the bound
native session, epoch and worker generation without selecting or creating a task.
It can observe or request supported cancellation of that one attempt; it cannot
submit a new attempt or create grants. Missing/corrupt/foreign selectors never
fall back to active-task discovery. `live_continuity` identifies the local
registry adapter/clock context, not proof that a process is alive. A fresh process
reports `recovery_unknown` until explicit qualified recovery; it never relaunches.

Production `submit` and `cancel` have no backend and return `unsupported_backend`.
Tests inject an actual counting adapter to exercise the contract. Any adapter
marked as externally mutating is refused on every platform. No managed launch,
process cancellation, remote retry or external exactly-once guarantee is supplied.
The registry canonicalizes arguments once into ephemeral immutable bytes. Both
the semantic digest and the adapter's fresh owned payload use that snapshot;
mutating the caller's original dict/list after intent cannot change dispatch.
Raw arguments are not persisted. An injected adapter must explicitly implement
`cooperative_admission` and call the supplied token's `consume` before counted
work. A short owner/epoch/generation/deadline check and durable CAS consumes that
token once. Already-revoked admission is refused before the adapter call;
revocation before its consumption prevents counted cooperative work. No task lock
spans arbitrary dispatch/cancel code. After valid consumption, an in-flight
revocation can still leave work running: this supplies no physical or external
fence. EX-03 must qualify any such backend before production use.

An interrupted claim is never dispatched again on replay. Different arguments,
backend kind, hard duration or operation/remote binding under one intent conflict.
Cancellation first saves one durable reservation with a fixed 30-second admission
budget. The cooperative adapter consumes it before its request effect. Concurrent
or uncertain retries never resend it. Only actual accepted consumption can record
`cancel_requested`; it never means `cancelled`. Lost responses and receipt failures
remain unknown. A terminal completion that wins a cancellation race stays
immutable; work may also finish successfully after cancellation was accepted.
No live cancellation implementation or qualification is claimed.

The registry uses existing kernel locks, safe descriptor reads, atomic writes,
file flushes and directory-entry flushes. It keeps at most 256 attempt/tombstone
slots and 4 MiB per envelope. A single-link regular file and stable parent
namespace are required. At most 16 interrupted publication files are admitted;
saturation refuses further publication and does not delete unknown state. CAS,
immutable fields, event digests and generation checks fence conflicting updates.
A failed intent publication makes zero adapter calls. A failed completion save
returns persistence uncertainty, never an acknowledged successful receipt.

Explicit `restore(root)` is local maintenance, not process recovery or external
reconciliation. Without proven live clock/adapter continuity, a nonterminal
attempt becomes orphaned with unconfirmed cleanup. Wall-clock rollback creates
no new execution budget. Terminal output expires after one day and becomes an
ACL-preserving tombstone in the same slot. Intent entries are never silently
evicted or rerun; capacity exhaustion returns `registry_full`. Safe retirement
and stronger recovery belong to EX-05.

Source observations retain the actual Git SHA only when the selected workspace
is the Git toplevel. Nested non-Git folders retain null SHA. The initial bounded
content inventory, dirty flag, existing tree fingerprint, continuity digest and
evidence links remain separate from the completion observation. Changed bytes
set `source_changed`; exit zero cannot rebind the old result to new source.
Sensitive `.env`/private-key paths and unavailable or oversized inventories refuse
new source binding. These are bounded observations, not immutable source copies.
Every execution view has `evidence_authority=false`: success is not a review,
CI result, approval, mandatory full report or external acceptance.

Output normalization runs before every view, wait, output read and explicit
restore. Historical stdout/stderr and job lists get a 4096-byte UTF-8 preview and
32768-byte JSON envelope. Malformed counters fail closed; unknown totals stay
null. Credential-label suppression is a heuristic and cannot detect all secrets.
Raw streams stay outside new registry records. Old host-path log strings are
never opened. Optional artifacts use a bounded reference in the existing `par`
namespace, content digest, size and inode/time identity; missing, linked, oversized
or replaced artifacts are unavailable. The API exposes no cursor or full-log
retrieval channel. Truncated diagnostic output never proves full-report retention.
A requested smaller output view also marks preview/view truncation and clears
`complete_output`, including a UTF-8 slice. Whole-stream observed/retained/dropped
counters continue to describe capture; cropping a view does not rewrite them.

Linux tests cover local filesystem fault injection and real child interruption
around file flush, rename and directory flush. They do not simulate hardware
power loss. Windows directory fsync is unsupported in the existing adapter;
atomic replacement and path checks do not prove power-loss durability. Native
Windows/macOS and network-filesystem qualification remain separate. External
mutation adapters stay disabled regardless of local test results. EX-03/EX-04
must supply real execution/cancellation, and EX-07 must qualify external intent
and reconciliation before any external backend can be enabled.
