# Execution registry contract

This private composition adopts the scoped #225 source as an UNVERIFIED dependency.
The main parallel runner has no shared preview helper. Core output sharing and its
retained assertion remain explicitly unsupported until ordered Core composition;
registry output redaction is exercised independently. This does not qualify #225.

The optional `getzilla.execution` Python API records one attempt per scoped intent.
It uses `.getzilla/runtime/executions/registry.json`, with version 1 retained for
historical storage and explicit version 2 provisioning for new execution. It adds
no service, database, queue, dependency or runtime approval. Existing
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

## Provisioning and the local stop latch

`getzilla trust provision --json` explicitly creates and flushes the sole registry
before arming `execution_store_required={version:1,generation:...}` on the existing
canonical task. The binding is monotone and survives task amendments and handoff.
An interrupted initial arm can resume with that same generation. Once armed,
missing, corrupt or mismatched state cannot recreate an empty running store.
Historical version 1 migration requires terminal attempts with confirmed or
unneeded cleanup and no unknown operation outcome. Stop controls and intent
tombstones are never silently removed.
The version 2 machine contract is `schemas/execution-registry.v2.schema.json`.

`getzilla trust stop --reason operator_stop --json` commits the stop before any
cleanup request. Other fixed reasons are `compromised_tool`, `tool_unavailable`
and `rollback`. Repeated stop is idempotent. New attempts and their cooperative
admission consume compare the same registry generation and stop revision. The
real hook checks the same armed control before later write or unclassified tool
requests. Known local read requests and exact status/control command forms still
pass through the existing secret, path and operation policy. This workflow check
cannot interrupt native host-owned tools or authenticate a customer against a
same-UID bypass. Unarmed projects keep their existing behavior.

`getzilla trust status --json` returns the stop revision and the number of
attempts with unconfirmed effects or cleanup. It remains available when source
observation is unavailable, with a null source fingerprint. `getzilla trust get
EXECUTION_ID --json` observes the existing attempt. `getzilla trust cancel
EXECUTION_ID --json` reserves and consumes the existing cancellation request;
accepted cancellation stays pending until the actual owner confirms cleanup.

`getzilla trust recover --expected-revision N --expected-source DIGEST --json`
requires the current stopped revision, current source/context observation and no
unconfirmed attempt. Pending or stale typed scope refuses recovery. This does
not reset operation grants, credential permissions, deadlines or budget authority.
Rollback restores reviewed source/declarations through ordinary delivery and
keeps stop engaged until the restored bytes and cleanup are requalified. No
unknown attempt is replayed. Canonical-owner handoff fences the old epoch and
retains the stopped control and required generation.

## Opt-in Linux managed execution

`getzilla trust run --tool TOOL_ID --intent INTENT --timeout SECONDS --json`
consumes the existing toolchain identity and the same attempt authority. No
shipped tool is enabled. An existing `.getzilla/config/toolchain.json` entry can
carry a closed `managed` object with an absolute `executable`, exact `sha256` and
fixed `argv` array. The executable basename must be in that entry's `commands`.
No request argument supplies an endpoint, principal, alternate command or grant.
This is an observed local binary pin, not upstream provenance or transitive
dependency attestation. Model aliases and declared minimum versions stay distinct.

The adapter admits a bounded, public-mode, single-link regular ELF file through
anchored no-follow descriptors and strict non-writable ancestry. It checks owner,
identity, size, mode and content before use. It executes the checked descriptor,
not a PATH lookup. Public configuration, current typed scope and existing command
policy are required and rechecked before release. A source/policy change fences
release. Public-source audit's limited same-group directory observations do not
widen executable custody. No permissions of shared parents are changed.

Managed source snapshots use the existing file reader's strict `public_source`
opt-in; its private workflow reader remains available to existing callers. Before
reading any source bytes, this mode requires an owner-matching, single-link,
regular file with public mode0444/0644/0555/0755. Anchored no-follow root and
directory checks reject writable ancestry, except a root-owned sticky system
parent. File and named-path identities are rechecked before each chunk and after
reading. Private, foreign, linked, oversized or changed input rejects the whole
snapshot. The4096-entry limit counts admitted files and directories cumulatively,
including completed directories. It is checked while listing, before collecting
entries for sorting, enqueueing directories or reading files. The fixed Git,
cache and runtime subtree exclusions remain. The16MiB aggregate byte bound remains. Each file's
read limit is the remaining aggregate budget, with a16MiB maximum for this opt-in
reader. Oversized metadata refuses before bytes; growth cannot consume bytes past
the supplied budget. Archives receive the same public custody checks as other files.

This POSIX metadata eligibility does not classify arbitrary content as nonsecret
or authenticate a customer. Known secret names remain refused. Windows public
source custody is unsupported until an actual ACL-qualified adapter exists.
Shared0775 path ancestry is also unqualified; later native integration must use
the reviewed kernel-CWD resource with the same public eligibility, without a
path waiver or a second anchor authority. A group-writable source root remains
refused. The audit command's limited directory observation does not widen this
managed source or executable policy.

After admission consumption, the attempt records `starting`. A fixed launcher
waits on a parent-owned pipe. The owner spawns outside task locks and records its
live Linux pidfd/start identity before the release check. The brief release
transaction persists a checked intent while retaining `registered`. The original
absolute deadline is checked after revalidation and durable intent publication,
then inside the owning callback immediately before the gate byte. `released` is
recorded only after that callback succeeds. Post-gate publication failure remains
uncertain and cannot replay the consumed intent. A stop committed
before this cut prevents the managed command, including late handle registration.
A stop after the cut requires cleanup and does not undo earlier effects. No task
lock spans child lifetime. Pipe drains are bounded; independent checks observe
stop and deadline at intervals of at most 50 ms plus local scheduling/store I/O.
Authority outage fails closed and triggers owned cleanup.

The child receives only fixed PATH, LANG and LC_ALL values. It inherits no HOME,
session ID, proxy or credential variable. The bootstrap uses isolated Python and
its observed pinned ELF descriptor. Its fixed code and bootstrap digest remain
diagnostic launch binding, not an authenticated customer identity. Output uses
the existing bounded preview/counters and has no approval or review authority.

## Factory provider stop boundary

Factory uses its existing PostgreSQL `kill_switches` history and
`kill_switch_heads` projection. Migration 026 assigns a serialized monotone
revision before each new same-scope event. Operator authorization and exact
idempotent replay remain unchanged. Neither local execution state nor landing's
SQLite projection replaces this authority.

A client chooses a validated landing job ID and knows the content SHA256 before
upload. It first submits a genuine Factory TaskIntake with its required authority
documents. Use `source_type=api` and source ID `landing:v1:` followed by the
SHA256 of that exact job ID's UTF-8 bytes. This 75-byte selector has no legacy
alias and grants no identity or permission. Then upload with the same job ID as
the landing Idempotency-Key. Factory allocates the actual task UUID.

The real server binds its existing Factory service to landing. An opaque local
capability requires exactly one active, unexpired task with the same repository,
base, content hash, original intake actor and immutable stored landing creator.
The full job ID and stored input remain separately bound. Request labels,
provider profiles and serialized capability text cannot supply this authority.
Separate access and permission freshness still require their actual authority;
this stop capability does not authenticate a customer against a same-UID bypass.

The provider checks the capability before credential lookup and just before its
local POST admission. During connect, headers and body waits, an independent
observer checks both global and exact-repository revisions every 50 ms. One
750 ms deadline covers each PostgreSQL connect, existing capability-role checks,
setup and snapshot query. Source observation has two separate 50 ms SQLite
owner-lock bounds. An outage closes the owned DB connection before cancelling
and joining its query task. No DB transaction or task lock spans provider IO.
These are local measured controls; OS scheduling and remote cancellation are
not guaranteed.

A stop, changed revision, stale source or authority outage cancels owned HTTP
work and produces a non-fallback policy outcome. After local admission, remote
usage remains unknown unless a valid result established it. Local cancellation
does not reverse a provider effect. A cancelled job cannot accept a late result
or replay its provider call. An operator's disable event changes the revision;
it cannot revive an earlier capability.

Standalone live landing lacks this Factory boundary and refuses before keys or
POST. Its offline path remains available. The programmatic synthetic Qwen probe
also requires a real capability for its exact synthetic source. The public probe
CLI has no authenticated capability issuer and therefore refuses live execution.
No deployment or real-provider qualification is implied by source tests.

## Rollback and recovery

Stop the owning local task with reason `rollback` and inspect every existing
attempt. Keep its required-store generation, stopped control, intent tombstones
and unknown outcomes. A missing registry is an outage, not a fresh installation.
Do not replay a consumed intent or treat accepted cancellation as cleanup proof.

Restore tool declarations, dependencies or binaries through normal reviewed
delivery while retaining this stop-aware hook, admission and version2 reader.
Downgrading to a client that ignores the required store is unsupported. Source
restore does not remove runtime state or create a new attempt ledger. Recheck
pins, policy, task context and cleanup. Only then use the exact current stopped
revision and current source fingerprint with `trust recover`. Stale revisions,
unknown operations, pending attempts and unconfirmed cleanup refuse recovery.

For Factory, its authorized operator must retain the existing global/repository
kill while a compatible source change is qualified. Keep migration026 and its
revision-aware claim/provider consumers; do not restore an older live path that
ignores the stop fence. New capabilities require the current canonical task,
creator and source after the operator's new revision. A local source rollback
cannot reverse a sent provider effect or revoke a provider credential. Any real
credential revocation remains a separate authorized operator action.

Cleanup kills the owned process group while its leader remains unreaped, then
waits for the child and observes group disappearance. The live pidfd belongs only
to the owning process; persisted PID/start metadata is observation, never restart
kill authority. Restore with a lost handle remains orphaned/unconfirmed and never
spawns or kills by PID. An escaped POSIX session is outside this cleanup scope;
this adapter is not an OS sandbox. Other hosts and scripts are unsupported and
refused. Native Windows/macOS qualification remains a full-scope dependency;
existing Windows Job Object helpers alone do not prove executable ACL custody.

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
This generic contract alone supplies no physical cancellation. The opt-in Linux
adapter above owns and confirms only its supported local cleanup scope.

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
mutation adapters stay disabled regardless of local test results. Other adapters
must supply qualified execution/cancellation, and EX-07 must qualify external intent
and reconciliation before any external backend can be enabled.
