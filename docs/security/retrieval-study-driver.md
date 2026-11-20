# Fixed public study source components

These optional leaves implement computation and data-plane checks for the fixed
issue162 public study. They do not enable study execution. Import and status do
not import NumPy, ONNX Runtime, tokenizers or tiktoken, load models, create a
process, or access the network. The existing experiment `execute` action remains
unavailable. No retained-corpus ranks or native runtime qualification are supplied
by the tiny fixture tests.

`study_windows` preserves original function and window IDs, explicit overload
exclusions, Protocol ellipsis rows, greedy254 windows and two-line overlap.
Counts include the tokenizer's special tokens, matching the published
`len(tokenizer.encode(text).ids)`. Truncation is reported only above256, including
a single overlong line; truncation never changes retained source bytes.
`study_tokenizer` disables automatic padding/truncation, counts actual specials,
then applies the registered256-token bound preserving the inspected final special
ID. A digest or special ID is data and grants no model access.

`study_metrics` projects repeated known function IDs before R@5/MRR@10, as the
published benchmark does. It retains the mapping to original positions. Each
position outside the frozen function universe remains unjudged and receives no
credit; it is not removed or replaced. Label0 is unjudged, not nonrelevant.
Missing paired values make the registered sixteen-task slice INCONCLUSIVE,
without reducing its denominator. Pure arithmetic does not enforce single use of
the final holdout; that belongs to the existing execution owner.

`study_context` matches published citation headers, source-line overlap removal,
newlines and separators. The counter sees the complete accumulated context,
including every header. It accepts only the registered2048/8192 limits, never
refills beyond original top100, and reports unavailable/skipped original slots.
Returned context contains source bytes and must remain behind current native
source and operation fences. Hash validation here is not source authorization.

`study_vectors` supplies scalar reference checks and fixed three-arm RRFk60 with
original-ID ties. Its scalar floating point operations are not an FP32 model
runtime or a claim of bitwise publisher parity. `study_onnx_worker` uses the
published NumPy mean operations for actual MiniLM inference and first-token CLS
for BGE, followed by L2 normalization and FP32 output. It binds inspected input
and all output signatures, explicitly selects the raw rank3 output, fixes CPU
provider and intra/inter thread counts1, and rejects unexpected dtype, shape or
nonfinite output. BGE's separate rank2 output can remain symbolically shaped in
the bound signature and is never used for pooling. Runtime conformance still
requires the separately admitted real image and inspected artifacts.

`study_resources` compares readback data against the fixed offline profile:
two CPUs,6GiB,swap0,pids128,networknone,read-only root/model/software,nonprivileged
UID,capdrop,no-new-privileges,seccomp,boundedtmpfs and no Docker log persistence.
Passing dictionaries cannot mint a resource reference. `study_supervisor` accepts
only the genuine operation owner's reference, uses the existing execution CAS
and its original monotonic deadline, and owns the exact local-daemon container
and attach process. Docker uses a pinned executable descriptor and private empty
CLI configuration. Its stdlib PID1 controller owns exactly one separately
killable native child; heartbeat loss, EOF, stage/global expiry or protocol faults
retire that tree. Heartbeats never extend deadlines. Native code cannot block
PID1's independent timers by holding the child's Python GIL.

Only actual held image/process/channel, mount, kernel and artifact readback can
issue a process-local live resource reference. Numeric Docker daemon PIDs are
never treated as local PIDs without matching namespaces, starttime and argv.
When direct host proc observation is unavailable, its gap and daemon PID scope
remain explicit; fresh actual inside PID1 facts and owned Docker lifecycle stay
mandatory. Same kernel boot/time namespace is required for absolute deadlines.
Missing facts required by the selected profile refuse execution.

The fixed worker export contains only its reviewed Python source closure, no
bytecode, archive, runtime, credentials or corpus. The separately held software
export preserves the entire pinned wheel union, including inert .pth, entrypoint
metadata and .data members; isolated startup and direct paths never process
those mechanisms. Source bytes cross only the admitted private pipe.

The result port binds actual terminal execution and the existing captured
diagnostic artifact. Its current observation definition explicitly reports an
incomplete scientific manifest and cannot qualify PhaseB. The full fixed study
driver, independent scientific manifest assembly and actual native qualification
remain outstanding. No real model/container execution is supplied by these
inert source controls.

Before any actual tokenizer/model or lexical/dense/fusion ranking, the native
composition still needs genuine PhaseA/B, separately explicit current operation
consent, the frozen concrete runtime/artifact registration, and an owned
supervisor. That supervisor must verify actual executable/image/container and
PID/starttime/cgroup identities, effective and ancestor limits, argv/mounts and
host artifact custody; bound all IPC, logs and wall time; and cancel/reap/remove
only its own complete childtree. Both fresh public source cuts and their complete
derivative lineage must be checked after resource readback and before each
encoder input and final release. Long compute ceilings never renew a two-second
source or query deadline. Missing authority, policy, source, runtime, enforcement
or currentness remains unavailable, with no host-venv fallback. These public-only
components establish no private-corpus or enterprise ACL authority.
