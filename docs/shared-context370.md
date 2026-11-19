# Shared local code context

Issue #370 adds bounded source selection and a provider-neutral context packet. It reuses the existing Python graph and the #162 exact-symbol/BM25 retrieval code. It does not create another graph, registry, permission store, model service or background worker.

This is a narrow native-local profile. It qualifies local source → local stdout and an explicitly selected installed native hook. It does not qualify an actual model/backend, private-egress confinement, enterprise ACLs, token billing or savings. Actual model comparisons remain **NOT_TESTED**.

## Opt in and disable

Use the existing optional-module lifecycle in an installed project. Installing a module does not enable it.

```sh
getzilla components module install context-retrieval@0.1.0 --source /path/to/Getzilla
getzilla components module enable context-retrieval
getzilla context query --root "$PWD" --query 'exact_symbol' --format json
```

To send selected source to one installed native harness, install and explicitly enable its separate sink module. For example:

```sh
getzilla components module install context-hook-grok@0.1.0 --source /path/to/Getzilla
getzilla components module enable context-hook-grok --grant context.hook.grok
```

The sink artifact names the harness. Activation consents to sanitized, verified source entering that installed client's configured model. The actual backend, provider, privacy confinement and prices remain unverified. Only the native ingress for that selected installed harness can use the sink. A caller profile string, root path, session string or manually constructed source packet cannot activate it. The current route owner, actual kernel CWD, held filesystem resources and existing Read policy remain mandatory.

Sink modules also exist for `claude`, `codex`, `copilot`, `gemini` and `qwen`. Their protocol shape uses the existing hook integration. This checkpoint directly exercises the Grok hook process; it does not claim runtime qualification of those other clients.

Existing free-only and local/closed-network admission profiles in `model-continuation.json` retain their restrictions. Source delivery to a model through those hooks refuses without actual backend/resource proof. Module activation cannot waive that condition. Such proof is not implemented here. Local stdout remains an ordinary local read.

Disable the selected sink before disabling its dependency:

```sh
getzilla components module disable context-hook-grok
getzilla components module disable context-retrieval
```

Disabled hooks do not open or build the graph, start workers or call models. Disablement keeps source and the existing cache. Explicit `context deliver` is a caller-invoked ordinary-text process adapter, separate from automatic hook retrieval.

## Local contract and plaintext adapters

Run from the actual project root, under the current route owner's existing session. `--root` must name that exact held CWD. The native profile requires Linux/POSIX `/proc/self/fd`, OS-owned source paths without group/other writes, owned private runtime metadata, and a private `0700` graph directory with `0600` cache files. It refuses unsafe resources; it does not change their ownership or modes. Missing policy, unknown policy metadata, foreign sessions and unresolved roots refuse before source delivery.

`getzilla context query --root "$PWD" --query TASK --format json|text` returns a bounded packet or an explicit unavailable result. `--mandatory-stdin` adds caller task text, subject to a bound. Canonical original task scope, pending amendments and evidence gaps are always retained. The CLI cannot replace them with caller text. A mandatory-text overflow refuses code packing; it never drops the stored task scope.

The packet has source and generation identities, independently checked file/range/fragment hashes, graph references, component status, coverage gaps, source/index counters and text. It uses exact symbols, paths, imports, callers and callees with depth ≤3 and ≤128 selected nodes. Natural-language selection uses exact/BM25 rank fusion; dense retrieval is unavailable. Classes and file headers use checked graph spans. File headers stop at 128 lines and disclose that limit. Nothing injects a complete graph export.

Without an exact supplied tokenizer, packing counts UTF-8 bytes as a conservative size estimate. This is explicitly labelled `utf8_bytes_upper_bound_estimate`. Actual input, cached input, output and billed tokens remain `null`. The native profile uses an 8192-byte context limit. The hook envelope also retains the existing 16384-byte full-handoff bound.

For a client without hooks or tools, the adapter accepts ordinary UTF-8 text on stdin and a literal local argv. It uses no shell and does not change retrieval. These commands describe the interface; they do not grant private-source egress to an arbitrary program:

```sh
# Caller supplies ordinary text to a compatible client's stdin.
getzilla context deliver --transport stdin -- /path/to/client --stdin
# Client supports a prompt file; the unique file is0600 under an owned0700 runtime parent.
getzilla context deliver --transport file --scratch "$PWD/.getzilla/runtime/context-delivery" -- /path/to/client --prompt-file '{context_file}'
```

`{context_file}` must occur exactly once for file transport. The adapter removes its own private file and directory after completion or error. Unsupported transports refuse. Text is limited to262144 bytes and process time to60 seconds. The inert-client integration tests prove actual text delivery and cleanup, not source authorization or model behavior. A standalone unmediated client is not a qualified private-source sink.

## Freshness, coverage and recovery

The native reader captures one current authorized cut. It evaluates the existing Read policy for each source path, rejects sensitive source classes, scans content with the existing admission secret scanner (a rule pass does not prove that all secrets are absent), rejects links/special files, and holds descriptors through final broker admission. Policy, component state, route/context revision, Git HEAD/tree, source inventory and source hashes are rechecked. Source or authority changes before admission refuse delivery. Source text is not written to the graph cache.

The existing graph store owns publication and corruption recovery. An unchanged generation is reused without graph parsing or link resolution. Changed files use its incremental parser; rename and source changes cannot keep old citations. Configuration/extractor identities remain in the graph input. Retrieval function extraction still reads/parses current authorized bytes for each invocation; its cost is separate from graph reuse. Native counters separate graph parsing/link work, local reads and rechecks, retrieval AST files and emitted context bytes. None counts emitted bytes as model input usage.

This profile admits at most112 Python source files, a bounded4096-entry inventory,1MiB per file, an8MiB access cut, and the existing two-second broker/retrieval deadline. Larger or unsafe projects fall back visibly to authorized ordinary search/reads. Other languages, dynamic/unresolved calls, ambiguous names, missing matches and exhausted budgets retain explicit coverage reasons. These limits do not prove whole-project analysis. No mandatory check or conservative impact rule is reduced.

At startup, the hook emits only a brief disabled/present/missing/unverified status and the shared command. It selects code after a task arrives. Failure adds a brief fallback only if it fits; the original handoff remains intact. Child/system notices do not start retrieval.

## Capability and measurement matrix

| Path | Repository behavior / delivery observation | Actual model/backend | Usage and paired savings |
| --- | --- | --- | --- |
| Local JSON/text query | Tested with real OS-owned root, current route, policy, Git/Gitless bytes and local output | No model call | NOT_TESTED / unknown |
| Grok native prompt/startup scripts | Tested as real hook subprocesses; selected sink, fragments and original scope observed | NOT_TESTED | NOT_TESTED / unknown |
| Claude/Codex/Copilot/Gemini/Qwen hook protocols | Existing protocol integration; sink modules available; runtime combinations NOT_TESTED | NOT_TESTED | NOT_TESTED / unknown |
| Arbitrary compatible stdin client without tools | Tested with inert local executable | NOT_TESTED | NOT_TESTED / unknown |
| Arbitrary compatible prompt-file client | Tested with inert local executable, private modes and cleanup | NOT_TESTED | NOT_TESTED / unknown |
| Strict free/local/closed-egress model sink | Refused without actual backend proof; refusal tested | NOT_TESTED | NOT_TESTED / unknown |
| Qwen0.24.7 + Ollamav0.40.16 + Qwen3:1.7b | Runtime/model acquired and hash-verified after retained earlier failures; fixed two-CPU/4 GiB qualification attempted twice | FAILED: requests timed out at 280 s and 700 s; no response, tool call or patch; ordinary eligibility remains disabled | Retrieval/UDS pairs NOT_TESTED; usage and savings unknown |
| Remote/cloud or private enterprise sources/sinks | Unsupported by this narrow profile | NOT_TESTED | NOT_TESTED / unknown |

The #277 observations retain acquisition and metadata failures, followed by verified runtime/model acquisition and two failed normal-workflow trials. Combined generation time was 980.235 s within the 1200 s cap; both workspaces stayed unchanged and trial processes terminated. Filesystem/network controls held, but no coding result or token usage was established. Cause remains unresolved: the qualification proxy forced non-streaming upstream responses and buffered complete JSON, while roughly 3900 prompt tokens used a 4096-token context. Generated tokens, effective thinking and server output-cap mapping were not observed. CPU saturation does not prove a universal hardware limitation. These trials did not exercise retrieval or the new #151/#235 UDS handoff and cannot establish savings or ordinary Factory admission.

## Fixed paired-comparison protocol

Before any model run, pin small and large source snapshots, public tasks and judgments, CLI/version, backend/provider/model/revision, tokenizer, generation settings, prompt-cache state and context/output budgets. Use the same actual client/model and task within each pair. Compare the client's normal workflow with the context integration, not an invented whole-repository-read baseline. Include initial, repeated, small-change and outside-coverage cases. Run order must be balanced and recorded. Keep model settings and permitted quality regressions fixed before measurement.

Record initial build and update time, query time, local reads/bytes, graph parsing/link work, retrieval parsing, CPU/memory/disk, tool output bytes, actual provider input/output usage and cache input separately. Keep unavailable API counters unknown. Record solution quality, citation correctness, regressions and failures for each exact CLI/model combination. Include initial construction/update costs in totals. A tokenizer estimate is not billed usage. Reject an enablement recommendation when quality falls or total cost rises under the fixed criteria.

All paired small/large project model runs, two-provider comparisons, local-model retrieval/UDS runs, actual usage and savings measurements in this checkpoint are **NOT_TESTED**. No result is extrapolated between combinations. This document is a protocol and an honest capability matrix, not a full issue370 or release acceptance receipt.
