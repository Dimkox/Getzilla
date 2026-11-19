# Retrieval engine and provenance

The initial `getzilla.retrieval` pure core provides bounded Python function extraction,
exact identifier lookup, BM25 and explicit rank fusion. It performs no filesystem
source discovery, network access, model loading or source authorization.

`SourceSnapshot` binds byte provenance to a tenant/project/provider/site/resource
namespace and a Git or Gitless source identity. These are data identities. Creating
one does not grant permission. Original file/range/chunk hashes remain separate
from the transform policy, revision and exact transformed-input identity.

`build_generation` excludes overload stubs and retains implementation and nested
function spans. With an explicitly supplied counter it uses the published issue162
254-token, two-line-overlap window algorithm and records truncation. The counter's
identity enters the generation identity. No counter is loaded automatically. The
default function-window profile is distinct from the original sealed MiniLM windows.
Test counters establish algorithm behavior, not actual model/token measurements.

`search` keeps component ranks separate. Dense retrieval is unavailable in this
checkpoint. RRF therefore reports degraded coverage over the available exact/BM25
components; its score is not confidence. Answerability and billed usage remain
unknown. The original research report and labels are unchanged.

`pack_context` verifies citation bytes and includes mandatory text, citation headers,
line markers and separators in the 2048/8192 token-proxy budget. A mandatory-budget
failure cannot silently remove mandatory context. This pure helper does not grant
access, build trusted mandatory-source lineage or qualify an output sink.

`RetrievalService` requires an injected native adapter and token counter. Its default
is `authority_unavailable`, with no raw-reader or cached-allow fallback. It checks
generation/source/transform coherence, calls the native recheck before ranking and
before preparation, and returns only an owned prepared reference. A Python adapter
or test fixture alone does not qualify native identity, permissions or release.
Actual composition must use the current operator authority, original task/run/fence,
complete service-owned transitive lineage and the registered destination protocol.

The private POSIX projection accepts an already-open owned0700 directory descriptor.
It atomically publishes a0600 metadata-only generation pointer with a nonblocking
publication lock and expected-generation comparison. It stores no source text or
permission. It cannot restore an executable generation, model or authority handle.

One budget spans all engine stages. The initial profile caps query size, source and
chunk counts/bytes, scoring, source-byte verification and the whole two-second
deadline. Native adapters must additionally enforce their actual authorization,
queue, cancellation and memory bounds; cooperative algorithm checks are not a
qualified host isolation mechanism.

The optional public experiment-input audit reconstructs the original fixed
function identities, file/range hashes, grouped language tasks, partition and
development-English pins. Its default profile retains the original55/2194 function
universes and240 variants/80 tasks/40 holdout slots. It rejects missing or reordered
judgment cells and preserves0 as UNJUDGED. Authored labels and caller review flags
cannot create an independent review, human attestation or data seal.

Run `python3 scripts/getzilla_retrieval_inputs.py CANDIDATE --public-source-root PUBLIC_CORPUS`
to check the four draft JSON artifacts through the existing bounded anchored
reader. The result is `draft_valid` with `unsealed_metadata_only` qualification,
zero primary-eligible tasks and ranking disabled. `--require-ranking` returns2
with `independent_seals_required`. This command performs no ranks or model work.
The public-artifact reader is not a private-source adapter and is never a query
fallback when native authority is unavailable.

An explicitly selected [Factory retrieval profile](factory-retrieval.md) now
connects current operator authority and task/fence to the existing protected
result outbox and authenticated UDS. It uses the same registered source owner,
Core algorithms and final release checks. Its deterministic controls include
different principals, projects and tenants, group removal, source deletion and
actual PostgreSQL/UDS delivery. These controls do not qualify a model backend.

Full issue162 still requires durable derived-data retirement across the existing
result journal and actual recipients, broader native/provider profiles, real
optional dense integration and the independently sealed RU/EN/BGE-M3 experiment.
BGE-M3 is not selected or loaded by this library. No benchmark quality, native ACL,
provider, retention or complete-delivery claim follows from this checkpoint.


The optional issue370 native-local composition now adds actual owned-CWD source
reads, current route-owner checks, existing Read policy and admission scanning,
verified packets, local stdout and explicitly selected installed-harness sinks.
See `docs/shared-context370.md` for its narrow scope, activation disclosure,
strict-profile refusals, tested transport matrix and all NOT_TESTED model facts.
It reuses this core and the existing graph store. It does not qualify enterprise
ACLs, an actual backend/provider, private-egress confinement or model savings.
