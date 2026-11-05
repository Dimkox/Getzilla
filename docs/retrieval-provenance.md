# Retrieval engine and provenance

The initial `getzilla.retrieval` library provides bounded Python function extraction,
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

Full issue162 still requires actual current-authority/native-sink integration,
two-principal/two-project access and revocation tests, derivative deletion, real
optional dense integration and the independently sealed RU/EN/BGE-M3 experiment.
BGE-M3 is not selected or loaded by this library. No benchmark quality, native ACL,
provider, retention or complete-delivery claim follows from this checkpoint.
