# Optional Factory retrieval

The fixed `factory.local-retrieval162/v1` profile composes retrieval with the
existing `AccessReleaseService`, `FactoryNativeAccessHost`, operator
`AccessAuthority`, task fence, `ResultBroker`, result outbox and authenticated
UDS. Trusted parent composition selects it with the `retrieval_profile` argument
of the existing service. Ordinary Factory startup does not enable it. It is
mutually exclusive with the separate payload151 profiles.

The registered reader/computation is `factory.retrieval162/v1`. Its one scope
locator is `current-destination`. Its closed parameters are query text,
`destination_id` and `token_budget` (2048 or 8192). A destination name locates a
registered channel; it grants nothing. Caller source IDs, paths, classifications,
lineage, permission flags and arbitrary computations are rejected.

The current destination authority supplies tenant/project/repository. The actual
task proposal context supplies repository/workspace and permitted paths/tools.
Before any source read, the service filters its registered local sources by
that scope, current source read/release rights and current recipient rights.
The existing source reader repeats authorization and verifies owned file custody,
version and exact hash. Unknown or unavailable authority has no cached-allow or
raw-reader fallback. An authorized source with unsupported class/path refuses
the request; it cannot be silently relabelled public.

The fixed producer accepts source-owned `public`/`internal` Python text only.
It constructs a one-field code projection using the existing payload policy and
secret recognizers, then applies the existing bounded email/phone recognizers.
Those recognizers do not prove universal secret or PII absence. Personal, secret
and unknown classes refuse before private-source reading. Original file/range
hashes remain distinct from transformed hashes. A transform which changes line
mapping refuses rather than inventing original citations.

The existing exact-symbol/BM25/RRF algorithms build cited context from that
authorized cut. Semantic retrieval remains unavailable and RRF is explicitly
degraded; answerability remains unknown. The UTF-8 byte counter is labelled an
upper-bound estimate. Actual model usage/billing is unknown. The profile starts
no model and calls no provider or external reranker.

The complete candidate dependency set, immutable query, transform policy and
generation identity remain bound through preparation. Current source custody,
bytes, classes, permission revision, task/fence and destination are checked again
before release and dispatch. The exact payload is recomputed and compared before
the existing UDS consumes it. The same task/run/attempt/fence/packet identifies
one retrieval stage; changed or consumed preparations cannot create a new send.
The original two-second absolute lifetime, at most128 sources and262144-byte
source/output ceilings remain. These checks are not a hard real-time guarantee
for arbitrary filesystem/database waits.

## Revocation and retention

The revocation clock starts when the existing operator update successfully
publishes its new current authority. Subsequent capture, preparation, admission
and pre-dispatch checks deny revoked/deleted sources, including old authenticated
sessions and prepared references. Duplicate or stale expected revisions cannot
restore old access. This profile uses direct current checks; it does not depend
on an event cache or claim provider reconciliation coverage. Effects already
admitted at their transport cut cannot be recalled by a later update.

`NativeAccessBroker.discard(handle)` cancels pending owned work and drops broker,
host and service references. Dispatcher ticks retire expired retrieval payloads;
completion/failure/close retires their source/payload references as well. Only
bounded replay/accounting facts remain in the existing prepared map. No retrieval
index, embeddings or source text are written to a new cache. A returned cut is
already disclosed to its trusted recipient; disposal does not erase a recipient's
copies or securely overwrite Python memory.

The existing durable `result_sources_v1` envelope and an actual recipient can
still retain delivered snippets. This change does not delete that journal or
define its retirement protocol. Therefore it does **not** satisfy full162
derivative-deletion acceptance or qualify private production retention. Full
issue closure also requires the independently sealed RU/EN/BGE-M3 experiment,
dense evaluation and any separately selected provider/model profiles. Neither
source presence nor PostgreSQL/UDS tests establish those outcomes.

Disable the profile by omitting `retrieval_profile` in trusted composition.
Close/discard owned requests before replacement. Existing source-only and
payload151 profiles retain their own contracts; there is no data migration.
