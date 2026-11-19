# Optional Factory retrieval

The fixed `factory.local-retrieval162/v1` profile composes retrieval with the
existing `AccessReleaseService`, `FactoryNativeAccessHost`, operator
`AccessAuthority`, task fence, `ResultBroker`, result outbox and authenticated
UDS. Trusted parent composition selects it with the `retrieval_profile` argument
of the existing service. Ordinary Factory startup does not enable it. It is
mutually exclusive with the separate payload151 profiles.

The separate `factory.ephemeral-retrieval162/v1` profile explicitly selects
automatic retirement of its owned derivatives at the original capture deadline.
The old manual profile does not gain automatic deletion from this change.
The ephemeral profile requires an actual `OwnedRetrievalReceiver` resource,
not a profile name supplied by a request. Start that receiver on an owned private
UDS, construct the existing client/service with the same explicit profile, and
call `receiver.attach(service, destination_id)` in trusted parent composition
before binding a native query. No network listener or cleanup worker starts in
ordinary Core/Factory startup. The existing selected server/service ticks own
the work; no permission service, queue or model is added.

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

## Revocation and explicit retirement

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

An authenticated current operator with `factory:access-admin` and the matching
tenant/project/repository scope can request earlier retirement through
`POST /v1/access/result-retirement` with the closed `envelope_digest`/`reason`
body. Reasons are `source_deleted`, `retention_expired` and `operator_retire`;
they record the requested reason, not a separate proof of an upstream event.
Source-read permission is not required to erase an already deleted source's
owned derivative. Unknown and foreign result locators have opaque outcomes.
The GET of that path plus the envelope digest only observes an existing result.

Migration030 retains original envelope/source/payload/request digests and replaces
the stored payload with the explicitly tagged `factory-retired-result/v1`
projection. That projection has its own digest; it never validates as the old
envelope. The existing outbox replaces resource lineage with dependency hashes
and owns the single retirement claim/outcome. Original grades and identities
remain immutable. A retired payload cannot be restored or dispatched. Retrieval
retirement/audit rows are retained; they cannot be pruned into an orphan source
record. This audit metadata is not represented as anonymous or erased.

The same registered UDS receives a fixed metadata-only retirement command. The
actual owned receiver clears its one payload and retains a tombstone before
acknowledgement. That tombstone rejects a delayed original handoff. Unarmed
startup denies data; arming checks the existing durable source tombstone even
after a fresh service/receiver restart. Missing DB, changed destination revision,
changed socket or an unsupported recipient cannot produce a deletion receipt.

`local_retired`, `ephemeral_retired` and `recipient` describe separate outcomes.
A lost COMMIT or reply remains unknown. An exact duplicate never renews the
original claim/deadline or reposts the mutation. A later authenticated read-only
observation can confirm an already performed retirement. Busy source operations
are fenced before their result can repopulate an owned cut; they remain pending
until they actually exit. Disposal never claims to erase already copied text.

## Explicit ephemeral lifetime

The actual attached receiver reserves one current task/run/fence/packet/attempt
before private reading. Its first wall-clock mapping and absolute monotonic
capture deadline are immutable and at most two seconds apart. Repeated handles
cannot extend that lifetime. Source/query/config/clock provenance survives into
the exact payload and existing outbox; admission does not grant a fresh TTL.
Future/invalid clock mappings deny admission. A rollback behind capture is a
deny/expiry condition, not permission to renew a cached result.

After a verified COMMIT, the existing service checks the exact stored profile,
original clock, binding and non-retired state before arming the actual receiver
and making its existing pending entry ready. The original 250ms queue window
does not change. A failure is unavailable, not an override. The receiver's own
existing server tick clears its payload and fixed broker/service memory holders
at the original monotonic due time, including when the service loop is paused.
Its `context` property checks expiry before returning owned bytes.

The existing service reconciles at most eight due rows per bounded tick through
the same outbox. This lifecycle authority comes only from the originally selected
ephemeral contract; it does not invent an operator session or store credentials.
Restart reads the original due time and cannot reconstruct a new lifetime.
The fixed receiver expires independently, so read-only observation can converge
an unknown retirement without reposting it. Due/clock validity and actual
database cleanup delay remain visible to the operator. Paused services, database
outages, scheduling and in-flight IO can delay persistent cleanup; these are
not hard real-time deletion guarantees or permission to disclose expired text.

This protocol covers only the bounded first-party holder/UDS profile. It does not erase
arbitrary provider caches, model memory or recipient copies. Full issue closure
still requires broader selected profiles, the independently sealed RU/EN/BGE-M3
experiment, dense evaluation and actual model usage/quality observations. Neither
source presence nor PostgreSQL/UDS tests establish those outcomes.

Disable the profile by omitting `retrieval_profile` in trusted composition.
Close/discard owned requests before replacement. Existing source-only and
payload151 profiles retain their own contracts. Migration030 is required for the
new retrieval retirement protocol; it does not alter historical migrations or
retroactively qualify an old unbound transport.
