# ADR 0002: Declarative media design on existing control contracts

**Status:** design decision with a bounded offline example.

**Related:** [GH165](https://github.com/Dimkox/Getzilla/issues/165), [ADLC handoffs](../../docs/adlc-handoffs.md).

**Availability:** source checkout/archive; no installed consumer command or active module.

## Context and decision

The design must describe a nine-scene 92-second promo and a fifty-slide 2730-second webinar, their assets, timelines, output families and human decisions before any paid work. A supplied private brief has conflicting requirements and lacks verified asset binaries, licenses and consents. Its detailed audit, source revisions, full manifests and historical measurements remain restricted evidence.

Use a versioned declarative manifest and dependency graph with a pure offline compiler. Bind source revision, semantic asset slots, exact integer-frame intervals, profiles and seven future owner gates. Keep execution disabled and every node planned_not_run. Do not add a mandatory dependency, another orchestrator, a durable job engine, provider integration or renderer. GH164 remains excluded Future.

The new public examples contain freshly authored neutral content. They preserve only the two scenario sizes and use explicitly synthetic timing and derivative choices. Their schema and hashes have new identities; they do not replace the restricted source-bound prototype.

## Existing contracts to reuse later

The [ADLC audit](../../docs/adlc-handoffs.md) pins the source evidence and its 68-file unchanged comparison. The following are integration seams, not evidence that media execution is already connected.

| Concern | Existing seam | Required later mapping |
|---|---|---|
| Requirements and source | Typed change specification, provenance and existing decisions | Bind selected source/criteria/conflict decisions and immutable asset identity |
| Decomposition | Core workflow source/task/convergence graphs | Map media nodes to existing task/criterion contracts explicitly |
| Execution ownership | Factory task/run/lease fence and execution/result contracts | Recheck current owner, scope and fence before each effect |
| Submission and recovery | Existing intent, outbox, reconciliation and result paths | Persist intent before submit; reconcile unknown outcomes before retry |
| Budget and usage | Existing reservation and usage observations | Aggregate caps across attempts/providers; estimates are not permissions or charges |
| Collection/publication | Scoped external action, source/rights and audience checks | Bind exact output, destination, recipient, expiry and revocation at the effect |
| Optional lifecycle | GH166 | Disabled means no provider import, credential lookup, background process or network |

Local human-gate flags are workflow evidence. The eventual execution adapter must consume current scoped authority; setting a flag is insufficient.

## Alternatives

| Alternative | Benefit | Reason for decision |
|---|---|---|
| One-off vendor script | Low initial effort | Reject as the system contract: weak revision, permission and cost trace |
| New workflow service/queue | Independent scheduling | Reject: duplicates existing authority and expands excluded Future scope |
| Single prompt for a whole video | Little segmentation | Do not use as the default: weak exact text, timing and identity control |
| Declarative plan with later optional adapters | Reproducible planning, explicit uncertainty and reuse | Select; actual rendering/providers still need separate qualification |

## Public contract

[media-plan-v1.schema.json](../../examples/media-design/media-plan-v1.schema.json) has its own identifier, `urn:getzilla:example:media-design-plan:v1`. It uses the intersection supported by Core's pure validator and the independent test subset validator. Objects are closed, constants/enums have explicit scalar types, and semantic numbers are integers. Rational fps is 30/1. No remote schema lookup or new validation dependency is used.

The input records source kind/revision/content digest; ordered segments; unresolved asset slots; main/muted/vertical/square families; seven not_requested gates with owner roles; fixed ceilings; and zero paid/network/execution settings. Provider/model, approval evidence, binary asset digests and produced-media digests must remain null.

Validation covers exact segment order and contiguous frame coverage, asset identities/references, transition handles, supported dimensions and audio/subtitle combinations. Main and muted output families cover the full timeline. Derivative families have no approved edit list. A count greater than one represents a family awaiting per-item editorial choices; it does not represent produced exports.

The fixed ceilings are 1 MiB per JSON input/plan, depth 16, 60 segments, 64 assets, 24 families, 500 nodes and 4000 edges. Input cannot raise them. Reads are bounded and regular-file-only. Strict parsing rejects duplicate keys, nonfinite/floating semantic values and non-NFC strings.

File opens require `O_NOFOLLOW` and `O_NONBLOCK` before descriptor type/identity checks. Missing primitives cause an explicit capability refusal; there is no blocking fallback. This prevents a FIFO replacement from waiting for a writer, but does not provide a hard timeout for arbitrary filesystem calls. The example closes a descriptor on refusal even if creation of its buffered stream fails.

## Planning identity and dependencies

Canonical bytes are ASCII JSON with sorted object keys, compact separators, finite integer numbers and one final newline. Ordered segments retain order; unordered asset/dependency inventories have a required order and reject duplicates.

The hash direction is semantic inputs → node planning keys → graph digest:

1. Input digest uses domain `media-input.v1` and includes all semantic input plus the canonical schema digest. It excludes the derived graph and measurements.
2. Node key uses domain `media-node.v1` and binds full input digest, node ID/kind, sorted dependency IDs and input references.
3. Graph digest uses domain `media-graph.v1` and binds complete nodes/keys, edges and topological order, excluding its own digest.

Each domain is ASCII followed by a NUL byte and canonical payload bytes. Any semantic input change conservatively invalidates every node key. Keys prove deterministic planning, not provider idempotency, authority or a lease.

The graph includes source; scope/rights/paid-action gates; asset/voice preparation; identity/brand; layouts; storyboard/timing; segments; assembly; output families; technical QA; final and publication gates. Validation recomputes the expected graph and checks semantic dependencies before digest errors. Acyclicity alone is insufficient. Removing a gate dependency, changing a node kind or changing an input reference fails even when all hashes are recomputed.

## Seven future owner gates

| Gate | Owner role | Evidence required before an actual effect | Stop condition |
|---|---|---|---|
| Scope | Brief owner | Exact source revision, contradiction decisions, script/cuts/output set | Changed source or unresolved required choice |
| Rights | Rights owner | Asset binary hashes, licenses, likeness/voice consent, destinations and expiry | Missing, expired, revoked or mismatched rights |
| Paid action | Budget owner | Provider/model/version, permitted recipient, current quote, units, finite cap/retries | No current authority, unknown quote/outcome or exhausted cap |
| Identity/brand | Creative owner | Exact images/logos/fonts and approved reference comparison | Unapproved likeness, altered identity or absent files |
| Storyboard/timing | Creative owner | Per-ratio previews, measured voice, text/QR bounds and edit lists | Unmeasured narration, crop loss, conflict or invalid timing |
| Final | Creative owner | Exact exports and measured technical QA | Missing/failed QA or changed output |
| Publication | Publication owner | Exact files, audience, target, timing/retention and current action scope | Target/audience mismatch or revoked permission |

All public-example gates remain not_requested. Owner roles do not identify authenticated people. These future production decisions do not block the already authorized design-only work.

## Later adapter semantics

Proposed capability/estimate/submit/query/cancel/reconcile/collect operations must map into existing Factory contracts. Capability records need supported formats, input limits, lookup/idempotency, cancellation/billing, retention and versioned pricing. Unsupported requirements fail before reservation.

Persist scoped intent and reservation before submission. Record the provider job/call identifier on acknowledgement. A timeout after possible submission is an unknown outcome; reconcile by qualified identifier before another charged call. If lookup cannot settle the outcome, stop affected work instead of retrying blindly.

Bound attempts, paid units, elapsed time, polling, transfers and temporary output. Source/model/template changes create a new plan revision without resetting the logical task budget. Resume rechecks source, rights, cancellation, grant currency and lease fence. A cancellation request proves neither cancellation nor refund; reconcile outstanding outcomes and charges.

None of these live operations is implemented by this example. It starts no job, claims no descendant-only resume and creates no native authority or second ledger.

## Media QA, privacy and consequences

Later rendering needs measured voice duration, per-ratio text/layout/crop regions, explicit subtitle cue lineage and transition handles inside the nominal timeline. Metadata cannot establish media quality. Pinned bounded local decoding/probing must verify codec, dimensions, fps/timebase, duration, streams, audio absence for muted output, loudness/color and decode integrity. Human review assesses pacing, identity, semantic accuracy and brand fidelity.

Private source text, document/paragraph IDs, catalogue details, contacts and brand decisions stay outside public fixtures, logs and exception reports. Source read access does not authorize sending assets or finished media to another audience. A later collection/publication effect rechecks both action and recipient permission.

The design makes blockers and dependencies inspectable without expenditure. Its cost is a later explicit integration and qualification step. [The delivery plan](../../docs/media-production.md) separates current planning evidence from that future work. Rollback is a reviewed corrective PR or revert of the source example/docs; no paid job, installed runtime or user media artifact exists to migrate or delete.
