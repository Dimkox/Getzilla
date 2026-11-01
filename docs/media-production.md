# Media production design

This is a vendor-neutral design and a reproducible offline planning example for [GH165](https://github.com/Dimkox/Getzilla/issues/165). The [ADR](../engineering/adr/0002-media-production.md) defines reuse, rights, budget, retry and publication boundaries. The [ADLC map](adlc-handoffs.md) connects it to existing workflow contracts.

## Run the source example

From a Getzilla source checkout or an extracted source archive:

```bash
python3 examples/media-design/dry_run.py --case both
python3 examples/media-design/dry_run.py --case both --benchmark 10
python3 -m unittest tests.test_media_design
```

An absolute path to the script also works from an unrelated directory. The command accepts only promo, webinar or both and an optional benchmark count from 1 to 20. It reads its own fixed schema/fixtures and prints JSON to stdout. It has no arbitrary file/URL input, output-writing option, provider call, subprocess, inference, renderer or native state mutation.

File admission requires no-follow and nonblocking open primitives. A platform without either returns status 2 and a fixed capability message before opening an input; no plan is emitted. This is also the contract for native Windows, whose execution is not claimed here. The [example README](../examples/media-design/README.md) explains the FIFO replacement check and why it does not guarantee a hard deadline for arbitrary filesystem calls.

These files are source-archive content. The explicit consumer installer inventory does not install the example or register a media command. No VERSION, release state, Core schema inventory, dependency or client mirror changes are needed.

## Two neutral synthetic cases

| Case | Segments | Main seconds | Main frames at 30/1 fps | Asset slots | DAG nodes / edges |
|---|---:|---:|---:|---:|---:|
| Promo | 9 | 92 | 2760 | 3 | 45 / 113 |
| Webinar | 50 | 2730 | 81900 | 5 | 170 / 527 |

Text and asset labels are newly authored geometric placeholders. The promo timing is 8 seconds, seven 10-second segments and 14 seconds. The webinar uses forty-nine 54-second segments and an 84-second segment. These are synthetic arrangements, not a transcription of the private brief. No asset binary, narration audio or output file exists.

| Family | Dimensions | Promo duration/count | Webinar duration/count | Audio and subtitles |
|---|---|---|---|---|
| Main | 1920×1080 | 92 s × 1 | 2730 s × 1 | Proposed stereo AAC, sidecar |
| Muted | 1920×1080 | 92 s × 1 | 2730 s × 1 | No audio stream, burn-in |
| Vertical | 1080×1920 | 60 s × 1 | 45 s × 2 | Proposed stereo AAC, burn-in |
| Square | 1080×1080 | 15 s × 1 | 60 s × 2 | Proposed stereo AAC, burn-in |

These are planned families. Derivative edit lists are empty and need editorial decisions. No family count is a delivered export count. A future full delivery package may also need a mezzanine/master, podcast and cover, thumbnails, caption files and editable source with licensed inputs. Those profiles need explicit scope and real outputs; the four-family example does not claim to validate them.

## Contract and gates

The [closed public schema](../examples/media-design/media-plan-v1.schema.json) is deliberately restricted to the existing Core/test-validator intersection. The historical private prototype used a different full Draft202012 schema; its private schema, hashes and results remain unchanged.

Both cases use exact integer frame intervals and 30/1 fps. Semantic numbers, caps and counts are integers. Execution and network remain false; paid-call and micro-USD caps remain integer zero. Provider/model, approval evidence, binary asset hashes and produced-media hashes remain null. All graph nodes stay planned_not_run.

Seven future gates remain not_requested: scope, rights, paid action, identity/brand, storyboard/timing, final and publication. Their owner roles and effect stop conditions are specified in the ADR. The graph checks required gate dependencies, not just cycles and hashes. Source/identity changes invalidate all planning keys; they do not create new authority.

The public command can retain unresolved inputs while designing. Actual paid preparation needs current source/rights/budget permission. Actual rendering needs approved identity/storyboard and measured timing. Publication needs QA, final acceptance and current destination-specific authority for the exact outputs.

## Measured planning benchmark

A Linux Python 3.12.14 run on 2026-11-01 compiled both fixed cases ten times through the promoted path: bounded JSON read, schema validation, source/timeline/profile checks, graph construction and graph validation. Median pair time was **51.181399 ms**; nearest-rank p95 was **57.004393 ms**. The ten measured samples, in milliseconds, were:

```text
52.732200 52.410160 51.037592 48.986719 50.426971
48.244695 47.294734 57.004393 53.150056 51.325206
```

The even-count median is the integer nanosecond midpoint; p95 is sample ceil(0.95×n) in sorted order. The measurement covers ten repeated pair compilations after interpreter/import startup, with no cache reset or cold-start guarantee. RSS is unmeasured. Timing, Python/platform details and samples are outside semantic hashes.

The measured compiler SHA-256 was `c1df2b6aa385c96bce5b3b700cc2f09a1fe40c11843e405ed17596f99a4a2fa6`. The schema SHA-256 was `d252473380a6254aad24d728207d2b5491a0efe0ed50b42db12e8040d1bc98ba`. This binds the observation if later source changes. Full raw output and source hashes remain qualification evidence.

This measures synthetic planning only. It gives no render speed, visual QA, provider reliability, accepted-media throughput or production-cost forecast. The separate private-case measurement retains its original source and time; it is not relabelled as this public benchmark.

## Illustrative cost, not a quote or permission

Use integer micro-USD and explicit hypothetical units. Let n be prepared segments and s be nominal timeline seconds:

```text
known scenario subtotal = n × 20,000 + s × 300 + s × 100 micro-USD
```

The three invented rates represent preparation per segment, voice per nominal second and assembly per nominal output second. They are arithmetic assumptions, not vendor prices, actual compute measurements or an approved cap.

| Component | Assumed rate | Promo quantity / micro-USD | Webinar quantity / micro-USD |
|---|---:|---:|---:|
| Preparation | 20,000 / segment | 9 / 180,000 | 50 / 1,000,000 |
| Voice | 300 / nominal second | 92 / 27,600 | 2730 / 819,000 |
| Assembly | 100 / nominal output second | 92 / 9,200 | 2730 / 273,000 |
| Known illustrative subtotal | — | 216,800 | 2,092,000 |
| Licenses, human work, storage, egress, retries and actual unit differences | unknown | unknown | unknown |
| Full expected production cost | — | unknown | unknown |

Unknown components are not zero. Actual future pricing must bind provider/model, rate version/date, units, rounding and currency; a reservation differs from a charge. The offline run made zero media-provider calls and incurred zero observed media-provider charges. Analyst/model/hardware/electricity/human costs were not measured. The valid example still permits no paid action.

## Phased delivery and stop conditions

| Phase | Deliverable | Required evidence and owner | Boundary |
|---|---|---|---|
| Current: design and pure example | ADLC map, ADR, restricted case crosswalk, public schema/fixtures/DAG, deterministic no-paid checks, benchmark/cost assumptions | Selected writer; independent code/security design review; normal exact-source checks | No real media, paid effect or creative acceptance |
| Optional module mapping | Explicit mapping to existing task/criteria/lease/reservation/result contracts | GH166 lifecycle, GH158 provenance; selected integration owner; disabled-mode no-effect controls | No second scheduler, identity or ledger |
| Offline renderer proof | Tiny synthetic source assets, pinned renderer/probe, bounded owned processes and immutable outputs | Real metadata/decode/crop/subtitle checks, timeout/output/disk limits and owned cancellation cleanup | Separate implementation scope; no paid provider |
| One provider qualification | Capability/estimate/submit/query/cancel/reconcile/collect using existing intents and budgets | Exact rights/recipient/model/quote/cap; before/after-ack failures, duplicate delivery, stale fences, revocation and unknown outcomes | Separate current paid authority; no blind retry |
| Creative production | Verified licensed binaries, resolved source conflicts, measured narration, approved storyboard/cuts | Brief, rights and creative owners; actual output QA and acceptance | No fictitious consent or approved unrendered file |
| Distribution and feedback | Exact approved files to permitted audience, receipt/accept/reject/retention/cost evidence | Current publication authority; GH152/GH162/GH200; accepted-task denominator explicit | Source access does not imply publication permission |

GH164 stays excluded Future. If a later adapter requires durability that existing qualified contracts cannot provide, stop that later effect and scope its dependency; do not silently build the excluded engine.

## Evidence and limitations

Ordinary discovered tests exercise both formats, scalar confusion, fake approval/output evidence, duplicate/unknown references, frame/profile failures, strict parsing/bounds, deterministic identity and required gate removal after hashes are recomputed. They run the fixed CLI from an unrelated directory and observe no planning write/network/process effects. Explicit lint/static scans are needed because the repository's default scan exclusions include examples.

The restricted case study supplies actual-brief audit, unresolved contradictions, source-backed manifests and its original dry-run evidence. The public example supplies independent neutral reproduction and current contract checks. Both sets need review before claiming the complete GH165 design acceptance. Neither set proves real media quality, licenses, provider cancellation/refunds or creative approval.
