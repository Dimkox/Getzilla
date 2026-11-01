# Offline media design example

This source-only example compiles two newly authored neutral fixtures into bounded non-executable plans. It contains no private brief, narration, catalogue, contact or brand data.

```bash
python3 examples/media-design/dry_run.py --case both
python3 examples/media-design/dry_run.py --case promo --benchmark 10
python3 -m unittest tests.test_media_design
```

Run from a source checkout/archive, or pass the script's absolute path from another directory. The consumer installer does not install this example. Use only the built-in promo/webinar/both selector; there is no arbitrary input/URL/output path. JSON goes to stdout. Benchmark count is limited to 1–20 and always measures both cases.

- `promo.json`: nine synthetic segments, 92 seconds, 2760 frames.
- `webinar.json`: fifty synthetic segments, 2730 seconds, 81,900 frames.
- `media-plan-v1.schema.json`: separate versioned public plan contract.
- `dry_run.py`: standard-library planning plus existing pure Core schema validation.

The schema uses the intersection exercised by Core and the independent test subset validator. Every constant/enum has an explicit type. Counts, frames and money are integers; fps is the rational pair 30/1. The private full Draft202012 prototype has a different identity and is not this example's dependency.

The command reads bounded regular fixed files, rejects duplicate JSON keys, floats/nonfinite values, non-NFC text and excess depth/size. It checks asset/gate identity, contiguous timelines, transition handles, dimensions, audio/subtitles, graph closure/cycles and exact required dependency semantics. Input cannot raise the fixed ceilings.

Canonical bytes are sorted compact ASCII JSON plus one newline. Versioned input/node/graph hash domains have a noncircular dependency order. All keys change conservatively when semantic input changes. Benchmark fields stay outside those hashes.

Every node is planned_not_run. Execution/network flags are false, paid caps are zero, all seven owner gates are not_requested, and approval/binary/output digests remain null. Derivative counts describe families awaiting edit lists, not exports. No renderer, provider, network, subprocess, native state or output file is created.

See the [design, measured benchmark and illustrative cost](../../docs/media-production.md), [ADR](../../engineering/adr/0002-media-production.md) and [ADLC map](../../docs/adlc-handoffs.md). Real assets, rights, creative decisions, technical QA, paid approval and publication remain later evidence.
