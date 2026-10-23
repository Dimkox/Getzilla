# Independent source/qrel review

PASS for the sealed source/qrel gate. No label changes required.

- Both corpora have 4 exact, 4 behavior, 4 boundary, 4 multi-function and 4 no-answer queries.
- Validated all 22 unique small and 15 unique large positive labels against actual AST functions, registry records, file hashes and span hashes.
- All positive labels point to implementations. None points to an overload stub.
- All source/support manifest hashes and recorded Git blob IDs match. Candidate inventories contain exactly 8 and 140 regular Python files. Separate documents and supporting tests are excluded from candidates.
- Inspected every labeled implementation. The behavior, boundary and multi-function labels fit their queries.
- No-answer controls fit the closed inventories. Small source has no PostgreSQL revocation, AES encryption, HTTP middleware or cloud key-refresh worker. Large source has no native BM25, cross-encoder endpoint or jscpd adapter. Graph generation has no tenant-isolation field.
- The three supplied qrel/config SHA-256 values match.

Limits: Large judgments cover graph and ingestion code within the larger inventory. They do not measure broad repository coverage. Multi-function recall measures registered evidence, not complete call-chain recovery. Other hits remain unjudged. No-answer controls cannot establish semantic abstention without a calibrated rejection rule.

Validation command: `python3 .getzilla/runtime/scratch/issue162-qrel-audit.py` — exit 0. The audit script is outside the research candidate. No candidate files changed. No source code or model rankings executed.

Bindings: small qrels `ae77c4d1f73f1743531ff1359878de0ddf12b3c30d82efa040ee037e77f5fb31`; large qrels `3844fe8fd64495478c91a9f98db3f52c11c722c615ac99375ede23959a267ecd`; config `94d5a64c26348608037772569c0a2fd794d3db47f27d8594e3df1d379935e6d4`.
