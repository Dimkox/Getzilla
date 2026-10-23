# Fixed source retrieval experiment, issue 162

The experiment ran actual local embeddings and all four fixed retrieval arms. It changes no installed product source. The tables describe recall against registered qrels only. They do not establish universal retrieval recall or broad superiority.

## Inputs and gate

Small: itsdangerous 2.2.0 at `096c8d42545d3b68ea21a4f890fb2b2d8979c0bd`, eight Python source files. Large: Getzilla at `8352756ccddbb7b9f13da2da689ef633d968e30f`, 140 approved Python runtime/script files. This is a bounded source scope inside the large repository. It is not whole-repository coverage. Separate documentation, tests, packages, fixtures and generated mirrors are not candidates. Source docstrings remain code bytes. Tests are retained separately for source review.

Each corpus has 16 positive questions: four exact-symbol, four behavior, four boundary and four multi-function questions. Four no-answer controls are separate. The selected independent repo explorer checked source spans, hashes, identities and non-overload labels before any ranking. `data/seal.json` binds the unchanged manifest, query, qrel and config bytes. Large questions concentrate on graph and ingestion behavior. Other retrieved hits remain unjudged.

## Registered-qrel quality

| Corpus | Arm | Function R@1 | R@5 | R@10 | R@20 | MRR@10 | Budget 2048 recall | Budget 8192 recall |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| small | exact_symbol | 0.250 | 0.250 | 0.250 | 0.250 | 0.250 | 0.250 | 0.250 |
| small | bm25 | 0.172 | 0.646 | 0.745 | 0.844 | 0.495 | 0.729 | 0.906 |
| small | semantic | 0.208 | 0.714 | 0.875 | 0.906 | 0.519 | 0.812 | 0.938 |
| small | rrf | 0.344 | 0.823 | 0.844 | 0.875 | 0.608 | 0.844 | 0.984 |
| large | exact_symbol | 0.250 | 0.250 | 0.250 | 0.250 | 0.250 | 0.250 | 0.250 |
| large | bm25 | 0.219 | 0.594 | 0.656 | 0.708 | 0.414 | 0.635 | 0.771 |
| large | semantic | 0.167 | 0.490 | 0.635 | 0.635 | 0.408 | 0.490 | 0.823 |
| large | rrf | 0.385 | 0.656 | 0.688 | 0.781 | 0.615 | 0.688 | 0.781 |

`results/summary.csv` includes file recall and query-class slices. `per-query.csv`, `paired-differences.csv` and the full result JSON preserve each question, failure and top-100 list. A function counts once even if several windows occur. File metrics deduplicate paths. Budget recall means that at least one window from a registered function fit in the packed context. It does not prove that the complete answer or all relevant lines fit. Overlap lines are included once. Citation headers, included line labels, separators and source text count toward the pinned o200k_base context proxy. These counts are not measured LLM billing. Encoder token counts are separate.

## Runtime and storage

| Corpus | Functions | Windows | Truncated windows | Model load s | Index build s | Peak RSS KiB | Semantic warm p50 ms | Semantic warm p95 ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| small | 55 | 64 | 0 | 0.310 | 7.142 | 819236 | 8.762 | 10.468 |
| large | 2194 | 3820 | 0 | 0.313 | 406.915 | 868224 | 13.043 | 15.155 |

Three fresh-process model loads took 0.271, 0.309, 0.281 seconds. These are process-cold, not guaranteed cold OS page-cache loads. Warm timing uses ten passes over all questions. Query embedding time is included in semantic and RRF end-to-end figures. Ranking-only and query-embedding figures remain separate in timing JSON. BM25 and symbol latency do not include an unnecessary model call. Peak RSS covers the process, including later parity checks; it is not a baseline-subtracted allocation.

Measured bytes: model assets 91,114,788; codec cache 3,613,922; source view 2,334,487; duplicate Gitless view 2,334,487; result artifacts 16,083,830. The full ONNX model is 90,405,214 bytes, verified against its pinned SHA256. Source-window vectors are stored as float32. Package versions, image identity and exact commands are retained. The image dependency installation pins the four direct packages; transitive versions are captured in `execution/packages.stdout` but not individually resolver-locked. Image bytes are identified by digest. The compact publication excludes models, tool caches, duplicate source trees and vectors.

## Controls and limits

The experimental trusted reader passed stale-file, deleted-file, rename, forged-range, chunk-hash, tenant, repository, path-filter, traversal and symlink controls. The first characterization run failed because the reader module did not exist. The later run passed twelve tests. The reader operates on read-only offline source mounts. It is not a production sandbox and does not claim protection from hostile concurrent replacement of parent directories.

Every stored chunk was read again with its file hash, range and chunk hash. Direct pinned Git-object bytes, raw/copied source bytes and the independent Gitless view match. Re-encoding the Gitless view produced identical rankings. The inference containers had no Git dependency or Git ancestor. Declared upstream commits remain provenance; copied-byte manifests establish snapshot identity.

No-answer controls report candidate return counts and raw scores separately in full result JSON. Semantic ranking always returns candidates. No calibrated abstention threshold was fitted. These controls do not prove that retrieval can decide answerability. Pinned large-corpus absence judgments remain valid at 8352756 even if later product work adds a jscpd adapter.

Quality comes from one deterministic ranking. Ten warm repetitions measure timing only. Parameters and qrels were not tuned after ranking. The corpus is Python only. AST function chunks omit standalone module/class-only content from ranked candidates. Nested functions may overlap outer bodies. The English generic MiniLM model was not trained here for code. Line windows can separate useful evidence. Unjudged hits are not known false positives. The small curated set does not support statistical or cross-language claims.

Offline inference used two one-CPU containers at most, one ORT thread each, a read-only root, dropped capabilities, no-new-privileges, bounded memory and processes, and no network. Network preparation downloaded only fixed model/tool/source assets. No source was uploaded. External scan/index LLM calls and tokens: zero. Orchestration model usage: unmeasured (`null`).

## Decision and next step

Keep exact symbols and BM25 as cheap explicit components. Treat local embeddings and RRF as optional candidates for a later prototype. Assess the paired per-query evidence before selecting defaults. Preserve component ranks and exact citation bytes. Expand blind labels across more tasks and repositories before any general claim. `design.md` records the contract, lifecycle, tradeoffs, future implementation steps and rollback. No product PR, merge, release or production operation is part of this research contour.

Timing notes: semantic and RRF end-to-end fields sum the measured embedding and required component intervals. `all_arms_end_to_end_ms` records the full measured wall interval. The warm passes use a fixed arm order on a shared host with other bounded work. CPU quota is one per container; CPU affinity is not pinned to a private core. Treat these latency values as observations for this environment. Recall@k takes the first k distinct functions or files after window ranking, within the retained top-100 window list. No confidence interval or broad significance claim is made.

References: https://www.dobryakov.com/howto/book-as-context.html and https://www.dobryakov.com/howto/hybrid-search.html motivated source provenance and complementary signals. They are not evidence that this model or these fusion weights work best for code. No book corpus was downloaded or indexed.
Five separate metric controls passed for recall arithmetic, context-window deduplication, hard budgets, exact symbol matching and identifier tokenization. A directory-as-file negative control is included in the twelve reader tests.

Candidate-kind limit: the extractor excludes decorated overload stubs, but retains other AST functions, including the small corpus protocol declarations `_PDataSerializer.loads` and `_PDataSerializer.dumps`. Thus function counts mean non-overload AST candidates, not exclusively executable implementations. Positive qrels point only to implementations. The retained declarations were not removed after ranking. A later experiment should preregister a separate declaration category.

Exact source counts: small: 8 files, 1,199 physical lines, 42,346 bytes, 62 AST function declarations, 7 decorated overload stubs, 64 windows; large: 140 files, 52,123 physical lines, 2,292,141 bytes, 2194 AST function declarations, 0 decorated overload stubs, 3820 windows.

