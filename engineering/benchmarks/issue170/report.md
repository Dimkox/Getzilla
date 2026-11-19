# Issue 170: real isolated benchmark

The benchmark succeeded on itsdangerous 2.2.0. Zero-Git adoption, graph export, both clone scans and a true local ONNX index ran. The upstream suite passed **297 tests**. The adopted candidate fast verifier passed after installing a missing test dependency. No refactor or Getzilla product change was made.

Inputs: upstream commit `096c8d42545d3b68ea21a4f890fb2b2d8979c0bd`; Getzilla **2.3.1**, commit `8352756ccddbb7b9f13da2da689ef633d968e30f`; MiniLM model revision `1110a243fdf4706b3f48f1d95db1a4f5529b4d41`. See `artifacts/input-pins.json` for URLs, sizes and SHA-256 hashes. The upstream BSD-3-Clause license is preserved in the source archive. The model repository declares Apache-2.0. No remote model code was loaded.

The 60-file original remained unchanged. The eligible scope has **14 Python files, 1,681 physical lines and 116 AST function declarations**: 62 in production code and 54 in tests. Nine declarations are `@overload` signatures. There are 107 non-overload declarations, including nested functions. These counts do not include installed Core code. The empty test package file is eligible but has no tokens. jscpd reports 13 nonempty sources and 1,668 lexer lines; that is a different line convention.

Core plan and apply exited 0. Adoption created two local commits, with no remote. The original baseline is `c51f4f1f95afb2408cff5c23ac8fb53e4151869b`. The managed commit is `81eadf1d28792d79e49c0c538080ba5b9c8799e9`. All **710 expected payload files** match their pinned installer bytes and executable modes. The only additional non-source file outside that payload is `.getzilla/source-baseline.json`. The adopted tree has 771 regular non-Git files before verification. The installer returned `integrity_status=verified` and `project_health_status=not_run`. It installed the actual full managed payload; this was not a minimal-component install.

The separate candidate fast verifier passed with `--no-record`. It wrote its runtime JSON in the disposable candidate. It had no active route and no comparison base. It is **not a PR gate or merge receipt**. The first run failed because `freezegun` was missing. The owned tool image then added upstream-pinned freezegun 1.4.0, python-dateutil 2.9.0.post0 and six 1.16.0. Both the original-source suite and the candidate verifier passed on retry. Candidate test imports used candidate/src on retry. The original first-run failures remain in the evidence.

Getzilla graph parsed 15 Python files, including docs/conf.py outside the eligible scan scope. It exported **136 symbols: 107 functions and 29 classes**, plus 379 calls and 132 imports. Its whole-source coverage is incomplete: 250 calls and 73 imports remain unresolved, and non-Python files are not covered. Three overloaded identities collapse to one graph symbol each. For example, TimestampSigner.unsign points at its first overload span, not its runtime body. The AST supplement keeps every declaration with file, range, signature, decorators and source hash. See graph-summary.json for exact collapsed groups.

| Text scan | Raw clone pairs | Within file | Across files | Raw span clusters | Raw line % | Raw token % |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| minLines 10 | 4 | 4 | 0 | 3 | 2.52 | 4.34 |
| minLines 5 | 5 | 5 | 0 | 4 | 3.06 | 5.37 |

Both runs used jscpd 4.0.5, Python lexer, mild mode and minTokens 50. Both scanned only original src/tests. Zero cross-file pairs is an observed result. The raw reports contain reversed end ranges (2 at minLines 10; 2 at minLines 5) and per-pair tokens=0. The reports remain unchanged. Clusters connect exact raw file/start/end labels, including malformed ones; they are **not validated semantic duplicate groups**. The minLines 10 fragments repeat serializer overload signature scaffolding. Do not use the raw reversed ranges for edits.

The local index uses ONNX Runtime 1.23.2, tokenizers 0.22.1 and NumPy 2.2.6. It uses CPUExecutionProvider, one intra-op thread, one inter-op thread, batch size 16, max sequence 256, attention-mask mean pooling and L2 normalization. All 116 vectors are finite and have 384 dimensions and unit norm within tolerance. There are 6,670 canonical non-self pairs and ten deterministic cosine neighbors per declaration. Raw float32 cosine can exceed 1 by rounding (maximum observed 1.000000119); display values round to six decimals. A cosine is not a duplicate probability.

Correct token counts: **12,619** before truncation; **11,566** after truncation; **7** truncated declarations. Counts include tokenizer special tokens and exclude padding. The tokenizer JSON had pre-enabled padding/truncation. The initial measurement therefore miscounted tokens and falsely showed zero truncation. The corrected run first disables those settings. Initial index files are retained as `initial-*` and are superseded. Corrected vectors reproduce the initial ranking.

Source checks of the top 20 found **one confirmed identical getter pair, 11 overload false positives and eight related but distinct pairs**. The getter pair returns the newest secret key in two public classes. It has no external effect. Its tiny size does not justify a refactor. Distinct timestamp validation, fixture roles and error contracts explain the other runtime candidates. The low-score control pairs base64 decoding with UTC timestamp conversion (cosine 0.036764); their types, dependencies and error contracts differ. `candidate-assessment.md` and its JSON give all 20 decisions, source ranges, signatures, calls and related tests. These are bounded source reviews, not a proof of equivalence or global recall.

Local scan/index external LLM calls and tokens are **0**. Local encoder token counts are above. Overall orchestration and candidate-review LLM token use is **null**, because it was not measured.

| Stage | Exit | Wall s | CPU s | Peak RSS MiB | Retained stage log bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| core-plan | 0 | 0.265 | 0.21 | 21.2 | 16871 |
| core-apply | 0 | 3.725 | 3.69 | 38.3 | 2077 |
| candidate-verify | 1 | 8.588 | 2.29 | 46.6 | 11585 |
| graph-build | 0 | 0.518 | 0.26 | 24.0 | 2837 |
| upstream-tests | 2 | 1.068 | 1.01 | 46.8 | 2493 |
| jscpd-10 | 0 | 1.218 | 1.68 | 112.4 | 1640 |
| jscpd-5 | 0 | 1.218 | 1.66 | 113.8 | 1801 |
| index | 0 | 12.302 | 12.20 | 471.3 | 1914 |
| graph-export | 0 | 0.215 | 0.19 | 23.4 | 247314 |
| index-corrected | 0 | 11.999 | 11.85 | 448.8 | 2060 |
| upstream-tests-final | 0 | 1.719 | 1.67 | 43.7 | 1182 |
| candidate-verify-final | 0 | 2.922 | 2.85 | 43.8 | 10271 |

Wall time uses a monotonic clock. CPU time is GNU time user+system. Peak RSS is the stage process accounting reported by GNU time; it is not whole-host or image-build peak memory. Independent graph, clone scans, index and original tests overlapped. Do not add their wall times to estimate elapsed time. Full metrics and exact argv are in metrics-derived.json and raw *.time files. Disk sizes are retained logical file bytes in disk-sizes.json. Per-stage log bytes exclude shared index/candidate products. No peak temporary disk figure was measured.

Preparation had 276 GiB free space and a mode-0700 experiment root. Immutable source/model downloads and registry/package downloads succeeded. BuildKit showed apt 114.6 s, pip 65.4 s, npm 18.5 s and image export/unpack 79.9 s. Overall initial setup wall time and peak RSS were not captured and remain null. The test-dependency build has separate raw logs and GNU time metrics. Image identities, all wheel hashes, installed package versions and npm lock integrity hashes are retained. The base Python image is pinned by digest in Dockerfile.

The host startup measured 26 effective CPUs. The Docker daemon rejected quota 24 with exit 125 because it reported 22 available CPUs. That failure is retained. The successful container independently reported affinity/cpuset 0-19, cpu.max=2000000/100000 (20 CPUs) and memory.max=4 GiB. The container had no network, dropped all capabilities, had no-new-privileges, and ran as the host user's numeric UID. Original source, pinned Core and model mounts were read-only. Only owned work/artifact paths were writable. No host home, credential, Docker socket or production mount was given to project execution.

For issue 162: retain source-span provenance; distinguish overload declarations from implementations before ranking; expose incomplete graph coverage; validate clone tool ranges before consuming them; log model/tokenizer/tool revisions and real truncation; require contract/test review before any refactor. This small benchmark does not establish a universal similarity threshold, precision or recall.

Reproduce in a fresh owned experiment directory: run prepare.py; run test_inputs.py; build Dockerfile with tag getzilla-issue170:20261023; run launch.py; build Dockerfile.tests (assert the local base identity, or update that assertion only for a deliberately rebuilt tool image); run launch_followup.py; run summarize.py and assess.py. Dependencies are in the Dockerfiles, the exact resolved wheel hashes and npm package-lock are in artifacts. Downloads require network; all project stages run with network=none. The first setup intentionally lacks freezegun and records its failure before the declared dependency repair. Do not rerun adoption against its existing target. The candidate Git bundle preserves both actual commits for inspection.

No product rollout occurred. Rollback is deletion of experiment-owned targets and caches only. Independent review passed the repaired bundle at reviewed manifest SHA-256 `2691718b629fe348f99514006f71a950cbc152da840cfc8f0e819a4a47b736ba`. Cleanup then removed the owned work, model, Core, downloads and original directories, plus both exact owned image tags. Post-cleanup checks found all five directories and both image tags absent. The complete review, reviewed manifest snapshot and cleanup log remain in the publication bundle. The cleanup script validated ownership, retained artifact hashes and exact paths before deletion. It never prunes shared Docker or package caches. Docker build-cache layers may remain in the shared daemon because shared pruning is out of scope. The publication bundle retains source/license, reproducible scripts, raw evidence, index and candidate bundle. The coordinator handles the unmerged evidence branch and issue links. No merge, CI integration or external source upload is part of this run.
