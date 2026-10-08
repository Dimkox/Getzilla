# Independent test-review supplement: license whitespace normalization

Date: 2026-10-07 UTC. Route `b1693e9cb114`; change `20261007-task-b1693e`. Reviewer: independent route-selected `test_reviewer`.

## Verdict

**PASS for this narrow affected review.** The distributed Onest license differs from the original by exactly one trailing ASCII space at line 21. Every other byte, including all license/copyright words and line endings, is preserved. The corresponding documentation accurately discloses the normalization and both hashes. All 14 landing tests pass without skips. No new finding.

This supplements the complete initial review at `/workspace/scratch/d8e33c67341b/audit-live/test-review.md` and TR-1 closure at `/workspace/scratch/d8e33c67341b/audit-live/test-review-followup.md`. All earlier limitations and declined judgments remain. This local review provides no protected-merge, production-deployment or external-write authorization.

## Identity and isolation

| Item | Observed value |
| --- | --- |
| Candidate | `/workspace/scratch/d8e33c67341b/getzilla-seo` |
| Original comparison base | `b7aa0a55f3236c578d4365f3f0e58ce5962cf319` |
| Prior reviewed HEAD | `b7f156b60d270a16f1a4f2f9a3ff979fff08b54a` |
| License repair commit | `80a3e72cd3fab9f6c9c4872b4bd40b895bd42e5e` |
| Current HEAD, before and after | `4b9aa2dd7fbe54efb984e576421a6b488b8323a7` |
| Git tree | `b34f9a335d1449665e3db7f175dbc9d636786026` |
| `getzilla.util.tree_fingerprint`, before and after | `3f64bb7e236f3e89693cda79e3cd6c70d849e984b2a434149dc000ac2f52d101` |
| Candidate status before and after | Empty `git status --porcelain=v1 --untracked-files=all` |
| Observation times | `2026-10-07T12:08:09.638413+00:00` / `2026-10-07T12:08:10.690148+00:00` |
| Exact snapshot | `/workspace/scratch/d8e33c67341b/test-review-oe_94aie/license/pristine` |
| Archive SHA-256 | `5a3a6ef771968dec4d73bd6383970b829fcac3329d30b23309137d0fd64c1512` |
| Snapshot verification | All 4,608 tracked files compared byte-for-byte against the clean candidate; symlink targets checked where applicable |

reviewed-tree-modified: no

Scratch is under the trusted, non-sticky, mode-0700 private parent `/workspace/scratch/d8e33c67341b/test-review-oe_94aie`. Its `license` child is also owner-matched, non-symlink and exactly mode 0700. No staged, unstaged or untracked state required a snapshot overlay. No candidate/index/HEAD writes, restoration or artifacts occurred. All execution and outputs remained in private scratch. Resource observation was refreshed in `license/capacity.json`: affinity and cpuset 0–8, quota 8 CPU equivalents. Tests ran serially as one Python process and its light Node child. No subagents were used.

## Delta inspected and direct byte proof

I read `/workspace/scratch/d8e33c67341b/audit-live/license-normalization-report.md`, the fresh bounded-smoke artifact, and the actual Git diff from the prior reviewed HEAD. Only four product paths changed: landing `assets/fonts/OFL.txt`, `ASSETS.md`, `README.md` and `SERVER-SETUP.md`. Every other changed path is active-package workflow evidence. Test, HTML, template, analytics, WOFF2 and image bytes are unchanged. No Git attributes, gate or factory change appears in the delta.

The original license was read directly with:

```text
git show b7f156b60d270a16f1a4f2f9a3ff979fff08b54a:side-projects/getzilla-landing/assets/fonts/OFL.txt
```

The distributed license came from the byte-verified current snapshot. Python comparison established:

```text
original: 4384 bytes
distributed: 4383 bytes
removed byte: 0x20, zero-based offset 940, line 21
original[940:942] == bytes([32, 10]): true
distributed == original[:940] + original[941:]: true
newline counts equal: true
```

| Version | Computed SHA-256 |
| --- | --- |
| Original | `071195d8806e226faeee60259c28ca67b458227af5195a73f5cfcab06e3003bc` |
| Distributed | `7805ccc507e6dc0c0796f1afa4f03ad413a9d302a30a24f8dbeb1aeef07a6c17` |

Both computed hashes appear in ASSETS.md. README and SERVER-SETUP preserve the complete-license-text statement while disclosing the single removed space. The unchanged page hash is `185ffa66df11bce9becf04d3e15f180c1c908d596cf5f5d4170f001f36676a62`.

## Actual commands and results

Full executable procedure: `/workspace/scratch/d8e33c67341b/test-review-oe_94aie/license/run_license_review.py`. Entrypoint actually executed:

```text
python3 -B /workspace/scratch/d8e33c67341b/test-review-oe_94aie/license/run_license_review.py
```

The helper archives the exact HEAD with:

```text
git archive --format=tar --output /workspace/scratch/d8e33c67341b/test-review-oe_94aie/license/candidate.tar 4b9aa2dd7fbe54efb984e576421a6b488b8323a7
```

It extracts the archive, compares snapshot bytes and the license delta, and invokes the following from the `license/pristine` snapshot, with a 20-second bound:

```text
python3 -B -m unittest tests.test_getzilla_landing -v
Ran 14 tests in 0.091s
OK
```

Exit 0; no skips. Full output is in `license/pristine.txt`; `before.json`, `after.json` and `metadata.json` retain exact identities, hashes, commands and changed inventory. The coordinator's separate `/workspace/scratch/d8e33c67341b/audit-live/bounded-observation-license.txt` records exit 0 in 0.153s, stable fingerprint and no receipt. The pristine result above was independently executed.

An initial scratch-helper creation attempt had a quoting syntax error before the helper or any test observation was created. It was corrected; the report uses only the successful complete run above. Candidate bytes were unaffected.

## Explicit limits and unexecuted claims

TR-1 remains closed by the prior follow-up. Its killed-mutant evidence is historical at `b7f156b60d270a16f1a4f2f9a3ff979fff08b54a`; I confirmed test and HTML/template bytes are unchanged and did not rerun that mutation. No new test writing, mutation campaign, adjacent-test run, browser/media work or full qualifying gate occurred. Earlier mutation, optional-Chrome skip, browser/Nu/Lighthouse results remain historical/separate observations, with all limitations in the initial full report preserved.

The direct comparison establishes the bounded text normalization; it is not a new legal or license audit. Synthetic DOM execution, file signatures/provenance, metadata tests, contrast calculations and documentation assertions retain their earlier limitations. I did not independently rerun the base-range whitespace gate; I inspected the actual diff and the writer/coordinator's recorded pass. No coverage, PostgreSQL, architecture/governance, final PR gate, live deployment, server behavior, vendor-dashboard collection, indexing/ranking, field-performance or rollback-execution claim is made. The coordinator still owns persistence, final freeze and qualifying gates.
