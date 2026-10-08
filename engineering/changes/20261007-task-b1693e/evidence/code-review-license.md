# Independent code-review supplement — OFL whitespace normalization

## Verdict and scope

**PASS.** The affected license differs by exactly one trailing ASCII space removed on line 21. All license/copyright words, line boundaries and every other byte are unchanged. The three documentation changes accurately disclose the original and distributed files. No other product change was found, and all 14 existing landing tests pass in private scratch. No new finding or repair is requested.

This supplement preserves the complete initial report (`evidence/code-review-initial.md`, reviewed `61861f819f7a2803261f752c5a5b61a90ac221d0`) and subsequent report originally returned as `/workspace/scratch/d8e33c67341b/audit-live/code-review-followup.md` (reviewed `b7f156b60d270a16f1a4f2f9a3ff979fff08b54a`). Their other findings, executed checks and limitations remain historical evidence with their original identities. The initial statement that the distributed OFL was byte-identical is superseded only by this explicitly documented one-byte normalization; the original source hash remains recorded.

Review is workflow evidence, not merge authority or deployment approval. The final report-containing candidate still requires its qualifying local gate and applicable external exact-head CI process.

## Exact identity and isolation

| Field | Before and after review |
| --- | --- |
| Route / change | `b1693e9cb114` / `20261007-task-b1693e` |
| Candidate / branch | `/workspace/scratch/d8e33c67341b/getzilla-seo` / `codex/getzilla-seo-v111` |
| Original comparison base | `b7aa0a55f3236c578d4365f3f0e58ce5962cf319` |
| Prior reviewed HEAD used for affected comparison | `b7f156b60d270a16f1a4f2f9a3ff979fff08b54a` |
| Normalization commit | `80a3e72cd3fab9f6c9c4872b4bd40b895bd42e5e` |
| Current reviewed HEAD | `4b9aa2dd7fbe54efb984e576421a6b488b8323a7` |
| Git tree | `b34f9a335d1449665e3db7f175dbc9d636786026` |
| `getzilla.util.tree_fingerprint` | `3f64bb7e236f3e89693cda79e3cd6c70d849e984b2a434149dc000ac2f52d101` |
| `git status --porcelain=v1` | Empty at both checkpoints; no staged, unstaged or untracked changes |
| Private parent | `/workspace/scratch/d8e33c67341b/code-review-license-y5d9f179` |
| Snapshot | `/workspace/scratch/d8e33c67341b/code-review-license-y5d9f179/candidate` |
| Permissions | Reviewer-created parent, mode `0700`, verified non-sticky |

reviewed-tree-modified: no

Startup resource observations were recorded before inspection: nine online CPUs, affinity/effective cpuset `0-8`, cgroup quota `800000 100000` (eight CPU equivalents). Review used one lightweight Python process plus the bounded existing Node test; no affinity widening was applicable. A fresh `git archive 4b9aa2dd7fbe54efb984e576421a6b488b8323a7` was extracted into the private snapshot. Affected files, page and test bytes were compared with exact `git show HEAD:<path>` bytes. All tests and generated transcripts stayed outside the candidate, with Python `-B`.

## Executed checks

### Direct byte-delta fault check

Read old bytes with:

```text
git show b7f156b60d270a16f1a4f2f9a3ff979fff08b54a:side-projects/getzilla-landing/assets/fonts/OFL.txt
```

Read current bytes from the fresh archived snapshot. A Python assertion required equal line counts, exactly one differing line (`[21]`), and exact full-file equality after removing only the space immediately before that line's newline. Observed:

```text
old line 21: b'fonts, including any derivative works, can be bundled, embedded, \n'
new line 21: b'fonts, including any derivative works, can be bundled, embedded,\n'
old bytes: 4384
new bytes: 4383
old SHA-256: 071195d8806e226faeee60259c28ca67b458227af5195a73f5cfcab06e3003bc
new SHA-256: 7805ccc507e6dc0c0796f1afa4f03ad413a9d302a30a24f8dbeb1aeef07a6c17
all direct byte assertions passed
```

This full-byte comparison is the change-relevant fault check for the authorized low-impact normalization. No new test or broad mutation campaign was introduced; there are no attempted-mutant killed/survived scores to report.

### Scope, documentation and accounting

`git diff --name-only b7f156b60d270a16f1a4f2f9a3ff979fff08b54a..HEAD`, followed by an assertion excluding only the active workflow package, yielded exactly four product paths: `ASSETS.md`, `README.md`, `SERVER-SETUP.md`, and `assets/fonts/OFL.txt` under `side-projects/getzilla-landing/`. No HTML, template, analytics, font binary, photograph, test, Git attribute or gate changed.

Read the complete license-normalization report and actual documentation diff. `ASSETS.md:9` retains both measured lengths and SHA-256 values and identifies line 21; programmatic assertions confirm all four accounting values are present. README's license inventory and SERVER-SETUP's upload step replace the obsolete unchanged-file description with the disclosed whitespace normalization. The coordinator's archive metadata reports the correct one-byte reduction: 80 public files, 3,466,693 uncompressed bytes. The unchanged page SHA-256 was independently recomputed as `185ffa66df11bce9becf04d3e15f180c1c908d596cf5f5d4170f001f36676a62` and matches that metadata.

### Existing tests and whitespace gate

Executed in the fresh snapshot, with a 40-second subprocess timeout:

```text
python3 -B -m unittest tests.test_getzilla_landing -v
Ran 14 tests in 0.082s
OK
exit=0; no skips
```

Resolved interpreter: `/opt/codex/runtimes/codex-primary-runtime/dependencies/python/bin/python3`.

Executed read-only against the reviewed candidate:

```text
git diff --check b7aa0a55f3236c578d4365f3f0e58ce5962cf319..HEAD
exit=0; no output
```

Also read the coordinator's `bounded-observation-license.txt`: named smoke exit 0 in 0.153 seconds; source stability passes; `receipt=not_recorded`, `scope=not-run`. This is separately supplied bounded observation, not a qualifying local gate. Private `capacity.json`, `delta.json`, `tests.txt`, `identity-before.json` and `identity-after.json` retain this review's raw observations.

## Limitations and handoff

No new media decoding, browser/HTML/Lighthouse runs, original-download retrieval, broad mutation campaign, legal opinion, ZIP-entry recheck, production readback, credentials, subagents, full gate or external write was performed. The prepared archive's rebuilt-entry equality remains coordinator evidence; this supplement checks its documented accounting rather than re-performing that independent work. Existing limitations concerning vendor dashboards, field metrics, other browsers, assistive technologies, hosting behavior and merge authority continue to apply.

Current HEAD/status/fingerprint stayed identical before and after the review. The narrowly authorized license normalization is correctly implemented and documented; persist this supplement with the earlier complete reports and proceed through the required frozen-candidate gates.
