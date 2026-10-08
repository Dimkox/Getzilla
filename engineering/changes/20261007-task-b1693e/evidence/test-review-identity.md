# Independent test-review supplement: migration-question identity repair

Date: 2026-10-07 UTC. Route `b1693e9cb114`; change `20261007-task-b1693e`. Reviewer: independent route-selected `test_reviewer`.

## Verdict

**PASS for the narrow affected review.** The unchanged identity assertion reproduces exactly the two prior predecessor-name occurrences. On the repaired exact snapshot, that identity test and all 14 landing tests pass without skips. Independent comparisons prove that each HTML file differs only by the approved opening question and that the new strict main-copy hash equals original baseline copy with exactly that substitution. Both protected analytics blocks are unchanged. No new finding or requested repair.

This supplements the complete initial review and the TR-1/license supplements at `/workspace/scratch/d8e33c67341b/audit-live/test-review.md`, `test-review-followup.md`, and `test-review-license.md`. Their explicit limits and declined judgments remain, except that strict copy preservation now includes this disclosed one-question exception. The initial full-gate failure remains a failure; these bounded observations do not replace a successful final gate or authorize protected merge, deployment or external writes.

## Identity and private snapshot

| Item | Observed value |
| --- | --- |
| Candidate | `/workspace/scratch/d8e33c67341b/getzilla-seo` |
| Original comparison base | `b7aa0a55f3236c578d4365f3f0e58ce5962cf319` |
| Prior frozen candidate used for reproduction | `04bd89da67048f633e5160a3888ac2b0018aa3cf` |
| Branding repair commit | `b1a6fbb1d7521ee1a4dc126765324671e87952b6` |
| README disclosure commit | `5d0321ea5bfd2c7e3528d8e2962014fb5e6796b0` |
| Reviewed HEAD before and after | `ef7574324876d9859d6ef6265929af5fa34263b4` |
| Reviewed Git tree | `fa2307871107d5b4f357c3f24a2b73da3abedb53` |
| `getzilla.util.tree_fingerprint` before and after | `0eccd154a7871fefc5338047197f0bc74d16fd357295cc987944be30f747c4c9` |
| Status before and after | Empty `git status --porcelain=v1 --untracked-files=all` |
| Observation times | `2026-10-07T12:25:05.186408+00:00` / `2026-10-07T12:25:08.481044+00:00` |
| Current exact snapshot | `/workspace/scratch/d8e33c67341b/test-review-oe_94aie/identity/current` |
| Prior exact snapshot | `/workspace/scratch/d8e33c67341b/test-review-oe_94aie/identity/prior` |
| Current archive SHA-256 | `0877fb859b3fd32c787eef8dcefe85b9c32f2b3f194dbe13bd101c0ea0430dea` |
| Prior archive SHA-256 | `ac595332808b8fa23f8043077c5c73157b104ff75ffc433d36633f97df725411` |
| Current snapshot verification | All 4,615 tracked files compared byte-for-byte to the clean candidate; symlink targets checked where applicable |

reviewed-tree-modified: no

Both snapshots were created with `git archive` under the trusted non-sticky private parent `/workspace/scratch/d8e33c67341b/test-review-oe_94aie`, mode exactly 0700. The `identity` child is also owner-matched, non-symlink and mode 0700. There was no dirty state to overlay. No candidate/index/HEAD writes, restoration, artifact generation or receipt occurred. Refreshed capacity is recorded in `identity/capacity.json`: affinity/cpuset 0–8, quota 8 CPU equivalents. Work stayed serial, one Python process and its light Node subprocess. No subagents, new tests, mutation campaign, media/browser job or full gate were run.

## Scope and repaired oracle

I read the complete package `evidence/identity-diagnosis.md`, `evidence/identity-repair-report.md`, current `evidence/upload-archive.json`, the relevant implementation-brief/review-resolution entries, the unchanged identity-test implementation, and the actual prior-to-current diff. I also read `/workspace/scratch/d8e33c67341b/audit-live/bounded-observation-identity.txt`.

The executable/product delta is limited to index and template, the existing main-copy assertion's hash/comment, and README disclosure. All other changed paths are active-package workflow evidence. No identity test, historical exclusion, marker, scope selector, attribute or gate was changed.

At `side-projects/getzilla-landing/index.html:729` and the same template line, only `Used adaptive-grok-build-pro before?` becomes `Upgrading an existing installation?`. Direct byte comparison verifies, for both complete HTML files:

```text
old.count(old_question) == 1
new == old.replace(old_question, new_question, 1)
```

Both original-base HTML files contain the old question. Independently normalized main text from the original base and the new candidate satisfies the same one-substitution equality. Thus the updated oracle at `tests/test_getzilla_landing.py:206–212` preserves the exact remaining main text; it does not merely bless arbitrary current copy.

| Evidence | SHA-256 |
| --- | --- |
| Original normalized main text | `a3d2060727a295dd57806ecb5ce630d28593d8b6f8dc8ce79529a01035ea4b07` |
| Original plus exactly the approved substitution / current main text | `70c6bf2a4e097bc61d2460d6bd9db772abb2f9fcb45000940ad003891bb394c9` |
| Current index.html | `92e2aa7999065e75b21f76809db46db0095029114e7a553e83093f95fe288604` |
| Protected head, 1,014 bytes, equal original base | `c45825f2f9b0117307fe0fbf5c875ef0b9ab15d19e3cfd481045ef91c47fdb04` |
| First-body noscript, 130 bytes, equal original base | `3576068d6e4ac30fc0bc8b3cffe297bec5180da34462409ab106ec00d2f4e679` |

The main copy's one approved branding exception is explicit in the package and test comment. The user's analytics invariant remains absolute. The existing tracking test additionally passes fixed reference hashes, immediate locations and GA async source; the template test confirms exact production substitution parity.

## Commands and actual results

The complete procedure is retained as `/workspace/scratch/d8e33c67341b/test-review-oe_94aie/identity/run_identity_review.py`, executed with:

```text
python3 -B /workspace/scratch/d8e33c67341b/test-review-oe_94aie/identity/run_identity_review.py
```

The helper runs `git archive --format=tar --output <private archive path> <exact SHA>` for the two SHAs above. It confirms neither extracted snapshot is inside another Git worktree. The existing identity test therefore exercises its unmodified archive fallback, enumerating actual snapshot files rather than a different repository or an empty index. No test mocking or exclusion was introduced.

In the prior snapshot:

```text
python3 -B -m unittest tests.test_getzilla_identity.GetzillaIdentityTests.test_no_predecessor_product_names_in_live_files -v
Ran 1 test in 0.669s
FAILED (failures=1)
```

Exit 1. The original assertion at `tests/test_getzilla_identity.py:129` reports exactly these two product offenders:

```text
side-projects/getzilla-landing/index.html:729: adaptive-grok-build-pro
side-projects/getzilla-landing/template/index.template.html:729: adaptive-grok-build-pro
```

In the current snapshot:

```text
python3 -B -m unittest tests.test_getzilla_identity.GetzillaIdentityTests.test_no_predecessor_product_names_in_live_files tests.test_getzilla_landing -v
Ran 15 tests in 0.756s
OK
```

Exit 0, no skips. Each invocation had a 20-second bound. Only the named existing identity assertion and the existing 14 landing tests were run. Full logs are in `identity/prior-tests.txt` and `identity/current-tests.txt`; `before.json`, `after.json` and `metadata.json` retain commands, identities, hashes and inventory. The coordinator's separately observed bounded smoke records exit 0 in 0.553s, stable source and no receipt; the results above were independently executed.

## Archive metadata and remaining limits

I read the current public-archive metadata: 80 files, 3,466,692 uncompressed bytes, ZIP size 3,429,245 bytes, ZIP SHA-256 `a165931e036ae512364ecfae65b2c4544e4e2520d3fc6c7fc259847ce019aef6`. Its page hash matches the page hash independently computed above. I did not reopen or revalidate the public ZIP's entries; this is metadata inspection, not a new archive-build claim.

TR-1's killed-mutant evidence remains historical, with its relevant source-binding test and picture code unchanged. I did not repeat any mutation, adjacent-test suite, browser, Nu, Lighthouse, coverage, PostgreSQL, architecture/governance or final full-gate work. Earlier full browser/performance evidence belongs to the earlier page hash and differs from this page by the disclosed question; the package's fresh bounded 320px/Nu observations remain coordinator evidence, not personally executed checks here.

All earlier synthetic-DOM, media-signature/provenance, metadata/schema, CSS-contrast and documentation-test limits remain. No conclusion about live deployment, vendor dashboards, server headers, indexing/ranking, field Core Web Vitals or production rollback follows from these tests.

This report binds the reviewed HEAD and tree above. A future remote commit may have different commit metadata and a different HEAD-derived fingerprint; the coordinator must establish tree equality, adopt the actual remote HEAD and run the final qualifying gate on that candidate. No future exact-head gate or external merge outcome is asserted here.
