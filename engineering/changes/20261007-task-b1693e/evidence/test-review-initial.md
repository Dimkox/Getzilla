# Independent test review: Getzilla landing v1.11 follow-through

Date: 2026-10-07 UTC. Reviewer role: route-selected `test_reviewer`. Route: `b1693e9cb114`. Change: `20261007-task-b1693e`.

## Verdict

**Changes requested for one medium, tests-only regression gap (TR-1).** The 14 new landing tests pass without skips and substantiate most of the intended source and behavior contracts. Three of four relevant mutations are rejected for the intended reason. The surviving mutation shows that the claimed photograph-preservation guard does not bind responsive source candidates to their intended photograph. This is a concrete missing assertion, not evidence of a wrong photograph in the current product. An independent check of all 72 current responsive references passes.

A small change to the existing media test should close TR-1; no product HTML, image, font, analytics or dependency change is requested. This review does not authorize protected merge, production deployment or any external operation.

## Exact source identity and isolation

| Item | Observed value |
| --- | --- |
| Candidate | `/workspace/scratch/d8e33c67341b/getzilla-seo` |
| Branch specified by coordinator | `codex/getzilla-seo-v111` |
| Comparison base | `b7aa0a55f3236c578d4365f3f0e58ce5962cf319` |
| HEAD before and after | `61861f819f7a2803261f752c5a5b61a90ac221d0` |
| Git tree | `f255057a6e0c8f90fcdbac55caf191dccaa13bbe` |
| `getzilla.util.tree_fingerprint` before and after | `382a7cdb81b6220a37265c39d8afb184371ad42878a2f9e1a3a8347caf6c413e` |
| Candidate status before and after | Empty `git status --porcelain=v1 --untracked-files=all` |
| Private parent | `/workspace/scratch/d8e33c67341b/test-review-oe_94aie` |
| Scratch safety | Owner matches reviewing process; non-symlink parent; mode exactly `0700`, including no sticky bit |
| Exact snapshot | `/workspace/scratch/d8e33c67341b/test-review-oe_94aie/snapshot` |
| Snapshot archive | `/workspace/scratch/d8e33c67341b/test-review-oe_94aie/candidate.tar` |
| Archive SHA-256 | `35f7ae7e1def233f59c7adcf8bdddd4c62c1901011199eb9ad68a5178c53c858` |
| Snapshot verification | All 4,590 tracked files compared byte-for-byte to the clean candidate; symlink targets compared where applicable |
| Current index.html SHA-256 | `185ffa66df11bce9becf04d3e15f180c1c908d596cf5f5d4170f001f36676a62` |
| Final identity check | `2026-10-07T11:50:00.402659+00:00` |

reviewed-tree-modified: no

The clean candidate had no staged, unstaged or untracked material to overlay. `git archive --format=tar --output /workspace/scratch/d8e33c67341b/test-review-oe_94aie/candidate.tar 61861f819f7a2803261f752c5a5b61a90ac221d0` captured the exact snapshot; Python `tarfile.extractall(..., filter='data')` extracted it. Each mutation was applied to a separately extracted copy under the private parent. No candidate/index/HEAD modification, restoration, test artifact generation or Git receipt write occurred. Python commands used `-B`; tests executed only in scratch. `before.json` and `after.json` contain the identity observations.

Resource observation is in `capacity.json`: 9 allowed online logical CPUs, affinity/effective cpuset 0–8, cgroup v2 `/` quota `800000 100000` (8 CPU equivalents). No widening was needed because affinity already matched cpuset. I kept execution serial: one Python test process and its light Node subprocess, within the coordinator's 1–2-process allocation while Lighthouse ran elsewhere. No subagents were spawned.

## Scope and material inspected

I read the root `AGENTS.md`, including independent review and private mutation requirements. No additional `AGENTS.md` was found under the relevant product, tests, `.getzilla` or active package paths. I read the package's `requirements.md`, `change-spec.yaml`, `test-plan.md`, `evidence/implementation-report.md`, `evidence/browser-and-html.md`, failure evidence and selected browser JSON structure, and inspected the actual product diff and surrounding HTML/CSS/JavaScript. I reviewed all of `tests/test_getzilla_landing.py` and the named smoke path through `scripts/getzilla_verify.py`, `.getzilla/getzilla/verification.py:2093–2129` and `.getzilla/getzilla/python_test_runner.py:310–323`.

The smoke harness invokes the real Python unittest module with a bounded subprocess, requires a clean committed candidate, checks HEAD/fingerprint stability and publishes no receipt. The coordinator's `/workspace/scratch/d8e33c67341b/audit-live/bounded-observation.txt` says `PASS python-named-smoke: exit=0 seconds=0.151 budget=180`, `PASS source-stability`, and `receipt=not_recorded`. I independently ran the test module from the byte-verified snapshot instead of running a gate or generating artifacts inside the candidate.

## Executed controls and observations

Commands ran with the stated working directories. Full mutation runner and logs remain under the private parent; they are review artifacts, not product files.

| Claim/check | Command / working directory | Actual result |
| --- | --- | --- |
| Exact candidate regressions | `python3 -B -m unittest tests.test_getzilla_landing -v`, cwd `.../test-review-oe_94aie/snapshot` | `Ran 14 tests in 0.104s` / `OK`; no skips. The retained runner baseline repeats this in 0.074s with the same result. |
| Adjacent SEO skill/showcase compatibility | `python3 -B -m unittest tests.test_seo_landing_side_project -v`, same cwd | `Ran 11 tests in 0.008s` / `OK (skipped=1)`; 10 pass. Skip: optional PATH-discoverable Chrome unavailable for the existing showcase lifecycle case. |
| Four bounded mutations | `python3 -B /workspace/scratch/d8e33c67341b/test-review-oe_94aie/run_probes.py`, cwd `/workspace/scratch/d8e33c67341b` | Baseline passes; three mutants killed, one survives. Every mutant executes all 14 exact candidate tests, with a 20-second subprocess timeout. |
| Tracking and main copy equal base | Python read-only `git show b7aa0a55f3236c578d4365f3f0e58ce5962cf319:side-projects/getzilla-landing/index.html`, regex extraction of tracking blocks and normalized `Elements(main).text_parts`, equality against snapshot | Both protected blocks and normalized main text equal base; both analytics reference files also equal base. Full values in `source-comparisons.json`. |
| Current responsive source binding | Python loops all eight parsed pictures, their three srcsets, and every candidate; asserts intended identity in URL, matching declared width in filename and correct AVIF/WebP/JPEG suffix | 72 candidate bindings checked; all pass. This independent probe checks what TR-1 shows the committed tests miss. |
| Browser evidence binding | `git diff 7c32ea46b99182ff6e76b47a438c5f4522cb16b7 61861f819f7a2803261f752c5a5b61a90ac221d0 -- side-projects/getzilla-landing/index.html` | Empty; browser report's exact HTML hash also equals current snapshot. Historical product-HEAD browser observations remain relevant to these unchanged HTML bytes. |

Protected head: 1,014 bytes, SHA-256 `c45825f2f9b0117307fe0fbf5c875ef0b9ab15d19e3cfd481045ef91c47fdb04`. First-body noscript: 130 bytes, SHA-256 `3576068d6e4ac30fc0bc8b3cffe297bec5180da34462409ab106ec00d2f4e679`. Normalized main text: SHA-256 `a3d2060727a295dd57806ecb5ce630d28593d8b6f8dc8ce79529a01035ea4b07`. These agree with both the candidate's hard-coded test oracles and the comparison base, so they are meaningful preservation checks rather than freshly blessed changed content.

The historical TDD artifact records 11 tests: 7 failures, 2 missing-file errors, 2 passes. The failures correspond to missing social/local media/fonts, invalid controls/headings, the obsolete request URL and absent discovery/setup files. The later CTA contrast artifact records the actual ratio `4.464976671382634` failing the 4.5 requirement. I inspected these artifacts; I did not recreate the historical preimplementation tree/run and do not claim to have personally executed those earlier tests.

## Mutation results

The exact mutation implementation and commands are preserved in `run_probes.py`; machine results are in `probe-results.json`. Matching edits were applied to index and template for product mutations, so template parity could not accidentally kill them. The placeholder probe intentionally changes only the template.

| Probe | Applied mutation | Outcome and actual assertion |
| --- | --- | --- |
| `remove_prevent_default` | Replace the one `      e.preventDefault();` line in both HTML files with a comment | **Killed.** `test_controls_execute_click_and_keyboard_contract` fails at Python line 327, Node assertion `false !== true` for handled-key prevention. `Ran 14 tests in 0.075s`; `FAILED (failures=1)`. Template parity and all other tests pass. |
| `wrong_avif_picture` | Parse first and second `<picture>`; replace first picture's entire `<source type="image/avif" ...>` with the second picture's valid AVIF source in both HTML files | **Survived.** `Ran 14 tests in 0.092s`; `OK`. All files, dimensions, formats, hashes, fallback src, alt, copy and template parity remain valid, but AVIF-capable browsers would select the team image for the founder card. See TR-1. |
| `skip_demo_heading` | Change `<h2 id="demo-heading">` and its closing tag to `h4` in both files, retaining content and IDs | **Killed.** `test_heading_ids_fragments_and_no_js_accessibility` fails at line 176: `AssertionError: 4 not less than or equal to 2`. `Ran 14 tests in 0.079s`; `FAILED (failures=1)`. |
| `wrong_template_placeholder` | Replace the first `__GA_MEASUREMENT_ID__` with `__WRONG_GA_ID__` in template only | **Killed.** `test_template_reproduces_production_bytes` fails at line 73 because `b'__WRONG_GA_ID__'` is an unexpected placeholder. `Ran 14 tests in 0.075s`; `FAILED (failures=1)`. |

One initial heading-probe setup used the nonexistent ID `demo-title` and stopped at its precondition before executing that mutant. The scratch-only helper was corrected to the observed `demo-heading`; the reported result is the successful corrected probe. No inconclusive mutant remains. These four results do not imply a blanket mutation score requirement or complete coverage.

## Finding TR-1 — medium: bind every responsive candidate to its intended photograph

**Location:** `tests/test_getzilla_landing.py:153–165`, specifically the srcset loop at lines 156–165. Product context: `side-projects/getzilla-landing/index.html:464` and the analogous template source.

The only photograph identity assertion is `self.assertIn(identity, img['src'])` at line 153. For each srcset entry, the test checks an absolute local path, existence, length and a digest appearing somewhere in the global provenance document. That permits a different existing photograph's perfectly valid candidate to stand in for this photograph. Widths and formats match between the first two photos, and the fallback src/alt remain unchanged, so every existing test passes the `wrong_avif_picture` mutation.

This is material to AC-003 and the user's explicit request to preserve the existing photographs. In modern AVIF selection the visible image can change while assistive text continues describing the original. It is especially easy to introduce by copying a picture source line during future maintenance. The independent current-tree check found no such defect now.

**Requested repair:** In the existing srcset loop, bind each candidate to the expected `identity` from `PHOTOS`; additionally tie the descriptor to the filename width and source MIME type to the expected extension if doing so remains a small coherent assertion. Checking identity alone kills this demonstrated mutant. Retain the actual existing test module and reapply this same scratch mutation to verify it is rejected. No new test framework, browser dependency, asset generation or product modification is needed.

## What the tests prove, and their limits

- **Strong preservation oracles:** Analytics block/reference hashes, immediate positions, GA async script count, exact template expansion and main-copy hash are fixed against the prior product. The byte comparison and placeholder mutation support these contracts. The hashes also pin the existing analytics options/order; they do not prove post-deploy vendor collection or rule out every possible future extra inline script elsewhere in the page.
- **Meaningful behavior execution:** `tests/test_getzilla_landing.py:273–327` extracts the actual inline UI script and invokes registered handlers. It checks Before/After pressed state, initial Build state, exclusive panel visibility, roving tab index, Left/Right wrap, Home/End, focus transfer, native Tab non-interception, click selection and handled-key suppression. The failed preventDefault mutant establishes an actual behavioral oracle. It does not reimplement the production show/selection function as its expected result.
- **Synthetic DOM boundaries:** The fixture uses real HTML attributes, but selector methods return convenient preselected arrays and elements. It does not model query-selector matching, native event dispatch/bubbling, CSS visibility, layout, accessibility tree, browser focus behavior or scrolling. Node availability is optional at lines 274–276; an environment without it can skip this entire behavior case. Here Node v24.19.0 ran it, without a skip. The coordinator's independent real-browser matrix is complementary evidence, not an implied capability of this unit test.
- **Static structural coverage:** Heading progression, unique IDs, fragment and ARIA target existence, hidden-control startup and visible no-JS panel markup are useful guards. The heading mutation demonstrates one of them. The Python `HTMLParser` is not an HTML conformance validator or browser layout engine.
- **Media checks:** Local-reference presence, width descriptor lists, file signatures, preload policy, fixed PNG dimensions, WOFF2 headers and provenance hashes are useful accidental-breakage guards. They do not fully decode media, prove provenance licensing, establish responsive visual selection, or validate every font glyph. TR-1 is the demonstrated missing binding. Decoding and browser display remain separate evidence.
- **Metadata/discovery limits:** Canonical agreement, fixed factual schema fields, no invented offers/dates, JSON parsing and sitemap root are checked. The tests compare OG/Twitter image URLs to each other, but do not independently bind both URLs to the real local social-card path; they also do not prove every JSON-LD semantic condition or metadata uniqueness. Actual source inspected here is consistent. These are unprobed limits, not additional verified mutation findings.
- **Contrast/doc limits:** The contrast test computes numeric ratios from selected CSS declarations, not the cascade at every rendered state. Deployment checks at lines 265–271 largely look for required strings and absence of `.htaccess`; they cannot prove upload ordering, backup execution or complete live public inventory. Those require the surrounding source/doc/browser review and deployment process.

## Evidence not independently executed / declined judgments

1. I did not run the full unittest discovery, coverage, PostgreSQL checks, architecture/governance gate or final `--mode pr`. The coordinator must perform the final qualifying gate after review persistence/freeze; this bounded review creates no receipt or scope admission.
2. I did not rerun Chromium, Nu or Lighthouse. I read the retained browser/HTML report and checked its HTML source binding. The report records widths 320/768/1280/1920, no-JS, keyboard and fonts/photos, zero Nu errors plus the two unchanged tracking information messages. Those remain the coordinator's observations, not tests personally executed by this reviewer. The adjacent existing Chrome skip does not negate the separate real-browser run.
3. I decline to infer production HTTP status, MIME/cache headers, deploy success, tracking dashboard delivery, crawling/indexing/ranking, rich-result eligibility, field Core Web Vitals or post-deploy rollback from source tests. No production deployment or external writes were performed here.
4. I decline to recommend altering or removing analytics for a Lighthouse Best Practices score. GA/Metrika must remain immutable under the user instruction. Network observations do not prove vendor dashboards received every event; navigation-aborted requests remain limited observations.
5. I did not audit the runtime/factory, upstream skill implementation, licenses beyond recorded source checks, infrastructure security, remote policy or merge approvals. This review's decision is limited to this landing change's tests and associated evidence claims.

After TR-1 is repaired by the sole writer, rerun the focused module and this specific wrong-picture mutation on the newly frozen exact candidate, record updated identity/fingerprint, and close the finding before recording a clean test-review receipt. Any source change after this report makes its exact-HEAD verdict historical until that affected review is refreshed.
