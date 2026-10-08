# Independent code review — Getzilla landing SEO completion

## Verdict

**PASS for the reviewed source candidate.** No blocking correctness, scope, analytics-preservation or asset-integrity finding was identified by this reviewer. The implementation meets the six stated source-level acceptance criteria within the evidence boundaries below. At final handoff the coordinator relayed a separate test-review coverage gap requiring a narrow test-only repair; that finding is explicitly recorded below and is not overruled by this source verdict.

This is an independent `code_reviewer` report and a broad review of the branch's actual changed-file inventory. It is not merge authority, a final verification receipt, or a deployment approval. The report-containing candidate still requires the final qualifying local PR gate and applicable external exact-head CI/approval process. Production deployment and public readback remain separate, pending operations.

## Exact reviewed identity and isolation

| Field | Value |
| --- | --- |
| Review date | 2026-10-07 UTC |
| Route | `b1693e9cb114` |
| Change | `20261007-task-b1693e` |
| Candidate | `/workspace/scratch/d8e33c67341b/getzilla-seo` |
| Branch | `codex/getzilla-seo-v111` |
| Comparison base | `b7aa0a55f3236c578d4365f3f0e58ce5962cf319` |
| Reviewed HEAD, before and after | `61861f819f7a2803261f752c5a5b61a90ac221d0` |
| Git tree, before and after | `f255057a6e0c8f90fcdbac55caf191dccaa13bbe` |
| `getzilla.util.tree_fingerprint`, before and after | `382a7cdb81b6220a37265c39d8afb184371ad42878a2f9e1a3a8347caf6c413e` |
| Working-tree inventory, before and after | Empty `git status --porcelain=v1`; no staged, unstaged or untracked candidate changes |
| Exact page SHA-256 | `185ffa66df11bce9becf04d3e15f180c1c908d596cf5f5d4170f001f36676a62` |
| Private parent | `/workspace/scratch/d8e33c67341b/code-review-b00jw0jx` |
| Parent permissions | `0700`, non-sticky, reviewer-created using `tempfile.mkdtemp`; verified with `stat` |
| Snapshot used for tests/mutations | `/workspace/scratch/d8e33c67341b/code-review-b00jw0jx/candidate` |

reviewed-tree-modified: no

The snapshot was created using `git archive 61861f819f7a2803261f752c5a5b61a90ac221d0` to the private parent's `candidate.tar`, then `tar -xf ... -C .../candidate`. An independent comparison against `git ls-tree -rz --full-tree HEAD` verified all **4,590 tracked blobs and modes**: each snapshot blob's Git SHA-1 was recomputed from its bytes and compared to the recorded object ID. Symlinks and executable bits were accounted for. Thus the archive was checked for omissions or export transformations rather than merely assumed exact. The clean candidate had no additional staged/unstaged/untracked changes requiring reproduction.

All executable checks and mutations ran outside the reviewed worktree with Python `-B`. The reviewer did not modify the candidate, index, branch, HEAD, runtime state or product files; did not run a full gate, browser, push, deployment or subagent; and did not access credentials, private keys or environment files. There is no OS-enforced isolation claim.

Resource observations were recorded in `capacity.json` before executable probes. This process saw nine online CPUs and affinity/effective cpuset `0-8`, with cgroup v2 `cpu.max = 800000 100000`, giving eight quota-limited CPU equivalents. Affinity already equalled the effective cpuset, so no widening probe was applicable. The assigned review used one lightweight Python process, with a bounded Node child for the interface test; no browser or full-suite load was added. Initial read-only inspection preceded this reviewer's own measurement; the coordinator had already supplied the measured eight-CPU allocation.

## Scope and material reviewed

Read the applicable root `AGENTS.md`, requirements, `change-spec.yaml`, sole-writer implementation brief, implementation report, browser/HTML evidence, deployment/release/rollback guidance, actual source diff, relevant surrounding HTML/CSS/JavaScript, regression tests and asset provenance. No nested `AGENTS.md` was found under the changed product/test/evidence directories.

The exact base-to-HEAD diff contains **108 changed files**. Independent inventory checking found no path outside:

- `side-projects/getzilla-landing/**`;
- `tests/test_getzilla_landing.py`;
- `engineering/changes/20261007-task-b1693e/**`.

There are no changed factory/runtime/API/event/workflow/governance files, active hosting files, package manifests or build/runtime dependencies. The unchanged vendored SEO skill is outside this implementation diff. The upstream comparison and live-page audit are coordinator evidence, not newly repeated external lookups by this reviewer.

## Findings and requirement assessment

**Severity assessment:** no P0, P1 or P2 finding, and no concrete P3 source defect requiring repair was established. This verdict does not assert that every possible mutation, hosting state or browser has been tested.

| Criterion | Assessment and supporting source |
| --- | --- |
| AC-001 — preserve analytics | Pass. `index.html:4–25` keeps both original blocks immediately after charset; `index.html:356–357` keeps the noscript pixel first in body. Independent base/current byte comparison and the frozen-source test agree. No new code wraps, delays, duplicates or suppresses analytics. |
| AC-002 — consistent SEO/discovery | Pass. `index.html:27–68` aligns canonical, Open Graph, Twitter and the two factual schema nodes. The PNG resources are real decoded images; `robots.txt` and `sitemap.xml` use the sole canonical root without a fabricated date. |
| AC-003 — preserve and self-host assets | Pass. `index.html:71–87` uses the two original local font subsets; picture blocks use local responsive resources with dimensions, fallback JPEG, lazy loading and asynchronous decoding. Provenance, hashes, sizes and actual decoded bytes agree. |
| AC-004 — controls/accessibility | Pass within the static/behavior scope. `index.html:114–117`, `:403–417`, `:578–587` and `:786–823` provide skip navigation, semantic comparison state, progressive enhancement, roving tab focus, wrapping/Home/End and visible panels. Source behavior tests execute the actual inline script. The coordinator's real Chromium matrix is separately attributed below. |
| AC-005 — existing copy/Pricing/template | Pass. Normalized main text was independently compared directly to the exact base, rather than relying only on the newly introduced frozen hash. `index.html:733–764` retains the merged Pricing and ordinary access-request URL. Template substitution passes byte equality. Contrast changes are narrow and preserve the separate logo geometry/color. |
| AC-006 — static delivery and rollback | Pass for source documentation. README's public inventory and `SERVER-SETUP.md:7–11,24–36` specify assets first, HTML last, private reference material, MIME/revalidation guidance and rollback using actual production HTML. No hosting policy is activated. A real deployment must create the described backup, including any existing stable-name resources it will replace. That operational backup was not performed or verified here. |

### Strengths material to this decision

The patch fixes existing defects while preserving the merged source's offer and layout. It does not silently revert to the different current live page. Font/photo hosting is a bounded static change, and a failed or disabled interface script leaves readable workflow content. The canonical/social/schema facts are consistent and do not manufacture reviews, prices, addresses or dates. Tests protect actual source invariants and execute the interface state logic; the implementation report correctly describes the fake DOM as a state test rather than a browser-layout result.

Analytics preservation is unusually explicit: source bytes, location, reference snippets and script attributes are protected. The test and documentation do not equate a request stub, source hash or local lab score with vendor collection. The retained third-party behavior must not be modified to improve Lighthouse scores.

## Independent executed evidence

All Python commands below used the resolved interpreter `/opt/codex/runtimes/codex-primary-runtime/dependencies/python/bin/python3`; `python3` is its shell invocation. Test commands ran with cwd set to the snapshot directory above and a 40-second subprocess timeout. Tests' Node interface execution has its own 10-second timeout.

### Pristine source and behavior tests

```text
python3 -B -m unittest tests.test_getzilla_landing -v
Ran 14 tests in 0.076s
OK
exit=0
```

This covers frozen tracking/reference bytes and placement; template equality; canonical/social/JSON-LD/crawl contracts; local resources; headings/IDs/ARIA/fragment references; no-JS initial source; exact current main text and photo alts; contrast in repaired contexts; Pricing; deployment inventory; and actual inline JavaScript click/keyboard/focus behavior. No test was skipped in this module.

The coordinator's supplied bounded observation was also read:

```text
python3 scripts/getzilla_verify.py --mode fast --no-record --test tests.test_getzilla_landing --budget 180
PASS python-named-smoke: exit=0 seconds=0.151 budget=180
PASS source-stability: repository fingerprint remained stable
RESULT: PASS | mode=fast scope=not-run evidence=not-run ... receipt=not_recorded
```

That is explicitly pre-review observation, not a qualifying gate or a receipt. This reviewer did not repeat that wrapper inside the candidate.

### Independent comparisons and real assets

The reviewer ran `python3 -B - <<'PY' ... PY` checks using `git show <base>:side-projects/getzilla-landing/index.html`, `HTMLParser`, `hashlib`, Pillow `Image.open(...).load()` and the retained original downloads. The executed claims and their exact comparison operations were:

| Claim / command or operation | Observed output |
| --- | --- |
| `git diff --name-only b7aa0a55f3236c578d4365f3f0e58ce5962cf319..HEAD`, followed by closed allowed-path checking | 108 changed files; `outside_approved_scope=[]` |
| `git ls-tree -rz --full-tree HEAD`; for each blob, `sha1(b'blob ' + str(len(data)).encode() + b'\0' + data)` plus symlink/mode comparison | 4,590 archive blobs/modes match |
| Normalize main text from base and candidate with `HTMLParser`, collapse whitespace, then direct equality | Equal; SHA-256 `a3d2060727a295dd57806ecb5ce630d28593d8b6f8dc8ce79529a01035ea4b07` |
| Extract `<!-- Google tag.*?<!-- /Yandex.Metrika counter -->` with DOTALL from base/current and compare bytes | Equal; 1,014 bytes; SHA-256 `c45825f2f9b0117307fe0fbf5c875ef0b9ab15d19e3cfd481045ef91c47fdb04` |
| Extract first `<noscript>.*?</noscript>` with DOTALL from base/current and compare bytes | Equal; 130 bytes; SHA-256 `3576068d6e4ac30fc0bc8b3cffe297bec5180da34462409ab106ec00d2f4e679` |
| Parse every `ASSETS.md` raster row; compare byte length/SHA-256; `Image.open(path).load()` and compare dimensions | All 74 raster rows pass: 72 photographs, share PNG and favicon PNG |
| Hash each `assets/fonts/*` file and require its full digest in `ASSETS.md` | All three files pass: two WOFF2 and OFL |
| Extract all eight original `https://images.unsplash.com/...` URLs from base and require them in provenance | 8/8 exact URL matches |
| Hash the eight retained `audit-live/original-assets/photo-*.original` files and compare documented source hashes; decode originals/local full-size JPEGs; compare dimensions and mean absolute RGB pixel error | 8/8 hashes and dimensions pass; mean absolute RGB difference 0.765–6.586 out of 255, consistent with retained crops and JPEG recompression |
| Require both exact retained WOFF2 URLs in `original-assets/google-fonts-chrome.css` | Both original CSS URLs present |
| `view_image` on the snapshot's `assets/images/social-card.png` | Actual 1200×630 composition inspected; readable existing wording, correct identity, no clipping or missing glyphs observed |

The raster comparison is not an independent reconstruction of every encoder invocation. It establishes readable actual files and strong identity/crop consistency against the retained originals. Those originals are coordinator/implementer capture artifacts; this reviewer did not redownload them.

Full observed values are retained outside the candidate in `independent-checks.json`, `source-asset-checks.json`, `identity-before.json`, `identity-after.json`, `capacity.json`, `probes.json` and the individual test transcripts under the private parent. No review artifact was generated in the candidate.

## Mutation probes

Mutations touched only the archived scratch copy. Each started from the pristine HTML/resources; a `finally` block restored original scratch bytes/files before the next probe. The final scratch HTML was checked byte-equal to the pristine copy. These probes measure three specific regression contracts, not a blanket mutation-score threshold.

| Mutant | Exact scratch mutation | Exact test command | Observed result | Disposition |
| --- | --- | --- | --- | --- |
| M1 — change analytics option | `original.replace(b'webvisor:true', b'webvisor:false', 1)` written to scratch `index.html` | `python3 -B -m unittest tests.test_getzilla_landing.GetzillaLandingTests.test_tracking_bytes_location_and_reference_snippets -v` | Exit 1; `Ran 1 test in 0.005s`; `FAILED (failures=1)` at frozen head length/hash comparison | **Killed** |
| M2 — wrong canonical | Replace `b'rel="canonical" href="https://getzilla.app/"'` with `b'rel="canonical" href="https://wrong.example/"'` once | `python3 -B -m unittest tests.test_getzilla_landing.GetzillaLandingTests.test_canonical_social_and_factual_schema -v` | Exit 1; `Ran 1 test in 0.004s`; `FAILED (failures=1)` at canonical equality | **Killed** |
| M3 — missing responsive resource | Rename scratch `assets/images/photo-1685716851721-7e1419f2db18-360-c8a694e95701.avif` to the same stem with `.quarantine`, leaving HTML references intact | `python3 -B -m unittest tests.test_getzilla_landing.GetzillaLandingTests.test_resource_references_are_local_and_have_real_media_signatures -v` | Exit 1; `Ran 1 test in 0.005s`; `AssertionError: False is not true : /assets/images/photo-1685716851721-7e1419f2db18-360-c8a694e95701.avif`; `FAILED (failures=1)` | **Killed** |

Survived: none of the three attempted mutants. Inconclusive: none. Unattempted mutants include unrelated script additions, server response/header changes, every possible corrupt binary and browser-specific rendering regressions. No claim is made that the test module would kill all such cases.

## Separately attributed evidence and limitations

`evidence/browser-and-html.md` is a coordinator-authored observation on product commit `7c32ea46b99182ff6e76b47a438c5f4522cb16b7`. Its recorded page SHA-256 is exactly the page hash independently measured at this reviewed HEAD. It reports Chromium 153 at 320/768/1280/1920, native keyboard controls/focus, no-JS readability, fonts/photos, no overflow/local errors, and Nu 26.10.7 with zero errors plus two retained informational messages inside immutable Metrika code. Those observations were read and checked for source identity, not rerun or claimed as independently executed by this reviewer.

The same document distinguishes actual vendor network responses from dashboard confirmation and describes TLS verification remaining enabled. No test here intercepted, replaced, disabled or postponed analytics. At final handoff the coordinator reported three candidate Lighthouse runs, each Performance 99 / Accessibility 100 / Best Practices 77 / SEO 100, and a correct-TLS base run 76 / 95 / 77 / 100; the retained vendor behavior contributes the Best Practices deductions. These are coordinator observations, not scores rerun by this reviewer, and they are not field metrics or a production-delivery claim.

### Late coordinated test-review finding

The separate test reviewer reported that replacing one picture's complete AVIF `srcset` with another valid photograph's AVIF `srcset` in both production HTML and template survives the existing 14 tests. The coordinator confirmed that `tests/test_getzilla_landing.py:153–165` checks global provenance but binds photo identity only to `img.src`, not each responsive candidate. This is a test-coverage finding; the currently reviewed source's responsive images are correct. It was not one of this reviewer's three attempted mutants and was not independently rerun here. The coordinator will have the same sole writer add per-`srcset` photo identity/width/format assertions, then request a narrow review of that delta. This report remains bound to the current exact HEAD and cannot serve as review of that future test change.

### Declined-to-judge list

- **Production deployment, actual public MIME/cache/canonical redirects and rollback backup availability:** no hosting action/readback was assigned to this review. Static source/documentation cannot establish these operational facts. Existing stable-name files must be retained if they will be overwritten.
- **GA/Metrika dashboard delivery, consent configuration or data quality:** preserved code and the coordinator's network responses do not prove vendor-side event attribution. No credentials or dashboards were accessed.
- **Guaranteed ranking, indexing, rich-result eligibility or field Core Web Vitals:** this is local source/lab work, and no such guarantee is introduced by the patch.
- **Safari, Firefox, assistive-technology combinations and full WCAG conformance:** no new cross-browser or screen-reader matrix was run; the bounded source/Node review plus separately attributed Chromium findings has that limit.
- **Fresh font decoding/complete glyph repertoire and fresh external provenance retrieval:** local WOFF2 signatures/hashes, captured original CSS, page content and recorded real-browser font loading were checked. This review did not install font tooling or refetch upstream bytes.
- **The entire factory implementation, unrelated historical evidence, CI policy enforcement and merge authorization:** these are outside the approved changed product scope. The broad inventory found no such implementation changes. Applicable final gates remain required.

## Final assessment

The source changes are coherent, bounded and supported by direct integrity checks, real media decoding, passing focused behavior tests and three successful fault-detection probes. Exact source identity remained stable throughout review. Persist this complete report, freeze the report-containing candidate and run the prescribed final gates; source-review approval must remain distinct from exact-head CI and any later deployment decision.
