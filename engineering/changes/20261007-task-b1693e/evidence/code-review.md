# Independent code-review follow-up — TR-1 responsive photograph binding

## Verdict

**PASS.** The narrow tests-only repair correctly closes the demonstrated wrong-photo AVIF `srcset` coverage gap. All 14 pristine landing tests pass, and the previously surviving mutation now fails the new intended assertion. No new source or workflow-disposition finding was identified. This report approves only the reviewed delta and retains the initial review's explicitly bounded historical evidence for unchanged product files.

The complete initial report is preserved in `engineering/changes/20261007-task-b1693e/evidence/code-review-initial.md` and was originally returned as `/workspace/scratch/d8e33c67341b/audit-live/code-review.md`. It reviewed `61861f819f7a2803261f752c5a5b61a90ac221d0`, with fingerprint `382a7cdb81b6220a37265c39d8afb184371ad42878a2f9e1a3a8347caf6c413e`. Its media decoding, provenance checks, source comparisons and three mutation results remain historical results, not reruns on this candidate.

This is source-review evidence, not merge authority. The report-containing frozen candidate still requires the final qualifying local gate and applicable external exact-head CI/approvals. No deployment or production verification is authorized or asserted by this report.

## Exact identity and scratch isolation

| Field | Before and after review |
| --- | --- |
| Route / change | `b1693e9cb114` / `20261007-task-b1693e` |
| Candidate | `/workspace/scratch/d8e33c67341b/getzilla-seo` |
| Branch | `codex/getzilla-seo-v111` |
| Original comparison base | `b7aa0a55f3236c578d4365f3f0e58ce5962cf319` |
| Follow-up comparison | `61861f819f7a2803261f752c5a5b61a90ac221d0..b7f156b60d270a16f1a4f2f9a3ff979fff08b54a` |
| Reviewed HEAD | `b7f156b60d270a16f1a4f2f9a3ff979fff08b54a` |
| Git tree | `0a4f75945dc0e788e8f48e727e19b9355fde11aa` |
| `getzilla.util.tree_fingerprint` | `2e20b7e63e280d2966efd4329aee64c4011ac158371cde988ed057989709400a` |
| Staged/unstaged/untracked inventory | Empty `git status --porcelain=v1` at both checkpoints |
| Repair commit | `9e78d893e0aaf1e894d726af85fc52c81dd056bf` |
| Landing subtree at both old and new HEAD | `4a711c6a912fd28b23c73cb8942e6c3ad384b5eb` |
| Exact public page SHA-256 | `185ffa66df11bce9becf04d3e15f180c1c908d596cf5f5d4170f001f36676a62` |
| Private parent | `/workspace/scratch/d8e33c67341b/code-review-followup-ix6lg817` |
| Scratch snapshot | `/workspace/scratch/d8e33c67341b/code-review-followup-ix6lg817/candidate` |
| Private-parent permissions | Reviewer-created `0700`, verified non-sticky |

reviewed-tree-modified: no

A fresh resource observation preceded this follow-up's source inspection: nine online CPUs, affinity and effective cpuset `0-8`, cgroup v2 membership `/`, finite `cpu.max` of `800000 100000`, for eight quota-limited CPU equivalents. No affinity widening was applicable. Review used one lightweight Python process with a bounded Node child and no browser/full-gate load. The full observation is in scratch `capacity.json`.

The snapshot was reproduced with `git archive b7f156b60d270a16f1a4f2f9a3ff979fff08b54a`, then extracted under the private parent. Independent comparison with `git ls-tree -rz --full-tree HEAD` recomputed Git blob hashes and checked executable modes/symlink handling for all **4,603 tracked blobs**. All matched. The clean candidate contained no additional changes needing reproduction. All test execution, mutation and restoration occurred only in this scratch copy, using Python `-B`; the original candidate/index/HEAD/branch were not edited.

## Delta and coherent disposition

The actual diff from the previous reviewed HEAD changes only `tests/test_getzilla_landing.py` outside the active change package. That product-test delta is eight additions and two deletions. The entire `side-projects/getzilla-landing` Git subtree is unchanged, independently confirmed using `git rev-parse` at both HEADs. Therefore HTML/template, analytics, fonts/photos, discovery files and deployment documentation remain exactly the previously reviewed source.

At `tests/test_getzilla_landing.py:160–168`, the test derives the expected extension from each source's MIME type or the JPEG `img` fallback. It parses every candidate URL and width descriptor, then requires the URL to match that picture's frozen expected photograph identity, declared width, 12-character hexadecimal content suffix and matching extension. The existing expected-width-list, local-file and provenance checks remain. This targets the missing per-picture binding directly and introduces no product behavior or dependency.

Read `evidence/review-resolution.md`, the complete repair report, fresh bounded-smoke output, changed state/release records and public-archive metadata. The workflow preserves the initial review reports, records TR-1 and its sole-writer repair, then returns to reviewing rather than claiming completion. It clearly keeps captured production HTML as historical evidence, separates lab measurements from field claims, and requires an actual later hosting backup/readback. The stated public inventory remains 80 files; this follow-up did not independently re-open or validate the prepared ZIP. Production capture and internal reports are excluded from the documented public release inventory. These dispositions are coherent with the initial review's limits.

## Fresh executable evidence

Actual resolved interpreter: `/opt/codex/runtimes/codex-primary-runtime/dependencies/python/bin/python3` (`python3` below). Cwd for every test was the fresh snapshot. Each subprocess had a 40-second timeout; the existing inline-JavaScript test keeps its own bounded Node execution.

### Pristine repaired candidate

```text
python3 -B -m unittest tests.test_getzilla_landing -v
Ran 14 tests in 0.088s
OK
exit=0
```

All 14 tests passed, with no skips. This runs the changed photo test and the existing tracking/template/metadata/resource/control regressions. It is a bounded observation, not full PR verification.

### TR-1 — wrong AVIF donor

The mutation was applied independently to both scratch production HTML and template. Exact Python mutation logic:

```python
avif = re.findall(r'(<source type="image/avif" srcset=")([^"]+)(")', html)
assert len(avif) == 8
wrong = html.replace(avif[0][1], avif[1][1], 1)
assert wrong != html
path.write_text(wrong)
```

Thus the first picture's whole AVIF `srcset` was replaced by the second picture's existing valid AVIF candidates, preserving valid assets and production/template parity. The complete module was run again:

```text
python3 -B -m unittest tests.test_getzilla_landing -v
FAIL: test_local_photos_keep_provenance_dimensions_and_loading
File ".../candidate/tests/test_getzilla_landing.py", line 165
    self.assertRegex(
AssertionError: Regex didn't match:
  expected ^/assets/images/photo\-1685716851721\-7e1419f2db18-360-[0-9a-f]{12}\.avif$
  actual /assets/images/photo-1521737711867-e3b97375f902-360-276541ffc39e.avif
Ran 14 tests in 0.072s
FAILED (failures=1)
exit=1
```

**Mutation disposition: KILLED**, by the intended new photo-identity assertion. The other 13 tests passed. Original scratch HTML/template text was restored in `finally` and then compared equal to the pristine values. No mutant survived and no attempted probe was inconclusive. The pre-repair survival is the historical initial test-review/repair evidence; this follow-up did not rerun the obsolete test module.

The provided coordinator observation `/workspace/scratch/d8e33c67341b/audit-live/bounded-observation-repair.txt` records:

```text
PASS python-named-smoke: exit=0 seconds=0.151 budget=180
PASS source-stability: repository fingerprint remained stable
RESULT: PASS | mode=fast scope=not-run evidence=not-run ... receipt=not_recorded
```

This was read as an independently supplied committed-HEAD observation; it is not a newly created review receipt or final gate. Private raw transcripts and identities are retained in `pristine.txt`, `mutant-tr1-wrong-avif-donor.txt`, `probes.json`, `identity-before.json`, `identity-after.json` and `capacity.json` under the new private parent.

## Findings, limits and unexecuted claims

- **TR-1: resolved.** The exact demonstrated failure mode is now detected. No new P0/P1/P2/P3 finding was established in the small delta.
- **Independent width/format mutations were not executed.** The assertions were inspected and the wrong-donor mutant exercised the new binding. This is one targeted mutation result, not proof of all mutation classes or a blanket coverage threshold.
- **No repeated media decoding, provenance download, browser matrix, Nu validation or Lighthouse run.** Product subtree equality preserves the applicability of the initial source observations, with their original identities and limitations. Historical runs are not represented as fresh tests.
- **No ZIP integrity recheck or real deployment/backup/MIME/cache verification.** These are separate operational artifacts/actions; this report reviews the documented inventory/disposition without claiming their execution.
- **No analytics dashboard access, field metrics, ranking/SEO eligibility or full WCAG claim.** Those remain outside the available source/lab evidence.
- **No full factory suite, final qualifying gate, remote CI, push, merge, deployment, credentials or subagents.** Scope selection and applicable CI authority remain for the coordinator's prescribed final process; local source review does not substitute for them.

## Handoff

The repaired test is small, correctly bound to the existing asset naming contract, and independently kills the known surviving mutation. Candidate HEAD/status/tree fingerprint remained unchanged across the follow-up. Persist this complete follow-up with the initial full reports, freeze the resulting candidate and proceed to the required final gate and applicable exact-head CI process.
