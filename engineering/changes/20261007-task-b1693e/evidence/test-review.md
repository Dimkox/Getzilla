# Independent test-review follow-up: TR-1

Date: 2026-10-07 UTC. Route: `b1693e9cb114`. Change: `20261007-task-b1693e`. Reviewer: independent route-selected `test_reviewer`.

## Verdict

**PASS for this affected review. TR-1 is closed.** The pristine new exact snapshot passes all 14 landing tests without skips. The same wrong-photo AVIF-source mutation that survived the initial review now fails exactly one test, at the intended source-identity assertion. The other 13 cases, including exact template parity and immutable analytics, pass. No product defect or additional repair is identified by this narrow follow-up.

This report supplements the complete initial review at `/workspace/scratch/d8e33c67341b/audit-live/test-review.md`, reviewed HEAD `61861f819f7a2803261f752c5a5b61a90ac221d0`. That report's methods, earlier mutation results, evidence limits and declined judgments remain part of the review; its TR-1 changes-requested verdict is superseded by this affected review of the repair. This local review is evidence only and does not authorize protected merge, production deployment or other external operations.

## Exact identities and review isolation

| Item | Observed value |
| --- | --- |
| Candidate | `/workspace/scratch/d8e33c67341b/getzilla-seo` |
| Branch identified by coordinator | `codex/getzilla-seo-v111` |
| Original comparison base | `b7aa0a55f3236c578d4365f3f0e58ce5962cf319` |
| Prior reviewed HEAD | `61861f819f7a2803261f752c5a5b61a90ac221d0` |
| Tests-only repair commit | `9e78d893e0aaf1e894d726af85fc52c81dd056bf` |
| New reviewed HEAD, before and after | `b7f156b60d270a16f1a4f2f9a3ff979fff08b54a` |
| New Git tree | `0a4f75945dc0e788e8f48e727e19b9355fde11aa` |
| `getzilla.util.tree_fingerprint`, before and after | `2e20b7e63e280d2966efd4329aee64c4011ac158371cde988ed057989709400a` |
| Candidate status before and after | Empty `git status --porcelain=v1 --untracked-files=all` |
| Before / after observations | `2026-10-07T11:58:34.575097+00:00` / `2026-10-07T11:58:36.974764+00:00` |
| Trusted private parent | `/workspace/scratch/d8e33c67341b/test-review-oe_94aie`, owner matches process, non-symlink, mode exactly `0700`, no sticky bit |
| Follow-up scratch | `/workspace/scratch/d8e33c67341b/test-review-oe_94aie/followup`, same ownership/safety checks, mode `0700` |
| Exact pristine snapshot | `/workspace/scratch/d8e33c67341b/test-review-oe_94aie/followup/pristine` |
| Mutation copy | `/workspace/scratch/d8e33c67341b/test-review-oe_94aie/followup/wrong_avif_picture` |
| Archive SHA-256 | `72e754c36c8d85eb2bb74234abd5205a6e83cb84f045ebac7a97ee485e6d3ae9` |
| Snapshot verification | All 4,603 tracked files byte-compared to the clean candidate; symlink targets compared where applicable |
| Unchanged index.html SHA-256 | `185ffa66df11bce9becf04d3e15f180c1c908d596cf5f5d4170f001f36676a62` |

reviewed-tree-modified: no

There were no staged, unstaged or untracked candidate changes to overlay. The exact HEAD was archived using `git archive`, then separately extracted into the pristine and mutation directories. All test execution and artifacts remained in private scratch. No candidate, index or HEAD write, mutation/restoration, receipt generation, push, deployment, full gate or subagent work occurred. The source was frozen throughout.

The refreshed capacity snapshot is in `followup/capacity.json`: affinity and effective cpuset 0–8, 9 logical CPUs, cgroup quota `800000 100000` (8 CPU equivalents). No affinity widening was necessary. Execution stayed serial with one Python test process and its light Node subprocess.

## Affected source review

I read `/workspace/scratch/d8e33c67341b/audit-live/repair-report.md` and `/workspace/scratch/d8e33c67341b/audit-live/bounded-observation-repair.txt`, and inspected the exact diff from the prior reviewed HEAD to the new candidate. The entire `side-projects/getzilla-landing/**` diff is empty. The only new source delta is `tests/test_getzilla_landing.py`, 8 added and 2 removed lines; all other changed paths are under this change package's workflow-evidence directory. These checks confirm that the earlier product/browser source binding has not been disturbed.

At `tests/test_getzilla_landing.py:160–169`, the existing per-picture srcset loop now derives the expected extension from the source MIME type (JPEG for the img fallback), parses each declared width, and requires the URL to match the expected frozen photo identity, that declared width, the existing 12-hex content-addressed naming shape, and the expected extension. Existing file existence/size/provenance checks remain. The expected photo identity comes from `PHOTOS`; it is independent of the candidate srcset being checked. This directly closes the demonstrated copied-source regression without changing test count, dependencies or product bytes.

The coordinator's fresh bounded-smoke artifact records `PASS python-named-smoke: exit=0 seconds=0.151 budget=180`, stable source fingerprint, and `receipt=not_recorded`. My independent results below are from the exact verified private snapshot, not from relying on that smoke assertion or the implementer's report.

## Exact commands and observed results

The full executable procedure is retained at `/workspace/scratch/d8e33c67341b/test-review-oe_94aie/followup/run_followup.py`. Entrypoint actually run:

```text
python3 -B /workspace/scratch/d8e33c67341b/test-review-oe_94aie/followup/run_followup.py
```

It uses this snapshot command, with cwd `/workspace/scratch/d8e33c67341b/getzilla-seo`:

```text
git archive --format=tar --output /workspace/scratch/d8e33c67341b/test-review-oe_94aie/followup/candidate.tar b7f156b60d270a16f1a4f2f9a3ff979fff08b54a
```

Each test observation runs the same command with a 20-second subprocess bound:

```text
python3 -B -m unittest tests.test_getzilla_landing -v
```

The resolved interpreter was `/opt/codex/runtimes/codex-primary-runtime/dependencies/python/bin/python3`.

| Working directory | Outcome | Concise actual output |
| --- | --- | --- |
| `.../followup/pristine` | **PASS**, exit 0, no skips | `Ran 14 tests in 0.080s` / `OK` |
| `.../followup/wrong_avif_picture` | **Mutant killed**, exit 1 | `Ran 14 tests in 0.073s` / `FAILED (failures=1)` |

The mutation is identical in substance to the initial review: use `re.findall(r'<picture>(.*?)</picture>', raw, re.S)` to obtain the first two pictures; find each complete `<source type="image/avif"[^>]+>` element; replace the first picture's entire AVIF source with the second picture's valid source in both `index.html` and `template/index.template.html`. All source files still exist; format, dimensions, original fallback src, alt text, main copy and template parity remain valid. Only the displayed photograph selected through that AVIF source is wrong.

The sole failing case is `test_local_photos_keep_provenance_dimensions_and_loading`, at line 165:

```text
AssertionError: Regex didn't match: '^/assets/images/photo\\-1685716851721\\-7e1419f2db18-360-[0-9a-f]{12}\\.avif$' not found in '/assets/images/photo-1521737711867-e3b97375f902-360-276541ffc39e.avif'
```

This is the intended first-photo identity mismatch, not an incidental missing file, template mismatch, syntax error, changed test oracle or environment failure. The template, tracking and all other cases report `ok`. No surviving or inconclusive mutant remains in this affected probe.

An initial evidence-collector assertion looked for an unescaped photo prefix in Python's escaped regex diagnostic. Both test executions had completed with the correct outcomes, but that collector assertion stopped metadata publication. I corrected the scratch-only collector's diagnostic check to recognize the observed escaped form and reran the same bounded procedure successfully. The results above are the successful final run; no product or test source was changed to accommodate the collector.

Full retained evidence:

- `followup/pristine.txt` and `followup/wrong_avif_picture.txt`: complete test output.
- `followup/results.json`: commands, working directories, statuses and concise output.
- `followup/before.json` and `followup/after.json`: exact candidate status/HEAD/fingerprint.
- `followup/metadata.json`: archive/source hashes, verified snapshot count and changed inventory.
- `followup/run_followup.py`: exact read-only snapshot and mutation procedure.

## Limits retained from the initial review

This is a narrow affected review, not a new broad mutation campaign. The other three initial mutants were not rerun; their results remain historical at the prior exact HEAD, with their relevant product and assertion bytes unchanged. The earlier adjacent 10-pass/1-optional-Chrome-skip result was not rerun. No new assertion is made that those observations were executed on this HEAD.

The synthetic DOM test still models handler state, not actual browser layout/events/selector behavior. Media signatures and filename/provenance assertions do not fully decode media or establish licensing, visual identity against remote originals, or all font glyphs. Metadata/schema and documentation string checks retain the explicit limits stated in the initial report, as do numeric CSS contrast tests versus actual cascade states. Node remains optional in that test module; it was available and executed here.

I did not rerun Chromium, Nu, Lighthouse, coverage, PostgreSQL, architecture/governance or the final PR gate. Previously recorded browser/HTML observations remain separate coordinator evidence for the unchanged product. I decline to infer live deployment, server MIME/cache behavior, vendor-dashboard collection, crawling/indexing/ranking, field Core Web Vitals, rollback execution or external merge authority from these source tests. Analytics remain immutable; no score-driven tracking change is requested.

The coordinator must persist the complete review evidence, freeze the report-containing candidate and complete the final qualifying exact-head process under the existing rules. A later source repair requires a newly bound affected review; this PASS is scoped to the exact HEAD and fingerprints above.
