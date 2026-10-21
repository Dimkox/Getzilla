# Getzilla release review

Release-scope checks: **PASS**. Overall candidate: **BLOCKED**. The independent code review confirmed a critical standalone-token boundary defect involving Unicode identifier continuations. The coordinator supplied that confirmed finding while this report was being finalized. I did not independently reproduce it. The frozen candidate remains unchanged; a repair and fresh review are required. This report does not qualify merge or completion. The final full local gate and required exact-head external CI are **NOT_RUN**.

## Identity and scope

- Route: `d834158878e0`; change: `20261021-task-d83415`.
- Candidate: `/home/pall/projects/liqvera/.getzilla/runtime/getzilla-dispositions`.
- Base: `e158ddc7263a55f5308944c5a426eb1e9f1a4327`, also the observed merge base with local `origin/main`. Published tags were inventoried; no fetch or tag change was performed.
- Before and after HEAD: `9e29128aed4abea3dbe50d7f797aecbb26ff17d9`.
- Before and after Git tree: `eb9006a8a0e0b861a101b15d6094ddb6df228f96`; both status checks were empty.
- Scratch: `/home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-release-review`, mode `0700`, under an owned non-sticky parent without group/world write access. The archived HEAD snapshot reproduced the exact candidate Git tree. All probes used CPUs 16–17 and scratch `tmp` as `TMPDIR`.

reviewed-tree-modified: no

I inspected the verifier integration, new disposition helper and tests, manifest/installer selection, reference documentation and change package. I checked native report aggregation and receipt boundaries. No candidate files were generated or changed.

## Findings and release controls

- **Security:** The independent code-review finding above blocks the candidate. My bounded release probes found no additional blocker. No active `engineering/verification-dispositions.json` ships in this candidate. The helper falls within installer-owned `.getzilla`; the consumer policy falls outside installer ownership. Existing bounded cases confirm absent policy retains blocking findings, every occurrence remains distinct, private-key/AWS detections stay blocking, and invalid, stale, untracked, symlinked or changed inputs fail. Those passing cases do not cover the newly reported Unicode boundary defect. The supported whitespace exception remains exact Markdown EOF; mixed diagnostics, Git errors and mismatched index/HEAD bytes still fail. The reference explains the narrow schema, byte bindings, limits and review requirement. Local policy records do not confer authenticated approval or merge authority.
- **Report compatibility:** No blocking finding. Schema version 1 retains raw severity and original observations, with additive effective severity and disposition metadata. Git command output and actual exit codes remain visible. Native quality admission and overall verification consume check status, so disposed raw errors do not silently bypass those controls. Documentation tells other consumers to use check status or effective severity. Arbitrary third-party consumers and a complete CLI/receipt lifecycle were not executed in this review.
- **Duplicate writes and rollback:** No new external mutation path is introduced. The added subprocess calls inspect Git source; matching and classification do not write consumer policy, evidence or runtime receipts. Receipt publication remains the existing verifier path. Reverting the implementation and omitting consumer policy restores strict findings. No database migration, service operation, new tag or release artifact is needed. The delivery note requires PR-only delivery after the gates and an exact tool pin for the later Liqvera audit.
- **Tests and evidence honesty:** No blocking finding. The package keeps implementation observations separate from final verification. All six external bounded-log hashes and sizes match their tracked bindings. Their recorded RED runs, interrupted broad control and packaging failure remain visible; later focused/package results are not presented as a full gate. The recorded 23-test observation at `71c0cd7` is historical to this review. A fresh independent 23-test run on the exact reviewed tree passed below. The package remains at `reviewing`; it claims no completed full gate, external CI, successor Liqvera audit or fresh final receipt.

## Executed checks

The snapshot was made with `git archive 9e29128aed4abea3dbe50d7f797aecbb26ff17d9`, then indexed only inside scratch. `git write-tree` there returned `eb9006a8a0e0b861a101b15d6094ddb6df228f96`. Candidate and scratch remained clean after the tests.

From the scratch snapshot, with `TMPDIR` set to its sibling `tmp` directory:

```text
taskset -c 16,17 env PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest -v tests.test_verification_dispositions tests.test_manifest_package.ManifestTests.test_disposition_helper_ships_without_target_review_policy
```

Observed: `Ran 23 tests in 4.828s`, `OK`, process exit 0. Full output and command metadata are in scratch `bounded-tests.log` and `bounded-tests.json`. This exercises strict defaults, raw/effective fields, retained diagnostics, malformed/stale policy, real Git layers, source fingerprints and manifest inclusion. An additional read-only AST check confirmed helper installer ownership, no policy ownership and policy absence. `git diff --check e158ddc7263a55f5308944c5a426eb1e9f1a4327 HEAD` exited 0. Identity records are `identity-before.json` and `identity-after.json` in scratch.

Mutation probes were not performed by this release reviewer; critical mutation review belongs to the selected code/test reviewers. No mutant outcome is claimed. A new package artifact, consumer installation, full test suite, full qualifying verifier, external CI and live operations were not run. Repair the confirmed defect and obtain fresh independent reviews of the new frozen candidate. Then persist all selected reports unchanged, freeze a report-only successor, and require the pending gates before merge. Pin the verified tool commit before the separate Liqvera successor review.
