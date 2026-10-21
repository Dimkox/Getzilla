# Core test review, wave 3

**PASS for the observed Core scope.** No new blocking finding. The two repaired Medium defects now have meaningful regression tests. Existing Low gaps remain deferred in issue 122, including first-use provider-cache coverage. They do not block this review.

Reviewer: independent `test_reviewer`; route `route44fe064efbab`; package `20261021-task-44fe06`. Scope: security, duplicate writes and tests. Inspected the complete changed-path inventory, product diff, contracts and surrounding tests. The repair changes audit capture and inventory handling; it adds no external mutation.

Source identity before and after:

- Candidate: `/home/pall/projects/getzilla/.getzilla/runtime/worktrees/eu-ai-act-phase2`.
- Comparison base: `287e64f99b01db44cb6eeeb10f307ccda6f91c1d`.
- HEAD: `cf18a79cf1e97a4100e9999be7ce212e3f258974`.
- Tree: `c815f538aa54997519674497ec3776dccd199a9d`.
- Fingerprint: `a6f96921f402d3b375a369079bc1e2be676ff8db37b07b54b15ef1041b525fdf`.
- Staged, unstaged and untracked inventories: empty before and after. Base-to-HEAD inventory: 49 paths.

Exact inventory SHA-256: `f02aef2876ab16832678c4c9936cfcbcfbb9cb68303ca6c302933fd6e25c53de`. The inventory is saved as `test-review-wave3/source-inventory.tsv` beside this report.

Private scratch: `/home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/test-review-wave3/snapshot`. The parent, reviewer directory and snapshot are owned, non-sticky directories with mode `0700`. The clean snapshot reproduces all 5,525 tracked paths, modes and contents. Its manifest digest is `a0bac548446c49ef5f04af2860870d49fa2efa2fe5b86ce33f1ca1c7c465e7c5`. Its final HEAD, tree, fingerprint and clean status match the candidate. See `snapshot-proof.json`, `source-before.json`, `source-after.json` and `snapshot-after.json` in the reviewer directory.

reviewed-tree-modified: no

Commands and observed results:

1. `python3 scripts/getzilla_startup_cpu.py` recorded capacity 26 with reserve 2. This review used the assigned eight workers on CPUs 8–15.
2. `python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/source_identity.py /home/pall/projects/getzilla/.getzilla/runtime/worktrees/eu-ai-act-phase2` returned the same clean identity before and after. The same command with the snapshot path returned matching identity after restoration.
3. `git diff --name-status 287e64f99b01db44cb6eeeb10f307ccda6f91c1d cf18a79cf1e97a4100e9999be7ce212e3f258974` recorded the inventory. `git diff --exit-code` for the same range and paths `.getzilla/getzilla/util.py` and `engineering/contracts/schemas/trust-ci-attestation-envelope.v1.json` returned 0: both are unchanged.
4. In the snapshot, `taskset -c 8-15 /usr/bin/python3 -B -m pytest -q -n 8 -p no:cacheprovider --tb=short tests/test_eu_ai_act.py tests/test_eu_audit_attestation.py` returned 0: **48 passed, 67 subtests passed in 3.17 s**. All temporary fixtures used the private `tmp` directory. The repository fixtures were independent Git repositories.
5. `python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/test-review-wave3/run_probes.py captured_optin_guard null_report_guard skip_report_guard wave2_ci_regression` ran four sequential mutations on the same scratch file. Each was restored before the next probe. Exact expanded test commands, environment and complete output are in each named `.json` and `.log` file. The private harness holds mutation details.

| Claim probed | Mutant | Observed result |
| --- | --- | --- |
| Captured opt-in has its own refusal | `captured_optin_guard` | **Killed**: 2 failed. The expected opt-in error became the evaluated-report error. The second guard still refused CI; this probe alone does not show an authorization bypass. |
| Null EU evaluation cannot pass CI | `null_report_guard` | **Killed**: null-report subtest failed because no exception occurred; skip subtest passed. |
| Skipped EU evaluation cannot pass CI | `skip_report_guard` | **Killed**: skip-report subtest failed because no exception occurred; null subtest passed. |
| Regression test detects the prior race | `wave2_ci_regression` | **Killed**: 1 failed at the real file-swap assertion after restoring the wave 2 capture and CI functions. The expected refusal did not occur. |

The passing control also checks global and system ignore compatibility, receipt invalidation for unignored source, Git redirection rejection, required-input capture despite ignore rules, and bounded malformed inventory refusal. It checks freshness, risk metadata, exact attested identity/argv, normal receipt requirements and no CI receipt or bytecode writes.

Limits: receipt-query mutations belong to the separate code review. Scaffold retry, template subprocess and Windows-refusal mutation results from prior waves are historical; they were not rerun here. Their unchanged implementation and test coverage were inspected. The full PR gate, real Windows execution, real C2PA signing and real signed V2 Trust CI integration were not run. V2 production signing belongs to the successor. This report makes no merge-authority or full-suite claim.
