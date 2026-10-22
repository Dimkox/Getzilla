# Core test review, wave 4

**PASS for the observed Core scope.** No new finding. The new tests detect lost fixture isolation and weakened scan limits. Six existing Low findings remain deferred in issue 122.

Independent reviewer: `test_reviewer`; route `44fe064efbab`; package `20261021-task-44fe06`. Reviewed the actual 55-path diff, test support, policy budget code, installed-component tests and surrounding implementation. Scope: security, duplicate writes and tests. Installed lean/chosen tests check file contents before and after dispatch. The new CLI guard precedes scaffold creation. No new external-write path was found by inspection.

Source identity before and after:

- Candidate: `/home/pall/projects/getzilla/.getzilla/runtime/worktrees/eu-ai-act-phase2`.
- Base: `f9f02dd53ba9f6e69d51ae5322df0c96e3d41b02`.
- HEAD: `ccfe4a404c33003ede0cf0ef42c0faf91f9ce67d`.
- Tree: `889358dc9453cf77df73ec23dd0ed7f10f6c1229`.
- Fingerprint: `24262cfdb7ad5afd747b4ad924f32ecfff9271336b97fdf7fa3744cda03c34c8`.
- Staged, unstaged and untracked inventories: empty before and after.
- Base-to-HEAD inventory: 55 paths. Saved as `test-review-wave4/source-inventory.tsv`; SHA-256 `60ef5052cd97836da5dc8d6814276b38d8940dacbc5c94ba2dd1d27be5323527`.

Private snapshot: `/home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/test-review-wave4/snapshot`. The trusted parent, reviewer directory and snapshot are owned, non-sticky directories with mode `0700`. The materializer verified all 5,525 tracked paths, modes and contents. Manifest digest: `e0db8b14597acfe35e3fd6bb976c26a48465bd150d3c3f99ab0172f3134b56c9`. The restored snapshot matches the candidate identity and clean status. Proof and before/after JSON records remain in the private reviewer directory.

reviewed-tree-modified: no

Commands and observations:

1. `python3 scripts/getzilla_startup_cpu.py` recorded verified capacity 26 with reserve 2. Tests used CPUs 8–15 and two pytest workers. This leaves room for their hook and policy child processes within the assigned process limit.
2. `python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/source_identity.py /home/pall/projects/getzilla/.getzilla/runtime/worktrees/eu-ai-act-phase2` returned the assigned clean identity. `python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/test-review-wave4/run_probes.py identity_after` returned matching candidate and restored-snapshot identities.
3. `git diff --name-status f9f02dd53ba9f6e69d51ae5322df0c96e3d41b02 ccfe4a404c33003ede0cf0ef42c0faf91f9ce67d` recorded the inventory. `git diff --exit-code` on this range for `tests/test_hook_degraded.py`, `.getzilla/getzilla/_policy_legacy.py`, `.getzilla/getzilla/policy.py`, `.grok/hooks/pre_tool_use.py`, `.coveragerc`, `.getzilla/getzilla/util.py` and `engineering/contracts/schemas/trust-ci-attestation-envelope.v1.json` returned 0 with no output.
4. `python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/test-review-wave4/run_probes.py control` returned 0: **14 passed, 36 subtests passed in 13.07 s**. It ran both degraded/enforcement modules, the three affected policy-limit tests and the V2/legacy schema test. The child passed its CPU, trace/profile/monitoring and fixture-origin assertions. The host schema version was **4.10.3**.
5. `python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/test-review-wave4/run_probes.py support_fixture_path enforcement_fixture_path scan_deadline scan_entries scan_fail_closed measured_fixture_origin` ran six sequential mutations. Each used the passing control and was restored before the next probe. Exact expanded pytest commands, selected test IDs, environment and output are saved in each named `.json` and `.log`. Mutation details remain in the private harness.

| Claim probed | Mutant | Result |
| --- | --- | --- |
| Hook fixture overrides the parent import path | `support_fixture_path` | **Killed**: 1 failed; expected two degraded events, observed zero. |
| Enforcement self-test uses the broken fixture | `enforcement_fixture_path` | **Killed**: 1 failed; broken self-test incorrectly returned pass. |
| The scan deadline is enforced | `scan_deadline` | **Killed**: expired-budget subtest failed; unexpired control passed. |
| The entry cap is enforced | `scan_entries` | **Killed**: 1 failed; the expected budget exception did not occur. |
| Exhaustion produces a denial marker | `scan_fail_closed` | **Killed**: both exhausted-budget tests failed; the marker became absent. |
| Timed child imports the fixture policy | `measured_fixture_origin` | **Killed**: 1 failed at the module-origin assertion. |

All fixtures and test output stayed in private scratch. The parent import path was deliberately bound to the intact scratch source. No synthetic protected command was executed.

Limits: the 4.26.0 dependency installation and exact-base extraction remain **BLOCKED/NOT_RUN**. No pip retry, guard diagnosis or alternate installation ran. The schema result covers host 4.10.3 only. No full PR gate, fresh coverage gate, real Windows run or signed V2 service integration ran in this review. Installed-dispatch and audit boundary execution belong to the separate code/security reviews. Earlier review results are historical. This PASS does not replace final local or external checks.
