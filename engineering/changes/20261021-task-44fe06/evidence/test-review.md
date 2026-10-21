FAIL. Two Medium regression gaps cover confirmed defects. The known Low findings remain deferred to issue 122.

- **Medium — required opt-in is not bound to captured bytes.** Tests at `tests/test_eu_audit_attestation.py:59` and `:107` cover stable disabled config and edits before capture. They miss a change between the live opt-in check and committed-byte capture. Security review reproduced PASS with null EU compliance for committed opt-out, with unchanged HEAD and clean final status. Add a regression that requires enabled captured config and rejects skipped CI evaluation. This needs concurrent local mutation; it does not prove an attack on an immutable deployed runner.
- **Medium — receipt parity test omits global Git exclusions.** The test at `tests/test_eu_audit_attestation.py:208` covers an ordinary untracked note. It misses global `core.excludesFile`. Code review reproduced eligible-to-blocked behavior after adding an ignored editor note: the verifier fingerprint stayed unchanged, but the audit fingerprint changed. Add a private-config regression that preserves receipt eligibility and Git identity isolation.
- **Low — provider-cache regression can mask its own failure.** The test at `tests/test_eu_audit_attestation.py:139` runs an audit before priming stale data. A mutant that uses the path cache stores valid data during that first audit and survives. A private first-use cache test passes current code and kills that mutant. Add this coverage gap to issue 122; current production parsing is correct.

The two Medium reproductions belong to the complete independent reports `core-wave2-security-review.md` and `core-wave2-code-review.md` under the private parent below. I inspected those reports and the relevant implementation/tests. I did not repeat their probes.

Source: `/home/pall/projects/getzilla/.getzilla/runtime/worktrees/eu-ai-act-phase2`; route `44fe064efbab`.

- Base: `287e64f99b01db44cb6eeeb10f307ccda6f91c1d`.
- HEAD before/after: `61827791b7f49a5ad340a62f07756888a03964a3`.
- Tree before/after: `96612a25a2dca3ed8e306f622e82ed2c8b3cbecf`.
- Fingerprint before/after: `53a32ef677284d79a7de11b13b81176fce0e520d485d247c522883f21cb5c733`.
- Staged, unstaged and untracked inventories: empty before and after.
- Comparison inventory: 49 added/modified paths. Exact statuses and paths are in `test-review-wave2/source-inventory.tsv`, SHA-256 `f02aef2876ab16832678c4c9936cfcbcfbb9cb68303ca6c302933fd6e25c53de`.

Private parent: `/home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021`. Scratch: `test-review-wave2/snapshot` beneath that parent. Parent, private directory and snapshot had mode `0700`; the parent was trusted and non-sticky. All 5,525 tracked paths matched candidate bytes and modes. Source and snapshot fingerprints matched before testing and after restoration.

reviewed-tree-modified: no

Snapshot command: `python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/test-review-wave2/prepare_snapshot.py`. Observed: 5,525 paths, clean source and snapshot, exact match. The identity command below ran before and after:

```bash
python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/source_identity.py /home/pall/projects/getzilla/.getzilla/runtime/worktrees/eu-ai-act-phase2
```

All tests ran in the private snapshot with six workers on CPUs 6-11. The helper used `taskset -c 6-11 /usr/bin/python3 -B -m pytest -q -n 6 -p no:cacheprovider --tb=short`. It set `PYTHONDONTWRITEBYTECODE=1`, `GIT_OPTIONAL_LOCKS=0`, and all three temporary-directory variables to `test-review-wave2/tmp`. Exact expanded argv, environment and output are saved in each named JSON/log pair.

```bash
python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/test-review-wave2/run_probes.py baseline
python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/test-review-wave2/run_probes.py control
python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/test-review-wave2/run_probes.py hidden_decision_edit executable_union rules_capture provider_cache windows_refusal node_kill_signal
python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/test-review-wave2/run_probes.py cache_control provider_cache_first_use
```

Observed controls:

- `baseline`: **2 failed, 86 passed, 82 subtests passed** in 43.15s. Scope: EU, audit, scaffold, templates, cost diff, diff risk, existing Git ingestion and ingestion routing. Both failures are unchanged Zero-Git fixture assumptions: required scratch placement puts their plain folders inside the canonical Git worktree. They return `INSIDE_PARENT_GIT_WORKTREE`. This is not a passing broad run. No candidate or fixture repair was made.
- `control`: **24 passed, 33 subtests passed** in 3.38s. The audit and scaffold modules provide the passing mutation control. Captured identity/date, ordinary receipt parity, signed-command claims, retries and read-only audit behavior pass within that scope.
- The real stubborn Node child test passed in the broad run. The original-media preservation assertions passed.
- `cache_control`: **1 passed** in 5.35s. It primes stale provider data before the first audit and confirms current code uses committed bytes.

Mutants ran sequentially because they shared private source files. Each run restored those files.

| Claim / private probe label | Existing-test result |
|---|---|
| Hidden changes to five decision inputs must fail — `hidden_decision_edit` | Killed; 5 failed, 17 passed, 16 subtests passed |
| Deleted committed executables must remain in the checked inventory — `executable_union` | Killed; 1 failed, 17 passed, 20 subtests passed |
| Audit must use captured project rules — `rules_capture` | Killed; 1 failed, 16 passed, 21 subtests passed |
| Audit must bypass stale provider path cache — `provider_cache` | Survived; 17 passed, 21 subtests passed |
| Windows must refuse before creation — `windows_refusal` | Killed; 2 failed, 5 passed, 12 subtests passed |
| Node timeout must stop a child that ignores SIGTERM — `node_kill_signal` | Killed; 1 failed at the outer timeout, 46.72s total; fixture cleanup completed |

The same provider-cache mutant was then killed by the private `provider_cache_first_use` test: **1 failed** in 5.41s. That test is outside the candidate. The existing-test survivor remains a Low finding. No mutant was inconclusive. No blanket mutation threshold was used.

Fresh V1 preservation command in the candidate:

```bash
git diff --exit-code 287e64f99b01db44cb6eeeb10f307ccda6f91c1d HEAD -- engineering/contracts/schemas/trust-ci-attestation-envelope.v1.json
```

Observed: exit 0, no output.

Unexecuted limits: fingerprint/Git-state mutations and the two Medium reproductions belong to the named parallel reviews. Native Windows, real signed V2 integration, real C2PA signing, TypeScript type checking, full PR verification and external checks were not run here. The Node fallback case `test_node_adapter_behavior` was excluded because its cleared environment would create temporary files outside the required runtime root. The two Zero-Git fixture expectations remain unverified under this scratch constraint. Inspection found no new duplicate external-write path; that static statement is not an executable probe. Historical 212-test evidence is not reused as fresh verification. No receipt or phase-2 completion is established.
