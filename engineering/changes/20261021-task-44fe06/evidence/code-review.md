# Core code review — wave 3

**Recommendation: PASS within the reviewed Core scope.** No new material security, duplicate-write, or test defect was found. The six known Low test gaps remain deferred to issue #122. This review grants no merge authority.

## Source and isolation

- Candidate: `/home/pall/projects/getzilla/.getzilla/runtime/worktrees/eu-ai-act-phase2`.
- Route: `44fe064efbab`; `code_reviewer` is selected. Package: `engineering/changes/20261021-task-44fe06`.
- Comparison base: `287e64f99b01db44cb6eeeb10f307ccda6f91c1d`.
- Private scratch: `/home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/code-review-wave3`.
- The scratch parent and child are trusted, non-sticky, and mode `0700`. The private clone reproduced all 5,525 tracked entries, including bytes and modes, at the exact committed source. Source and clone were clean. All tests and mutations ran in that clone; temporary outputs stayed in private scratch.
- Base-to-HEAD inventory: 49 paths. The complete inventory is `code-review-wave3/source-inventory.tsv`, SHA256 `f02aef2876ab16832678c4c9936cfcbcfbb9cb68303ca6c302933fd6e25c53de`. It covers EU policy/audit modules, decision data, templates, installer/dispatcher, V2 schema/architecture, tests, documentation, and change evidence. I inspected the actual diff and surrounding code. The latest product repair changes the audit script and its tests.
- Startup measured 26 usable logical CPUs with a two-CPU reserve. This review used at most eight test workers on CPUs `0-7`.

| Identity | Before review | After review |
| --- | --- | --- |
| HEAD | `cf18a79cf1e97a4100e9999be7ce212e3f258974` | same |
| Git tree | `c815f538aa54997519674497ec3776dccd199a9d` | same |
| Tree fingerprint | `a6f96921f402d3b375a369079bc1e2be676ff8db37b07b54b15ef1041b525fdf` | same |
| Git status | empty | empty |

The restored private clone also has these exact final identities and empty status.

reviewed-tree-modified: no

Identity command, run before and after review:

```sh
python3 /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/source_identity.py /home/pall/projects/getzilla/.getzilla/runtime/worktrees/eu-ai-act-phase2
```

Final clone identity command:

```sh
python3 /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/source_identity.py /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/code-review-wave3/candidate
```

Both final commands exited `0` and returned the identities above.

## Findings and claims checked

- The original wave 2 receipt-fingerprint failure now passes. Global and system ignore rules preserve the receipt digest for ignored notes. Untracked source still changes it. The check also passes in a linked worktree.
- Redirecting Git environment values do not redirect the new untracked query. The query has explicit repository paths, output and time limits, path validation, and owned-process cleanup. Fresh mutations exercised these boundaries below.
- Fingerprint parity passed for staged, unstaged, deleted, renamed, symlink, unusual-name, untracked, and runtime-noise cases. Captured HEAD remains fixed. Replacement objects and inherited repository redirection do not alter strict audit reads.
- Static inspection confirms captured committed opt-in and CI refusal of null/skipped EU results. Fresh executable probes for those repairs belong to the parallel test/security reviews; they are not claimed as my own executions.
- Static inspection found no new duplicate external-write path. Earlier exclusive scaffold writes, Windows refusal, and Node hard timeout remain present. This wave did not repeat their platform/process probes.
- V1, receipt grammar, and Trust CI producer bytes are unchanged in the comparison below. Core accepts V2 evidence without importing the Trust CI producer. The isolated successor producer remains outside this completion claim.

## Fresh controls

Working directory for the bounded test command: the private `code-review-wave3/candidate` clone.

```sh
TMPDIR=/home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/code-review-wave3/tmp PYTHONDONTWRITEBYTECODE=1 taskset -c 0-7 python3 -m pytest -q -n 8 -p no:cacheprovider --tb=short /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/code-review-wave3/test_global_ignore_receipt.py /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/code-review-wave3/test_fingerprint_parity.py /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/code-review-wave3/test_linked_worktree_receipt.py tests/test_eu_audit_attestation.py::CiAuditTests::test_receipt_keeps_global_and_system_ignored_notes_but_not_source_changes tests/test_eu_audit_attestation.py::CiAuditTests::test_receipt_global_excludes_cannot_redirect_git_identity tests/test_eu_audit_attestation.py::CiAuditTests::test_global_ignore_cannot_admit_uncommitted_decision_input tests/test_eu_audit_attestation.py::CiAuditTests::test_receipt_untracked_inventory_is_bounded_and_validated tests/test_eu_audit_attestation.py::AttestationClaimTests::test_exact_successful_execution_is_required
```

Observed: exit `0`; **12 passed, 29 subtests passed in 5.60s**.

Read-only unchanged-byte control, run in the source candidate:

```sh
git diff --exit-code 287e64f99b01db44cb6eeeb10f307ccda6f91c1d HEAD -- .getzilla/getzilla/util.py engineering/contracts/schemas/trust-ci-attestation-envelope.v1.json trust-ci/
```

Observed: exit `0`, no output.

## Fresh mutation probes

The private harness changes only the private clone and restores original bytes after each run. Runs were sequential because they share one private file. Each child uses the same eight-CPU allocation. These are private harness references, not exploit instructions.

```sh
GETZILLA_SERIAL=1 python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/code-review-wave3/run_mutant.py G1
GETZILLA_SERIAL=1 python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/code-review-wave3/run_mutant.py G2
GETZILLA_SERIAL=1 python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/code-review-wave3/run_mutant.py G3
GETZILLA_SERIAL=1 python3 -B /home/pall/projects/getzilla/.getzilla/runtime/scratch/eu-act-reviews-20261021/code-review-wave3/run_mutant.py G4
```

| Probe | Fault introduced | Observed result | Outcome |
| --- | --- | --- | --- |
| G1 | Suppress global/system ignore configuration | Test exit `1`; 2 failed, 1 passed, 4.78s | killed |
| G2 | Retain inherited redirecting Git environment | Test exit `1`; 1 failed, 4.22s | killed |
| G3 | Remove the untracked-output bound | Test exit `1`; 1 failed, 4.05s | killed |
| G4 | Disable the untracked-query deadline | Test exit `1`; 1 failed, 14.16s | killed |

Exact child commands and concise failure output are retained in private `code-review-wave3/out-G1.txt` through `out-G4.txt`. Four mutants were killed; none survived or remained inconclusive in this bounded set. This is not a blanket mutation-coverage claim.

## Limits

Direct opt-in race and null/skip mutation probes were assigned to the parallel reviewers to avoid duplicate work. Native Windows behavior, real C2PA signing, TypeScript type checking, the joined signed V2 producer flow, the full local PR gate, and external exact-head checks were not executed in this review. Those claims remain unexecuted here. Static observations above have only the stated executable support. Prior wave reports remain historical failures, not current passing evidence. No candidate report, verification receipt, or approval was written by this reviewer.
