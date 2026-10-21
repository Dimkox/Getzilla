# Test review: strict verification dispositions

FAIL. One blocking security test gap needs repair and a fresh review. The final qualifying gate is NOT_RUN.

Route: d834158878e0. Candidate: /home/pall/projects/liqvera/.getzilla/runtime/getzilla-dispositions. Comparison base: e158ddc7263a55f5308944c5a426eb1e9f1a4327.

Before and after identity were identical:

- HEAD: 9e29128aed4abea3dbe50d7f797aecbb26ff17d9
- Git tree: eb9006a8a0e0b861a101b15d6094ddb6df228f96
- Actual tracked-byte/mode manifest SHA-256: c7cc1491cb39110fbd95a460ccbf9c8afdb9c8cf5c84288f666fb14ef2c393b2
- Status: clean, including untracked files.
- reviewed-tree-modified: no

The merge base with origin/main is the stated comparison base; local main is ancestor 2bb417431f1e4b9494e4af71ebf27adb1d04d898. Merged published tags include v2.2.0, v2.2.1 and v2.3.0. Worktrees were inventoried without cleanup.

Private scratch: /home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-test-review, mode 0700 under trusted non-sticky runtime parents. Its snapshot reproduced all 5,471 tracked blobs (53,272,235 checkout bytes), content and executable modes. The normal CRLF checkout of bin/getzilla.cmd was preserved and checked against its Git-normalized blob; the first strict raw-blob preflight detected that difference before probes. All candidate and snapshot contents were rechecked after probes; every mutation was restored. before.json, after.json and source-manifest.json retain the checks. Tests used only CPUs 6-11 and private TMPDIR; mutations ran sequentially.

## Blocking finding

T1: The standalone-token boundary is not tested with valid hostile-name bindings, and the current implementation accepts Unicode and escaped credential suffixes. At .getzilla/getzilla/verification_dispositions.py:79-83, Python \w does not cover ZWNJ, ZWJ or combining marks. A preceding closing brace in an escaped identifier also passes. With correct file hash, match hash and scanner column, the reviewer reproduced auth\u200ctoken, auth\u200dtoken, auth\u0301token and auth\u{61}token. Each returned pass with disposed=1 and unresolved=0; all must remain blocking under the documented standalone-token contract. The four strings used synthetic address-shaped values in local Git fixtures only.

At tests/test_verification_dispositions.py:140-149, auth_token and obj.token use column=1 and hash the whole assignment, although the scanner matches only the token suffix. Those fixtures reject an invalid locator/hash before exercising the boundary. Removing the entire preceding-character guard survived all 22 native disposition tests. A separate reviewer oracle with correct bindings passes on the original ASCII guard and fails on that mutant. Repair the boundary and bind each hostile fixture to the actual scanner occurrence, including Unicode and escaped identifier cases. The parallel code reviewer first identified the Unicode issue; this review independently reproduced it and identified the masked native coverage.

## Executed checks and mutations

Working directory for test commands: private scratch/snapshot. Common command prefix P (literal absolute TMPDIR):

```text
taskset -c 6-11 env TMPDIR=/home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-test-review/tmp PYTHONDONTWRITEBYTECODE=1 GETZILLA_SERIAL=1 python3 -B
```

Baseline: P -m unittest tests.test_verification_dispositions tests.test_manifest_package.ManifestTests.test_disposition_helper_ships_without_target_review_policy. Observed: 23 tests in 7.453s, OK, exit 0. This includes real local Git fixtures, raw/effective findings, repeated matches, closed-schema and path guards, source changes, EOF worktree/index/HEAD binding, error retention, long output and package inclusion/exclusion.

Mutation driver command: python3 /home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-test-review/mutation_runner.py. Each row below was run as P -m unittest followed by the exact listed case names prefixed with tests.test_verification_dispositions.DispositionTests. Mutations affect only private scratch; logs and complete argv/edits are retained in mutation-results.json.

| ID | Mutation | Exact test suffixes | Observed result |
|---|---|---|---|
| M1 | Disable duplicate JSON-key rejection | test_malformed_duplicate_key_version_and_size_fail_without_findings | Killed: 1 assertion failure, exit 1 |
| M2 | Replace preceding-character eligibility expression with True | test_address_shape_does_not_admit_credential_names_or_opaque_values | Survived: 1 test OK, exit 0 |
| M3 | Enumerate only the first match per rule | test_absent_policy_keeps_every_match_blocking; test_one_disposition_never_suppresses_second_match_on_same_line | Killed: 2 assertion failures, exit 1 |
| M4 | Disable evidence-content hash comparison | test_closed_schema_rejects_invalid_and_duplicate_entries_outside_selection | Killed: 2 assertion failures, exit 1 |
| M5 | Allow Git stderr when other output is disposed | test_unknown_git_output_errors_and_selection_findings_cannot_be_disposed | Killed: 1 assertion failure, exit 1 |
| M6 | Use worktree bytes for every Git layer | test_staged_and_worktree_eof_are_bound_to_their_own_bytes; test_current_worktree_hash_cannot_dispose_a_different_head_blob | Killed: 2 assertion failures, exit 1 |
| M7 | Return immediately from assert_current | test_evidence_mutation_during_scan_fails_closed | Killed: 1 assertion failure, exit 1 |

M2 confirmation: P -m unittest tests.test_verification_dispositions, with M2 applied, ran 22 tests in 2.353s, OK, exit 0. Thus the survivor is a demonstrated coverage gap, not an inconclusive test crash.

Reviewer probe: P /home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-test-review/boundary_probe.py. Original source: nine cases, four unexpected passes, exit 1. With --ascii-only: original source five cases, zero mismatches, exit 0; M2 source five cases, two unexpected passes, exit 1. Correctly bound ASCII tests kill M2, while the independent Unicode/escape probe exposes the current implementation defect. boundary-results.json and logs retain exact commands and outputs. No mutant was inconclusive.

## Evidence limits

The changed code, tests, reference documentation, package assertion and change analyses/control evidence were read. Documentation promises standalone token assignments and no active shipped policy; the executed package assertion confirms helper inclusion and policy exclusion. No new external mutation path was identified by static review, so duplicate external writes are not applicable to this diff. A live external-write or installed-target scenario was not executed.

The prior committed named control passed 23 tests at 71c0cd7 and is historical evidence, separate from this fresh 9e29128 scratch baseline. The recorded 58-case packaging run and neighboring checks were reviewed, not rerun here. The earlier scanner-heavy broad run was interrupted after 53 passes and remains incomplete. No full suite, qualifying PR gate, cross-platform run, Liqvera successor acceptance, deployment, publication, payment or other live action was executed. Aggregate size exhaustion and adversarial filesystem races beyond the included deterministic source-change tests were not separately probed. These unexecuted claims are not passes. The candidate must be repaired and independently reviewed again before a qualifying gate or passing receipt.
