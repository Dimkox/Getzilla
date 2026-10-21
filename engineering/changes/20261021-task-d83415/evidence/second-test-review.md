# Fresh test review: repaired verification dispositions

FAIL. The first repair closes the original four bypasses, but mixed Unicode/ASCII whitespace still admits member-access assignments. The final qualifying gate is NOT_RUN.

Route d834158878e0; candidate /home/pall/projects/liqvera/.getzilla/runtime/getzilla-dispositions; comparison base e158ddc7263a55f5308944c5a426eb1e9f1a4327.

Before and after review:

- HEAD: 98ff57375f95cc93e5f3cc785a8105f23743d0a3
- Git tree: 52ffc8f3b4e8acec6c0f618cf062d388e84b6782
- Actual tracked-byte/mode manifest SHA-256: c1b15efef3aef509e3e2680e190455fb26401185faedfcf50b090ee673091682
- Status: clean, including untracked files.
- reviewed-tree-modified: no

The origin/main merge base remains the stated base; local main remains ancestor 2bb417431f1e4b9494e4af71ebf27adb1d04d898. Tags v2.2.0, v2.2.1 and v2.3.0 are ancestors. Worktrees were inventoried without cleanup.

Private scratch /home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-r2-test-review has mode 0700 under trusted non-sticky runtime parents. All 5,478 tracked blobs, 53,311,357 checkout bytes and executable modes were verified before testing and again afterward, against both candidate and restored scratch. The configured CRLF checkout of bin/getzilla.cmd was preserved and checked against its Git-normalized blob. before.json, source-manifest.json and after.json retain the identities. Only assigned CPUs 6-11 and private TMPDIR were used. Mutations were sequential and restored only in scratch.

## Blocking finding

R2-T1: Member-access whitespace combinations remain insufficiently tested. At .getzilla/getzilla/verification_dispositions.py:82-126, only ASCII whitespace is skipped. Other whitespace becomes previous, erasing the preceding dot. A final ASCII space satisfies the immediate separator guard. The current code therefore disposes client.<NBSP><space>token = <synthetic address>, and equivalent U+3000, U+2028 and U+FEFF forms. NBSP followed by a block comment and ASCII space also bypasses the guard. All five exact-bound fixtures returned pass, disposed=1, unresolved=0. Each source passed node --check. This violates the documented rejection of member access across whitespace/comments.

The repaired tests correctly compute the scanner's actual match hash and position, and the original ZWNJ, ZWJ, combining-mark and escaped-identifier cases now remain blocking. However, they cover a non-ASCII separator immediately before token without covering mixed separators that alter the remembered preceding punctuation. A related mutation removing form-feed and vertical-tab from the ASCII whitespace class survives all 24 native disposition tests. Reviewer control cases reject those member assignments on unmodified code and expose two unexpected passes under that mutant. Correct the Unicode context handling conservatively and add exact-bound member tests across whitespace classes, including combinations followed by ASCII whitespace and comments. This is one related security/test finding, not a blanket mutation-score requirement.

## Fresh commands and results

Test working directory: scratch/snapshot. Common literal prefix P:

```text
taskset -c 6-11 env TMPDIR=/home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-r2-test-review/tmp PYTHONDONTWRITEBYTECODE=1 GETZILLA_SERIAL=1 python3 -B
```

Baseline command: P -m unittest tests.test_verification_dispositions tests.test_manifest_package.ManifestTests.test_disposition_helper_ships_without_target_review_policy. Result: 25 tests in 4.684s, OK, exit 0. The package check confirms helper inclusion and active policy exclusion. Existing strict schema, source, occurrence, EOF, Git-error and output-retention tests ran freshly on this snapshot.

Independent closure/extension command: P /home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-r2-test-review/boundary_probe.py. Result: 14 cases, five unexpected passes, exit 1. Three legitimate controls pass; ASCII member/credential forms and all four original bypasses fail. The five new whitespace cases pass incorrectly. Every fixture uses the actual scanner line, column and match SHA, whole-file SHA and tracked local evidence. For each generated synthetic source, node --check <scratch>/tmp/<case>.js returned 0. Complete argv and results are in boundary-results.json and logs/boundary.log.

Fresh mutation driver: python3 /home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-r2-test-review/mutation_runner.py. All mutations were applied separately to the exact restored snapshot. The following suffixes run as P -m unittest tests.test_verification_dispositions.DispositionTests.<suffix>, except M3 runs the named module. mutation-results.json records each exact edit, full argv, exit and log hash.

| ID | Mutation | Test suffixes | Outcome |
|---|---|---|---|
| M1 | Remove standalone-context admission guard | test_address_shape_does_not_admit_credential_names_or_opaque_values; test_real_scanner_suffix_never_disposes_unicode_or_escaped_credentials | Killed, 26 assertions, exit 1 |
| M2 | Replace final previous-punctuation check with True | test_real_scanner_suffix_never_disposes_unicode_or_escaped_credentials | Killed, six assertions, exit 1 |
| M3 | Remove form-feed and vertical-tab from whitespace class | Entire tests.test_verification_dispositions module | Survived, 24 tests in 3.424s, OK, exit 0 |
| M4 | Scan only the first match per rule | test_absent_policy_keeps_every_match_blocking; test_one_disposition_never_suppresses_second_match_on_same_line | Killed, two assertions, exit 1 |
| M5 | Treat Git stderr as covered by disposed stdout | test_unknown_git_output_errors_and_selection_findings_cannot_be_disposed | Killed, one assertion, exit 1 |
| M6 | Use worktree bytes for index and HEAD | test_staged_and_worktree_eof_are_bound_to_their_own_bytes; test_current_worktree_hash_cannot_dispose_a_different_head_blob | Killed, two assertions, exit 1 |

Supplemental command: P /home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-r2-test-review/boundary_probe.py --ascii-control-space-only. Original source: four cases, zero mismatches, exit 0. M3 source: four cases, two unexpected passes, exit 1. Thus M3 survives native coverage but is killed by the supplemental oracle. No mutation was inconclusive. whitespace-results.json and logs retain the outputs.

## Limits

The actual implementation/test repair, complete disposition integration, reference documentation, package assertion and change evidence were reviewed. No new external write path was found by static inspection; duplicate external writes are not applicable to this diff. No live or installed-target mutation was exercised.

The earlier FAIL reports remain historical evidence for 9e29128. Source 4998635's bounded/committed observations and reported two real Liqvera classifications were read, not reused as fresh acceptance. The previous 58-case packaging result was not rerun beyond the changed package assertion. The abandoned broad control remains incomplete. No full suite, final qualifying gate, cross-platform run, exhaustive language-parser proof, aggregate-size exhaustion, adversarial filesystem-race campaign or Liqvera successor audit was executed. No credentials or live payments, deployments, publications or other external mutations were involved. Unexecuted claims are not passes. A repaired successor needs fresh independent review before the final frozen gate and receipts.
