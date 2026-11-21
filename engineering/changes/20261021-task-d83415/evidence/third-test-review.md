# R3 independent test review

PASS within the bounded review scope. No remaining security or test blocker found. Both earlier findings are closed on this candidate. Final qualifying gate: NOT_RUN.

Route d834158878e0. Candidate: /home/pall/projects/liqvera/.getzilla/runtime/getzilla-dispositions. Base: e158ddc7263a55f5308944c5a426eb1e9f1a4327, still the merge base with fetched origin/main e42398ddaa41e662e921d7af68ab87b1e28e3554. Fifty worktrees were inventoried without cleanup; published tags v2.2.0, v2.2.1 and v2.3.0 remain ancestors.

Before and after:

- HEAD: 4c4cd124b2e382d3c6d8b19e2efe2c8fb45219ae
- Git tree: 3dd0c14d38b13e618a736735d5eefb830295cf32
- Actual tracked-byte/mode manifest SHA-256: 740ec75f6e32735aa860f17e5acabe9e967617bc4addc897cc394f97d734f6ba
- Status: clean, including untracked files.
- reviewed-tree-modified: no

Scratch: /home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-r3-test-review, mode 0700 under trusted non-sticky runtime parents. The snapshot exactly reproduced 5,487 tracked blobs, 53,359,467 checkout bytes and executable modes. Configured CRLF in bin/getzilla.cmd was preserved and verified against its Git-normalized blob. All candidate and scratch contents/modes were rechecked after restoring every mutation. before.json, source-manifest.json and after.json retain these checks. Tests/probes used CPUs 6-11 and private TMPDIR; mutations ran sequentially.

## Fresh verification

The actual disposition integration, repaired context scanner, occurrence-bound tests, reference documentation, package assertion and change evidence were reviewed. Rejection of the entire non-ASCII prefix, including comments/strings, matches the documented conservative eligibility rule. Unknown contexts keep the raw blocking finding. No new external-write path was identified by static inspection; duplicate external writes are not applicable to this diff.

Common exact test prefix P, working directory scratch/snapshot:

```text
taskset -c 6-11 env TMPDIR=/home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-r3-test-review/tmp PYTHONDONTWRITEBYTECODE=1 GETZILLA_SERIAL=1 /home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-gate-venv/bin/python -B
```

Baseline: P -m unittest tests.test_verification_dispositions tests.test_manifest_package.ManifestTests.test_disposition_helper_ships_without_target_review_policy. Result: 29 tests in 69.264s, OK, exit 0, with Python 3.12.3. This freshly exercises strict policy/source checks, raw findings, all-match scanning, EOF layers, Git errors/output retention and package inclusion/exclusion. baseline.json and logs/baseline.log retain the command/output.

Independent probe: P /home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-r3-test-review/boundary_probe.py; then the same command with --ascii-control-space-only. Results: 22 and four cases respectively, zero mismatches, both exit 0. Exact scanner bindings were used. Original Unicode/escaped credential suffixes, all five R2 mixed-whitespace forms, U+2028/U+2029 comment terminators hiding member access, Unicode in comments/strings, HTML-comment syntax and ASCII control whitespace now remain blocking. Four legitimate declaration/comment controls remain eligible. For all 26 synthetic sources, node --check <scratch>/tmp/<case>.js returned 0 (Node v24.22.0). Complete commands/results are in boundary-results.json and logs.

## Fresh mutation evidence

Driver command: /home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-gate-venv/bin/python /home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-r3-test-review/mutation_runner.py. Every row ran as P -m unittest with the listed suffixes prefixed by tests.test_verification_dispositions.DispositionTests. Exact edits, complete argv and output hashes are retained in mutation-results.json; raw output is in logs/<ID>*.log.

| ID | Mutation | Test suffixes | Outcome |
|---|---|---|---|
| M1 | Remove standalone-context admission guard | test_address_shape_does_not_admit_credential_names_or_opaque_values; test_real_scanner_suffix_never_disposes_unicode_or_escaped_credentials | Killed: 26 assertion failures |
| M2 | Disable entire-prefix ASCII check | test_non_ascii_comment_and_string_prefixes_are_conservatively_refused | Killed: eight assertion failures |
| M3 | Remove form-feed/vertical-tab from whitespace class | test_ascii_whitespace_preserves_declarations_and_member_rejection | Killed: six assertion failures |
| M4 | Disable HTML-comment rejection | test_unsupported_ascii_constructs_cannot_manufacture_standalone_context | Killed: three assertion failures |
| M5 | Replace final member-punctuation gate with True | test_ascii_whitespace_preserves_declarations_and_member_rejection | Killed: 18 assertion failures |
| M6 | Use worktree bytes for every Git layer | test_staged_and_worktree_eof_are_bound_to_their_own_bytes; test_current_worktree_hash_cannot_dispose_a_different_head_blob | Killed: two assertion failures |
| M7 | Permit Git stderr alongside disposed stdout | test_unknown_git_output_errors_and_selection_findings_cannot_be_disposed | Killed: one assertion failure |

All seven mutants exited 1 through expected assertions, with zero test errors. None survived or was inconclusive. The earlier boundary and FF/VT coverage gaps are now caught by native tests. This result applies to these selected probes, without an inferred blanket mutation-score threshold.

## Limits

Prior FAIL reports and implementation observations remain historical. The writer's reported 193 subtests, 131-failure mutation and real Liqvera 2/2/0 observation were reviewed, not substituted for this review's independently observed results. The earlier broader packaging controls were not repeated beyond the changed package assertion, and the abandoned broad run remains incomplete. No full suite, final gate, installed-target scenario, cross-platform run, exhaustive language-parser proof, aggregate-size exhaustion or adversarial filesystem-race campaign was executed. This review does not establish real public-contract provenance or complete the Liqvera successor audit. No secrets, live payments, deployments, publications or other external mutations were used. Unexecuted claims are not passes; final acceptance still requires the frozen candidate's qualifying gate and receipts after all reports are persisted.
