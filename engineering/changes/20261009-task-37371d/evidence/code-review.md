# Code review — PASS with deferred Low finding #73

Fresh scope: security, duplicate external writes and tests across base `5d5b45f42f8a9f2bc0303b4d16b5d4e54caad5b9` through current HEAD. Inspected repair `75ff49d..HEAD`. No blocking defect found. Historical reports in the candidate are not this review's PASS evidence.

- Low #73 remains: removing the ancestry guard survives `test_rejects_nonancestor`, because that fixture also changes source. An independent equal-tree orphan probe isolates the guard and confirms current code rejects it.
- The installer repair correctly binds documented installation to the published release rather than an unpublished source version. Tests retain repository, tag, object-format and installer-digest checks. The no-history fixture rejects each invalid binding and changed installer bytes.
- No external-write implementation changed. Duplicate external writes do not apply.
- `prepare_review_source` commits fixture changes; dedicated dirty/staged/untracked tests retain rejection coverage. Its committed success fixtures do not establish dirty admission.

Source before/after: HEAD `3e59aa153e4eb0c2d1b71e5b55d723d14949ac9b`; tree `08c67e409236086b4e890384071876b464a48073`; fingerprint `70b24e2556958d779dda0131a90368abe7b2f50247223fc35fb4af99853d105a`. Candidate clean before/after.

reviewed-tree-modified: no

Scratch `/home/pall/getzilla-session/code-review-repaired-6qbwsqzk`, mode0700, under owner-controlled non-sticky mode0700 `/home/pall/getzilla-session`. `git clone --quiet --no-hardlinks /home/pall/getzilla-session/Getzilla <scratch>/repo` reproduced exact HEAD/tree. Tests and mutations ran only in scratch, sequentially, with `PYTHONDONTWRITEBYTECODE=1 TMPDIR=<scratch>/tmp taskset -c 0-3`.

Executed control:

```text
python3 -m unittest tests.test_review_source tests.test_install_scripts.InstallScriptContractTests.test_documented_install_checks_sha256_of_the_pinned_installer_before_running_it tests.test_install_scripts.InstallScriptContractTests.test_published_install_contract_allows_a_new_source_version_without_git_history -q
16 tests; OK, 7.294s.
```

Fresh mutation probes changed one scratch guard to `if False`, ran the exact named command, then restored original bytes:

| Guard disabled | Exact command | Result |
|---|---|---|
| Ancestry | `python3 -m unittest tests.test_review_source.ReviewSourceTests.test_rejects_nonancestor -q` | SURVIVED, exit0; Low #73. |
| Report path allowlist | `python3 -m unittest tests.test_review_source.ReviewSourceTests.test_rejects_source_delta_and_dirty_or_untracked_candidate -q` | KILLED, exit1; committed-delta assertion failed. |
| Consumption binding validation | `python3 -m unittest tests.test_review_source.ReviewSourceTests.test_consumption_rejects_missing_and_forged_binding -q` | KILLED, exit1; four forged/missing-binding assertions failed. |

Fresh independent ancestry probe used `git commit-tree <fixture HEAD tree> -m 'unrelated equal tree'` without parents, followed by `review_source_binding(fixture_root, orphan_commit, report)` in a fresh Python subprocess. Original code exited1: `reviewed commit is not an ancestor of frozen HEAD`. The ancestry mutant exited0: ADMITTED. This independent probe kills that mutant.

Final source check: `git rev-parse HEAD HEAD^{tree}`, `git status --porcelain`, and `getzilla.util.tree_fingerprint(Path.cwd())` returned the identities above and empty status.

Limits: no Windows execution, full-suite run, concurrent filesystem-race probe, external checks, or production qualification. Static path/publication/external-write inspection is not executable proof. Installer controls prove local bytes and declared publication binding, not fresh remote tag authenticity. Final exact-head verifier and external gates remain pending.
