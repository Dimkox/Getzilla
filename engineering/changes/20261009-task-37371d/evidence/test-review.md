# Test review: PASS, bounded scope

No blocking finding in tests, security or duplicate mutations. Route `37371d21accb`. Inspected full base `5d5b45f42f8a9f2bc0303b4d16b5d4e54caad5b9`..HEAD and repair delta `75ff49d`..HEAD. Prior reports are historical.

Candidate before and after: HEAD `3e59aa153e4eb0c2d1b71e5b55d723d14949ac9b`; Git tree `08c67e409236086b4e890384071876b464a48073`; fingerprint `70b24e2556958d779dda0131a90368abe7b2f50247223fc35fb4af99853d105a`. Status clean at both observations.

reviewed-tree-modified: no

Scratch `/home/pall/getzilla-session/test-review-repaired-vLGD8n/repo` was created with `git clone -q --no-hardlinks /home/pall/getzilla-session/Getzilla <scratch>`. Its private parent and trusted enclosing parent are owned by pall, mode0700, non-sticky. Exact committed snapshot and fingerprint matched before execution. One sequential unittest worker used CPU4-7. No candidate tests or artifacts were written.

Fresh baseline command:

```text
taskset -c 4-7 python3 -m unittest tests.test_review_source tests.test_install_scripts tests.test_history tests.test_project_state tests.test_ci_gate -q
107 tests; OK; 18.551s.
```

Fresh scratch mutation probes:

- Consumer binding: replaced the PASS review-source consumption condition in receipts.py with false. Command `taskset -c 4-7 python3 -m unittest tests.test_review_source.ReviewSourceTests.test_consumption_rejects_missing_and_forged_binding -q`. Four missing/tree/commit/report-digest assertions failed. KILLED; 2.235s.
- Report guard: replaced the six-name allowlist with generic Markdown under evidence. Command `taskset -c 4-7 python3 -m unittest tests.test_review_source.ReviewSourceTests.test_index_and_analysis_cannot_be_supplied_as_review_report tests.test_review_source.ReviewSourceTests.test_rejects_other_report_directory_and_executable_evidence_delta -q`. Four assertions failed for README, analysis and checkpoint admission. KILLED; 1.989s.
- Installer provenance test contract: removed its repository identity assertion. Command `taskset -c 4-7 python3 -m unittest tests.test_install_scripts.InstallScriptContractTests.test_published_install_contract_allows_a_new_source_version_without_git_history -q`. Negative repository case failed because no AssertionError was raised. KILLED; 0.013s. This probes the binding test, not production installer behavior.

Restored each mutant in scratch. Baseline tests exercise real Git receipt admission and consumption. Negative cases retain the earlier reviewed commit; fixture freezing does not hide those source deltas. New installer cases admit a newer source VERSION without Git history and reject wrong repository, malformed tag/object, absent installer digests and changed installer bytes. History tests pass unchanged. No new external mutation path exists. Deferred Low issue73 remains outside this repair.

Limits: Windows workflow selects review-source tests and the portable Git-index mode check. Native Windows execution is pending; symlink cases can skip when permissions deny symlinks. Published provenance tests bind recorded local facts and digest bytes; they do not reobserve the remote publication. Full final PR verification, external exact-head checks and production acceptance were not executed or established here. Existing fixture/status/hook/recovery edits were inspected; this fresh bounded run does not claim all their modules passed.
