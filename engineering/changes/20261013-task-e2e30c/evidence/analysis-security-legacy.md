# Legacy security issues: criterion audit

Route e2e30c9f2878. Candidate HEAD 6dd06ff5b96692a01812fbac6252fd08f6169f91, tree 8278dd37de4c79edaac4bb62e1c1884f20cd04f6. Actual PR base/main 540c12f93e798c2f483455a5086ab0018ac3216e. Source read-only; only this controller runtime report written. Issue bodies/comments read from saved all-issues.json and issue-N-comments.json. No full verifier, CI, test run or dangerous command execution.

## Criteria and disposition

- #36 shell secret reads: repaired in source. evaluate_pre_tool calls shell_secret_reference for Bash at _policy_legacy.py:2257; policy.py sensitive classifier uses the same scan. test_policy_bypasses.SecretReadTests.test_shell_secret_reads_are_blocked and test_shell_secret_glob_read_is_blocked bind the claim. Later hardening/parser modules cover quoting, recursive readers, enclosing secret directories and bounded fail-closed scans.
- #36 root secret glob paths: repaired. _glob_match adds the leading **/ pattern without that prefix, so root keys/PEMs/id_rsa/credentials/secrets paths match. test_root_level_secrets_are_blocked_for_read and nested/read controls cover this. No remaining repair identified for either original criterion.
- #37 gh global options before merge/workflow: repaired by argument parser. test_gh_global_repo_option_does_not_hide_merge and test_gh_global_repo_option_does_not_hide_workflow_or_release cover it.
- #37 gh API equals-method syntax: repaired. test_gh_api_method_equals_form_is_an_external_write covers it.
- #37 low-level git push helper/global options: repaired. test_git_send_pack_is_a_push and test_git_global_flags_do_not_hide_push cover it; hardening covers helper executables, aliases and nested command authority.
- #37 docker/npm publication variants/global options: repaired. test_docker_and_npm_publish_spellings plus parser tests for publisher global options bind the criterion.
- #37 root recursive removal, reordered/separate flags: repaired. test_recursive_remove_of_root_or_home_is_blocked covers original forms; hardening expands root-like operands, wrappers and other deletion tools.
- #37 PR review approval: repaired as external write. test_gh_pr_review_requires_external_write_grant and exact-grant positive control bind it. No remaining repair identified for the listed criteria.
- #38 protected-path wildcard creation: repaired by _normalize_grant_resource, rejecting * ? [] {} before grant writes. test_protected_path_grant_refuses_patterns binds it.
- #38 external wildcard acceptance without route gate: repaired by unconditional resource normalization before gate evaluation. test_external_write_grant_refuses_patterns_without_route_gate binds it. External URLs may contain literal query ?; approval matching is exact equality, not fnmatch, so query punctuation does not widen authority.
- #38 stored legacy/tampered wildcard matching: repaired; has_valid_approval compares exact resources at state.py:428. test_stored_pattern_grant_does_not_authorize_control_plane_writes covers protected targets.
- #38 CLI promises fnmatch: repaired; --resource help says wildcard patterns are refused. test_cli_refuses_wildcard_resource_without_traceback binds CLI rejection. No remaining repair identified.

## Delivered history

Git history contains merged PR53 (9d1e97f, exact grants), PR54 (07b461c, original secret/action fixes), PR59 (d438de5, follow-up authority/read/delete hardening), PR62 (0d88581, bounded scans/wrappers), PR69 (5d2d631, parser-gap fixes). All are in candidate ancestry. Saved #36/#37 comments state the original repair landed in PR54; saved issue state remains open. #38 has no closure comment but its dedicated repair and tests are present.

## Necessary remaining work and limits

No new implementation is required for these original issue-body criteria based on source/history inspection. Keep dedicated regression coverage in the later repair-batch verification. Closure needs fresh criterion-specific evidence on the final candidate, not old PASS claims. This report is static analysis, not a passing review or test receipt. The earlier 123-test observation belonged to HEAD 5d5b45f and is historical; it is not reused here. This audit does not claim every shell language, tool alias, dynamic interpreter or deployed installation is secure. New cmd/root-selection repairs are distinct candidate work, not proof that arbitrary shell bypasses cannot exist.

Commands: git rev-parse HEAD HEAD^{tree}; git log --all --oneline with PR/issue filters; bounded rg/sed of policy/state/CLI and tests; saved JSON issue/comment inspection; git status --short (only active change package untracked).
