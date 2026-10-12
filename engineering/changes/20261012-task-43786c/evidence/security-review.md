Recommendation: PASS for source repair and refreshed consent metadata. Final local PR and external exact-head gates remain required.

- Security: no blocking finding. Actual full base-to-candidate code diff was reviewed previously. Fresh comparison confirms only human-gates.json changed since that review. Consent records cover isolated branch transport and conditional merge. They require exact runtime grants. They claim no signed human security approval, deployment authority or passing gate. Null resources in these metadata records do not serve as external-write grants.
- Double writes: none added. Consent metadata performs no mutation. Command normalization executes no commands.
- Tests: fresh private-copy payload run passed 23 tests in 13.430s. Consent-record consistency assertions passed. Existing source checks and mutation evidence below are historical/reused for byte-identical code only.
- Residual risk: unchanged outer hook and import failures remain fail-open. Early validation denial bypasses the existing denial ledger. Full shell-policy abuse and deployed authorization were not verified. Final gates remain pending.

Source: /home/pall/.local/share/getzilla-worktrees/fix-codex-cmd-20261011
Route: 43786cadd549; security_reviewer is allowed.
Base: 540c12f93e798c2f483455a5086ab0018ac3216e
HEAD before/after: 66049ff92c52a088d21560c093f7234b2d5f84cb
Git tree before/after: 24200066e9388f7dbe36c58b5846868e82c25fd0
Fingerprint before/after: c7c0b4e3e8374b2a66affe66da010df1f8d34609c3f0fb34f56f8f2141923790
Inventory before/after: clean.
reviewed-tree-modified: no

Fresh scratch: /home/pall/.local/share/getzilla-cmd-review-20261012/security/refreshed-snapshot
Parent and reviewer directory: trusted non-sticky 0700. Local no-hardlink clone reproduced the exact clean HEAD. Fresh command from refreshed-snapshot:
taskset -c 12-17 python3 -B -m unittest tests.test_harness_hook_payloads -q
Observed: Ran 23 tests in 13.430s; OK.
Fresh metadata assertions: actions equal [None, git-push-branch, pull-request-merge]; every actor equals owner-standing-L5. Result PASS. Static record review confirms transport is labelled UNVERIFIED and merge requires green exact-head checks, independent review and resolved threads. Capacity and allocation remain unchanged: CPUs 12-17, at most two concurrent test processes.

Historical/reused evidence ONLY, not fresh qualification or probes for new HEAD:
Original HEAD cde3947fde6aca4c7058c7114af957b61043a661; Git tree 56f76f3306e0a346910c3fcf2d009ebddeb892c9; fingerprint f04f3fcfd219ad3585f7500f7d7e8b2ba1ab8c9940d29bb1a9225e895b3644f5. Original report retained at security/historical-cde-security-review.md. Original scratch security/snapshot. Reuse covers unchanged hook code and tests only. No new critical code was introduced by the metadata delta. The historical probe commands, results and limits follow:

Commands (run from scratch unless stated):
1. taskset -c 12-17 python3 -m unittest tests.test_harness_hook_payloads -q
   Result: Ran 23 tests; OK.
2. taskset -c 12-17 python3 -B /home/pall/.local/share/getzilla-cmd-review-20261012/security/extra.py
   Result: 32 malformed-envelope/root-alias checks PASS; payload commands were never executed.
3. taskset -c 12-17 python3 /home/pall/.local/share/getzilla-cmd-review-20261012/security/probes.py
   Result: mapping initially SURVIVED; gate KILLED (9 failures); type KILLED (5 failures); conflict KILLED (1 failure). Driver and exact test commands are retained in probes.py and probes.log.
   Each mutant runs: taskset -c 12-17 python3 -B -m unittest tests.test_harness_hook_payloads.HarnessHookPayloadTests.<test> -q
   Mapping test: test_codex_cmd_payload_reaches_sensitive_command_policy.
   Other three: test_codex_conflicting_and_malformed_commands_are_denied.
4. Expanded mapping mutant command:
   taskset -c 12-17 python3 -B -m unittest tests.test_harness_hook_payloads.HarnessHookPayloadTests.test_normalization_preserves_input_and_does_not_invent_alias_contracts -q
   Result: KILLED; expected normalized command differs from empty result. Exact output: mapping-expanded.log.

Probe claims: mapping native command to policy text; explicit validation denial; nonstring validation does not escape into fail-open; conflicting aliases deny. Mapping mutant replaced cmd assignment with the prior alias or empty string. Gate mutant disabled the early denial. Type mutant removed the string guard before strip. Conflict mutant disabled alias mismatch validation. Initial mapping survival demonstrates that a denial alone cannot prove correct normalization; the expanded direct assertion killed that mutant. No unresolved mutant remains within these four claims.

Unexecuted claims: exhaustive JSON size/depth abuse, every shell syntax, deployed policies, production authz and external Trust CI. These require other scope or gates. Full PR qualification was not run by this reviewer. Parent-provided committed-HEAD smoke observations are not substituted for final verification. Findings remain limited to security, double writes and tests.
