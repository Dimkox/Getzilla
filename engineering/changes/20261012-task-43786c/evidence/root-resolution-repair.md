# Root-resolution repair observation

Issue: #80. Existing branch: fix/codex-cmd-hooks-20261011. Starting HEAD: 6dd06ff5b96692a01812fbac6252fd08f6169f91. PR comparison base: 540c12f93e798c2f483455a5086ab0018ac3216e. This report records implementation controls, not a qualifying verification receipt or independent review.

## Cause and bounded change

The root parser treated a dot in any argv position as shell source dispatch. It also searched raw command text for control characters inside quoted arguments. Ambiguous-shell denial objectives omitted command identity and therefore grouped independent commands. The repair checks dynamic dispatch at executable positions, recognizes literal POSIX quoted arguments while retaining dynamic substitution/operator denial, and includes only a normalized-command/workdir digest for ambiguous-shell objectives. Known sensitive-action objective grouping stays unchanged. Windows control-flow parsing retains its previous conservative behavior.

## Observed controls

- RED: the initial two-method module produced four failed safe-command subtests. Adding quote and independent-objective cases produced six further failed subtests/assertions before their repair.
- GREEN: tests.test_hook_command_arguments plus tests.test_pre_tool_circuit_breaker passed 10 tests in 1.077 seconds after the source changes.
- Nearby controls: tests.test_hooks, tests.test_harness_hook_payloads, tests.test_policy_shell_targets, tests.test_policy_bypasses and tests.test_policy_parser_gaps passed 105 tests in 60.648 seconds, under a 180-second timeout on CPUs20-23.
- The expanded tests.test_hook_command_arguments passed eight methods in 0.623 seconds. Its fresh copied-repository hook admits the native Trivy and quoted-search payloads and denies a protected external action. Payload command text is never executed by this fixture.
- getzilla_harness.py reported no generated drift. git diff --check passed.

The hook on the host has not been replaced. Trivy version0.74.0 was observed earlier; actual scanning remains unproved. No provider call, production write, merge or deployment occurred. Full verification and fresh independent reviews remain pending.

## Preserved work and remaining issue

The all-issues candidate remains at 574c1e10d98fea96a0b31417d502faa0a3f67d08 with its prior uncommitted repair batch. Its six-part plan and leaf branches remain intact. Do not transplant this patch into that dirty worktree without a coordinated owner handoff.

The canonical root active-route changed to another session during this work. This invalidated an exact local grant before its TTL expired. The observed external state change required a fresh exact grant for the same already authorized file; no wildcard or new operation was granted. Session isolation and non-development prompt routing are not repaired by this parser patch.

Rollback: revert this isolated source patch through the normal PR path. Preserve all other issue repairs and immutable published assets. Do not disable the policy or delete denial ledgers. Existing main and deployed trust material remain unchanged.
