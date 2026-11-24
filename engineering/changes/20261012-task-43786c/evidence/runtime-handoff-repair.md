# Runtime handoff repair — UNVERIFIED

Owner handoff from session 01a1343a-1cde-74e0-b0b7-e6155829f8fb is accepted into the existing plan. Original diagnostics remain in canonical checkout engineering/observations/diagnostic-issues-20261013.json and startup-d7d4871cafb3.json. They bind 540c12f93e798c2f483455a5086ab0018ac3216e. Interrupted tests are INCOMPLETE, not PASS or functional FAIL.

PR79 branch: fix/codex-cmd-hooks-20261011. Starting HEAD aaa41fc616b1bd7c931bb1dd9534b44e104343f4. PR base 540c12f93e798c2f483455a5086ab0018ac3216e. Root remains sole writer.

## Defects

1. Session isolation remains OPEN. All hooks, nested policy/grant/receipt consumers, direct workflow authority readers and active-change binding need consistent selection. Do not claim isolation from a prompt-only fix. Identity comes from harness context, never tool_input. Preserve CLI compatibility and one writer per candidate. Fail closed on foreign route/change bindings.
2. Literal shell parsing is committed in dab4bf1/aaa41fc; historical observations are in root-resolution-repair.md. Installed host hook is unchanged.
3. Fixture repair excludes machine runtime before copytree traversal, then creates empty runtime with .gitkeep. HTTP non-mutation assertions use synthetic fixture state. No real runtime snapshot is needed.

## Acceptance and tests

- New tests/test_fixture_runtime_isolation.py rejects source runtime traversal through a scandir sentinel in a synthetic source, in both minimal modes. It checks ordinary source copying and empty runtime creation.
- tests/test_demo_http.py keeps subprocess prohibition and compares paths, contents and mtime before and after requests in the isolated fixture.
- Session repair must test A/B separation, foreign legacy fallback refusal, nested consumers, CLI selection, separate worktrees, route/change mismatch, context reset, and one candidate owner. Implementation pending.

## BLOCKED validation

Regression was added before repair. Command `env TMPDIR=/home/pall/projects/getzilla/.getzilla/runtime/issues taskset -c 20-23 python3 -m unittest tests.test_fixture_runtime_isolation -v` was rejected before execution by host PreToolUse with an existing same-objective circuit breaker and ambiguous-command-root. Tests NOT RUN. No retries through another executor, guard disabling, passing receipts, dependent review, or final qualifying verifier. Source remains UNVERIFIED. No manual override was created.

Read-only analyses by repo_explorer, architect, docs_researcher and integration_architect completed. They confirmed the fixture repair approach and identified the cross-cutting route/change isolation requirements above. They did not execute tests or approve the source.

## Preserved work and rollback

The all-issues branch fix/all-open-issues-20261013 remains in .getzilla/runtime/worktrees/all-issues-20261013 at 574c1e10d98fea96a0b31417d502faa0a3f67d08 with its dirty repairs preserved. Its engineering/changes/20261013-task-e2e30c/issues-ledger.md retains all six numbered slices and original hashes. Do not blindly reset or cherry-pick into it.

Revert this fixture commit to roll back. No deployment, installed hook or production state changed. Resume blocked test work only after a verified relevant change to the active hook/denial state, then run regression and HTTP controls, independent reviews and exact-head gates. Do not retry an unchanged denied objective.
