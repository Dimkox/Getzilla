# Test plan — Close hook policy bypasses (secret reads, merge/push/publish spellings, rm -rf /)

## Risk-based scenarios

| Priority | Scenario | Evidence |
| --- | --- | --- |
| P0 | Shell/Read secret reads denied (root, nested, outside repo, glob, nested shell, unparseable) | `tests/test_policy_bypasses.py::SecretReadTests` |
| P0 | gh/git/docker/npm spellings of merge/push/publish denied; grant still works | `tests/test_policy_bypasses.py::ProductionActionSpellingTests` |
| P0 | `rm -rf /` spellings denied, bounded removes allowed | `tests/test_policy_bypasses.py::RecursiveRemoveTests` |
| P1 | `gh pr review` needs exact external-write grant | `tests/test_policy_bypasses.py::PullRequestReviewTests` |
| P1 | No regression in hook/policy/protected-write behaviour | `tests/test_policy.py`, `tests/test_hooks.py`, `tests/test_policy_shell_targets.py`, `tests/test_protected_write*.py`, `tests/test_pre_tool_circuit_breaker.py` |

## Automated checks

- Unit: `python -m pytest -n 2 tests/test_policy_bypasses.py tests/test_policy.py tests/test_hooks.py ...` (130 passed, 2 skipped before freeze).
- Integration: reviewer probe harness through `.grok/hooks/pre_tool_use.py` (all S1-S6/S8/S9 probes deny).
- Static analysis: ruff, bandit (clean on changed files).
- Final: `python3 scripts/getzilla_verify.py --mode pr`.

## Manual checks

- `python3 scripts/getzilla_harness.py` reports no drift.
