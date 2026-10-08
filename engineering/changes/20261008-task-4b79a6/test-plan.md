# Test plan — Move the informational Windows full suite to a nightly workflow

## Risk-based scenarios

| Priority | Scenario | Evidence |
| --- | --- | --- |
| P0 | PR workflow is fast and the nightly workflow carries the suite | test_pr_workflow_gates_quickly_and_the_windows_full_suite_runs_nightly |

## Automated checks

- Unit: tests/test_structure.py.
- Integration: `getzilla_verify.py --mode pr`.
- Contract: n/a.
- E2E: n/a.
- Static analysis: ruff, bandit and OpenGrep via verify.

## Manual checks

- Timings from run 37790284333: windows 14:10:27–14:47:07 UTC, informational step 14:11:01–14:47:03 UTC, linux 14:10:27–14:16:37 UTC.
