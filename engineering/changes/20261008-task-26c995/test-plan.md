# Test plan — Refuse missing bandit and OpenGrep binaries in pr/release gates

## Risk-based scenarios

| Priority | Scenario | Evidence |
| --- | --- | --- |
| P0 | bandit binary missing | test_missing_bandit_binary_is_refused_in_pr_and_release |
| P1 | opengrep binary missing | test_missing_binary_is_refused_and_opengrep_is_mandatory_in_pr_and_release |

## Automated checks

- Unit: tests/test_quality_gates.py.
- Integration: `getzilla_verify.py --mode pr`.
- Contract: n/a.
- E2E: n/a.
- Static analysis: ruff, bandit and OpenGrep via verify.

## Manual checks

- Findings C2 (review of the verifier) and M1 (review of #31).
