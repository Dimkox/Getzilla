# Test plan — Refuse unchecked pinned dependencies in pr/release gates

## Risk-based scenarios

| Priority | Scenario | Evidence |
| --- | --- | --- |
| P0 | Unchecked pins refused | test_unchecked_pinned_dependencies_refuse_pr_and_release |

## Automated checks

- Unit: tests/test_known_vulns.py.
- Integration: `getzilla_verify.py --mode pr`.
- Contract: n/a.
- E2E: n/a.
- Static analysis: ruff, bandit and OpenGrep via verify.

## Manual checks

- Review finding C1 (known_vulns.py:461-475 + quality_gates.py:79-82).
