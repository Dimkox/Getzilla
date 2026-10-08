# Test plan — Show package and advisory in known-vulnerabilities details

## Risk-based scenarios

| Priority | Scenario | Evidence |
| --- | --- | --- |
| P0 | Detail carries path and message | VerifierDetailTests |

## Automated checks

- Unit: tests/test_known_vulns.py.
- Integration: `getzilla_verify.py --mode pr`.
- Contract: n/a.
- E2E: n/a.
- Static analysis: ruff, bandit and OpenGrep via verify.

## Manual checks

- Observed `HIGH None: None` lines in the 2026-10-08 verify of fix/queue-analysis-loop-widening.
