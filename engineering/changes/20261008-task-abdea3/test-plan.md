# Test plan — trust-ci vulnerable pins

## Risk-based scenarios

| Priority | Scenario | Evidence |
| --- | --- | --- |
| P0 | Trust CI suite on new pins | trust-ci tests (266 OK) |
| P1 | OSV clean for trust-ci | `getzilla_vulns.py --online` |

## Automated checks

- Unit: Trust CI suite.
- Integration: n/a.
- Contract: n/a.
- E2E: n/a.
- Static analysis: OSV.

## Manual checks

- None.
