# Test plan — fix main ci failures 19-23

## Risk-based scenarios

| Priority | Scenario | Evidence |
| --- | --- | --- |
| P0 | OpenGrep stage present and allowed to skip | tests/test_opengrep.py, tests/test_quality_gates.py |
| P1 | Architecture drift, landing digest, OSV, bandit | tests/test_architecture_model.py, tests/test_getzilla_landing.py, `getzilla_vulns.py --online`, bandit |

## Automated checks

- Unit: full Core suite (pytest-xdist) and pilot tests.
- Integration: factory-unit; Trust CI suite on the new pins.
- Contract: contract-structure.
- E2E: seo-landing chrome runner (Node 24).
- Static analysis: ruff, bandit, OpenGrep, OSV.

## Manual checks

- Local replay of the linux CI job (gz_ci_local.sh).
