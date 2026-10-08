# Test plan — Remove predecessor name from the freeze digest comment

## Risk-based scenarios

| Priority | Scenario | Evidence |
| --- | --- | --- |
| P0 | Identity scan clean | test_no_predecessor_product_names_in_live_files |

## Automated checks

- Unit: tests/test_getzilla_identity.py.
- Integration: `getzilla_verify.py --mode pr`.
- Contract: n/a.
- E2E: n/a.
- Static analysis: ruff, bandit and OpenGrep via verify.

## Manual checks

- Found by the full verify of main 07b461c on 2026-10-08.
