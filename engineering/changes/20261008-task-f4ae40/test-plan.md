# Test plan — Declare the jsonschema CLI as a factory test dependency

## Risk-based scenarios

| Priority | Scenario | Evidence |
| --- | --- | --- |
| P0 | No CLI: semantic tests pass, 3 skipped | uv run --project factory |
| P1 | CLI present: 31 pass | uv run --with jsonschema==4.25.1 |

## Automated checks

- Unit: factory/tests/test_bb_contracts.py.
- Integration: `getzilla_verify.py --mode pr`.
- Contract: n/a.
- E2E: n/a.
- Static analysis: ruff, bandit and OpenGrep via verify.

## Manual checks

- Ran both scenarios on the box.
