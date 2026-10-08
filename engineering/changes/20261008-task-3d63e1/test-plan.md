# Test plan — Run landing publication tests on a device-consistent filesystem

## Risk-based scenarios

| Priority | Scenario | Evidence |
| --- | --- | --- |
| P0 | Fixture target satisfies the device invariant | test_fixture_target_is_on_a_device_consistent_filesystem |
| P1 | Publication tests pass on the box | test_landing_publication_cli (87 tests incl. backup/live executors) |

## Automated checks

- Unit: factory/tests/test_landing_publication_cli.py.
- Integration: `getzilla_verify.py --mode pr`.
- Contract: n/a.
- E2E: n/a.
- Static analysis: ruff, bandit and OpenGrep via verify.

## Manual checks

- Reproduced on main with `uv run --project factory python -m unittest factory.tests.test_landing_publication_cli` (7 failures); after the fix 87/87 pass across the three landing publication modules.
