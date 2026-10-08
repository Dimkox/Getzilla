# Test plan — Skip real-process adapter tests on unsupported hosts

## Risk-based scenarios

| Priority | Scenario | Evidence |
| --- | --- | --- |
| P0 | Unsupported host: 9 skipped, 4 pass | test_linux_process_adapter |
| P1 | Supported host: 13 run | unchanged tests |

## Automated checks

- Unit: factory/tests/test_linux_process_adapter.py.
- Integration: `getzilla_verify.py --mode pr`.
- Contract: n/a.
- E2E: n/a.
- Static analysis: ruff, bandit and OpenGrep via verify.

## Manual checks

- Ran `uv run --project factory python -m unittest factory.tests.test_linux_process_adapter` on the box: before 7 errors + 2 failures, after OK (skipped=9).
