# Test plan — Reject wildcard resources in delegated grants

## Risk-based scenarios

| Priority | Scenario | Evidence |
| --- | --- | --- |
| P0 | Wildcard protected-path grant refused | `tests/test_approval_resources.py` |
| P0 | Stored pattern grant does not authorize hook/policy/AGENTS.md/trust-ci writes | `tests/test_approval_resources.py` |
| P1 | CLI refusal without traceback | `tests/test_approval_resources.py` |
| P1 | Exact grants unchanged | `tests/test_policy.py`, `tests/test_protected_write.py`, `tests/test_human_gates.py`, `tests/test_hooks.py` |

## Automated checks

- Unit: `python -m pytest -n 2 tests/test_approval_resources.py tests/test_policy.py tests/test_hooks.py tests/test_human_gates.py tests/test_protected_write*.py tests/test_runtime_state.py tests/test_change_receipts.py` (119 passed before freeze).
- Static analysis: ruff, bandit clean on changed files.
- Final: `python3 scripts/getzilla_verify.py --mode pr`.

## Manual checks

- None.
