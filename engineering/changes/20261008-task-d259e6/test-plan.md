# Test plan — Queue provenance analysis converges on list-append loops

## Risk-based scenarios

| Priority | Scenario | Evidence |
| --- | --- | --- |
| P0 | List-append loop converges (also with pre-filled lists in nested loops); queue in/after loop still flagged | `test_list_append_loops_converge_in_queue_importing_modules` |
| P0 | architecture_diff.py and spec.py (via adapter) analysable within default limits | `test_getzilla_architecture_diff_is_queue_analyzable_within_default_limits` |
| P1 | Unchanged bindings do not consume value budget | `test_unchanged_bindings_do_not_consume_queue_value_budget` |

## Automated checks

- Unit: tests/test_architecture_fitness.py (147 existing plus 3 new).
- Integration: architecture fitness inside `getzilla_verify.py --mode pr`.
- Contract: n/a.
- E2E: n/a.
- Static analysis: ruff, bandit and OpenGrep via verify.

## Manual checks

- Re-ran fitness on the stacked bugfix branch (verification.py edit): FIT-BOUNDED-WORKER-JOBS no longer unsupported.
