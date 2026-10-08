# Test plan — Pin summary soundness of sequence widening

## Risk-based scenarios

| Priority | Scenario | Evidence |
| --- | --- | --- |
| P0 | Pre-loop queue survives widening | test_sequence_widening_keeps_pre_loop_queue_in_its_summary |

## Automated checks

- Unit: tests/test_architecture_fitness.py.
- Integration: `getzilla_verify.py --mode pr`.
- Contract: n/a.
- E2E: n/a.
- Static analysis: ruff, bandit and OpenGrep via verify.

## Manual checks

- Mutation check recorded in evidence/mutation-m4.md. The independent review report is in evidence/independent-review-prs-29-31.md.
