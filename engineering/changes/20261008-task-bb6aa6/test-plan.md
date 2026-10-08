# Test plan — Cursor rules as a harness target

## Risk-based scenarios

| Priority | Scenario | Evidence |
| --- | --- | --- |
| P0 | Committed Cursor rules match sources, documented frontmatter, core prohibitions | tests/test_harnesses.py |
| P0 | Symlinked directory refused, 0644, stale extras removed | tests/test_harnesses.py |
| P0 | One delivery order in five documents; weakenings rejected | tests/test_delivery_sequence.py |
| P1 | `.cursor/**` protected | tests/test_harnesses.py, tests/test_harness_hook_payloads.py, tests/test_structure.py |

## Automated checks

- Unit: the modules above.
- Integration: `getzilla_verify.py --mode pr`.
- Contract: n/a.
- E2E: n/a.
- Static analysis: ruff, bandit and OpenGrep via verify.

## Manual checks

- Mutation probes in a private 0700 copy (results in the PR body).
- Live Cursor: NOT_RUN (owner).
