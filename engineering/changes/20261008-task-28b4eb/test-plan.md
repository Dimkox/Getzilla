# Test plan — Refreeze the migration digest after the package rename

## Risk-based scenarios

| Priority | Scenario | Evidence |
| --- | --- | --- |
| P0 | Freeze test passes on the current tree | test_landing_api |
| P1 | Any byte change to the frozen files fails | digest comparison |

## Automated checks

- Unit: factory/tests/test_landing_api.py.
- Integration: `getzilla_verify.py --mode pr`.
- Contract: n/a.
- E2E: n/a.
- Static analysis: ruff, bandit and OpenGrep via verify.

## Manual checks

- `git diff ceea797 HEAD -- factory/contracts side-projects/seo-landing-showcase factory/src/getzilla_factory/resources` reviewed; migrations recomputed under old paths give the old digest 7f66b4b7.
