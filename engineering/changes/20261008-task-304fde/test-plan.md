# Test plan — Verify the OpenGrep binary digest at run time and quarantine unverified binaries (#39)

## Risk-based scenarios

| Priority | Scenario | Evidence |
| --- | --- | --- |
| P0 | PATH opengrep with wrong digest | test_binary_on_path_that_does_not_match_the_pin_is_refused_unexecuted |
| P0 | previous unverified binary on failed/mismatched update | test_unverified_previous_opengrep_is_quarantined_not_kept |
| P1 | pinned binary runs by resolved path | test_pinned_binary_runs_by_its_resolved_path |

## Automated checks

`python3 -m unittest tests.test_opengrep tests.test_updater`; `getzilla_verify.py --mode pr`.

## Manual checks

Ran `_opengrep(Path('.'))` with the real pinned v1.30.1 binary: pass.
