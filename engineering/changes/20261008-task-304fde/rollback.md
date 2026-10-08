# Rollback plan — Verify the OpenGrep binary digest at run time and quarantine unverified binaries (#39)

## Trigger conditions

Valid pinned installs refused by the verifier.

## Application rollback

Revert the `fix(verify)` commit; the regression test commit then fails and documents the reopened issue.

## Data recovery / forward-fix

None; quarantined binaries can be restored by hand.

## Verification after rollback

`python3 -m unittest tests.test_opengrep tests.test_updater`.
