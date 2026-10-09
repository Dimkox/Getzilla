# Rollback plan — Pin and checksum third-party tool downloads in the updater

## Trigger conditions

A pinned asset becomes unavailable upstream.

## Application rollback

Revert the `fix(update)` commit; the regression test commit then fails and documents the reopened issue.

## Data recovery / forward-fix

No data; forward-fix by bumping the pin.

## Verification after rollback

`python -m unittest tests.test_updater`.
