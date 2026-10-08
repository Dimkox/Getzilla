# Rollback plan — Cursor rules as a harness target

## Trigger conditions

Cursor misreads the rules or a harness write fails.

## Application rollback

Revert the PR merge commit and run `python3 scripts/getzilla_harness.py --write`.

## Data recovery / forward-fix

No data is involved.

## Verification after rollback

tests/test_harnesses.py.
