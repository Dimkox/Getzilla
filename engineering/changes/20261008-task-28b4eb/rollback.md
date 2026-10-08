# Rollback plan — Refreeze the migration digest after the package rename

## Trigger conditions

The change misbehaves in verification.

## Application rollback

Revert the fix commit.

## Data recovery / forward-fix

No data is involved.

## Verification after rollback

factory/tests/test_landing_api.py.
