# Rollback plan — Move the informational Windows full suite to a nightly workflow

## Trigger conditions

The change misbehaves in verification.

## Application rollback

Revert the fix commit.

## Data recovery / forward-fix

No data is involved.

## Verification after rollback

tests/test_structure.py.
