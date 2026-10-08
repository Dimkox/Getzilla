# Rollback plan — Remove predecessor name from the freeze digest comment

## Trigger conditions

The change misbehaves in verification.

## Application rollback

Revert the fix commit.

## Data recovery / forward-fix

No data is involved.

## Verification after rollback

tests/test_getzilla_identity.py.
