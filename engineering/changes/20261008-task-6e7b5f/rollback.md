# Rollback plan — Pin summary soundness of sequence widening

## Trigger conditions

The change misbehaves in verification.

## Application rollback

Revert the fix commit.

## Data recovery / forward-fix

No data is involved.

## Verification after rollback

tests/test_architecture_fitness.py.
