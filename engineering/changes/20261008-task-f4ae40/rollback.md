# Rollback plan — Declare the jsonschema CLI as a factory test dependency

## Trigger conditions

The change misbehaves in verification.

## Application rollback

Revert the fix commit.

## Data recovery / forward-fix

No data is involved.

## Verification after rollback

factory/tests/test_bb_contracts.py.
