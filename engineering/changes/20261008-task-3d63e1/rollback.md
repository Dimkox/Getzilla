# Rollback plan — Run landing publication tests on a device-consistent filesystem

## Trigger conditions

The change misbehaves in verification.

## Application rollback

Revert the fix commit.

## Data recovery / forward-fix

No data is involved.

## Verification after rollback

factory/tests/test_landing_publication_cli.py.
